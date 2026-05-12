use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::strategy_schema::{
    bytes_to_value, mask_match, value_to_bytes, AccessKind, ActionSpec, GuidanceFile, TriggerSpec,
};

static RUNTIME: OnceLock<Mutex<Option<RuntimeState>>> = OnceLock::new();

#[derive(Debug, Default, Clone)]
struct UartRuntimeState {
    armed: bool,
    status_issued: bool,
    await_d_window_remaining: u64,
    data_pos: usize,
}

#[derive(Debug, Clone)]
struct ActionRuntime {
    spec: ActionSpec,
    /// Semantic completion count. For example, a UART handshake increments this only when the
    /// whole handshake completes.
    fire_count: u64,
    /// Low-level event count. This increments every time the action actually changes or observes
    /// an MMIO access and is used by the online strategy scheduler.
    event_fire_count: u64,
    sequence_pos: usize,
    gate_armed: bool,
    uart: UartRuntimeState,
}

impl ActionRuntime {
    fn new(spec: ActionSpec) -> Self {
        Self {
            spec,
            fire_count: 0,
            event_fire_count: 0,
            sequence_pos: 0,
            gate_armed: false,
            uart: UartRuntimeState::default(),
        }
    }

    fn reset_for_execution(&mut self) {
        self.fire_count = 0;
        self.event_fire_count = 0;
        self.sequence_pos = 0;
        self.gate_armed = false;
        self.uart = UartRuntimeState::default();
    }
}

#[derive(Debug)]
struct StrategyEngine {
    guidance: GuidanceFile,
    summary_out: Option<PathBuf>,
    exec_counter: u64,
    global_reads: u64,
    global_writes: u64,
    read_touches: HashMap<u64, u64>,
    write_touches: HashMap<u64, u64>,
    active_stages: BTreeSet<String>,
    actions: Vec<ActionRuntime>,
    write_observations: Vec<WriteObservation>,
    verbose: bool,
}

#[derive(Debug)]
struct StrategyCatalog {
    candidates: Vec<StrategyCandidate>,
    active: usize,
    exec_counter: u64,
    next_explore: usize,
    warmup_execs: u64,
    explore_every: u64,
    summary_every: u64,
    summary_out: Option<PathBuf>,
    verbose: bool,
}

#[derive(Debug)]
struct StrategyCandidate {
    id: String,
    source: Option<PathBuf>,
    engine: StrategyEngine,
    stats: StrategyStats,
}

#[derive(Debug, Clone, Serialize, Default)]
struct StrategyStats {
    execs: u64,
    finds: u64,
    new_bits: u64,
    hangs: u64,
    crashes: u64,
    interrupted: u64,
    total_fire_count: u64,
    last_fire_count: u64,
    total_exec_micros: u128,
    score: f64,
}

#[derive(Debug)]
enum RuntimeState {
    Single(StrategyEngine),
    Catalog(StrategyCatalog),
}

#[derive(Debug, Clone, Serialize)]
struct WriteObservation {
    addr_hex: String,
    value_hex: String,
    write_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ActionSummary {
    index: usize,
    action_type: String,
    fire_count: u64,
    event_fire_count: u64,
    sequence_pos: usize,
    gate_armed: bool,
    uart_armed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineSummary {
    plan_name: String,
    exec_counter: u64,
    global_reads: u64,
    global_writes: u64,
    active_stages: Vec<String>,
    read_touches: Vec<(String, u64)>,
    write_touches: Vec<(String, u64)>,
    write_observations: Vec<WriteObservation>,
    actions: Vec<ActionSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct CandidateSummary {
    id: String,
    source: Option<String>,
    plan_name: String,
    action_count: usize,
    is_active: bool,
    stats: StrategyStats,
    active_engine: Option<EngineSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct CatalogSummary {
    schema: String,
    mode: String,
    exec_counter: u64,
    active_index: usize,
    active_id: String,
    warmup_execs: u64,
    explore_every: u64,
    summary_every: u64,
    candidates: Vec<CandidateSummary>,
}

#[derive(Debug, Deserialize)]
struct CatalogManifest {
    #[serde(default)]
    candidates: Vec<CatalogCandidateSpec>,
}

#[derive(Debug, Deserialize)]
struct CatalogCandidateSpec {
    id: Option<String>,
    guidance_path: PathBuf,
}

fn addr_hex(addr: u64) -> String {
    format!("0x{addr:08X}")
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn default_summary_out(guidance_path: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MF_MMIO_GUIDANCE_SUMMARY_OUT") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    if let Ok(observer_out) = std::env::var("MF_STREAM_OBSERVER_OUT") {
        if !observer_out.trim().is_empty() {
            return Some(PathBuf::from(observer_out).join("guidance_runtime_summary.json"));
        }
    }
    Some(guidance_path.with_extension("runtime_summary.json"))
}

fn default_catalog_summary_out(base: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MF_MMIO_GUIDANCE_SUMMARY_OUT") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    if let Ok(observer_out) = std::env::var("MF_STREAM_OBSERVER_OUT") {
        if !observer_out.trim().is_empty() {
            return Some(PathBuf::from(observer_out).join("strategy_catalog_runtime_summary.json"));
        }
    }
    if base.is_dir() {
        Some(base.join("strategy_catalog_runtime_summary.json"))
    }
    else {
        Some(base.with_file_name("strategy_catalog_runtime_summary.json"))
    }
}

fn runtime_cell() -> &'static Mutex<Option<RuntimeState>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
}

fn build_engine_from_guidance(
    guidance: GuidanceFile,
    summary_out: Option<PathBuf>,
    verbose: bool,
) -> StrategyEngine {
    StrategyEngine {
        guidance: guidance.clone(),
        summary_out,
        exec_counter: 0,
        global_reads: 0,
        global_writes: 0,
        read_touches: HashMap::new(),
        write_touches: HashMap::new(),
        active_stages: BTreeSet::new(),
        actions: guidance.actions.into_iter().map(ActionRuntime::new).collect(),
        write_observations: Vec::new(),
        verbose,
    }
}

fn build_control_engine(verbose: bool) -> StrategyEngine {
    build_engine_from_guidance(
        GuidanceFile {
            schema: "mf_runtime_strategy_v1".to_string(),
            plan_name: "control".to_string(),
            rationale: Some("No runtime guidance. Online scheduler baseline arm.".to_string()),
            actions: Vec::new(),
        },
        None,
        verbose,
    )
}

fn build_engine_from_path(path: &Path, summary_out: Option<PathBuf>, verbose: bool) -> Result<StrategyEngine> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read guidance {}", path.display()))?;
    let guidance: GuidanceFile = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse guidance {}", path.display()))?;
    guidance
        .validate()
        .with_context(|| format!("invalid guidance {}", path.display()))?;

    eprintln!(
        "[strategy-runtime] loaded guidance: path={} plan={} actions={}",
        path.display(),
        guidance.plan_name,
        guidance.actions.len()
    );
    if verbose {
        for (idx, action) in guidance.actions.iter().enumerate() {
            eprintln!("[strategy-runtime] action[{idx}] type={}", action.kind_name());
        }
    }

    Ok(build_engine_from_guidance(guidance, summary_out, verbose))
}

fn candidate_id_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|x| x.to_str())
        .map(|x| x.to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn load_catalog_from_dir(dir: &Path, verbose: bool) -> Result<StrategyCatalog> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read strategy dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");
        if file_name.contains("summary") {
            continue;
        }
        if path.extension().and_then(|x| x.to_str()) == Some("json") {
            entries.push(path);
        }
    }
    entries.sort();

    let mut candidates = Vec::new();
    candidates.push(StrategyCandidate {
        id: "control".to_string(),
        source: None,
        engine: build_control_engine(verbose),
        stats: StrategyStats::default(),
    });

    for path in entries {
        let id = candidate_id_from_path(&path);
        match build_engine_from_path(&path, None, verbose) {
            Ok(engine) => candidates.push(StrategyCandidate {
                id,
                source: Some(path),
                engine,
                stats: StrategyStats::default(),
            }),
            Err(e) => eprintln!("[strategy-runtime] skipping candidate: {e:#}"),
        }
    }

    if candidates.len() == 1 {
        anyhow::bail!("no valid guidance JSON files found in {}", dir.display());
    }

    Ok(StrategyCatalog::new(candidates, default_catalog_summary_out(dir), verbose))
}

fn load_catalog_from_manifest(path: &Path, verbose: bool) -> Result<StrategyCatalog> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read strategy catalog {}", path.display()))?;
    let manifest: CatalogManifest = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse strategy catalog {}", path.display()))?;

    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut candidates = Vec::new();
    candidates.push(StrategyCandidate {
        id: "control".to_string(),
        source: None,
        engine: build_control_engine(verbose),
        stats: StrategyStats::default(),
    });

    for spec in manifest.candidates {
        let guidance_path = if spec.guidance_path.is_absolute() {
            spec.guidance_path
        }
        else {
            base_dir.join(spec.guidance_path)
        };
        let id = spec.id.unwrap_or_else(|| candidate_id_from_path(&guidance_path));
        match build_engine_from_path(&guidance_path, None, verbose) {
            Ok(engine) => candidates.push(StrategyCandidate {
                id,
                source: Some(guidance_path),
                engine,
                stats: StrategyStats::default(),
            }),
            Err(e) => eprintln!("[strategy-runtime] skipping candidate: {e:#}"),
        }
    }

    if candidates.len() == 1 {
        anyhow::bail!("no valid guidance candidates found in {}", path.display());
    }

    Ok(StrategyCatalog::new(candidates, default_catalog_summary_out(path), verbose))
}

fn ensure_runtime_loaded_from_env() {
    let mut guard = runtime_cell().lock().unwrap();
    if guard.is_some() {
        return;
    }

    let verbose = env_bool("MF_MMIO_GUIDANCE_VERBOSE", false);

    if let Some(path) = std::env::var_os("MF_MMIO_GUIDANCE_CATALOG") {
        let path = PathBuf::from(path);
        match load_catalog_from_manifest(&path, verbose) {
            Ok(catalog) => {
                eprintln!(
                    "[strategy-runtime] loaded online strategy catalog: manifest={} candidates={}",
                    path.display(),
                    catalog.candidates.len()
                );
                *guard = Some(RuntimeState::Catalog(catalog));
            }
            Err(e) => eprintln!("[strategy-runtime] {e:#}"),
        }
        return;
    }

    if let Some(dir) = std::env::var_os("MF_MMIO_GUIDANCE_DIR") {
        let dir = PathBuf::from(dir);
        match load_catalog_from_dir(&dir, verbose) {
            Ok(catalog) => {
                eprintln!(
                    "[strategy-runtime] loaded online strategy catalog: dir={} candidates={}",
                    dir.display(),
                    catalog.candidates.len()
                );
                *guard = Some(RuntimeState::Catalog(catalog));
            }
            Err(e) => eprintln!("[strategy-runtime] {e:#}"),
        }
        return;
    }

    let Some(path) = std::env::var_os("MF_MMIO_GUIDANCE_FILE") else {
        return;
    };
    let path = PathBuf::from(path);
    let summary_out = default_summary_out(&path);
    match build_engine_from_path(&path, summary_out, verbose) {
        Ok(engine) => *guard = Some(RuntimeState::Single(engine)),
        Err(e) => eprintln!("[strategy-runtime] {e:#}"),
    }
}

fn with_runtime<F>(f: F)
where
    F: FnOnce(&mut RuntimeState),
{
    ensure_runtime_loaded_from_env();
    let Ok(mut guard) = runtime_cell().lock() else {
        return;
    };
    let Some(runtime) = guard.as_mut() else {
        return;
    };
    f(runtime);
}

pub fn clear_guidance() {
    let mut guard = runtime_cell().lock().unwrap();
    *guard = None;
}

pub fn load_guidance_from_file(path: &Path, summary_out: Option<PathBuf>) -> Result<()> {
    let verbose = env_bool("MF_MMIO_GUIDANCE_VERBOSE", false);
    let engine = build_engine_from_path(path, summary_out, verbose)?;
    let mut guard = runtime_cell().lock().unwrap();
    *guard = Some(RuntimeState::Single(engine));
    Ok(())
}

pub fn snapshot_summary() -> Option<EngineSummary> {
    ensure_runtime_loaded_from_env();
    let Ok(guard) = runtime_cell().lock() else {
        return None;
    };
    match guard.as_ref()? {
        RuntimeState::Single(engine) => Some(engine_summary(engine)),
        RuntimeState::Catalog(catalog) => Some(engine_summary(&catalog.candidates[catalog.active].engine)),
    }
}

fn engine_summary(st: &StrategyEngine) -> EngineSummary {
    let mut read_touches: Vec<_> = st
        .read_touches
        .iter()
        .map(|(k, v)| (addr_hex(*k), *v))
        .collect();
    read_touches.sort_by(|a, b| a.0.cmp(&b.0));
    let mut write_touches: Vec<_> = st
        .write_touches
        .iter()
        .map(|(k, v)| (addr_hex(*k), *v))
        .collect();
    write_touches.sort_by(|a, b| a.0.cmp(&b.0));
    EngineSummary {
        plan_name: st.guidance.plan_name.clone(),
        exec_counter: st.exec_counter,
        global_reads: st.global_reads,
        global_writes: st.global_writes,
        active_stages: st.active_stages.iter().cloned().collect(),
        read_touches,
        write_touches,
        write_observations: st.write_observations.clone(),
        actions: st
            .actions
            .iter()
            .enumerate()
            .map(|(idx, a)| ActionSummary {
                index: idx,
                action_type: a.spec.kind_name().to_string(),
                fire_count: a.fire_count,
                event_fire_count: a.event_fire_count,
                sequence_pos: a.sequence_pos,
                gate_armed: a.gate_armed,
                uart_armed: a.uart.armed,
            })
            .collect(),
    }
}

fn write_engine_summary(st: &StrategyEngine) {
    let Some(path) = st.summary_out.as_ref() else {
        return;
    };
    let summary = engine_summary(st);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(&summary) {
        let _ = fs::write(path, text);
    }
}

fn access_matches(expected: Option<AccessKind>, actual: AccessKind) -> bool {
    match expected {
        None => true,
        Some(v) => v == actual,
    }
}

fn trigger_match_read(
    trigger: &TriggerSpec,
    addr: u64,
    global_reads: u64,
    read_touches: &HashMap<u64, u64>,
    active_stages: &BTreeSet<String>,
) -> bool {
    match trigger {
        TriggerSpec::AfterGlobalReads { value } => global_reads >= *value,
        TriggerSpec::OnFirstTouch { addr: taddr, access } => {
            *taddr == addr
                && access_matches(*access, AccessKind::Read)
                && read_touches.get(&addr).copied().unwrap_or(0) == 1
        }
        TriggerSpec::OnNthTouch { addr: taddr, n, access } => {
            *taddr == addr
                && access_matches(*access, AccessKind::Read)
                && read_touches.get(&addr).copied().unwrap_or(0) == *n
        }
        TriggerSpec::WhenStageActive { stage } => active_stages.contains(stage),
        TriggerSpec::AfterWrite { .. } | TriggerSpec::AfterWriteValue { .. } => false,
    }
}

fn trigger_match_write(
    trigger: &TriggerSpec,
    addr: u64,
    value: u64,
    write_touches: &HashMap<u64, u64>,
    active_stages: &BTreeSet<String>,
) -> bool {
    match trigger {
        TriggerSpec::AfterWrite { addr: taddr } => *taddr == addr,
        TriggerSpec::AfterWriteValue { addr: taddr, mask, value: expected } => {
            *taddr == addr && mask_match(value, *mask, *expected)
        }
        TriggerSpec::OnFirstTouch { addr: taddr, access } => {
            *taddr == addr
                && access_matches(*access, AccessKind::Write)
                && write_touches.get(&addr).copied().unwrap_or(0) == 1
        }
        TriggerSpec::OnNthTouch { addr: taddr, n, access } => {
            *taddr == addr
                && access_matches(*access, AccessKind::Write)
                && write_touches.get(&addr).copied().unwrap_or(0) == *n
        }
        TriggerSpec::WhenStageActive { stage } => active_stages.contains(stage),
        TriggerSpec::AfterGlobalReads { .. } => false,
    }
}

fn overwrite_buf(buf: &mut [u8], value: u64) {
    let bytes = value_to_bytes(value, buf.len());
    buf.copy_from_slice(&bytes[..buf.len()]);
}

fn bit_update_buf(buf: &mut [u8], set_bits: &[u64], clear_bits: &[u64]) {
    let mut value = bytes_to_value(buf);
    for bit in set_bits {
        if *bit < 64 {
            value |= 1u64 << bit;
        }
    }
    for bit in clear_bits {
        if *bit < 64 {
            value &= !(1u64 << bit);
        }
    }
    overwrite_buf(buf, value);
}

fn maybe_activate_stage(action: &ActionSpec, active_stages: &mut BTreeSet<String>) {
    if let Some(stage) = action.activate_stage() {
        active_stages.insert(stage.to_string());
    }
}

impl StrategyEngine {
    fn on_reset(&mut self) {
        if self.verbose && (self.global_reads > 0 || self.global_writes > 0) {
            eprintln!(
                "[strategy-runtime] reset exec={} reads={} writes={} active_stages={:?}",
                self.exec_counter, self.global_reads, self.global_writes, self.active_stages
            );
        }
        if self.global_reads > 0 || self.global_writes > 0 {
            write_engine_summary(self);
        }
        self.exec_counter += 1;
        self.global_reads = 0;
        self.global_writes = 0;
        self.read_touches.clear();
        self.write_touches.clear();
        self.active_stages.clear();
        self.write_observations.clear();
        for action in &mut self.actions {
            action.reset_for_execution();
        }
    }

    fn current_event_fire_count(&self) -> u64 {
        self.actions.iter().map(|a| a.event_fire_count).sum()
    }

    fn on_write(&mut self, addr: u64, value_bytes: &[u8]) {
        self.global_writes += 1;
        *self.write_touches.entry(addr).or_insert(0) += 1;
        let value = bytes_to_value(value_bytes);
        if self.write_observations.len() < 256 {
            self.write_observations.push(WriteObservation {
                addr_hex: addr_hex(addr),
                value_hex: format!("0x{value:08X}"),
                write_count: self.write_touches.get(&addr).copied().unwrap_or(0),
            });
        }
        if self.verbose {
            eprintln!(
                "[strategy-runtime] write addr={} value=0x{:08X} write_count={} global_writes={}",
                addr_hex(addr),
                value,
                self.write_touches.get(&addr).copied().unwrap_or(0),
                self.global_writes
            );
        }

        let write_touches = &self.write_touches;
        let active_stages_snapshot = self.active_stages.clone();
        for action in &mut self.actions {
            match &action.spec {
                ActionSpec::MmioWriteObserve { addr: target, mask, value: expected, trigger, .. } => {
                    let value_ok = match expected {
                        Some(v) => mask_match(value, *mask, *v),
                        None => true,
                    };
                    if *target == addr
                        && value_ok
                        && trigger_match_write(trigger, addr, value, write_touches, &active_stages_snapshot)
                    {
                        action.fire_count += 1;
                        action.event_fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] fire write_observe addr={} fire_count={}",
                                addr_hex(addr),
                                action.fire_count
                            );
                        }
                    }
                }
                ActionSpec::MmioWriteThenReadGate {
                    write_addr,
                    write_mask,
                    write_value,
                    trigger,
                    ..
                } => {
                    let value_ok = match write_value {
                        Some(v) => mask_match(value, *write_mask, *v),
                        None => true,
                    };
                    if *write_addr == addr
                        && value_ok
                        && trigger_match_write(trigger, addr, value, write_touches, &active_stages_snapshot)
                    {
                        action.gate_armed = true;
                        action.event_fire_count += 1;
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] armed write_then_read_gate write_addr={} action_type={}",
                                addr_hex(addr),
                                action.spec.kind_name()
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        if self.verbose {
            write_engine_summary(self);
        }
    }

    fn on_read(&mut self, addr: u64, buf: &mut [u8]) {
        self.global_reads += 1;
        *self.read_touches.entry(addr).or_insert(0) += 1;

        let global_reads = self.global_reads;
        let read_touches = &self.read_touches;
        let active_stages_snapshot = self.active_stages.clone();
        let touch_count = self.read_touches.get(&addr).copied().unwrap_or(0);

        for action in &mut self.actions {
            match &action.spec {
                ActionSpec::MmioReadOverrideOnce { addr: target, width, value, trigger, .. } => {
                    if action.fire_count == 0
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        overwrite_buf(buf, *value);
                        action.fire_count = 1;
                        action.event_fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] fire read_override_once addr={} value=0x{:08X} global_reads={} touch_count={}",
                                addr_hex(addr),
                                value,
                                global_reads,
                                touch_count
                            );
                        }
                    }
                }
                ActionSpec::MmioReadOverrideRepeat { addr: target, width, value, repeat, trigger, .. } => {
                    if action.fire_count < *repeat
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        overwrite_buf(buf, *value);
                        action.fire_count += 1;
                        action.event_fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] fire read_override_repeat addr={} value=0x{:08X} fire_count={} global_reads={} touch_count={}",
                                addr_hex(addr),
                                value,
                                action.fire_count,
                                global_reads,
                                touch_count
                            );
                        }
                    }
                }
                ActionSpec::MmioReadSequence { addr: target, width, values, trigger, .. } => {
                    if action.sequence_pos < values.len()
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        let value = values[action.sequence_pos];
                        overwrite_buf(buf, value);
                        action.sequence_pos += 1;
                        action.event_fire_count += 1;
                        if action.sequence_pos == values.len() {
                            action.fire_count += 1;
                            maybe_activate_stage(&action.spec, &mut self.active_stages);
                        }
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] fire read_sequence addr={} value=0x{:08X} seq_pos={} global_reads={} touch_count={}",
                                addr_hex(addr),
                                value,
                                action.sequence_pos,
                                global_reads,
                                touch_count
                            );
                        }
                    }
                }
                ActionSpec::MmioBitUpdate { addr: target, width, set_bits, clear_bits, trigger, .. } => {
                    if action.fire_count == 0
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        bit_update_buf(buf, set_bits, clear_bits);
                        action.fire_count = 1;
                        action.event_fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] fire bit_update addr={} set_bits={:?} clear_bits={:?} global_reads={} touch_count={}",
                                addr_hex(addr),
                                set_bits,
                                clear_bits,
                                global_reads,
                                touch_count
                            );
                        }
                    }
                }
                ActionSpec::MmioWriteThenReadGate { read_addr, width, read_value, .. } => {
                    if action.gate_armed && *read_addr == addr && *width == buf.len() {
                        overwrite_buf(buf, *read_value);
                        action.gate_armed = false;
                        action.fire_count += 1;
                        action.event_fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] fire write_then_read_gate read_addr={} value=0x{:08X} fire_count={}",
                                addr_hex(addr),
                                read_value,
                                action.fire_count
                            );
                        }
                    }
                }
                ActionSpec::UartHandshakeOnce {
                    s1_addr,
                    d_addr,
                    s1_value,
                    data_bytes,
                    d_window_accesses,
                    trigger,
                    ..
                } => {
                    if !action.uart.armed
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        action.uart.armed = true;
                        if self.verbose {
                            eprintln!(
                                "[strategy-runtime] armed uart_handshake_once s1={} d={} global_reads={}",
                                addr_hex(*s1_addr),
                                addr_hex(*d_addr),
                                global_reads
                            );
                        }
                    }

                    if action.uart.armed {
                        if addr == *s1_addr && !action.uart.status_issued {
                            overwrite_buf(buf, *s1_value);
                            action.uart.status_issued = true;
                            action.uart.await_d_window_remaining = *d_window_accesses;
                            action.event_fire_count += 1;
                            if self.verbose {
                                eprintln!(
                                    "[strategy-runtime] fire uart status addr={} value=0x{:02X} window={}",
                                    addr_hex(addr),
                                    s1_value,
                                    d_window_accesses
                                );
                            }
                        }
                        else if action.uart.await_d_window_remaining > 0 {
                            if addr == *d_addr {
                                let value = data_bytes.get(action.uart.data_pos).copied().unwrap_or(0);
                                if !buf.is_empty() {
                                    buf[0] = value;
                                    for b in buf.iter_mut().skip(1) {
                                        *b = 0;
                                    }
                                }
                                action.uart.data_pos += 1;
                                action.event_fire_count += 1;
                                if action.uart.data_pos >= data_bytes.len() {
                                    action.uart.armed = false;
                                    action.uart.status_issued = false;
                                    action.uart.await_d_window_remaining = 0;
                                    action.fire_count += 1;
                                    maybe_activate_stage(&action.spec, &mut self.active_stages);
                                }
                                if self.verbose {
                                    eprintln!(
                                        "[strategy-runtime] fire uart data addr={} byte=0x{:02X} pos={} fire_count={}",
                                        addr_hex(addr),
                                        value,
                                        action.uart.data_pos,
                                        action.fire_count
                                    );
                                }
                            }
                            else {
                                action.uart.await_d_window_remaining -= 1;
                                if action.uart.await_d_window_remaining == 0 {
                                    action.uart.armed = false;
                                    action.uart.status_issued = false;
                                    action.uart.data_pos = 0;
                                }
                            }
                        }
                    }
                }
                ActionSpec::MmioWriteObserve { .. } => {}
            }
        }
        if self.verbose {
            write_engine_summary(self);
        }
    }
}

impl StrategyCatalog {
    fn new(candidates: Vec<StrategyCandidate>, summary_out: Option<PathBuf>, verbose: bool) -> Self {
        Self {
            candidates,
            active: 0,
            exec_counter: 0,
            next_explore: 0,
            warmup_execs: env_u64("MF_STRATEGY_WARMUP_EXECS", 50),
            explore_every: env_u64("MF_STRATEGY_EXPLORE_EVERY", 10),
            summary_every: env_u64("MF_STRATEGY_SUMMARY_EVERY", 500),
            summary_out,
            verbose,
        }
    }

    fn select_candidate(&mut self) -> usize {
        if let Some((idx, _)) = self
            .candidates
            .iter()
            .enumerate()
            .find(|(_, c)| c.stats.execs < self.warmup_execs)
        {
            return idx;
        }

        if self.explore_every > 0 && self.exec_counter % self.explore_every == 0 {
            let idx = self.next_explore % self.candidates.len();
            self.next_explore = self.next_explore.wrapping_add(1);
            return idx;
        }

        self.candidates
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.stats
                    .score
                    .partial_cmp(&b.stats.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.stats.execs.cmp(&a.stats.execs))
            })
            .map(|(idx, _)| idx)
            .unwrap_or(0)
    }

    fn on_reset(&mut self) {
        self.exec_counter += 1;
        self.active = self.select_candidate();
        if self.verbose {
            eprintln!(
                "[strategy-runtime] active_strategy={} exec={}",
                self.candidates[self.active].id,
                self.exec_counter
            );
        }
        self.candidates[self.active].engine.on_reset();
    }

    fn on_read(&mut self, addr: u64, buf: &mut [u8]) {
        self.candidates[self.active].engine.on_read(addr, buf)
    }

    fn on_write(&mut self, addr: u64, value: &[u8]) {
        self.candidates[self.active].engine.on_write(addr, value)
    }

    fn record_outcome(
        &mut self,
        new_coverage: bool,
        new_bits: u64,
        hang: bool,
        crash: bool,
        interrupted: bool,
        exec_micros: u128,
    ) {
        let fire_count = self.candidates[self.active].engine.current_event_fire_count();
        let should_write_summary = {
            let stats = &mut self.candidates[self.active].stats;
            stats.execs += 1;
            stats.last_fire_count = fire_count;
            stats.total_fire_count += fire_count;
            stats.total_exec_micros += exec_micros;
            if new_coverage {
                stats.finds += 1;
                stats.new_bits += new_bits;
            }
            if hang {
                stats.hangs += 1;
            }
            if crash {
                stats.crashes += 1;
            }
            if interrupted {
                stats.interrupted += 1;
            }

            let mut reward = 0.0;
            if new_coverage {
                reward += 10.0 + (new_bits.min(200) as f64 * 0.05);
            }
            else if fire_count > 0 {
                // A strategy that fires frequently but does not produce new coverage should be tried
                // less often. This avoids wasting long runs on over-eager MMIO overrides.
                reward -= (fire_count.min(100) as f64) * 0.01;
            }
            if hang {
                reward -= 1.0;
            }
            if crash {
                reward -= 5.0;
            }
            if interrupted {
                reward -= 1.0;
            }
            if exec_micros > 1_000_000 {
                reward -= 0.5;
            }

            stats.score = if stats.execs == 1 {
                reward
            }
            else {
                (stats.score * 0.80) + (reward * 0.20)
            };

            new_coverage || self.summary_every == 0 || stats.execs % self.summary_every == 0
        };

        if should_write_summary {
            self.write_summary();
        }
    }

    fn summary(&self) -> CatalogSummary {
        CatalogSummary {
            schema: "mf_runtime_strategy_catalog_summary_v1".to_string(),
            mode: "online_strategy_catalog".to_string(),
            exec_counter: self.exec_counter,
            active_index: self.active,
            active_id: self.candidates[self.active].id.clone(),
            warmup_execs: self.warmup_execs,
            explore_every: self.explore_every,
            summary_every: self.summary_every,
            candidates: self
                .candidates
                .iter()
                .enumerate()
                .map(|(idx, c)| CandidateSummary {
                    id: c.id.clone(),
                    source: c.source.as_ref().map(|p| p.display().to_string()),
                    plan_name: c.engine.guidance.plan_name.clone(),
                    action_count: c.engine.actions.len(),
                    is_active: idx == self.active,
                    stats: c.stats.clone(),
                    active_engine: if idx == self.active {
                        Some(engine_summary(&c.engine))
                    }
                    else {
                        None
                    },
                })
                .collect(),
        }
    }

    fn write_summary(&self) {
        let Some(path) = self.summary_out.as_ref() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&self.summary()) {
            let _ = fs::write(path, text);
        }
    }
}

pub fn on_execution_reset() {
    with_runtime(|runtime| match runtime {
        RuntimeState::Single(engine) => engine.on_reset(),
        RuntimeState::Catalog(catalog) => catalog.on_reset(),
    })
}

pub fn on_mmio_write(addr: u64, value: &[u8]) {
    with_runtime(|runtime| match runtime {
        RuntimeState::Single(engine) => engine.on_write(addr, value),
        RuntimeState::Catalog(catalog) => catalog.on_write(addr, value),
    })
}

pub fn on_mmio_read(addr: u64, buf: &mut [u8]) {
    with_runtime(|runtime| match runtime {
        RuntimeState::Single(engine) => engine.on_read(addr, buf),
        RuntimeState::Catalog(catalog) => catalog.on_read(addr, buf),
    })
}

pub fn on_execution_outcome(
    new_coverage: bool,
    new_bits: u64,
    hang: bool,
    crash: bool,
    interrupted: bool,
    exec_micros: u128,
) {
    with_runtime(|runtime| match runtime {
        RuntimeState::Single(engine) => {
            if engine.global_reads > 0 || engine.global_writes > 0 || new_coverage {
                write_engine_summary(engine);
            }
        }
        RuntimeState::Catalog(catalog) => catalog.record_outcome(
            new_coverage,
            new_bits,
            hang,
            crash,
            interrupted,
            exec_micros,
        ),
    })
}
