use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use serde::Serialize;

use crate::strategy_schema::{
    bytes_to_value, mask_match, value_to_bytes, AccessKind, ActionSpec, GuidanceFile, TriggerSpec,
};

static ENGINE: OnceLock<Option<Mutex<StrategyEngine>>> = OnceLock::new();

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
    fire_count: u64,
    sequence_pos: usize,
    gate_armed: bool,
    uart: UartRuntimeState,
}

impl ActionRuntime {
    fn new(spec: ActionSpec) -> Self {
        Self {
            spec,
            fire_count: 0,
            sequence_pos: 0,
            gate_armed: false,
            uart: UartRuntimeState::default(),
        }
    }

    fn reset_for_execution(&mut self) {
        self.fire_count = 0;
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
    sequence_pos: usize,
    gate_armed: bool,
    uart_armed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct EngineSummary {
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

fn addr_hex(addr: u64) -> String {
    format!("0x{addr:08X}")
}

fn default_summary_out(guidance_path: &PathBuf) -> Option<PathBuf> {
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

fn load_engine() -> Option<Mutex<StrategyEngine>> {
    let path = std::env::var_os("MF_MMIO_GUIDANCE_FILE")?;
    let path = PathBuf::from(path);
    let text = fs::read_to_string(&path).ok()?;
    let guidance: GuidanceFile = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[strategy-runtime] failed to parse guidance {}: {e}", path.display());
            return None;
        }
    };
    if let Err(e) = guidance.validate() {
        eprintln!("[strategy-runtime] invalid guidance {}: {e:#}", path.display());
        return None;
    }

    eprintln!(
        "[strategy-runtime] loaded guidance: path={} plan={} actions={}",
        path.display(),
        guidance.plan_name,
        guidance.actions.len()
    );
    for (idx, action) in guidance.actions.iter().enumerate() {
        eprintln!("[strategy-runtime] action[{idx}] type={}", action.kind_name());
    }

    Some(Mutex::new(StrategyEngine {
        guidance: guidance.clone(),
        summary_out: default_summary_out(&path),
        exec_counter: 0,
        global_reads: 0,
        global_writes: 0,
        read_touches: HashMap::new(),
        write_touches: HashMap::new(),
        active_stages: BTreeSet::new(),
        actions: guidance.actions.into_iter().map(ActionRuntime::new).collect(),
        write_observations: Vec::new(),
    }))
}

fn with_engine<F>(f: F)
where
    F: FnOnce(&mut StrategyEngine),
{
    let Some(engine) = ENGINE.get_or_init(load_engine).as_ref() else {
        return;
    };
    let Ok(mut st) = engine.lock() else {
        return;
    };
    f(&mut st);
}

fn write_summary(st: &StrategyEngine) {
    let Some(path) = st.summary_out.as_ref() else {
        return;
    };
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
    let summary = EngineSummary {
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
                sequence_pos: a.sequence_pos,
                gate_armed: a.gate_armed,
                uart_armed: a.uart.armed,
            })
            .collect(),
    };
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
        TriggerSpec::AfterWriteValue {
            addr: taddr,
            mask,
            value: expected,
        } => *taddr == addr && mask_match(value, *mask, *expected),
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

fn maybe_activate_stage(spec: &ActionSpec, stages: &mut BTreeSet<String>) {
    if let Some(stage) = spec.activate_stage() {
        stages.insert(stage.to_string());
    }
}

fn overwrite_buf(buf: &mut [u8], value: u64) {
    let bytes = value_to_bytes(value, buf.len());
    buf.copy_from_slice(&bytes);
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

impl StrategyEngine {
    fn on_reset(&mut self) {
        if self.global_reads > 0 || self.global_writes > 0 {
            eprintln!(
                "[strategy-runtime] reset exec={} reads={} writes={} active_stages={:?}",
                self.exec_counter, self.global_reads, self.global_writes, self.active_stages
            );
            write_summary(self);
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

    fn on_write(&mut self, addr: u64, value_bytes: &[u8]) {
        self.global_writes += 1;
        *self.write_touches.entry(addr).or_insert(0) += 1;
        let value = bytes_to_value(value_bytes);
        self.write_observations.push(WriteObservation {
            addr_hex: addr_hex(addr),
            value_hex: format!("0x{value:08X}"),
            write_count: self.write_touches.get(&addr).copied().unwrap_or(0),
        });
        eprintln!(
            "[strategy-runtime] write addr={} value=0x{:08X} write_count={} global_writes={}",
            addr_hex(addr),
            value,
            self.write_touches.get(&addr).copied().unwrap_or(0),
            self.global_writes
        );

        let write_touches = &self.write_touches;
        let active_stages_snapshot = self.active_stages.clone();
        for action in &mut self.actions {
            match &action.spec {
                ActionSpec::MmioWriteObserve {
                    addr: target,
                    mask,
                    value: expected,
                    trigger,
                    ..
                } => {
                    let value_ok = match expected {
                        Some(v) => mask_match(value, *mask, *v),
                        None => true,
                    };
                    if *target == addr
                        && value_ok
                        && trigger_match_write(trigger, addr, value, write_touches, &active_stages_snapshot)
                    {
                        action.fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        eprintln!(
                            "[strategy-runtime] fire write_observe addr={} fire_count={}",
                            addr_hex(addr),
                            action.fire_count
                        );
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
                        eprintln!(
                            "[strategy-runtime] armed write_then_read_gate write_addr={} action_type={}",
                            addr_hex(addr),
                            action.spec.kind_name()
                        );
                    }
                }
                _ => {}
            }
        }
        write_summary(self);
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
                ActionSpec::MmioReadOverrideOnce {
                    addr: target,
                    width,
                    value,
                    trigger,
                    ..
                } => {
                    if action.fire_count == 0
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        overwrite_buf(buf, *value);
                        action.fire_count = 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        eprintln!(
                            "[strategy-runtime] fire read_override_once addr={} value=0x{:08X} global_reads={} touch_count={}",
                            addr_hex(addr),
                            value,
                            global_reads,
                            touch_count
                        );
                    }
                }
                ActionSpec::MmioReadOverrideRepeat {
                    addr: target,
                    width,
                    value,
                    repeat,
                    trigger,
                    ..
                } => {
                    if action.fire_count < *repeat
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        overwrite_buf(buf, *value);
                        action.fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
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
                ActionSpec::MmioReadSequence {
                    addr: target,
                    width,
                    values,
                    trigger,
                    ..
                } => {
                    if action.sequence_pos < values.len()
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        let value = values[action.sequence_pos];
                        overwrite_buf(buf, value);
                        action.sequence_pos += 1;
                        if action.sequence_pos == values.len() {
                            action.fire_count += 1;
                            maybe_activate_stage(&action.spec, &mut self.active_stages);
                        }
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
                ActionSpec::MmioBitUpdate {
                    addr: target,
                    width,
                    set_bits,
                    clear_bits,
                    trigger,
                    ..
                } => {
                    if action.fire_count == 0
                        && *target == addr
                        && *width == buf.len()
                        && trigger_match_read(trigger, addr, global_reads, read_touches, &active_stages_snapshot)
                    {
                        bit_update_buf(buf, set_bits, clear_bits);
                        action.fire_count = 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
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
                ActionSpec::MmioWriteThenReadGate {
                    read_addr,
                    width,
                    read_value,
                    ..
                } => {
                    if action.gate_armed && *read_addr == addr && *width == buf.len() {
                        overwrite_buf(buf, *read_value);
                        action.gate_armed = false;
                        action.fire_count += 1;
                        maybe_activate_stage(&action.spec, &mut self.active_stages);
                        eprintln!(
                            "[strategy-runtime] fire write_then_read_gate read_addr={} value=0x{:08X} fire_count={}",
                            addr_hex(addr),
                            read_value,
                            action.fire_count
                        );
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
                        eprintln!(
                            "[strategy-runtime] armed uart_handshake_once s1={} d={} global_reads={}",
                            addr_hex(*s1_addr),
                            addr_hex(*d_addr),
                            global_reads
                        );
                    }

                    if action.uart.armed {
                        if addr == *s1_addr && !action.uart.status_issued {
                            overwrite_buf(buf, *s1_value);
                            action.uart.status_issued = true;
                            action.uart.await_d_window_remaining = *d_window_accesses;
                            eprintln!(
                                "[strategy-runtime] fire uart status addr={} value=0x{:02X} window={}",
                                addr_hex(addr),
                                s1_value,
                                d_window_accesses
                            );
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
                                if action.uart.data_pos >= data_bytes.len() {
                                    action.uart.armed = false;
                                    action.uart.status_issued = false;
                                    action.uart.await_d_window_remaining = 0;
                                    action.fire_count += 1;
                                    maybe_activate_stage(&action.spec, &mut self.active_stages);
                                }
                                eprintln!(
                                    "[strategy-runtime] fire uart data addr={} byte=0x{:02X} pos={} fire_count={}",
                                    addr_hex(addr),
                                    value,
                                    action.uart.data_pos,
                                    action.fire_count
                                );
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
        write_summary(self);
    }
}

pub fn on_execution_reset() {
    with_engine(|st| st.on_reset())
}

pub fn on_mmio_write(addr: u64, value: &[u8]) {
    with_engine(|st| st.on_write(addr, value))
}

pub fn on_mmio_read(addr: u64, buf: &mut [u8]) {
    with_engine(|st| st.on_read(addr, buf))
}
