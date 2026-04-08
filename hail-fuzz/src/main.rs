mod config;
mod coverage;
mod debug_alloc;
mod debugging;
mod fixed_trial;
mod dictionary;
mod extension;
mod havoc;
mod i2s;
mod input;
mod load_resizer;
mod monitor;
mod mutations;
mod p2im_unit_tests;
mod queue;
mod trim;
mod utils;
mod stream_observer;
mod strategy_schema;
mod strategy_runtime;

use std::{
    any::Any,
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context};
use hashbrown::{HashMap, HashSet};
use icicle_cortexm::{config::FirmwareConfig, genconfig, CortexmTarget};
use icicle_fuzzing::{
    cmplog2::CmpLog2Ref, parse_u64_with_prefix, utils::BlockCoverageTracker, CoverageMode,
    CrashKind, FuzzConfig, FuzzTarget, Runnable,
};
use icicle_vm::{
    cpu::{utils::UdpWriter, ExceptionCode},
    Vm, VmExit,
};
use rand::{rngs::SmallRng, seq::SliceRandom, Rng, SeedableRng};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    config::{Config, DebugSettings},
    coverage::{count_all_bits, CoverageAny},
    debugging::trace::{self, PathTracerRef},
    dictionary::{Dictionary, DictionaryRef, MultiStreamDict},
    extension::LengthExtData,
    input::{CortexmMultiStream, MultiStream, StreamKey},
    load_resizer::LoadResizeInjector,
    monitor::{CrashLogger, Monitor},
    mutations::random_input,
    queue::{CorpusStore, CoverageQueue, GlobalQueue, GlobalRef, InputId, InputQueue, InputSource},
};



fn de_u64_auto<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Int(u64),
        Str(String),
    }

    match Repr::deserialize(deserializer)? {
        Repr::Int(v) => Ok(v),
        Repr::Str(s) => parse_u64_with_prefix(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid integer: {s}"))),
    }
}

#[derive(Debug, Deserialize)]
struct FixedSweepTrialSpec {
    #[serde(deserialize_with = "de_u64_auto")]
    addr: u64,
    #[serde(default = "default_trial_touch", deserialize_with = "de_u64_auto")]
    nth_touch: u64,
}

fn default_trial_touch() -> u64 {
    1
}

#[derive(Debug, Deserialize)]
struct FixedSweepCandidateSpec {
    id: String,
    #[serde(default)]
    guidance_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct FixedSweepManifest {
    schema: String,
    input_path: PathBuf,
    trial: FixedSweepTrialSpec,
    #[serde(default = "default_continue_delta", deserialize_with = "de_u64_auto")]
    continue_icount_delta: u64,
    #[serde(default)]
    summary_out: Option<PathBuf>,
    candidates: Vec<FixedSweepCandidateSpec>,
}

fn default_continue_delta() -> u64 {
    200_000
}

#[derive(Debug, Serialize)]
struct FixedSweepTrialSummary {
    addr: String,
    nth_touch: u64,
    trial_pc: u64,
    trial_icount: u64,
}

#[derive(Debug, Serialize)]
struct FixedSweepCandidateResult {
    id: String,
    guidance_path: Option<String>,
    exit: String,
    exit_pc: u64,
    icount: u64,
    new_coverage: bool,
    new_bits: usize,
    coverage_bits: u64,
    guidance_summary: Option<crate::strategy_runtime::EngineSummary>,
}

#[derive(Debug, Serialize)]
struct FixedSweepSummary {
    schema: String,
    manifest_path: String,
    input_path: String,
    trial: FixedSweepTrialSummary,
    results: Vec<FixedSweepCandidateResult>,
}




#[derive(Debug, Clone, Serialize)]
struct ExecTraceEventRow {
    step: u64,
    event_type: String,
    pc: Option<String>,
    sp: Option<String>,
    icount: Option<u64>,
    fuzz_offset: Option<u32>,
    last_read: Option<String>,
    last_value: Option<String>,
    function: Option<String>,
    block: Option<String>,
    mmio_addr: Option<String>,
    mmio_value: Option<String>,
    mmio_size: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
struct ExecTraceRecord {
    exec_index: u64,
    input_id: Option<u64>,
    stage: String,
    exit: String,
    exit_pc: String,
    instructions: u64,
    event_count: usize,
    block_event_count: usize,
    mmio_read_count: usize,
    events: Vec<ExecTraceEventRow>,
}

#[derive(Debug, Clone, Serialize)]
struct ExecTraceMeta {
    schema: String,
    workdir: String,
    track_path_forced: bool,
    total_recorded_execs: usize,
    max_execs_kept: usize,
    max_blocks_per_exec: usize,
    trace_json: Option<String>,
    trace_text: Option<String>,
    latest_exec_index: Option<u64>,
    latest_event_count: usize,
    latest_block_event_count: usize,
    latest_mmio_read_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ExecTraceFile {
    schema: String,
    workdir: String,
    total_recorded_execs: usize,
    latest_exec: Option<ExecTraceRecord>,
    recent_execs: Vec<ExecTraceRecord>,
    events: Vec<ExecTraceEventRow>,
}

struct SessionTraceRecorder {
    json_out: Option<PathBuf>,
    text_out: Option<PathBuf>,
    meta_out: Option<PathBuf>,
    workdir: PathBuf,
    max_execs: usize,
    max_blocks: usize,
    symbolize: bool,
    track_path_forced: bool,
    total_recorded_execs: usize,
    recent_execs: VecDeque<ExecTraceRecord>,
}

impl SessionTraceRecorder {
    fn trace_requested_from_env() -> bool {
        Self::first_env_path(&[
            "MF_EXEC_TRACE_OUT",
            "MF_TRACE_OUT",
            "MF_RUNTIME_TRACE_OUT",
            "MF_EXEC_TRACE_TEXT_OUT",
            "MF_TRACE_TEXT_OUT",
            "MF_RUNTIME_TRACE_TEXT_OUT",
            "MF_EXEC_TRACE_META_OUT",
            "MF_TRACE_META_OUT",
            "MF_RUNTIME_TRACE_META_OUT",
        ])
        .is_some()
    }

    fn first_env_path(keys: &[&str]) -> Option<PathBuf> {
        for key in keys {
            if let Some(value) = std::env::var_os(key) {
                if !value.is_empty() {
                    let path = PathBuf::from(value);
                    if !path.as_os_str().is_empty() {
                        return Some(path);
                    }
                }
            }
        }
        None
    }

    fn parse_usize_env(keys: &[&str], default: usize) -> usize {
        for key in keys {
            if let Ok(v) = std::env::var(key) {
                if let Ok(parsed) = v.trim().parse::<usize>() {
                    return parsed;
                }
            }
        }
        default
    }

    fn parse_bool_env(keys: &[&str], default: bool) -> bool {
        for key in keys {
            if let Ok(v) = std::env::var(key) {
                match v.trim().to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "y" | "on" => return true,
                    "0" | "false" | "no" | "n" | "off" => return false,
                    _ => {}
                }
            }
        }
        default
    }

    fn from_env(workdir: &Path) -> Option<Self> {
        if !Self::trace_requested_from_env() {
            return None;
        }

        let json_out = Self::first_env_path(&["MF_EXEC_TRACE_OUT", "MF_TRACE_OUT", "MF_RUNTIME_TRACE_OUT"])
            .or_else(|| Some(workdir.join("replay_trace.json")));
        let text_out = Self::first_env_path(&[
            "MF_EXEC_TRACE_TEXT_OUT",
            "MF_TRACE_TEXT_OUT",
            "MF_RUNTIME_TRACE_TEXT_OUT",
        ])
        .or_else(|| Some(workdir.join("replay_trace.log")));
        let meta_out = Self::first_env_path(&[
            "MF_EXEC_TRACE_META_OUT",
            "MF_TRACE_META_OUT",
            "MF_RUNTIME_TRACE_META_OUT",
        ])
        .or_else(|| Some(workdir.join("replay_trace.meta.json")));

        Some(Self {
            json_out,
            text_out,
            meta_out,
            workdir: workdir.to_path_buf(),
            max_execs: Self::parse_usize_env(&["MF_TRACE_MAX_EXECS", "MF_EXEC_TRACE_MAX_EXECS"], 8).max(1),
            max_blocks: Self::parse_usize_env(&["MF_TRACE_MAX_BLOCKS", "MF_EXEC_TRACE_MAX_BLOCKS"], 4096).max(64),
            symbolize: Self::parse_bool_env(&["MF_TRACE_SYMBOLIZE", "MF_EXEC_TRACE_SYMBOLIZE"], true),
            track_path_forced: Self::parse_bool_env(&["MF_TRACE_TRACK_PATH_FORCED"], false),
            total_recorded_execs: 0,
            recent_execs: VecDeque::new(),
        })
    }

    fn maybe_symbolize(vm: &mut Vm, pc: u64) -> (Option<String>, Option<String>) {
        let location = vm
            .env
            .symbolize_addr(&mut vm.cpu, pc)
            .unwrap_or(icicle_vm::cpu::debug_info::SourceLocation::default());
        let rendered = format!("{location}").trim().to_string();
        if rendered.is_empty() {
            return (None, None);
        }
        let mut func = rendered
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split('+')
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| matches!(c, '[' | ']' | '(' | ')' | ','))
            .to_string();
        if func.is_empty() || func.starts_with("0x") {
            func.clear();
        }
        (if func.is_empty() { None } else { Some(func) }, Some(rendered))
    }

    fn ensure_parent(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    fn record_execution(
        &mut self,
        vm: &mut Vm,
        tracer: PathTracerRef,
        exec_index: u64,
        input_id: Option<usize>,
        stage: Stage,
        exit: VmExit,
        exit_pc: u64,
        instructions: u64,
    ) {
        let blocks = tracer.get_last_blocks(vm);
        let mmio_reads = tracer.get_mmio_reads(vm);

        let total_blocks = blocks.len();
        let keep_from = total_blocks.saturating_sub(self.max_blocks);
        let trimmed_blocks = &blocks[keep_from..];

        let mut events = Vec::with_capacity(trimmed_blocks.len() + mmio_reads.len());
        let mut step = 0u64;
        for entry in trimmed_blocks {
            let (function, block) = if self.symbolize {
                Self::maybe_symbolize(vm, entry.pc)
            } else {
                (None, None)
            };
            events.push(ExecTraceEventRow {
                step,
                event_type: "exec".to_string(),
                pc: Some(format!("0x{:08X}", entry.pc)),
                sp: Some(format!("0x{:08X}", entry.sp)),
                icount: Some(entry.icount),
                fuzz_offset: Some(entry.fuzz_offset),
                last_read: Some(format!("0x{:08X}", entry.last_read)),
                last_value: Some(format!("0x{:08X}", entry.last_value)),
                function,
                block,
                mmio_addr: None,
                mmio_value: None,
                mmio_size: None,
            });
            step += 1;
        }

        for &(addr, value, size) in &mmio_reads {
            events.push(ExecTraceEventRow {
                step,
                event_type: "mmio_read".to_string(),
                pc: None,
                sp: None,
                icount: None,
                fuzz_offset: None,
                last_read: None,
                last_value: None,
                function: None,
                block: None,
                mmio_addr: Some(format!("0x{:08X}", addr)),
                mmio_value: Some(format!("0x{:X}", value)),
                mmio_size: Some(size),
            });
            step += 1;
        }

        let record = ExecTraceRecord {
            exec_index,
            input_id: input_id.map(|x| x as u64),
            stage: format!("{:?}", stage),
            exit: format!("{:?}", exit),
            exit_pc: format!("0x{:08X}", exit_pc),
            instructions,
            event_count: events.len(),
            block_event_count: trimmed_blocks.len(),
            mmio_read_count: mmio_reads.len(),
            events,
        };

        self.total_recorded_execs += 1;
        self.recent_execs.push_back(record);
        while self.recent_execs.len() > self.max_execs {
            self.recent_execs.pop_front();
        }
        self.flush();
    }

    fn latest_exec(&self) -> Option<&ExecTraceRecord> {
        self.recent_execs.back()
    }

    fn flush(&self) {
        let latest = self.latest_exec().cloned();
        if let Some(path) = &self.json_out {
            Self::ensure_parent(path);
            let payload = ExecTraceFile {
                schema: "mf_exec_trace_v1".to_string(),
                workdir: self.workdir.display().to_string(),
                total_recorded_execs: self.total_recorded_execs,
                latest_exec: latest.clone(),
                recent_execs: self.recent_execs.iter().cloned().collect(),
                events: latest.as_ref().map(|x| x.events.clone()).unwrap_or_default(),
            };
            if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
                let _ = std::fs::write(path, bytes);
            }
        }

        if let Some(path) = &self.text_out {
            Self::ensure_parent(path);
            let mut out = String::new();
            if let Some(latest) = &latest {
                out.push_str(&format!(
                    "exec={} stage={} exit={} exit_pc={} instructions={}\\n",
                    latest.exec_index, latest.stage, latest.exit, latest.exit_pc, latest.instructions
                ));
                for ev in &latest.events {
                    match ev.event_type.as_str() {
                        "exec" => {
                            out.push_str(&format!(
                                "step={} pc={} icount={} function={} block={} last_read={} last_value={}\\n",
                                ev.step,
                                ev.pc.as_deref().unwrap_or(""),
                                ev.icount.unwrap_or(0),
                                ev.function.as_deref().unwrap_or(""),
                                ev.block.as_deref().unwrap_or(""),
                                ev.last_read.as_deref().unwrap_or(""),
                                ev.last_value.as_deref().unwrap_or(""),
                            ));
                        }
                        "mmio_read" => {
                            out.push_str(&format!(
                                "step={} mmio=read addr={} value={} size={}\\n",
                                ev.step,
                                ev.mmio_addr.as_deref().unwrap_or(""),
                                ev.mmio_value.as_deref().unwrap_or(""),
                                ev.mmio_size.unwrap_or(0),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            let _ = std::fs::write(path, out);
        }

        if let Some(path) = &self.meta_out {
            Self::ensure_parent(path);
            let latest = self.latest_exec();
            let payload = ExecTraceMeta {
                schema: "mf_exec_trace_meta_v1".to_string(),
                workdir: self.workdir.display().to_string(),
                track_path_forced: self.track_path_forced,
                total_recorded_execs: self.total_recorded_execs,
                max_execs_kept: self.max_execs,
                max_blocks_per_exec: self.max_blocks,
                trace_json: self.json_out.as_ref().map(|x| x.display().to_string()),
                trace_text: self.text_out.as_ref().map(|x| x.display().to_string()),
                latest_exec_index: latest.map(|x| x.exec_index),
                latest_event_count: latest.map(|x| x.event_count).unwrap_or(0),
                latest_block_event_count: latest.map(|x| x.block_event_count).unwrap_or(0),
                latest_mmio_read_count: latest.map(|x| x.mmio_read_count).unwrap_or(0),
            };
            if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
                let _ = std::fs::write(path, bytes);
            }
        }
    }
}

fn default_ghidra_src() -> PathBuf {
    let candidates = [PathBuf::from("./tools/ghidra"), PathBuf::from("./ghidra")];
    for path in candidates {
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("./tools/ghidra")
}

fn main() {
    let logger = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::from_env("ICICLE_LOG")
            .add_directive("cranelift_jit=warn".parse().unwrap())
            .add_directive("cranelift_codegen=warn".parse().unwrap()),
    );

    match std::env::var("ICICLE_LOG_ADDR").ok() {
        Some(addr) => {
            let addr = Arc::new(addr);
            logger
                .with_writer(move || std::io::BufWriter::new(UdpWriter::new(addr.as_ref())))
                .init()
        }
        None => logger.with_writer(std::io::stderr).init(),
    }

    if let Err(e) = run() {
        eprintln!("Error running fuzzer: {e:?}");
        std::process::exit(1);
    }
}


fn import_seed_inputs(global_queue: &Arc<GlobalQueue<MultiStream>>, dir: &Path, label: &str) -> anyhow::Result<usize> {
    if !dir.exists() {
        tracing::warn!("seed import dir does not exist ({}): {}", label, dir.display());
        return Ok(0);
    }
    if !dir.is_dir() {
        tracing::warn!("seed import path is not a directory ({}): {}", label, dir.display());
        return Ok(0);
    }

    let mut imported = 0usize;
    for entry in std::fs::read_dir(dir).with_context(|| format!("failed to read seed dir: {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        match MultiStream::from_path(&path) {
            Ok(input) => {
                global_queue.add_new(usize::MAX, input);
                imported += 1;
            }
            Err(err) => {
                tracing::error!("error importing seed `{}`: {err:#}", path.display());
            }
        }
    }

    tracing::info!("imported {} seed inputs from {} ({})", imported, dir.display(), label);
    eprintln!("[import] imported {} seeds from {} ({})", imported, dir.display(), label);
    Ok(imported)
}

fn import_optional_seed_dirs(
    global_queue: &Arc<GlobalQueue<MultiStream>>,
    workdir: &Path,
    resume_enabled: bool,
) -> anyhow::Result<usize> {
    let mut total = 0usize;

    if resume_enabled {
        total += import_seed_inputs(global_queue, &workdir.join("imports"), "resume-imports")?;
    }

    if let Some(raw) = std::env::var_os("MF_IMPORT_DIR") {
        for dir in std::env::split_paths(&raw) {
            total += import_seed_inputs(global_queue, &dir, "mf-import-dir")?;
        }
    }

    Ok(total)
}

fn run() -> anyhow::Result<()> {
    if let Some(path) = std::env::var_os("GENCONFIG") {
        return genconfig::generate_and_save(path.as_ref(), false);
    }
    if let Some(path) = std::env::var_os("FORCE_GENCONFIG") {
        return genconfig::generate_and_save(path.as_ref(), true);
    }

    if std::env::var_os("GHIDRA_SRC").is_none() {
        let ghidra_src = default_ghidra_src();
        // Safety: There are no other threads running yet.
        unsafe {
            std::env::set_var("GHIDRA_SRC", ghidra_src);
        }
    }

    let mut fuzzer_config = FuzzConfig::load().expect("Invalid config");

    let trace_requested = SessionTraceRecorder::trace_requested_from_env();
    if trace_requested && !fuzzer_config.track_path {
        tracing::info!("forcing track_path because runtime trace dumping was requested");
        fuzzer_config.track_path = true;
        unsafe {
            std::env::set_var("MF_TRACE_TRACK_PATH_FORCED", "1");
        }
    }

    // Icicle implements a shadow stack to catch return address corruption which is enabled by
    // default. However, this results in false positives crashes for firmware that implements
    // task-switching, so we disable it unless requested by the user.
    if std::env::var_os("ICICLE_ENABLE_SHADOW_STACK").is_none() {
        fuzzer_config.enable_shadow_stack = false;
    }

    if std::env::var_os("COVERAGE_MODE").is_none() {
        fuzzer_config.coverage_mode = CoverageMode::Blocks;
    }

    let interrupt_flag = config::add_ctrlc_handler();

    if let Some(path) = std::env::var_os("P2IM_UNIT_TESTS") {
        return p2im_unit_tests::run(fuzzer_config, path.as_ref(), interrupt_flag);
    }

    // We allow the fuzzer config to be passed either as an environment variable or from a file.
    let config_arg = std::env::args().nth(1);
    let firmware_config = match config_arg.as_deref() {
        Some("") | None => FirmwareConfig::from_env()?,
        Some(arg) => FirmwareConfig::from_path(arg.as_ref())?,
    };

    let workdir =
        std::path::PathBuf::from(std::env::var_os("WORKDIR").unwrap_or_else(|| "./workdir".into()));
    let config =
        Config { fuzzer: fuzzer_config, workdir, firmware: firmware_config, interrupt_flag };

    if let Some(path) = std::env::var_os("MF_FIXED_SWEEP_MANIFEST") {
        return run_fixed_sweep(config, path.as_ref());
    }

    if let Ok(path) = std::env::var("REPLAY") {
        return debugging::replay(config, &path);
    }
    if let Ok(path) = std::env::var("ANALYZE_CRASHES") {
        return debugging::analyze_crashes(config, &path);
    }
    if let Some(path) = std::env::var_os("RUN_I2S_STAGE") {
        return debugging::stage::run_stage(config, path.as_ref(), Stage::InputToState);
    }
    match std::env::var("GEN_BLOCK_COVERAGE").as_deref() {
        Ok("0") | Err(_) => {}
        Ok(mode) => {
            let mode = mode.parse().unwrap();
            return debugging::save_block_coverage(config, mode);
        }
    }

    tracing::info!("Starting fuzzer");
    let _workdir_lock = config::init_workdir(&config).with_context(|| {
        format!("Failed to initialize working directory at: {}", config.workdir.display())
    })?;

    let global_queue = Arc::new(GlobalQueue::init(config.fuzzer.workers as usize));
    let imported = import_optional_seed_dirs(&global_queue, &config.workdir, config.fuzzer.resume)?;
    if imported > 0 {
        tracing::info!("Seeded global queue with {} imported inputs", imported);
        eprintln!("[import] seeded global queue with {} imported inputs", imported);
    }
    else {
        eprintln!("[import] seeded global queue with 0 imported inputs");
    }

    let monitor = Arc::new(std::sync::Mutex::new(Monitor::new()));
    let global = GlobalRef::new(0, global_queue, Some(monitor));

    let run_for = match std::env::var("RUN_FOR") {
        Ok(duration) => Some(
            utils::parse_duration_str(duration.trim())
                .ok_or_else(|| anyhow::format_err!("Invalid duration specified: {duration}"))?,
        ),
        Err(_) => None,
    };

    std::thread::scope(|s| -> anyhow::Result<()> {
        for id in 1..config.fuzzer.workers {
            tracing::info!("spawning worker: {id}");

            let config = config.clone();
            let global = global.clone_with_id(id as usize);

            std::thread::Builder::new()
                .name(format!("worker-{id}"))
                .spawn_scoped(s, move || {
                    if let Err(e) =
                        Fuzzer::new(config, global).and_then(|fuzzer| fuzzing_loop(fuzzer, run_for))
                    {
                        tracing::error!("Error starting fuzzer for worker {id}: {e:?}");
                    }
                })
                .context("OS failed to spawn worker thread")?;

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Run the primary worker on the current thread (this helps for debugging and profiling).
        fuzzing_loop(Fuzzer::new(config, global)?, run_for)?;

        Ok(())
    })?;

    Ok(())
}


fn run_fixed_sweep(config: Config, manifest_path: &Path) -> anyhow::Result<()> {
    let manifest_text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read fixed sweep manifest: {}", manifest_path.display()))?;
    let manifest: FixedSweepManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("failed to parse fixed sweep manifest: {}", manifest_path.display()))?;
    if manifest.schema != "mf_fixedpoint_sweep_v1" {
        bail!("unsupported fixed sweep schema: {}", manifest.schema);
    }
    if manifest.candidates.is_empty() {
        bail!("fixed sweep manifest must contain at least one candidate");
    }

    let workdir = config.workdir.clone();
    let _workdir_lock = config::init_workdir(&config).with_context(|| {
        format!("Failed to initialize working directory at: {}", config.workdir.display())
    })?;

    let global_queue = Arc::new(GlobalQueue::init(1));
    let monitor = Arc::new(std::sync::Mutex::new(Monitor::new()));
    let global = GlobalRef::new(0, global_queue, Some(monitor));
    let mut fuzzer = Fuzzer::new(config, global)?;

    let input = MultiStream::from_path(&manifest.input_path)
        .with_context(|| format!("failed to load input: {}", manifest.input_path.display()))?;

    fixed_trial::arm(manifest.trial.addr, manifest.trial.nth_touch);
    crate::strategy_runtime::clear_guidance();
    fuzzer.state.reset();
    fuzzer.state.input = input.clone();
    Snapshot::restore_initial(&mut fuzzer);
    fuzzer.reset_input_cursor()?;
    fuzzer.write_input_to_target()?;
    let exit = fuzzer.execute().ok_or_else(|| anyhow::format_err!("trial capture interrupted"))?;
    let Some(hit) = fixed_trial::take_hit() else {
        bail!("trial point not reached before exit: {exit:?}");
    };
    let trial_snapshot = Snapshot::capture(&mut fuzzer);
    let trial_pc = fuzzer.vm.cpu.read_pc();
    let trial_icount = fuzzer.vm.cpu.icount();

    let mut results = Vec::with_capacity(manifest.candidates.len());
    for candidate in &manifest.candidates {
        trial_snapshot.restore(&mut fuzzer);
        fuzzer.state.reset();
        fuzzer.state.input = input.clone();
        fixed_trial::disable();
        crate::strategy_runtime::clear_guidance();
        if let Some(path) = candidate.guidance_path.as_ref() {
            crate::strategy_runtime::load_guidance_from_file(path, None).with_context(|| {
                format!("failed to load guidance for candidate {} from {}", candidate.id, path.display())
            })?;
        }
        crate::strategy_runtime::on_execution_reset();

        let exit_limit = trial_icount.saturating_add(manifest.continue_icount_delta);
        let exit = fuzzer
            .execute_with_limit(exit_limit)
            .ok_or_else(|| anyhow::format_err!("candidate execution interrupted: {}", candidate.id))?;
        fuzzer.check_exit_state(exit)?;

        results.push(FixedSweepCandidateResult {
            id: candidate.id.clone(),
            guidance_path: candidate
                .guidance_path
                .as_ref()
                .map(|x| x.display().to_string()),
            exit: format!("{exit:?}"),
            exit_pc: fuzzer.vm.cpu.read_pc(),
            icount: fuzzer.vm.cpu.icount(),
            new_coverage: fuzzer.state.new_coverage,
            new_bits: fuzzer.state.new_bits.len(),
            coverage_bits: fuzzer.state.coverage_bits,
            guidance_summary: crate::strategy_runtime::snapshot_summary(),
        });
    }

    let summary = FixedSweepSummary {
        schema: "mf_fixedpoint_sweep_summary_v1".to_string(),
        manifest_path: manifest_path.display().to_string(),
        input_path: manifest.input_path.display().to_string(),
        trial: FixedSweepTrialSummary {
            addr: format!("0x{:08X}", hit.addr),
            nth_touch: hit.nth_touch,
            trial_pc,
            trial_icount,
        },
        results,
    };

    let out_path = manifest
        .summary_out
        .clone()
        .unwrap_or_else(|| workdir.join("fixed_sweep_summary.json"));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out_path, serde_json::to_string_pretty(&summary)?)?;
    eprintln!("[fixed-sweep] summary written: {}", out_path.display());
    Ok(())
}

fn fuzzing_loop(mut fuzzer: Fuzzer, run_for: Option<Duration>) -> anyhow::Result<()> {
    let start_time = std::time::Instant::now();

    let span = tracing::span!(tracing::Level::INFO, "fuzz", id = fuzzer.global.id);
    let _guard = span.enter();

    let mut stats = monitor::LocalStats::default();
    while !fuzzer.vm.interrupt_flag.load(std::sync::atomic::Ordering::Relaxed)
        && run_for.map_or(true, |t| start_time.elapsed() < t)
    {
        fuzzer.state.reset();
        fuzzer.input_id = fuzzer.queue.next_input(&fuzzer.corpus);

        // Default to a very high length extension probability for randomly generated inputs. This
        // is overwritten if we are using an input from the corpus.
        let mut length_ext_prob = 0.9;

        if let Some(id) = fuzzer.input_id {
            let input = &mut fuzzer.corpus[id];

            let is_import = input.is_import;
            let has_unique_edge = input.has_unique_edge;

            // Skip non-favoured inputs with a certain probability.
            if !input.favored && fuzzer.rng.gen_bool(0.95) {
                continue;
            }

            if let std::collections::hash_map::Entry::Vacant(slot) =
                fuzzer.corpus[id].stage_data.entry(Stage::Trim)
            {
                slot.insert(Box::new(()));
                fuzzer.stage = Stage::Trim;
                if fuzzer.features.smart_trim && !is_import {
                    trim::TrimStage::run(&mut fuzzer, &mut stats)?;

                    // After trimming the input, send it to other workers.
                    if has_unique_edge {
                        fuzzer.global.add_new(fuzzer.state.input.clone());
                    }
                }
            }

            if fuzzer.features.cmplog && !is_import {
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    fuzzer.corpus[id].stage_data.entry(Stage::InputToState)
                {
                    slot.insert(Box::new(()));

                    if fuzzer.features.colorization {
                        tracing::debug!("[{id}] running colorization stage");
                        fuzzer.stage = Stage::Colorization;
                        i2s::ColorizationStage::run(&mut fuzzer, &mut stats)?;
                    }

                    tracing::debug!("[{id}] running I2S stage");
                    fuzzer.stage = Stage::InputToState;
                    i2s::I2SReplaceStage::run(&mut fuzzer, &mut stats)?;
                };
            }

            // If this is the first time we are performing length extension / havoc then update
            // `last_find` to avoid overcounting caused by executions that occured as part of the
            // i2s and trim stages.
            let input = &mut fuzzer.corpus[id];
            if input.metadata.rounds == 0 {
                input.metadata.last_find = input.metadata.execs;
                input.metadata.max_find_gap = 0;
            }
            input.metadata.rounds += 1;
            length_ext_prob = input.length_extension_prob();
        }

        let stage_exit = if !fuzzer.features.havoc || fuzzer.rng.gen_bool(length_ext_prob) {
            fuzzer.stage = Stage::MultiStreamExtend;
            extension::MultiStreamExtendStage::run(&mut fuzzer, &mut stats)?
        }
        else {
            fuzzer.stage = Stage::Havoc;
            havoc::HavocStage::run(&mut fuzzer, &mut stats)?
        };

        match stage_exit {
            StageExit::Skip => {}
            StageExit::Unknown(_) | StageExit::Interrupted => break,
            StageExit::Unsupported => {}
        }

        let new_inputs = fuzzer.corpus.inputs() - fuzzer.re_prioritization_inputs;
        if (fuzzer.re_prioritization_cycle != fuzzer.queue.cycles && new_inputs != 0)
            || new_inputs > 20
        {
            fuzzer.corpus.recompute_input_prioritization();
            fuzzer.re_prioritization_cycle = fuzzer.queue.cycles;
            fuzzer.re_prioritization_inputs = fuzzer.corpus.inputs();
        }

        fuzzer.stage = Stage::Import;
        if matches!(SyncStage::run(&mut fuzzer, &mut stats)?, StageExit::Interrupted) {
            break;
        }
    }

    if let Some(recorder) = fuzzer.exec_trace.as_ref() {
        recorder.flush();
    }

    if fuzzer.global.is_main_instance() {
        eprintln!("Fuzzing stopped, saving data");
        fuzzer.corpus.maybe_save(&fuzzer.workdir)?;

        let _ = std::fs::write(
            fuzzer.workdir.join("disasm.asm"),
            icicle_vm::debug::dump_disasm(&fuzzer.vm).unwrap(),
        );

        let mut coverage = String::new();
        fuzzer.coverage.serialize(&mut fuzzer.vm, &mut coverage);
        std::fs::write(fuzzer.workdir.join("coverage"), coverage)?;

        if icicle_fuzzing::parse_bool_env("DEBUG_IL")?.unwrap_or(false) {
            std::fs::write("il.pcode", icicle_vm::debug::dump_semantics(&fuzzer.vm)?)?;
        }
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "stage")]
pub enum MutationKind {
    Extension { stream: u64, kind: mutations::Extension },
    Mutation { stream: u64, kind: mutations::Mutation },
}

impl From<(u64, mutations::Extension)> for MutationKind {
    fn from((stream, kind): (u64, mutations::Extension)) -> Self {
        Self::Extension { stream, kind }
    }
}

impl From<(u64, mutations::Mutation)> for MutationKind {
    fn from((stream, kind): (u64, mutations::Mutation)) -> Self {
        Self::Mutation { stream, kind }
    }
}

#[derive(Default)]
pub struct State {
    /// The ID of the parent input.
    pub parent: Option<InputId>,
    /// The type of mutations performed on the source to generate `input`.
    pub mutation_kinds: Vec<MutationKind>,
    /// The current mutated fuzzing input.
    pub input: MultiStream,
    /// Is this input imported from another fuzzing instance.
    pub is_import: bool,
    /// The most recent VmExit generated by the VM.
    pub exit: VmExit,
    /// The pc at the end of the most recent execution.
    pub exit_address: u64,
    /// Did coverage increase after executing the current test case?
    pub new_coverage: bool,
    /// The time it took to execute the input.
    pub exec_time: Duration,
    /// The icount after the fuzzer finished executing the input.
    pub instructions: u64,
    /// Number of bits set in the coverage bitmap for this input (note: only updated if this input
    /// triggered new coverage).
    pub coverage_bits: u64,
    /// The new coverage bits discovered by the current test case
    pub new_bits: Vec<u32>,
    /// The list of coverage entries hit by this input
    pub hit_coverage: Vec<u32>,
}

impl State {
    pub fn reset(&mut self) {
        self.parent = None;
        self.mutation_kinds.clear();
        self.input.clear();
        self.is_import = false;
        self.exit = VmExit::Running;
        self.exit_address = 0;
        self.new_coverage = false;
        self.exec_time = Duration::ZERO;
        self.instructions = 0;
        self.coverage_bits = 0;
        self.hit_coverage.clear();
    }

    pub fn was_crash(&self) -> bool {
        CrashKind::from(self.exit).is_crash()
    }
    pub fn was_hang(&self) -> bool {
        CrashKind::from(self.exit).is_hang()
    }
}

/// A snapshot of the target at a particular point in time.
pub(crate) struct Snapshot {
    vm: icicle_vm::Snapshot,
    coverage: Box<dyn Any>,
    tracer: Option<trace::PathTracerSnapshot>,
}

impl Snapshot {
    pub fn capture(fuzzer: &mut Fuzzer) -> Self {
        Self {
            vm: fuzzer.vm.snapshot(),
            coverage: fuzzer.coverage.snapshot_local(&mut fuzzer.vm),
            tracer: fuzzer.path_tracer.map(|x| x.snapshot(&mut fuzzer.vm)),
        }
    }

    #[allow(unused)]
    pub fn restore(&self, fuzzer: &mut Fuzzer) {
        fuzzer.coverage.restore_local(&mut fuzzer.vm, &self.coverage);
        fuzzer.vm.restore(&self.vm);
        if let Some(x) = fuzzer.path_tracer {
            x.restore(&mut fuzzer.vm, self.tracer.as_ref().unwrap());
        }
        fuzzer.vm.cpu.mem.mapping_changed = false;
    }

    pub fn restore_initial(fuzzer: &mut Fuzzer) {
        fuzzer.coverage.restore_local(&mut fuzzer.vm, &fuzzer.snapshot.coverage);
        fuzzer.vm.restore(&fuzzer.snapshot.vm);
        if let Some(x) = fuzzer.path_tracer {
            x.restore(&mut fuzzer.vm, fuzzer.snapshot.tracer.as_ref().unwrap());
        }
        fuzzer.vm.cpu.mem.mapping_changed = false;
    }

    pub fn restore_prefix(fuzzer: &mut Fuzzer) {
        let snapshot = fuzzer.prefix_snapshot.as_ref().unwrap();
        fuzzer.coverage.restore_local(&mut fuzzer.vm, &snapshot.coverage);
        fuzzer.vm.restore(&snapshot.vm);
        if let Some(x) = fuzzer.path_tracer {
            x.restore(&mut fuzzer.vm, snapshot.tracer.as_ref().unwrap());
        }
        fuzzer.vm.cpu.mem.mapping_changed = false;
    }
}

pub fn setup_vm(
    config: &mut Config,
    features: &config::EnabledFeatures,
) -> anyhow::Result<(CortexmMultiStream, Vm)> {
    config.firmware.use_access_contexts = features.access_contexts;

    let mut target = CortexmTarget::new();
    let mut vm = target.create_vm(&mut config.fuzzer)?;
    vm.interrupt_flag = config.interrupt_flag.clone();
    vm.icount_limit = config.fuzzer.icount_limit;

    target.fuzzware_init(&config.firmware, &mut vm, MultiStream::default())?;

    if features.resize_load_level > 0 {
        tracing::info!("Registering load_resizer level={}", features.resize_load_level);
        let multiblock = features.resize_load_level > 1;
        let optimize_upper_bits = features.resize_load_level > 2;
        let mmio = target.mmio_handler.unwrap();
        let mut resizer = LoadResizeInjector::new(mmio, multiblock, optimize_upper_bits);
        for var in &vm.cpu.arch.temporaries {
            resizer.mark_as_temporary(*var);
        }
        vm.add_injector(resizer);
    }

    debugging::enable_checks(&mut vm)?;

    Ok((target, vm))
}

pub(crate) struct Fuzzer {
    /// Directory to store data into.
    pub workdir: PathBuf,
    /// The Vm instance use for executing the target.
    pub vm: Vm,
    /// Controls how to fuzz the target.
    pub target: CortexmMultiStream,
    /// Random number source for the fuzzer..
    pub rng: SmallRng,
    /// The root-level snapshot to restore from when running a new test case.
    pub snapshot: Snapshot,
    /// A snapshot corresponding to the execution from a prefix.
    pub prefix_snapshot: Option<Snapshot>,
    /// The current fuzzing stage.
    pub stage: Stage,
    /// A storage location for test cases.
    pub corpus: CorpusStore<MultiStream>,
    /// A queue for ordering the next test case to fuzz.
    pub queue: CoverageQueue,
    /// The ID of the current input input selected by the fuzzer.
    pub input_id: Option<InputId>,
    /// The state used for generating and monitoring test cases.
    pub state: State,
    /// Stores coverage information for the fuzzer.
    pub coverage: Box<dyn CoverageAny>,
    /// Keeps track of all the crashes discovered by the fuzzer.
    pub crash_logger: CrashLogger,
    /// Additional fuzzer configuration.
    pub config: FuzzConfig,
    /// A reference to the global state shared across fuzzing instances.
    pub global: GlobalRef,
    /// A reference to (optional) tracing instrumentation used for diagnosing fuzzing bugs.
    pub path_tracer: Option<PathTracerRef>,
    /// Session-level execution trace dumper used by the closed-loop pipeline.
    pub exec_trace: Option<SessionTraceRecorder>,
    /// A reference to CmpLog instrumentation.
    pub cmplog: Option<CmpLog2Ref>,
    /// The blocks seen by the fuzzer with the number of executions and input ID corresponding to
    /// when the first input reaching that block was found.
    pub seen_blocks: BlockCoverageTracker,
    /// Keeps track of bits (by index) in the coverage bitmap found by crashes before regular
    /// inputs.
    pub crash_coverage_bits: HashSet<u32>,
    /// The total number of executions performed by this fuzzing instance.
    pub execs: u64,
    /// The number of execs were were at the last time we found an interesting input.
    pub last_find: u64,
    /// A per stream dictionary.
    pub dict: MultiStreamDict,
    /// A global dictionary.
    pub global_dict: Dictionary,
    /// The total number of inputs stored in `dict`.
    pub dict_items: usize,
    /// The cycle count that we refreshed input prioritization at.
    pub re_prioritization_cycle: usize,
    /// The number of inputs we had when we last refreshed input prioritization.
    pub re_prioritization_inputs: usize,
    /// Controls which fuzzer features should be enabled or not. (used for benchmarking).
    pub features: config::EnabledFeatures,
    /// Controls which debugging features should be enabled.
    pub debug: config::DebugSettings,
}

impl Fuzzer {
    pub fn new_debug(config: Config) -> anyhow::Result<Self> {
        let global_queue = Arc::new(GlobalQueue::init(1));
        let monitor = Arc::new(std::sync::Mutex::new(Monitor::new()));
        let global = GlobalRef::new(0, global_queue, Some(monitor));
        Self::new(config, global)
    }

    pub fn new(mut config: Config, global: GlobalRef) -> anyhow::Result<Self> {
        let features = config::EnabledFeatures::from_env()?;
        eprintln!("HailFuzz start with features: {features:?}");
        let (mut target, mut vm) = setup_vm(&mut config, &features)?;
        icicle_fuzzing::add_debug_instrumentation(&mut vm);

        let mut path_tracer = None;
        if config.fuzzer.track_path && global.is_main_instance() {
            path_tracer = Some(trace::add_path_tracer(&mut vm, target.mmio_handler.unwrap())?);
        }
        let exec_trace = if global.is_main_instance() {
            SessionTraceRecorder::from_env(&config.workdir)
        } else {
            None
        };

        let mut cmplog = None;
        if features.cmplog {
            let check_indirect =
                icicle_fuzzing::parse_bool_env("CMPLOG_CHECK_INDIRECT")?.unwrap_or(false);
            let skip_call_instrumentation =
                icicle_fuzzing::parse_bool_env("CMPLOG_NO_CALLS")?.unwrap_or(false);
            cmplog = Some(
                icicle_fuzzing::cmplog2::CmpLog2Builder::new()
                    .instrument_calls(!skip_call_instrumentation)
                    .check_indirect_pointers(check_indirect)
                    .finish(&mut vm),
            );
        }
        let mut coverage = config::configure_coverage(&config.fuzzer, &mut vm);
        target.initialize_vm(&config.fuzzer, &mut vm)?;
        coverage.reset(&mut vm);

        // Execute until the first MMIO address is read.
        let exit = target.run(&mut vm)?;
        if !matches!(exit, VmExit::UnhandledException((ExceptionCode::ReadWatch, _))) {
            anyhow::bail!(
                "Failed to initialize VM for fuzzing execution, unexpected initial exit: {}\ncallstack:\n{}",
                target.exit_string(exit),
                icicle_vm::debug::backtrace(&mut vm)
            );
        }

        let snapshot = Snapshot {
            vm: vm.snapshot(),
            coverage: coverage.snapshot_local(&mut vm),
            tracer: path_tracer.map(|x| x.snapshot(&mut vm)),
        };
        let state = State { input: MultiStream::default(), ..State::default() };

        let rng = match std::env::var("SEED") {
            Ok(seed) => {
                let seed = parse_u64_with_prefix(&seed)
                    .ok_or_else(|| anyhow::format_err!("expected number for seed: {seed}"))?;
                tracing::info!("Using fixed seed: {seed:#x}");
                SmallRng::seed_from_u64(seed)
            }
            Err(_) => SmallRng::from_entropy(),
        };

        let crash_logger = CrashLogger::new(&config)?;

        let mut global_dict = Dictionary::default();
        if let Some(dict_path) = std::env::var_os("DICTIONARY") {
            let input = std::fs::read_to_string(&dict_path).with_context(|| {
                format!(
                    "failed to read dictionary file: {}",
                    AsRef::<Path>::as_ref(&dict_path).display()
                )
            })?;
            for entry in input.split_whitespace() {
                global_dict.add_item(entry.as_bytes(), 1 | 2 | 4);
            }
            global_dict.compute_weights();
        }

        Ok(Self {
            workdir: config.workdir,
            vm,
            target,
            snapshot,
            prefix_snapshot: None,
            queue: CoverageQueue::new(),
            stage: Stage::MultiStreamExtend,
            rng,
            corpus: CorpusStore::default(),
            input_id: None,
            state,
            coverage,
            crash_logger,
            config: config.fuzzer,
            global,
            path_tracer,
            exec_trace,
            cmplog,
            seen_blocks: BlockCoverageTracker::new(),
            crash_coverage_bits: HashSet::new(),
            execs: 0,
            last_find: 0,
            dict: HashMap::new(),
            global_dict,
            dict_items: 0,
            re_prioritization_cycle: 0,
            re_prioritization_inputs: 0,
            features,
            debug: DebugSettings::from_env()?,
        })
    }

    /// Copies the currently selected input into `state`.
    pub fn copy_current_input(&mut self) {
        self.state.reset();
        self.state.parent = self.input_id;
        match self.input_id {
            Some(id) => self.state.input.clone_from(&self.corpus[id].data),
            None => random_input(self),
        };
    }

    /// Runs the VM until it exits and updates the current fuzzing state.
    pub fn execute(&mut self) -> Option<VmExit> {
        self.execute_with_limit(self.config.icount_limit)
    }

    /// Runs the VM until it exits or executs `limit` number of instructions and update the current
    /// fuzzing state.
    pub fn execute_with_limit(&mut self, limit: u64) -> Option<VmExit> {
        let exec_start = std::time::Instant::now();

        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = limit;
        if let Some(tracer) = self.path_tracer {
            tracer.clear(&mut self.vm);
        }
        if let Some(cmplog) = self.cmplog {
            cmplog.clear_data(&mut self.vm.cpu);
        }
        let exit = self.target.run(&mut self.vm).unwrap();
        self.vm.icount_limit = old_limit;
        self.execs += 1;

        self.state.exec_time = exec_start.elapsed();
        self.state.instructions = self.vm.cpu.icount();
        self.state.exit = exit;
        self.state.exit_address = self.vm.cpu.read_pc();

        if let (Some(recorder), Some(tracer)) = (self.exec_trace.as_mut(), self.path_tracer) {
            recorder.record_execution(
                &mut self.vm,
                tracer,
                self.execs,
                self.input_id,
                self.stage,
                exit,
                self.state.exit_address,
                self.state.instructions,
            );
        }

        if matches!(exit, VmExit::Interrupted) {
            return None;
        }

        if self.global.is_main_instance() {
            let new_blocks = self.seen_blocks.add_new(&self.vm.code, self.corpus.inputs() as u64);
            if self.features.dump_jit_mapping && new_blocks {
                if let Err(e) = self
                    .vm
                    .jit
                    .dump_jit_mapping("jit_table.txt".as_ref(), self.vm.env.debug_info().unwrap())
                {
                    tracing::warn!("Failed to dump JIT table: {e}")
                }
            }

            if let Err(e) = self.seen_blocks.maybe_save(&self.workdir.join("cur_coverage.txt")) {
                tracing::error!("error saving coverage file: {e:?}");
            }
            let _ = self.corpus.maybe_save(&self.workdir);
        }

        Some(exit)
    }

    pub fn check_exit_state(&mut self, exit: VmExit) -> anyhow::Result<()> {
        if self.state.input.total_bytes() == 0 {
            // Discard zero length inputs, these can sometimes occur as a result of trimming very
            // small inputs.
            self.state.mutation_kinds.clear();
            return Ok(());
        }

        let crash_kind = CrashKind::from(exit);

        self.state.new_bits = self.coverage.new_bits(&mut self.vm);
        self.state.new_coverage = !self.state.new_bits.is_empty();
        if self.state.new_coverage {
            let bits = self.coverage.get_bits(&mut self.vm);
            self.state.coverage_bits = count_all_bits(bits);
            self.state.hit_coverage = coverage::bit_iter(bits).map(|x| x as u32).collect();

            if tracing::enabled!(tracing::Level::TRACE) {
                self.trace_new_bits();
            }
        }

        // Update coverage map if the input was non-crashing.
        //
        // Note: we intentionally save hangs here since we observe frequent hangs that reach new
        // coverage due to the nature of the hang heuristics.
        if !crash_kind.is_crash() {
            if self.state.new_coverage {
                if config::VALIDATE {
                    debugging::validate_last_exec(self, exit);
                }
                self.coverage.merge(&mut self.vm);
                self.state
                    .hit_coverage
                    .iter()
                    .for_each(|bit| _ = self.crash_coverage_bits.remove(bit));
                tracing::debug!("{} bits set in coverage map", self.coverage.count());
            }
            else if self.features.add_favored_inputs
                && self.queue.new_inputs() == 0
                && self.stage != Stage::Trim
                && self.rng.gen_bool(0.01)
            {
                // Occasionally check if the current input is favored over previous entries.
                let bits = self.coverage.get_bits(&mut self.vm);
                self.state.coverage_bits = count_all_bits(bits);
                self.state.hit_coverage = coverage::bit_iter(bits).map(|x| x as u32).collect();
                if queue::current_state_is_favored(&mut self.state, &mut self.corpus) {
                    self.state.new_coverage = true;
                }
            }

            if let Some(input_id) = self.queue.add_if_interesting(&mut self.corpus, &self.state) {
                self.update_input_metadata(input_id);
                self.last_find = self.execs;
            }
        }
        else {
            // If a crashing input contains unseen coverage, keep track of it in the input corpus
            // but mark it as crashing and do not update the coverage bitmap and queue (because we
            // want find & save a non-crashing seed to continue with).
            //
            // This is useful for identifying blocks only reachable by crashes.
            if self.state.new_coverage {
                let mut new_coverage = false;
                for bit in &self.state.new_bits {
                    new_coverage |= self.crash_coverage_bits.insert(*bit);
                }
                if new_coverage {
                    let input_id = self.corpus.add(&self.state);
                    self.update_input_metadata(input_id);
                }
            }
        }

        // Clear logged mutation events.
        self.state.mutation_kinds.clear();

        if matches!(crash_kind, CrashKind::Halt) {
            return Ok(());
        }

        if let Some(key) = self.crash_logger.add_if_new(&mut self.vm, &self.state) {
            if self.global.is_worker_instance() {
                // Send this input to the main process to save and analyze.
                // Note: hangs will already be sent if they are interesting in the code above.
                if crash_kind.is_crash() {
                    tracing::warn!("sending new crash to main process");
                    self.global.add_for_main(self.state.input.clone());
                }
            }
            else if self.global.add_crash_or_hang(key, crash_kind) {
                self.crash_logger.save(&self.state, &mut self.vm, &self.target, exit)?;
            }
        }

        if config::VALIDATE_CRASHES {
            tracing::info!("validating crash/hang");
            debugging::validate_last_exec(self, exit);
        }

        Ok(())
    }

    fn trace_new_bits(&mut self) {
        if let Some(block_cov) = self.coverage.as_any().downcast_ref::<coverage::BlockCoverage>() {
            let blocks = block_cov.blocks_for(&mut self.vm, &self.state.new_bits);
            tracing::trace!("New coverage: {blocks:x?} (bits={:?})", self.state.new_bits);
        }
        else {
            tracing::trace!("New coverage: (bits={:?})", self.state.new_bits);
        }
    }

    fn update_input_metadata(&mut self, id: InputId) {
        let depth = self.input_id.map_or(0, |x| self.corpus[x].metadata.depth + 1);

        let metadata = &mut self.corpus[id].metadata;
        metadata.parent_id = self.state.parent;
        metadata.coverage_bits = self.state.coverage_bits;
        metadata.instructions = self.state.instructions;
        metadata.depth = depth;
        metadata.len = self.state.input.total_bytes() as u64;
        metadata.streams = self.state.input.count_non_empty_streams() as u64;
        metadata.new_bits = self.state.new_bits.clone();
        metadata.stage = self.stage;
        metadata.is_crashing = self.state.was_crash();
        metadata.mutation_kinds.clone_from(&self.state.mutation_kinds);
    }

    fn update_stats(&mut self, stats: &mut monitor::LocalStats) {
        stats.update(self);

        // Update stats for the parent of the current input.
        if let Some(id) = self.input_id {
            let metadata = &mut self.corpus[id].metadata;
            metadata.time += self.state.exec_time;
            metadata.execs += 1;
            metadata.max_find_gap =
                u64::max(metadata.max_find_gap, metadata.execs - metadata.last_find);
            if self.state.was_crash() {
                metadata.crashes += 1;
            }
            if self.state.was_hang() {
                metadata.hangs += 1;
            }
            if self.state.new_coverage {
                metadata.finds += 1;
                metadata.last_find = metadata.execs;
            }
        }
    }

    fn reset_input_cursor(&mut self) -> anyhow::Result<()> {
        self.state.input.seek_to_start();
        Ok(())
    }

    fn write_input_to_target(&mut self) -> anyhow::Result<()> {
        let source = self
            .target
            .get_mmio_handler(&mut self.vm)
            .ok_or_else(|| anyhow::format_err!("target does not support MultiStream input"))?;
        source.clone_from(&self.state.input);
        Ok(())
    }

    fn auto_trim_input(&mut self) -> anyhow::Result<()> {
        let source = self
            .target
            .get_mmio_handler(&mut self.vm)
            .ok_or_else(|| anyhow::format_err!("target does not support MultiStream input"))?;
        if self.features.auto_trim {
            source.trim();
        }
        self.state.input.clone_from(source);
        Ok(())
    }

    fn get_extension_factor(&mut self, key: StreamKey) -> f64 {
        if !self.features.extension_factor {
            return 2.0;
        }
        self.input_id.map_or(1.0, |id| {
            self.corpus[id]
                .stage_data::<LengthExtData>(Stage::MultiStreamExtend)
                .extension_factor(key)
        })
    }

    #[allow(unused)]
    fn execs_since_last_find(&self) -> u64 {
        self.execs - self.last_find
    }
}

#[derive(
    Default, Debug, Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Stage {
    #[default]
    Import,
    Havoc,
    MultiStreamExtend,
    MultiStreamExtendI2S,
    Trim,
    Colorization,
    InputToState,
}

impl Stage {
    pub fn short_name(&self) -> &'static str {
        match self {
            Stage::Import => "imp",
            Stage::Havoc => "hav",
            Stage::MultiStreamExtend => "ext",
            Stage::MultiStreamExtendI2S => "ex2",
            Stage::Trim => "trm",
            Stage::Colorization => "col",
            Stage::InputToState => "i2s",
        }
    }

    pub fn is_extension(&self) -> bool {
        matches!(self, Self::MultiStreamExtend | Self::MultiStreamExtendI2S)
    }
}

#[derive(Debug)]
pub enum StageExit {
    /// This stage is unsupported by the current fuzzing mode.
    Unsupported,
    /// The stage should be skipped
    Skip,
    /// The stage was interrupt as part of execution.
    Interrupted,
    /// An unknown error occured
    Unknown(anyhow::Error),
}

impl std::fmt::Display for StageExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Unsupported Stage"),
            Self::Skip => f.write_str("Skipped Stage"),
            Self::Interrupted => f.write_str("Interrupted Stage"),
            Self::Unknown(err) => f.write_fmt(format_args!("Unknown StageStart error: {err}")),
        }
    }
}

impl From<anyhow::Error> for StageExit {
    fn from(err: anyhow::Error) -> Self {
        Self::Unknown(err)
    }
}

pub(crate) trait FuzzerStage {
    fn run(fuzzer: &mut Fuzzer, stats: &mut monitor::LocalStats) -> anyhow::Result<StageExit>;
}

pub(crate) trait StageData {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageExit>
    where
        Self: Sized;
    fn fuzz_one(&mut self, fuzzer: &mut Fuzzer) -> Option<VmExit>;
    fn end(&mut self, _fuzzer: &mut Fuzzer) {}
    fn after_check(&mut self, _fuzzer: &mut Fuzzer, _is_interesting: bool) {}
}

impl<S: StageData> FuzzerStage for S {
    fn run(fuzzer: &mut Fuzzer, stats: &mut monitor::LocalStats) -> anyhow::Result<StageExit> {
        let mut stage_data = match Self::start(fuzzer) {
            Ok(data) => data,
            Err(err) => match err {
                StageExit::Unknown(err) => return Err(err),
                exit => return Ok(exit),
            },
        };

        while let Some(exit) = stage_data.fuzz_one(fuzzer) {
            if fuzzer.vm.interrupt_flag.load(std::sync::atomic::Ordering::Relaxed)
                || matches!(exit, VmExit::Interrupted)
            {
                return Ok(StageExit::Interrupted);
            }
            fuzzer.check_exit_state(exit)?;
            stage_data.after_check(fuzzer, fuzzer.state.new_coverage);
            fuzzer.update_stats(stats);
        }

        stage_data.end(fuzzer);
        Ok(StageExit::Skip)
    }
}

#[allow(unused)]
struct DummyStage;

impl StageData for DummyStage {
    fn start(_: &mut Fuzzer) -> Result<Self, StageExit> {
        Ok(Self)
    }

    fn fuzz_one(&mut self, _: &mut Fuzzer) -> Option<VmExit> {
        None
    }
}

/// A stage that imports fuzzing inputs from other fuzzers.
struct SyncStage {
    inputs: Vec<(u64, Arc<MultiStream>)>,
    total: usize,
    interesting: usize,
    current_input_id: u64,
}

impl StageData for SyncStage {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageExit> {
        let mut inputs = fuzzer.global.take_all();
        if fuzzer.global.is_main_instance() && !inputs.is_empty() {
            tracing::info!("synchronizing {} inputs from other instances", inputs.len());
        }
        // Shuffle inputs to increase diversity across instances.
        inputs.shuffle(&mut fuzzer.rng);
        Ok(Self { total: inputs.len(), interesting: 0, inputs, current_input_id: 0 })
    }

    fn fuzz_one(&mut self, fuzzer: &mut Fuzzer) -> Option<VmExit> {
        let (id, input) = self.inputs.pop()?;
        self.current_input_id = id;

        Snapshot::restore_initial(fuzzer);
        fuzzer.state.reset();

        fuzzer.state.is_import = true;
        fuzzer.state.input.clone_from(&input);
        fuzzer.reset_input_cursor().unwrap();

        fuzzer.write_input_to_target().unwrap();
        let exit = fuzzer.execute()?;
        fuzzer.auto_trim_input().ok()?;

        Some(exit)
    }

    fn after_check(&mut self, fuzzer: &mut Fuzzer, interesting: bool) {
        if interesting {
            self.interesting += 1;
        }

        if fuzzer.global.is_main_instance() {
            // DEBUGGING:
            let bits = fuzzer.coverage.get_bits(&mut fuzzer.vm);
            let coverage_bits = count_all_bits(bits);
            tracing::info!(
                "sync {}: bits={coverage_bits}, new bits={:?}",
                self.current_input_id,
                fuzzer.state.new_bits
            );
        }
    }

    fn end(&mut self, fuzzer: &mut Fuzzer) {
        if fuzzer.global.is_main_instance() && self.total != 0 {
            tracing::info!(
                "{} out of {} inputs from external fuzzers were interesting",
                self.interesting,
                self.total
            );
        }
    }
}
const BASE_ENERGY: u64 = 100;

/// Calculates the energy to use for the current input.
fn calculate_energy(fuzzer: &mut Fuzzer) -> u64 {
    // If we have no information for the current input, just use the base energy.
    let Some(input_id) = fuzzer.input_id
    else {
        return BASE_ENERGY;
    };

    if fuzzer.features.simple_energy_assignment {
        let mut energy = BASE_ENERGY;
        if fuzzer.corpus[input_id].has_unique_edge {
            energy *= 5;
        }
        return energy;
    }
    // A significant amount of paths are found early in the fuzzing process from just random bytes
    // so we assign them a smaller amount of fuzzing energy to account for this.
    if fuzzer.corpus[input_id].metadata.parent_id.is_none() {
        return BASE_ENERGY;
    }

    let mut energy = BASE_ENERGY as f64;

    // Add a bonus for inputs that reach a new edge.
    if fuzzer.corpus[input_id].has_unique_edge {
        energy *= 5.0;
    }

    // Global statistics about the fuzzing corpus which is used to help normalize our energy
    // assignment for the current target.
    let total_inputs = fuzzer.corpus.inputs() as u64;
    let average_input_size = fuzzer.corpus.metadata.total_input_bytes as u64 / total_inputs;
    let global_find_rate = total_inputs as f64 / fuzzer.execs as f64;

    let input = &fuzzer.corpus[input_id];

    // Adjust energy based on the input size since smaller inputs enable more effective mutations.
    match fuzzer.state.input.total_bytes() as f64 / average_input_size as f64 {
        x if x < 0.5 => energy *= 1.5,
        x if x < 1.0 => energy *= 1.1,
        x if x < 2.0 => energy *= 0.9,
        _ => energy *= 0.5,
    }

    // Add a bonus for deeper inputs (note: this at least partially cancels out with input size
    // adjustment.
    energy *= (1.05_f64.powi(input.metadata.depth as i32)).min(4.0);

    // Bonus for inputs that have recently found new coverage
    if (input.metadata.execs - input.metadata.last_find) < 1000 * BASE_ENERGY {
        energy *= 2.0;
    }

    // Add a slight bonus for inputs that have found more inputs than average
    let input_find_rate = input.metadata.finds as f64 / input.metadata.execs as f64;
    if input_find_rate > global_find_rate {
        energy *= 1.5;
    }

    // Add a penalty for inputs that frequently hang.
    if input.metadata.hangs as f32 / input.metadata.execs as f32 > 0.2 {
        energy *= 0.1;
    }

    energy.clamp(10.0, 100_000.0).round() as u64
}
