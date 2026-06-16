use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Context;
use serde::Serialize;

use crate::{strategy_runtime, utils, Fuzzer};

#[derive(Debug, Clone, Serialize)]
struct AdaptiveWindowRecord {
    window_index: usize,
    elapsed_sec: f64,
    execs: u64,
    exec_delta: u64,
    corpus_inputs: u64,
    input_delta: u64,
    coverage_bits: u64,
    coverage_delta: u64,
    access_delta_total: u64,
    access_delta_unique: usize,
    top_accesses: Vec<(String, u64)>,
    top_access_ratio: f64,
    hotspot_key: String,
    input_stall: bool,
    coverage_stall: bool,
    access_repeated: bool,
    hotspot_stable: bool,
    input_stall_streak: usize,
    coverage_stall_streak: usize,
    repeat_streak: usize,
    hotspot_stable_streak: usize,
    activation_ready: bool,
}

#[derive(Debug, Serialize)]
struct AdaptiveSummary {
    schema: &'static str,
    enabled: bool,
    guidance_path: Option<String>,
    activated: bool,
    activation_reason: Option<String>,
    config: AdaptiveSummaryConfig,
    windows: Vec<AdaptiveWindowRecord>,
}

#[derive(Debug, Serialize)]
struct AdaptiveSummaryConfig {
    window_seconds: f64,
    min_windows: usize,
    plateau_windows: usize,
    input_stall_max_delta: u64,
    coverage_stall_max_delta: u64,
    access_repeat_ratio: f64,
    hotspot_stable_windows: usize,
    top_k: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AdaptiveGuidanceSwitch {
    enabled: bool,
    window: Duration,
    next_window_at: Instant,
    start: Instant,
    min_windows: usize,
    plateau_windows: usize,
    input_stall_max_delta: u64,
    coverage_stall_max_delta: u64,
    access_repeat_ratio: f64,
    hotspot_stable_windows: usize,
    top_k: usize,
    summary_out: PathBuf,
    guidance_path: Option<PathBuf>,
    activated: bool,
    activation_reason: Option<String>,
    last_inputs: u64,
    last_coverage: u64,
    last_execs: u64,
    last_access_map: BTreeMap<String, u64>,
    last_hotspot_key: String,
    input_stall_streak: usize,
    coverage_stall_streak: usize,
    repeat_streak: usize,
    hotspot_stable_streak: usize,
    windows: Vec<AdaptiveWindowRecord>,
}

fn env_bool(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref().map(str::trim),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES") | Ok("on") | Ok("ON")
    )
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(default)
}

fn env_duration(name: &str, default: Duration) -> anyhow::Result<Duration> {
    match std::env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => utils::parse_duration_str(raw.trim())
            .ok_or_else(|| anyhow::format_err!("invalid duration for {name}: {raw}")),
        _ => Ok(default),
    }
}

fn combined_access_map(snapshot: &strategy_runtime::AccessSnapshot) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (addr, count) in &snapshot.read_attempt_touches {
        *out.entry(addr.clone()).or_insert(0) += *count;
    }
    for (addr, count) in &snapshot.write_touches {
        *out.entry(addr.clone()).or_insert(0) += *count;
    }
    out
}

fn access_delta(
    current: &BTreeMap<String, u64>,
    previous: &BTreeMap<String, u64>,
) -> Vec<(String, u64)> {
    let mut rows = Vec::new();
    for (addr, count) in current {
        let old = previous.get(addr).copied().unwrap_or(0);
        let delta = count.saturating_sub(old);
        if delta > 0 {
            rows.push((addr.clone(), delta));
        }
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

impl AdaptiveGuidanceSwitch {
    pub(crate) fn from_env(workdir: PathBuf) -> anyhow::Result<Self> {
        let defer_guidance = env_bool("MF_DEFER_GUIDANCE_UNTIL_STABLE");
        let enabled = env_bool("MF_ADAPTIVE_GUIDANCE_SWITCH") || defer_guidance;
        let window = env_duration("MF_ADAPTIVE_RANDOM_WINDOW", Duration::from_secs(600))?;
        let summary_out = std::env::var_os("MF_ADAPTIVE_SWITCH_SUMMARY_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|| workdir.join("adaptive_guidance_switch_summary.json"));
        let guidance_path = std::env::var_os("MF_MMIO_GUIDANCE_FILE").map(PathBuf::from);
        let now = Instant::now();
        if defer_guidance {
            strategy_runtime::clear_guidance();
            strategy_runtime::set_env_auto_load_enabled(false);
        }
        Ok(Self {
            enabled,
            window,
            next_window_at: now + window,
            start: now,
            min_windows: env_usize("MF_ADAPTIVE_MIN_RANDOM_WINDOWS", 3).max(1),
            plateau_windows: env_usize("MF_ADAPTIVE_PLATEAU_WINDOWS", 2).max(1),
            input_stall_max_delta: env_u64("MF_ADAPTIVE_INPUT_STALL_MAX_DELTA", 0),
            coverage_stall_max_delta: env_u64("MF_ADAPTIVE_COVERAGE_STALL_MAX_DELTA", 0),
            access_repeat_ratio: env_f64("MF_ADAPTIVE_ACCESS_REPEAT_RATIO", 0.90).clamp(0.0, 1.0),
            hotspot_stable_windows: env_usize("MF_ADAPTIVE_HOTSPOT_STABLE_WINDOWS", 2).max(1),
            top_k: env_usize("MF_ADAPTIVE_HOTSPOT_TOP_K", 3).max(1),
            summary_out,
            guidance_path,
            activated: false,
            activation_reason: None,
            last_inputs: 0,
            last_coverage: 0,
            last_execs: 0,
            last_access_map: BTreeMap::new(),
            last_hotspot_key: String::new(),
            input_stall_streak: 0,
            coverage_stall_streak: 0,
            repeat_streak: 0,
            hotspot_stable_streak: 0,
            windows: Vec::new(),
        })
    }

    pub(crate) fn maybe_update(&mut self, fuzzer: &mut Fuzzer) -> anyhow::Result<()> {
        if !self.enabled || self.activated || !fuzzer.global.is_main_instance() {
            return Ok(());
        }
        let now = Instant::now();
        if now < self.next_window_at {
            return Ok(());
        }
        self.next_window_at = now + self.window;

        let access_snapshot = strategy_runtime::access_snapshot();
        let access_map = combined_access_map(&access_snapshot);
        let mut deltas = access_delta(&access_map, &self.last_access_map);
        let total_access_delta: u64 = deltas.iter().map(|(_, v)| *v).sum();
        let top: Vec<(String, u64)> = deltas.drain(..).take(self.top_k).collect();
        let top_total: u64 = top.iter().map(|(_, v)| *v).sum();
        let top_ratio = if total_access_delta == 0 {
            0.0
        } else {
            top_total as f64 / total_access_delta as f64
        };
        let hotspot_key = top
            .iter()
            .map(|(addr, _)| addr.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let inputs = fuzzer.corpus.inputs() as u64;
        let coverage = fuzzer.coverage.count();
        let execs = fuzzer.execs;
        let input_delta = inputs.saturating_sub(self.last_inputs);
        let coverage_delta = coverage.saturating_sub(self.last_coverage);
        let exec_delta = execs.saturating_sub(self.last_execs);

        let input_stall = input_delta <= self.input_stall_max_delta;
        let coverage_stall = coverage_delta <= self.coverage_stall_max_delta;
        let access_repeated = total_access_delta > 0 && top_ratio >= self.access_repeat_ratio;
        let hotspot_stable = !hotspot_key.is_empty() && hotspot_key == self.last_hotspot_key;

        self.input_stall_streak = if input_stall { self.input_stall_streak + 1 } else { 0 };
        self.coverage_stall_streak = if coverage_stall { self.coverage_stall_streak + 1 } else { 0 };
        self.repeat_streak = if access_repeated { self.repeat_streak + 1 } else { 0 };
        self.hotspot_stable_streak = if hotspot_stable { self.hotspot_stable_streak + 1 } else { 1 };

        let window_index = self.windows.len() + 1;
        let activation_ready = window_index >= self.min_windows
            && self.input_stall_streak >= self.plateau_windows
            && self.coverage_stall_streak >= self.plateau_windows
            && self.repeat_streak >= self.plateau_windows
            && self.hotspot_stable_streak >= self.hotspot_stable_windows;

        self.windows.push(AdaptiveWindowRecord {
            window_index,
            elapsed_sec: self.start.elapsed().as_secs_f64(),
            execs,
            exec_delta,
            corpus_inputs: inputs,
            input_delta,
            coverage_bits: coverage,
            coverage_delta,
            access_delta_total: total_access_delta,
            access_delta_unique: access_delta(&access_map, &self.last_access_map).len(),
            top_accesses: top,
            top_access_ratio: top_ratio,
            hotspot_key: hotspot_key.clone(),
            input_stall,
            coverage_stall,
            access_repeated,
            hotspot_stable,
            input_stall_streak: self.input_stall_streak,
            coverage_stall_streak: self.coverage_stall_streak,
            repeat_streak: self.repeat_streak,
            hotspot_stable_streak: self.hotspot_stable_streak,
            activation_ready,
        });

        self.last_inputs = inputs;
        self.last_coverage = coverage;
        self.last_execs = execs;
        self.last_access_map = access_map;
        self.last_hotspot_key = hotspot_key;

        if activation_ready {
            self.activated = true;
            self.activation_reason = Some("stable_random_windows".to_string());
            strategy_runtime::set_env_auto_load_enabled(true);
            match strategy_runtime::load_guidance_from_env_now() {
                Ok(true) => {}
                Ok(false) => {
                    self.activation_reason = Some("stable_random_windows_no_guidance_file".to_string());
                }
                Err(err) => {
                    self.activation_reason = Some(format!("stable_random_windows_load_error: {err:#}"));
                }
            }
        }

        self.flush_summary()
    }

    pub(crate) fn finish<T>(&self, _fuzzer: &mut T) {
        if self.enabled && !self.activated {
            strategy_runtime::set_env_auto_load_enabled(true);
        }
        let _ = self.flush_summary();
    }

    fn flush_summary(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if let Some(parent) = self.summary_out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let summary = AdaptiveSummary {
            schema: "mf_adaptive_guidance_switch_v1",
            enabled: self.enabled,
            guidance_path: self.guidance_path.as_ref().map(|p| p.display().to_string()),
            activated: self.activated,
            activation_reason: self.activation_reason.clone(),
            config: AdaptiveSummaryConfig {
                window_seconds: self.window.as_secs_f64(),
                min_windows: self.min_windows,
                plateau_windows: self.plateau_windows,
                input_stall_max_delta: self.input_stall_max_delta,
                coverage_stall_max_delta: self.coverage_stall_max_delta,
                access_repeat_ratio: self.access_repeat_ratio,
                hotspot_stable_windows: self.hotspot_stable_windows,
                top_k: self.top_k,
            },
            windows: self.windows.clone(),
        };
        std::fs::write(&self.summary_out, serde_json::to_string_pretty(&summary)?)
            .with_context(|| format!("failed to write {}", self.summary_out.display()))?;
        Ok(())
    }
}
