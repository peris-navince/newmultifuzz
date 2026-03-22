use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use hashbrown::{HashMap, HashSet};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct RecentRead {
    addr: u64,
    order: u64,
}

#[derive(Debug, Default, Clone)]
struct StreamCounters {
    read_count: u64,
    width_counts: HashMap<usize, u64>,
    first_seen_order: u64,
    last_seen_order: u64,
    total_bytes_requested: u64,
    executions_seen: u64,
    interesting_executions_seen: u64,
}

#[derive(Debug, Default, Clone)]
struct InterestingCounters {
    interesting_hit_count: u64,
    recent_window_hit_count: u64,
}

#[derive(Debug, Clone)]
struct ObserverConfig {
    out_dir: PathBuf,
    recent_window_size: usize,
    flush_every_execs: u64,
    window_secs: u64,
    window_execs: u64,
    live_snapshot_secs: u64,
    live_snapshot_execs: u64,
}

#[derive(Debug)]
struct ObserverState {
    cfg: ObserverConfig,

    global_order: u64,
    total_execs: u64,
    total_interesting_execs: u64,

    current_exec_seen: HashSet<u64>,
    current_exec_recent: VecDeque<RecentRead>,

    total_discovered: HashMap<u64, StreamCounters>,
    total_interesting: HashMap<u64, InterestingCounters>,

    window_index: u64,
    window_started_at: Instant,
    window_execs: u64,
    window_interesting_execs: u64,
    window_discovered: HashMap<u64, StreamCounters>,
    window_interesting: HashMap<u64, InterestingCounters>,

    last_live_snapshot_at: Instant,
    last_live_snapshot_total_execs: u64,
}

#[derive(Debug, Clone, Serialize)]
struct StreamRow {
    addr: String,
    read_count: u64,
    width_counts: std::collections::BTreeMap<String, u64>,
    first_seen_order: u64,
    last_seen_order: u64,
    total_bytes_requested: u64,
    executions_seen: u64,
    interesting_executions_seen: u64,
}

#[derive(Debug, Clone, Serialize)]
struct InterestingRow {
    addr: String,
    interesting_hit_count: u64,
    recent_window_hit_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct SummaryRow {
    total_execs: u64,
    total_interesting_execs: u64,
    window_index: u64,
    current_window_execs: u64,
    current_window_interesting_execs: u64,
    current_window_elapsed_secs: u64,
    recent_window_size: usize,
    flush_every_execs: u64,
    window_secs: u64,
    window_execs: u64,
    live_snapshot_secs: u64,
    live_snapshot_execs: u64,
}

#[derive(Debug, Clone, Serialize)]
struct WindowSummaryRow {
    window_index: u64,
    reason: String,
    snapshot_kind: String,
    finalized: bool,
    window_execs: u64,
    window_interesting_execs: u64,
    window_elapsed_secs: u64,
}

static OBSERVER: OnceLock<Option<Mutex<ObserverState>>> = OnceLock::new();

fn parse_u64_env(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(v) => v.trim().parse::<u64>().unwrap_or(default),
        Err(_) => default,
    }
}

fn parse_usize_env(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) => v.trim().parse::<usize>().unwrap_or(default),
        Err(_) => default,
    }
}

fn init_observer() -> Option<Mutex<ObserverState>> {
    let out_dir = match std::env::var("MF_STREAM_OBSERVER_OUT") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => return None,
    };

    let cfg = ObserverConfig {
        out_dir,
        recent_window_size: parse_usize_env("MF_STREAM_OBSERVER_WINDOW", 64),
        flush_every_execs: parse_u64_env("MF_STREAM_OBSERVER_FLUSH_EVERY", 200),
        window_secs: parse_u64_env("MF_STREAM_OBSERVER_WINDOW_SECS", 60),
        window_execs: parse_u64_env("MF_STREAM_OBSERVER_WINDOW_EXECS", 50_000),
        live_snapshot_secs: parse_u64_env("MF_STREAM_OBSERVER_LIVE_SNAPSHOT_SECS", 5),
        live_snapshot_execs: parse_u64_env("MF_STREAM_OBSERVER_LIVE_SNAPSHOT_EXECS", 5_000),
    };

    if let Err(e) = fs::create_dir_all(&cfg.out_dir) {
        eprintln!("[stream-observer] failed to create out dir {}: {e}", cfg.out_dir.display());
        return None;
    }
    if let Err(e) = fs::create_dir_all(cfg.out_dir.join("windows")) {
        eprintln!(
            "[stream-observer] failed to create windows dir {}: {e}",
            cfg.out_dir.join("windows").display()
        );
        return None;
    }

    eprintln!(
        "[stream-observer] enabled: out={} recent_window={} flush_every_execs={} window_secs={} window_execs={} live_snapshot_secs={} live_snapshot_execs={}",
        cfg.out_dir.display(),
        cfg.recent_window_size,
        cfg.flush_every_execs,
        cfg.window_secs,
        cfg.window_execs,
        cfg.live_snapshot_secs,
        cfg.live_snapshot_execs,
    );

    let now = Instant::now();
    Some(Mutex::new(ObserverState {
        cfg,
        global_order: 0,
        total_execs: 0,
        total_interesting_execs: 0,
        current_exec_seen: HashSet::new(),
        current_exec_recent: VecDeque::new(),
        total_discovered: HashMap::new(),
        total_interesting: HashMap::new(),
        window_index: 0,
        window_started_at: now,
        window_execs: 0,
        window_interesting_execs: 0,
        window_discovered: HashMap::new(),
        window_interesting: HashMap::new(),
        last_live_snapshot_at: now,
        last_live_snapshot_total_execs: 0,
    }))
}

fn with_state<F>(f: F)
where
    F: FnOnce(&mut ObserverState),
{
    let Some(observer) = OBSERVER.get_or_init(init_observer).as_ref() else {
        return;
    };
    let Ok(mut st) = observer.lock() else {
        return;
    };
    f(&mut st);
}

fn update_stream_map(map: &mut HashMap<u64, StreamCounters>, addr: u64, size: usize, order: u64) {
    let entry = map.entry(addr).or_default();
    if entry.read_count == 0 {
        entry.first_seen_order = order;
    }
    entry.read_count += 1;
    *entry.width_counts.entry(size).or_insert(0) += 1;
    entry.last_seen_order = order;
    entry.total_bytes_requested += size as u64;
}

fn mark_exec_seen(map: &mut HashMap<u64, StreamCounters>, addr: u64, interesting: bool) {
    let entry = map.entry(addr).or_default();
    entry.executions_seen += 1;
    if interesting {
        entry.interesting_executions_seen += 1;
    }
}

fn mark_interesting(map: &mut HashMap<u64, InterestingCounters>, addr: u64, in_recent_window: bool) {
    let entry = map.entry(addr).or_default();
    entry.interesting_hit_count += 1;
    if in_recent_window {
        entry.recent_window_hit_count += 1;
    }
}

fn serialize_stream_rows(map: &HashMap<u64, StreamCounters>) -> Vec<StreamRow> {
    let mut rows: Vec<_> = map
        .iter()
        .map(|(&addr, c)| {
            let mut widths = std::collections::BTreeMap::new();
            let mut width_pairs: Vec<_> = c.width_counts.iter().collect();
            width_pairs.sort_by_key(|(k, _)| **k);
            for (k, v) in width_pairs {
                widths.insert(k.to_string(), *v);
            }
            StreamRow {
                addr: format!("0x{addr:08X}"),
                read_count: c.read_count,
                width_counts: widths,
                first_seen_order: c.first_seen_order,
                last_seen_order: c.last_seen_order,
                total_bytes_requested: c.total_bytes_requested,
                executions_seen: c.executions_seen,
                interesting_executions_seen: c.interesting_executions_seen,
            }
        })
        .collect();

    rows.sort_by(|a, b| {
        b.read_count
            .cmp(&a.read_count)
            .then_with(|| b.executions_seen.cmp(&a.executions_seen))
            .then_with(|| a.addr.cmp(&b.addr))
    });
    rows
}

fn serialize_interesting_rows(map: &HashMap<u64, InterestingCounters>) -> Vec<InterestingRow> {
    let mut rows: Vec<_> = map
        .iter()
        .map(|(&addr, c)| InterestingRow {
            addr: format!("0x{addr:08X}"),
            interesting_hit_count: c.interesting_hit_count,
            recent_window_hit_count: c.recent_window_hit_count,
        })
        .collect();

    rows.sort_by(|a, b| {
        b.interesting_hit_count
            .cmp(&a.interesting_hit_count)
            .then_with(|| b.recent_window_hit_count.cmp(&a.recent_window_hit_count))
            .then_with(|| a.addr.cmp(&b.addr))
    });
    rows
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) {
    let bytes = match serde_json::to_vec_pretty(value) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[stream-observer] failed to serialize {}: {e}", path.display());
            return;
        }
    };
    if let Err(e) = fs::write(&path, bytes) {
        eprintln!("[stream-observer] failed to write {}: {e}", path.display());
    }
}

fn flush_cumulative(st: &ObserverState) {
    write_json(
        st.cfg.out_dir.join("discovered_streams.json"),
        &serialize_stream_rows(&st.total_discovered),
    );
    write_json(
        st.cfg.out_dir.join("interesting_streams.json"),
        &serialize_interesting_rows(&st.total_interesting),
    );
    write_json(
        st.cfg.out_dir.join("summary.json"),
        &SummaryRow {
            total_execs: st.total_execs,
            total_interesting_execs: st.total_interesting_execs,
            window_index: st.window_index,
            current_window_execs: st.window_execs,
            current_window_interesting_execs: st.window_interesting_execs,
            current_window_elapsed_secs: st.window_started_at.elapsed().as_secs(),
            recent_window_size: st.cfg.recent_window_size,
            flush_every_execs: st.cfg.flush_every_execs,
            window_secs: st.cfg.window_secs,
            window_execs: st.cfg.window_execs,
            live_snapshot_secs: st.cfg.live_snapshot_secs,
            live_snapshot_execs: st.cfg.live_snapshot_execs,
        },
    );
}

fn flush_live_window_snapshot(st: &mut ObserverState, reason: &str) {
    if st.window_execs == 0 {
        return;
    }

    let discovered = serialize_stream_rows(&st.window_discovered);
    let interesting = serialize_interesting_rows(&st.window_interesting);
    let summary = WindowSummaryRow {
        window_index: st.window_index + 1,
        reason: reason.to_string(),
        snapshot_kind: "live".to_string(),
        finalized: false,
        window_execs: st.window_execs,
        window_interesting_execs: st.window_interesting_execs,
        window_elapsed_secs: st.window_started_at.elapsed().as_secs(),
    };

    write_json(st.cfg.out_dir.join("latest_window_discovered_streams.json"), &discovered);
    write_json(st.cfg.out_dir.join("latest_window_interesting_streams.json"), &interesting);
    write_json(st.cfg.out_dir.join("latest_window_summary.json"), &summary);

    st.last_live_snapshot_at = Instant::now();
    st.last_live_snapshot_total_execs = st.total_execs;
}

fn flush_window(st: &mut ObserverState, reason: &str) {
    if st.window_execs == 0 {
        return;
    }

    st.window_index += 1;
    let elapsed = st.window_started_at.elapsed().as_secs();
    let prefix = format!("window_{:06}", st.window_index);
    let windows_dir = st.cfg.out_dir.join("windows");

    let discovered = serialize_stream_rows(&st.window_discovered);
    let interesting = serialize_interesting_rows(&st.window_interesting);
    let summary = WindowSummaryRow {
        window_index: st.window_index,
        reason: reason.to_string(),
        snapshot_kind: "finalized".to_string(),
        finalized: true,
        window_execs: st.window_execs,
        window_interesting_execs: st.window_interesting_execs,
        window_elapsed_secs: elapsed,
    };

    write_json(windows_dir.join(format!("{prefix}_discovered_streams.json")), &discovered);
    write_json(windows_dir.join(format!("{prefix}_interesting_streams.json")), &interesting);
    write_json(windows_dir.join(format!("{prefix}_summary.json")), &summary);

    write_json(st.cfg.out_dir.join("latest_window_discovered_streams.json"), &discovered);
    write_json(st.cfg.out_dir.join("latest_window_interesting_streams.json"), &interesting);
    write_json(st.cfg.out_dir.join("latest_window_summary.json"), &summary);

    let now = Instant::now();
    st.window_started_at = now;
    st.window_execs = 0;
    st.window_interesting_execs = 0;
    st.window_discovered.clear();
    st.window_interesting.clear();
    st.last_live_snapshot_at = now;
    st.last_live_snapshot_total_execs = st.total_execs;
}

pub fn on_exec_start() {
    with_state(|st| {
        st.current_exec_seen.clear();
        st.current_exec_recent.clear();
    });
}

pub fn on_next_bytes(addr: u64, size: usize) {
    with_state(|st| {
        st.global_order += 1;
        let order = st.global_order;

        update_stream_map(&mut st.total_discovered, addr, size, order);
        update_stream_map(&mut st.window_discovered, addr, size, order);

        st.current_exec_seen.insert(addr);
        st.current_exec_recent.push_back(RecentRead { addr, order });
        while st.current_exec_recent.len() > st.cfg.recent_window_size {
            st.current_exec_recent.pop_front();
        }
    });
}

pub fn on_exec_end(interesting: bool) {
    with_state(|st| {
        st.total_execs += 1;
        st.window_execs += 1;
        if interesting {
            st.total_interesting_execs += 1;
            st.window_interesting_execs += 1;
        }

        let mut recent_set = HashSet::new();
        for rr in &st.current_exec_recent {
            recent_set.insert(rr.addr);
        }

        for &addr in &st.current_exec_seen {
            mark_exec_seen(&mut st.total_discovered, addr, interesting);
            mark_exec_seen(&mut st.window_discovered, addr, interesting);

            if interesting {
                let in_recent = recent_set.contains(&addr);
                mark_interesting(&mut st.total_interesting, addr, in_recent);
                mark_interesting(&mut st.window_interesting, addr, in_recent);
            }
        }

        let flush_now = st.cfg.flush_every_execs > 0 && st.total_execs % st.cfg.flush_every_execs == 0;
        if flush_now {
            flush_cumulative(st);
        }

        let due_secs = st.cfg.window_secs > 0 && st.window_started_at.elapsed().as_secs() >= st.cfg.window_secs;
        let due_execs = st.cfg.window_execs > 0 && st.window_execs >= st.cfg.window_execs;
        if due_secs || due_execs {
            let reason = if due_secs && due_execs {
                "time+exec"
            } else if due_secs {
                "time"
            } else {
                "exec"
            };
            flush_window(st, reason);
            flush_cumulative(st);
            return;
        }

        let live_due_secs = st.cfg.live_snapshot_secs > 0
            && st.last_live_snapshot_at.elapsed().as_secs() >= st.cfg.live_snapshot_secs;
        let live_due_execs = st.cfg.live_snapshot_execs > 0
            && st.total_execs.saturating_sub(st.last_live_snapshot_total_execs) >= st.cfg.live_snapshot_execs;
        if live_due_secs || live_due_execs || interesting {
            let live_reason = if interesting {
                "interesting"
            } else if live_due_secs && live_due_execs {
                "time+exec"
            } else if live_due_secs {
                "time"
            } else {
                "exec"
            };
            flush_live_window_snapshot(st, live_reason);
        }
    });
}

pub fn flush_now() {
    with_state(|st| {
        flush_live_window_snapshot(st, "manual-live");
        flush_window(st, "manual");
        flush_cumulative(st);
    });
}
