use std::{
    io::Read,
    sync::{Mutex, OnceLock},
};

use anyhow::Context;
use hashbrown::HashMap;

use icicle_cortexm::{mmio::FuzzwareMmioHandler, CortexmTarget};
use icicle_vm::cpu::mem::{IoMemory, MemError, MemResult};

use crate::{debugging::trace::IoTracerAny, strategy_runtime};

pub type MultiStreamMmio = FuzzwareMmioHandler<MultiStream>;
pub type CortexmMultiStream = CortexmTarget<MultiStreamMmio>;

#[derive(Debug, Default)]
pub struct StreamData {
    pub bytes: Vec<u8>,
    pub cursor: u32,
    pub sizes: u32,
}

impl Clone for StreamData {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes.clone(), cursor: self.cursor, sizes: self.sizes }
    }

    fn clone_from(&mut self, source: &Self) {
        self.bytes.clone_from(&source.bytes);
        self.cursor = source.cursor;
        self.sizes = source.sizes;
    }
}

impl StreamData {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, cursor: 0, sizes: 0 }
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.cursor = 0;
        self.sizes = 0;
    }

    /// Returns whether the stream has been read as a certain sized value.
    pub fn read_as(&self, size: u32) -> bool {
        self.sizes & size != 0
    }

    /// Returns the minimum alignment of the stream, given the reads we have seen for this stream.
    pub fn min_alignment(&self) -> usize {
        1 << self.sizes.trailing_zeros()
    }
}

pub type StreamKey = u64;

#[derive(Debug, Clone)]
struct UartOneShotConfig {
    s1_addr: u64,
    d_addr: u64,
    trigger_reads: u32,
    s1_value: u8,
    data_bytes: Vec<u8>,
    max_events: u32,
    d_window_accesses: u32,
}

#[derive(Debug, Default, Clone)]
struct UartOneShotState {
    s1_reads_since_event: u32,
    await_d_window_remaining: u32,
    data_pos: usize,
    events_fired: u32,
}

static UART_ONESHOT_CFG: OnceLock<Option<UartOneShotConfig>> = OnceLock::new();
static UART_ONESHOT_STATE: OnceLock<Mutex<UartOneShotState>> = OnceLock::new();

fn parse_int_auto(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(x, 16).ok()
    }
    else {
        s.parse::<u64>().ok()
    }
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let part = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        let b = u8::from_str_radix(part, 16).ok()?;
        out.push(b);
        i += 2;
    }
    Some(out)
}

fn uart_oneshot_cfg() -> Option<&'static UartOneShotConfig> {
    UART_ONESHOT_CFG
        .get_or_init(|| {
            let spec = match std::env::var("MF_UART_ONESHOT") {
                Ok(v) => v,
                Err(_) => return None,
            };

            let mut parts = spec.split(':').map(str::trim);
            let Some(s1_s) = parts.next() else { return None };
            let Some(d_s) = parts.next() else { return None };
            let Some(trigger_s) = parts.next() else { return None };
            let Some(s1v_s) = parts.next() else { return None };
            let Some(data_s) = parts.next() else { return None };
            let max_s = parts.next();

            let s1_addr = parse_int_auto(s1_s)?;
            let d_addr = parse_int_auto(d_s)?;
            let trigger_reads = parse_int_auto(trigger_s)? as u32;
            let s1_value = parse_int_auto(s1v_s)? as u8;
            let data_bytes = parse_hex_bytes(data_s)?;
            if data_bytes.is_empty() {
                return None;
            }

            let max_events = if let Some(x) = max_s {
                parse_int_auto(x)? as u32
            }
            else {
                data_bytes.len() as u32
            };

            let cfg = UartOneShotConfig {
                s1_addr,
                d_addr,
                trigger_reads,
                s1_value,
                data_bytes,
                max_events,
                d_window_accesses: 4,
            };

            eprintln!(
                "[uart-oneshot] legacy shim enabled: s1={:#010x} d={:#010x} trigger_reads={} s1_value={:#04x} data_len={} max_events={} d_window_accesses={}",
                cfg.s1_addr,
                cfg.d_addr,
                cfg.trigger_reads,
                cfg.s1_value,
                cfg.data_bytes.len(),
                cfg.max_events,
                cfg.d_window_accesses,
            );

            Some(cfg)
        })
        .as_ref()
}

fn uart_oneshot_state() -> &'static Mutex<UartOneShotState> {
    UART_ONESHOT_STATE.get_or_init(|| Mutex::new(UartOneShotState::default()))
}

fn reset_uart_oneshot_state() {
    if uart_oneshot_cfg().is_none() {
        return;
    }
    let mut st = uart_oneshot_state().lock().unwrap();
    *st = UartOneShotState::default();
}

fn maybe_apply_uart_oneshot(addr: StreamKey, buf: &mut [u8]) {
    let Some(cfg) = uart_oneshot_cfg() else { return };
    let mut st = uart_oneshot_state().lock().unwrap();

    // If a short D-consume window is open, only a D read may consume the event.
    if st.await_d_window_remaining > 0 {
        if addr == cfg.d_addr {
            if st.events_fired < cfg.max_events && st.data_pos < cfg.data_bytes.len() {
                let byte = cfg.data_bytes[st.data_pos];
                if !buf.is_empty() {
                    buf[0] = byte;
                    for b in buf.iter_mut().skip(1) {
                        *b = 0;
                    }
                }
                st.data_pos += 1;
                st.events_fired += 1;
            }
            st.await_d_window_remaining = 0;
            st.s1_reads_since_event = 0;
            return;
        }

        st.await_d_window_remaining -= 1;
        if st.await_d_window_remaining == 0 {
            st.s1_reads_since_event = 0;
        }
        return;
    }

    if st.events_fired >= cfg.max_events || st.data_pos >= cfg.data_bytes.len() {
        return;
    }

    if addr == cfg.s1_addr {
        st.s1_reads_since_event = st.s1_reads_since_event.saturating_add(1);
        if st.s1_reads_since_event >= cfg.trigger_reads {
            for b in buf.iter_mut() {
                *b = cfg.s1_value;
            }
            st.await_d_window_remaining = cfg.d_window_accesses;
            st.s1_reads_since_event = 0;
        }
    }
}

const VERSION: u8 = 1;
const FILE_HEADER: [u8; 4] = [b'm', b'u', b'l', VERSION];

/// Represents an input source where every MMIO access is read from a global input stream.
#[derive(Default)]
pub struct MultiStream {
    /// A mapping from MMIO address to the target input stream.
    pub streams: HashMap<StreamKey, StreamData>,
    pub last_read: Option<StreamKey>,
    pub tracer: Option<Box<dyn IoTracerAny>>,
}

impl std::fmt::Debug for MultiStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiStream")
            .field("streams", &self.streams)
            .field("last_read", &self.last_read)
            .field("tracer", &self.tracer.is_some())
            .finish()
    }
}

impl Clone for MultiStream {
    fn clone(&self) -> Self {
        Self {
            streams: self.streams.clone(),
            last_read: self.last_read,
            tracer: self.tracer.as_ref().map(|x| x.dyn_clone()),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        for (addr, stream) in &mut self.streams {
            if !source.streams.contains_key(addr) {
                stream.clear();
            }
        }

        for (addr, stream) in &source.streams {
            let dst = self.streams.entry(*addr).or_default();
            dst.clone_from(stream);
        }

        self.last_read = source.last_read;
    }
}

impl MultiStream {
    pub fn new(streams: HashMap<StreamKey, StreamData>) -> Self {
        Self { streams, last_read: None, tracer: None }
    }

    pub fn next_bytes(&mut self, addr: StreamKey, size: usize) -> Option<&[u8]> {
        self.last_read = Some(addr);
        let stream = self.streams.get_mut(&addr)?;

        let start = stream.cursor as usize;
        let end = start.checked_add(size)?;
        let buf = stream.bytes.get(start..end)?;
        crate::stream_observer::on_next_bytes(addr, size);
        stream.sizes |= size as u32;
        stream.cursor += size as u32;
        Some(buf)
    }

    pub fn clear(&mut self) {
        self.streams.values_mut().for_each(|x| x.clear());
    }

    pub fn total_bytes(&self) -> usize {
        self.streams.values().map(|x| x.bytes.len()).sum()
    }

    pub fn count_non_empty_streams(&self) -> usize {
        self.streams.iter().filter(|(_, data)| !data.bytes.is_empty()).count()
    }

    pub fn bytes_read(&self) -> usize {
        self.streams.values().map(|x| x.cursor as usize).sum()
    }

    pub fn from_path(path: &std::path::Path) -> anyhow::Result<Self> {
        let buf =
            std::fs::read(path).with_context(|| format!("error reading: {}", path.display()))?;

        if let Some(data) = Self::from_bytes(&buf) {
            return Ok(data);
        }
        legacy::multi_stream_from_bytes_v0(&buf).ok_or_else(|| {
            anyhow::format_err!("error parsing {} as multistream data", path.display())
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut headers: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, data)| !data.bytes.is_empty())
            .map(|(addr, data)| (*addr, data.bytes.len() as u64))
            .collect();
        headers.sort_unstable();

        let mut out = FILE_HEADER.to_vec();
        out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        for (addr, len) in &headers {
            out.extend_from_slice(&addr.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
        }

        for (addr, _) in headers {
            out.extend_from_slice(&self.streams[&addr].bytes);
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        use byteorder::{ReadBytesExt, LE};

        let mut reader = std::io::Cursor::new(buf);

        let mut magic_with_version = [0; 4];
        reader.read_exact(&mut magic_with_version).ok()?;
        if !matches!(magic_with_version, FILE_HEADER) {
            return None;
        }

        let num_mmio = reader.read_u32::<LE>().ok()?;
        if num_mmio > 0x10000 {
            tracing::error!("Too many MMIO peripherals {num_mmio}");
            return None;
        }

        let mut headers = Vec::with_capacity(num_mmio as usize);
        for _ in 0..num_mmio {
            let addr = reader.read_u64::<LE>().ok()?;
            let len = reader.read_u64::<LE>().ok()?;
            headers.push((addr, len));
        }

        let mut streams = HashMap::default();
        streams.reserve(headers.len());
        for (addr, len) in headers {
            if len > 0x100000 {
                tracing::error!("{addr:#x} contains too many bytes: {len}");
                return None;
            }
            let mut buf = vec![0; len as usize];
            reader.read_exact(&mut buf).ok()?;
            streams.insert(addr, StreamData::new(buf));
        }
        Some(MultiStream { streams, last_read: None, tracer: None })
    }

    pub fn seek_to_start(&mut self) {
        reset_uart_oneshot_state();
        strategy_runtime::on_execution_reset();
        self.streams.values_mut().for_each(|x| x.cursor = 0);
    }

    pub fn trim(&mut self) {
        self.streams.values_mut().for_each(|x| x.bytes.truncate(x.cursor as usize));
    }

    pub fn snapshot_cursors(&self) -> Vec<(u64, u32)> {
        self.streams.iter().map(|(key, value)| (*key, value.cursor)).collect()
    }

    pub fn restore_cursors(&mut self, snapshot: &Vec<(u64, u32)>) {
        snapshot
            .iter()
            .for_each(|(key, cursor)| self.streams.get_mut(key).unwrap().cursor = *cursor);
    }
}

mod legacy {
    use std::io::Read;

    use hashbrown::HashMap;

    use crate::input::{MultiStream, StreamData};

    pub fn multi_stream_from_bytes_v0(buf: &[u8]) -> Option<MultiStream> {
        use byteorder::{ReadBytesExt, LE};

        let mut reader = std::io::Cursor::new(buf);

        let num_mmio = reader.read_u32::<LE>().ok()?;
        if num_mmio > 0x1000 {
            return None;
        }

        let mut mmio_addrs = Vec::new();
        for _ in 0..num_mmio {
            mmio_addrs.push(reader.read_u64::<LE>().ok()?);
        }

        let mut streams = HashMap::default();
        for addr in mmio_addrs {
            let len = reader.read_u64::<LE>().ok()?;
            let mut buf = vec![0; len as usize];
            reader.read_exact(&mut buf).ok()?;
            streams.insert(addr, StreamData::new(buf));
        }
        Some(MultiStream { streams, last_read: None, tracer: None })
    }
}

impl IoMemory for MultiStream {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        let data = self.next_bytes(addr, buf.len()).ok_or(MemError::ReadWatch)?;
        buf.copy_from_slice(data);
        maybe_apply_uart_oneshot(addr, buf);
        strategy_runtime::on_mmio_read(addr, buf);
        if let Some(tracer) = self.tracer.as_mut() {
            tracer.read(addr, buf);
        }
        Ok(())
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> MemResult<()> {
        strategy_runtime::on_mmio_write(addr, value);
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(self.snapshot_cursors())
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        let snapshot = snapshot.downcast_ref::<Vec<(u64, u32)>>().unwrap();
        self.restore_cursors(snapshot)
    }
}
