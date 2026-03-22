use anyhow::{anyhow, bail};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessKind {
    Read,
    Write,
}

fn parse_u64_auto(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(x, 16).ok()
    }
    else {
        s.parse::<u64>().ok()
    }
}

fn de_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
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
        Repr::Str(s) => parse_u64_auto(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid integer: {s}"))),
    }
}

fn de_opt_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Int(u64),
        Str(String),
        Null(()),
    }
    match Repr::deserialize(deserializer)? {
        Repr::Int(v) => Ok(Some(v)),
        Repr::Str(s) => parse_u64_auto(&s)
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid integer: {s}"))),
        Repr::Null(()) => Ok(None),
    }
}

fn de_vec_u64<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Int(u64),
        Str(String),
    }
    let vals = Vec::<Repr>::deserialize(deserializer)?;
    let mut out = Vec::with_capacity(vals.len());
    for v in vals {
        match v {
            Repr::Int(x) => out.push(x),
            Repr::Str(s) => out.push(
                parse_u64_auto(&s)
                    .ok_or_else(|| serde::de::Error::custom(format!("invalid integer in list: {s}")))?,
            ),
        }
    }
    Ok(out)
}

fn de_vec_u8<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let vals = de_vec_u64(deserializer)?;
    let mut out = Vec::with_capacity(vals.len());
    for v in vals {
        if v > u8::MAX as u64 {
            return Err(serde::de::Error::custom(format!("byte out of range: {v}")));
        }
        out.push(v as u8);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceFile {
    pub schema: String,
    pub plan_name: String,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub actions: Vec<ActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TriggerSpec {
    #[serde(rename = "after_global_reads")]
    AfterGlobalReads {
        #[serde(deserialize_with = "de_u64")]
        value: u64,
    },
    #[serde(rename = "on_first_touch")]
    OnFirstTouch {
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        #[serde(default)]
        access: Option<AccessKind>,
    },
    #[serde(rename = "on_nth_touch")]
    OnNthTouch {
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        #[serde(deserialize_with = "de_u64")]
        n: u64,
        #[serde(default)]
        access: Option<AccessKind>,
    },
    #[serde(rename = "after_write")]
    AfterWrite {
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
    },
    #[serde(rename = "after_write_value")]
    AfterWriteValue {
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        #[serde(default, deserialize_with = "de_opt_u64")]
        mask: Option<u64>,
        #[serde(deserialize_with = "de_u64")]
        value: u64,
    },
    #[serde(rename = "when_stage_active")]
    WhenStageActive {
        stage: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ActionSpec {
    #[serde(rename = "mmio_read_override_once")]
    MmioReadOverrideOnce {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        width: usize,
        #[serde(deserialize_with = "de_u64")]
        value: u64,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    #[serde(rename = "mmio_read_override_repeat")]
    MmioReadOverrideRepeat {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        width: usize,
        #[serde(deserialize_with = "de_u64")]
        value: u64,
        repeat: u64,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    #[serde(rename = "mmio_read_sequence")]
    MmioReadSequence {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        width: usize,
        #[serde(deserialize_with = "de_vec_u64")]
        values: Vec<u64>,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    #[serde(rename = "mmio_bit_update")]
    MmioBitUpdate {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        width: usize,
        #[serde(default, deserialize_with = "de_vec_u64")]
        set_bits: Vec<u64>,
        #[serde(default, deserialize_with = "de_vec_u64")]
        clear_bits: Vec<u64>,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    #[serde(rename = "mmio_write_observe")]
    MmioWriteObserve {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        addr: u64,
        #[serde(default, deserialize_with = "de_opt_u64")]
        mask: Option<u64>,
        #[serde(default, deserialize_with = "de_opt_u64")]
        value: Option<u64>,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    #[serde(rename = "mmio_write_then_read_gate")]
    MmioWriteThenReadGate {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        write_addr: u64,
        #[serde(default, deserialize_with = "de_opt_u64")]
        write_mask: Option<u64>,
        #[serde(default, deserialize_with = "de_opt_u64")]
        write_value: Option<u64>,
        #[serde(deserialize_with = "de_u64")]
        read_addr: u64,
        width: usize,
        #[serde(deserialize_with = "de_u64")]
        read_value: u64,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    #[serde(rename = "uart_handshake_once")]
    UartHandshakeOnce {
        #[serde(default)]
        id: Option<String>,
        #[serde(deserialize_with = "de_u64")]
        s1_addr: u64,
        #[serde(deserialize_with = "de_u64")]
        d_addr: u64,
        #[serde(deserialize_with = "de_u64")]
        s1_value: u64,
        #[serde(deserialize_with = "de_vec_u8")]
        data_bytes: Vec<u8>,
        #[serde(default = "default_d_window_accesses")]
        d_window_accesses: u64,
        trigger: TriggerSpec,
        #[serde(default)]
        activate_stage: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
}

fn default_d_window_accesses() -> u64 {
    4
}

impl ActionSpec {
    pub fn kind_name(&self) -> &'static str {
        match self {
            ActionSpec::MmioReadOverrideOnce { .. } => "mmio_read_override_once",
            ActionSpec::MmioReadOverrideRepeat { .. } => "mmio_read_override_repeat",
            ActionSpec::MmioReadSequence { .. } => "mmio_read_sequence",
            ActionSpec::MmioBitUpdate { .. } => "mmio_bit_update",
            ActionSpec::MmioWriteObserve { .. } => "mmio_write_observe",
            ActionSpec::MmioWriteThenReadGate { .. } => "mmio_write_then_read_gate",
            ActionSpec::UartHandshakeOnce { .. } => "uart_handshake_once",
        }
    }

    pub fn activate_stage(&self) -> Option<&str> {
        match self {
            ActionSpec::MmioReadOverrideOnce { activate_stage, .. }
            | ActionSpec::MmioReadOverrideRepeat { activate_stage, .. }
            | ActionSpec::MmioReadSequence { activate_stage, .. }
            | ActionSpec::MmioBitUpdate { activate_stage, .. }
            | ActionSpec::MmioWriteObserve { activate_stage, .. }
            | ActionSpec::MmioWriteThenReadGate { activate_stage, .. }
            | ActionSpec::UartHandshakeOnce { activate_stage, .. } => activate_stage.as_deref(),
        }
    }
}

impl GuidanceFile {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != "mf_runtime_strategy_v1" {
            bail!("unsupported schema: {}", self.schema);
        }
        if self.actions.is_empty() {
            bail!("guidance contains no actions");
        }
        for action in &self.actions {
            match action {
                ActionSpec::MmioReadOverrideOnce { width, .. }
                | ActionSpec::MmioReadOverrideRepeat { width, .. }
                | ActionSpec::MmioReadSequence { width, .. }
                | ActionSpec::MmioBitUpdate { width, .. }
                | ActionSpec::MmioWriteThenReadGate { width, .. } => {
                    if *width == 0 || *width > 8 {
                        bail!("invalid width {} for {}", width, action.kind_name());
                    }
                }
                ActionSpec::UartHandshakeOnce { data_bytes, .. } => {
                    if data_bytes.is_empty() {
                        bail!("uart_handshake_once requires at least one data byte");
                    }
                }
                ActionSpec::MmioWriteObserve { .. } => {}
            }
        }
        Ok(())
    }
}

pub fn value_to_bytes(value: u64, width: usize) -> Vec<u8> {
    let bytes = value.to_le_bytes();
    bytes[..width].to_vec()
}

pub fn bytes_to_value(bytes: &[u8]) -> u64 {
    let mut tmp = [0u8; 8];
    let n = usize::min(bytes.len(), 8);
    tmp[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(tmp)
}

pub fn mask_match(observed: u64, mask: Option<u64>, expected: u64) -> bool {
    match mask {
        Some(m) => (observed & m) == (expected & m),
        None => observed == expected,
    }
}
