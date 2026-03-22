from __future__ import annotations

from typing import Any, Dict, List


ACTION_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "mmio_read_override_once",
        "kind": "read-return",
        "description": "Override a single MMIO read with one concrete value.",
        "required_fields": ["addr", "width", "value", "trigger"],
        "optional_fields": ["activate_stage", "notes"],
        "example": {
            "type": "mmio_read_override_once",
            "addr": "0x4003D014",
            "width": 4,
            "value": "0x00000010",
            "trigger": {"kind": "after_global_reads", "value": 192},
            "activate_stage": "rtc_sr_unlocked",
        },
    },
    {
        "name": "mmio_read_override_repeat",
        "kind": "read-return",
        "description": "Override repeated MMIO reads with the same value for a bounded number of firings.",
        "required_fields": ["addr", "width", "value", "trigger", "repeat"],
        "optional_fields": ["activate_stage", "notes"],
        "example": {
            "type": "mmio_read_override_repeat",
            "addr": "0x4003D014",
            "width": 4,
            "value": "0x00000010",
            "repeat": 3,
            "trigger": {"kind": "on_first_touch", "addr": "0x4003D014"},
        },
    },
    {
        "name": "mmio_read_sequence",
        "kind": "read-return",
        "description": "Return a sequence of values across consecutive matching MMIO reads.",
        "required_fields": ["addr", "width", "values", "trigger"],
        "optional_fields": ["activate_stage", "notes"],
        "example": {
            "type": "mmio_read_sequence",
            "addr": "0x4003D014",
            "width": 4,
            "values": ["0x00000000", "0x00000010"],
            "trigger": {"kind": "on_first_touch", "addr": "0x4003D014"},
        },
    },
    {
        "name": "mmio_bit_update",
        "kind": "read-return",
        "description": "Update selected bits in the original MMIO read value without clobbering the entire word.",
        "required_fields": ["addr", "width", "trigger"],
        "optional_fields": ["set_bits", "clear_bits", "activate_stage", "notes"],
        "example": {
            "type": "mmio_bit_update",
            "addr": "0x4003D014",
            "width": 4,
            "set_bits": [4],
            "clear_bits": [0],
            "trigger": {"kind": "after_global_reads", "value": 192},
            "activate_stage": "rtc_sr_unlocked",
        },
    },
    {
        "name": "mmio_write_observe",
        "kind": "write-observe",
        "description": "Observe a write event and optionally activate a stage for later actions.",
        "required_fields": ["addr", "trigger"],
        "optional_fields": ["value", "mask", "activate_stage", "notes"],
        "example": {
            "type": "mmio_write_observe",
            "addr": "0x4003D01C",
            "mask": "0x00000001",
            "value": "0x00000001",
            "trigger": {"kind": "after_write_value", "addr": "0x4003D01C", "mask": "0x00000001", "value": "0x00000001"},
            "activate_stage": "rtc_ier_written",
        },
    },
    {
        "name": "mmio_write_then_read_gate",
        "kind": "write-read-gate",
        "description": "Wait for a write condition, then override a later read on a gated address.",
        "required_fields": ["write_addr", "read_addr", "width", "read_value", "trigger"],
        "optional_fields": ["write_mask", "write_value", "activate_stage", "notes"],
        "example": {
            "type": "mmio_write_then_read_gate",
            "write_addr": "0x4003D01C",
            "write_mask": "0x00000001",
            "write_value": "0x00000001",
            "read_addr": "0x4003D014",
            "width": 4,
            "read_value": "0x00000010",
            "trigger": {"kind": "after_write_value", "addr": "0x4003D01C", "mask": "0x00000001", "value": "0x00000001"},
        },
    },
    {
        "name": "uart_handshake_once",
        "kind": "device-sequence",
        "description": "Arm one UART status/data handshake with a status pulse and a short data consume window.",
        "required_fields": ["s1_addr", "d_addr", "s1_value", "data_bytes", "trigger"],
        "optional_fields": ["d_window_accesses", "activate_stage", "notes"],
        "example": {
            "type": "uart_handshake_once",
            "s1_addr": "0x4006A004",
            "d_addr": "0x4006A007",
            "s1_value": "0xC0",
            "data_bytes": ["0x41"],
            "d_window_accesses": 4,
            "trigger": {"kind": "on_nth_touch", "addr": "0x4006A004", "n": 2, "access": "read"},
            "activate_stage": "uart_handshake_done",
        },
    },
]

TRIGGER_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "after_global_reads",
        "description": "Fire after the per-execution global MMIO read counter reaches the given threshold before the target action site.",
        "required_fields": ["value"],
        "example": {"kind": "after_global_reads", "value": 192},
    },
    {
        "name": "on_first_touch",
        "description": "Fire when an address is touched for the first time by the specified access type.",
        "required_fields": ["addr"],
        "optional_fields": ["access"],
        "example": {"kind": "on_first_touch", "addr": "0x4003D01C", "access": "read"},
    },
    {
        "name": "on_nth_touch",
        "description": "Fire when an address is touched for the Nth time by the specified access type.",
        "required_fields": ["addr", "n"],
        "optional_fields": ["access"],
        "example": {"kind": "on_nth_touch", "addr": "0x4003D01C", "n": 3, "access": "read"},
    },
    {
        "name": "after_write",
        "description": "Fire immediately after a write to the specified MMIO address.",
        "required_fields": ["addr"],
        "example": {"kind": "after_write", "addr": "0x4003D01C"},
    },
    {
        "name": "after_write_value",
        "description": "Fire when a write satisfies a mask/value predicate.",
        "required_fields": ["addr", "value"],
        "optional_fields": ["mask"],
        "example": {"kind": "after_write_value", "addr": "0x4003D01C", "mask": "0x00000001", "value": "0x00000001"},
    },
    {
        "name": "when_stage_active",
        "description": "Fire only when the named stage has already been activated by an earlier action.",
        "required_fields": ["stage"],
        "example": {"kind": "when_stage_active", "stage": "rtc_sr_unlocked"},
    },
]

GROUP_TEMPLATE_CATALOG: List[Dict[str, Any]] = [
    {
        "template_id": "poll_ready_bit_set",
        "group_kinds": ["polling_group", "status_data_group", "status_config_group"],
        "description": "Set one ready-like/status-complete bit on the polling anchor.",
        "required_params": ["anchor_addr", "width", "field_or_bit", "trigger_family"],
    },
    {
        "template_id": "poll_busy_bit_clear",
        "group_kinds": ["polling_group", "status_data_group", "status_config_group"],
        "description": "Clear one busy/pending bit on the polling anchor.",
        "required_params": ["anchor_addr", "width", "field_or_bit", "trigger_family"],
    },
    {
        "template_id": "status_then_data",
        "group_kinds": ["status_data_group"],
        "description": "Use a status pulse followed by a short data path opportunity.",
        "required_params": ["anchor_addr", "data_addr", "trigger_family"],
    },
    {
        "template_id": "status_then_fifo",
        "group_kinds": ["status_data_group", "polling_group"],
        "description": "Use a status pulse for a FIFO-related companion path.",
        "required_params": ["anchor_addr", "companion_addr", "trigger_family"],
    },
    {
        "template_id": "status_then_config",
        "group_kinds": ["status_config_group", "polling_group"],
        "description": "Use a status pulse and activate a stage for config/control companions.",
        "required_params": ["anchor_addr", "companion_addr", "trigger_family"],
    },
    {
        "template_id": "config_bit_set",
        "group_kinds": ["config_group"],
        "description": "Set one configuration bit on the anchor register.",
        "required_params": ["anchor_addr", "width", "field_or_bit", "trigger_family"],
    },
    {
        "template_id": "config_bit_clear",
        "group_kinds": ["config_group"],
        "description": "Clear one configuration bit on the anchor register.",
        "required_params": ["anchor_addr", "width", "field_or_bit", "trigger_family"],
    },
    {
        "template_id": "config_bit_toggle",
        "group_kinds": ["config_group"],
        "description": "Try both set/clear style edits on a configuration bit.",
        "required_params": ["anchor_addr", "width", "field_or_bit", "trigger_family"],
    },
]


def llm_visible_schema() -> Dict[str, Any]:
    return {
        "schema_name": "llm_strategy_choice_v1",
        "rules": [
            "Only choose action types from action_catalog.",
            "Only choose trigger kinds from trigger_catalog.",
            "Only choose templates from group_template_catalog that are allowed for the hotspot group kind.",
            "Do not invent new actions, triggers, templates, or fields.",
            "All addresses must come from the evidence pack or hotspot groups.",
            "All bit-level edits must use SVD-defined fields/bits only.",
            "Return JSON only.",
        ],
        "action_catalog": ACTION_CATALOG,
        "trigger_catalog": TRIGGER_CATALOG,
        "group_template_catalog": GROUP_TEMPLATE_CATALOG,
    }
