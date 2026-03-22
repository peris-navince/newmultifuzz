#@runtime PyGhidra
#@author OpenAI
#@category MultiFuzz.KG
#@keybinding
#@menupath
#@toolbar

# PyGhidra / CPython 3 script for Ghidra headless.
#
# Main goals:
#   1) Export function / call / decompile / MMIO seed data for downstream KG building.
#   2) Improve MMIO extraction beyond raw constant scanning.
#   3) Emit structured debug artifacts so intermediate behavior is observable.
#
# Current MMIO pipeline:
#   - reference_manager      : high-confidence explicit memory references recognized by Ghidra
#   - highfunction pcode SSA : LOAD / STORE over decompiler SSA, with recursive constant resolution
#   - operand fallback       : very conservative last resort
#
# Extra output files written next to <out_json>:
#   - ghidra_debug.json   : detailed counters and samples for debugging
#   - ghidra_debug.log    : concise text log for quick inspection

import json
import os
import traceback
from collections import Counter, defaultdict

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.scalar import Scalar
from ghidra.util.task import ConsoleTaskMonitor


MMIO_RANGES = [
    (0x40000000, 0x5FFFFFFF),
    (0xE0000000, 0xE00FFFFF),
]


def jiter(obj):
    """
    Robustly iterate over PyGhidra / Java-backed collections.

    Supports:
      - Java iterators/enumerations exposing hasNext()/next()
      - Java arrays / Python sequences
      - Plain Python iterables
      - Objects exposing iterator()
    """
    if obj is None:
        return

    # Java iterator style
    try:
        has_next = getattr(obj, "hasNext", None)
        next_fn = getattr(obj, "next", None)
        if callable(has_next) and callable(next_fn):
            while obj.hasNext():
                yield obj.next()
            return
    except Exception:
        pass

    # Python iterable / Java array proxied as sequence
    try:
        for item in obj:
            yield item
        return
    except TypeError:
        pass
    except Exception:
        pass

    # Java object exposing iterator()
    try:
        it = obj.iterator()
        while it.hasNext():
            yield it.next()
        return
    except Exception:
        pass

    # Indexable fallback
    try:
        n = len(obj)
        for i in range(n):
            yield obj[i]
        return
    except Exception:
        pass


def to_int(v):
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        pass
    try:
        return int(v.getOffset())
    except Exception:
        return None


def is_mmio_value(v):
    x = to_int(v)
    if x is None:
        return False
    for lo, hi in MMIO_RANGES:
        if lo <= x <= hi:
            return True
    return False


def fmt_hex(v):
    x = to_int(v)
    if x is None:
        return None
    return "0x%08X" % (x & 0xFFFFFFFF)


def safe_str(obj):
    try:
        return str(obj)
    except Exception:
        try:
            return repr(obj)
        except Exception:
            return "<unprintable>"


def limit_append(lst, item, cap):
    if not isinstance(lst, list):
        return
    if len(lst) < cap:
        lst.append(item)


def is_isr_like(func):
    name = func.getName() or ""
    low = name.lower()
    if low.endswith("irqhandler") or low.endswith("handler") or "irq" in low or "isr" in low:
        return True
    entry = func.getEntryPoint().getOffset()
    return entry < 0x1000


def collect_calls(func):
    out = []
    try:
        called = func.getCalledFunctions(ConsoleTaskMonitor())
        for c in called:
            nm = c.getName()
            if nm:
                out.append(nm)
    except Exception:
        pass
    return sorted(list(set(out)))


def collect_disassembly(func, max_insn):
    listing = currentProgram.getListing()
    out = []
    it = listing.getInstructions(func.getBody(), True)
    c = 0
    while it.hasNext() and c < max_insn:
        insn = it.next()
        out.append(str(insn))
        c += 1
    return out


def classify_ref_kind(ref_type, default_kind="accesses_mmio"):
    try:
        if ref_type is not None:
            if ref_type.isRead():
                return "reads_mmio"
            if ref_type.isWrite():
                return "writes_mmio"
    except Exception:
        pass
    return default_kind


def classify_mnemonic_kind(insn):
    mnemonic = (insn.getMnemonicString() or "").lower()
    if mnemonic.startswith("ldr") or mnemonic.startswith("ld"):
        return "reads_mmio"
    if mnemonic.startswith("str") or mnemonic.startswith("st"):
        return "writes_mmio"
    return "accesses_mmio"


def describe_varnode(vn):
    if vn is None:
        return None
    try:
        parts = {
            "repr": safe_str(vn),
            "size": int(vn.getSize()),
            "is_constant": bool(vn.isConstant()),
            "is_register": bool(vn.isRegister()),
            "is_unique": bool(vn.isUnique()),
            "is_addr_tied": bool(vn.isAddrTied()),
            "offset_hex": fmt_hex(vn.getOffset()),
        }
        addr = vn.getAddress()
        if addr is not None:
            parts["address"] = safe_str(addr)
        try:
            high = vn.getHigh()
            if high is not None:
                parts["high_name"] = safe_str(high.getName())
        except Exception:
            pass
        return parts
    except Exception:
        return {"repr": safe_str(vn)}




def try_direct_varnode_address(vn, trace=None):
    """
    Best-effort direct address recovery for addr-tied memory varnodes.

    This is intentionally conservative:
      - accept concrete non-register / non-unique / non-constant memory-space varnodes
      - reject stack/register/unique/const/join-style spaces
    """
    if vn is None:
        return None
    try:
        if vn.isConstant() or vn.isRegister() or vn.isUnique():
            return None
    except Exception:
        return None

    try:
        addr = vn.getAddress()
    except Exception:
        addr = None
    if addr is None:
        return None

    try:
        space = addr.getAddressSpace()
        space_name = space.getName().lower()
    except Exception:
        space_name = ""

    # prune obvious non-memory or local-memory spaces
    bad_spaces = {
        "register", "unique", "const", "constant", "join", "hash", "stack",
        "overlay", "other"
    }
    if space_name in bad_spaces:
        if trace is not None:
            limit_append(trace, {"depth": 0, "event": "pruned-space", "space": space_name}, 40)
        return None

    try:
        val = int(addr.getOffset())
    except Exception:
        return None

    if trace is not None:
        limit_append(
            trace,
            {"depth": 0, "event": "direct-address", "space": space_name, "value_hex": fmt_hex(val)},
            40,
        )
    return val



def classify_non_mmio_unresolved(vn):
    """
    Cheap classifier for unresolved SSA address varnodes that are very likely
    *not* MMIO, so we can prune them from debug samples.

    Returns a short category string or None.
    """
    if vn is None:
        return None

    try:
        if vn.isRegister():
            return "register_based_pointer"
    except Exception:
        pass

    try:
        if vn.isConstant():
            val = int(vn.getOffset())
            return None if is_mmio_value(val) else "direct_non_mmio_memory"
    except Exception:
        pass

    try:
        addr = vn.getAddress()
    except Exception:
        addr = None

    if addr is not None:
        try:
            space = addr.getAddressSpace()
            space_name = space.getName().lower()
        except Exception:
            space_name = ""

        if space_name in ("ram", "mem", "memory"):
            try:
                val = int(addr.getOffset())
                return None if is_mmio_value(val) else "direct_non_mmio_memory"
            except Exception:
                return "direct_non_mmio_memory"

        if space_name in ("stack", "register", "unique", "join", "const", "constant", "hash", "overlay", "other"):
            return "register_based_pointer"

    try:
        defop = vn.getDef()
    except Exception:
        defop = None

    if defop is None:
        return None

    try:
        opc = defop.getOpcode()
    except Exception:
        return None

    try:
        if opc == PcodeOp.INDIRECT:
            base = defop.getInput(0)
            try:
                baddr = base.getAddress()
                bspace = baddr.getAddressSpace().getName().lower()
            except Exception:
                bspace = ""
            if bspace in ("ram", "mem", "memory"):
                try:
                    bval = int(baddr.getOffset())
                    return None if is_mmio_value(bval) else "indirect_non_mmio_memory"
                except Exception:
                    return "indirect_non_mmio_memory"
            return "indirect_non_mmio_memory"

        if opc in (PcodeOp.PTRSUB, PcodeOp.PTRADD):
            base = defop.getInput(0)
            try:
                if base.isRegister() or base.isUnique():
                    return "register_based_pointer"
            except Exception:
                pass
            try:
                baddr = base.getAddress()
                bspace = baddr.getAddressSpace().getName().lower()
            except Exception:
                bspace = ""
            if bspace in ("stack", "register", "unique"):
                return "register_based_pointer"
            if bspace in ("ram", "mem", "memory"):
                try:
                    bval = int(baddr.getOffset())
                    return None if is_mmio_value(bval) else "indirect_non_mmio_memory"
                except Exception:
                    return "indirect_non_mmio_memory"
    except Exception:
        return None

    return None

def resolve_const_varnode(vn, depth=0, seen=None, trace=None):
    """
    Best-effort constant resolver over decompiler SSA varnodes.
    Conservative by design. Returns integer or None.
    Optional trace receives human-readable steps for debugging.
    """
    if vn is None or depth > 10:
        if trace is not None:
            limit_append(trace, {"depth": depth, "event": "stop", "reason": "none-or-depth"}, 40)
        return None

    if seen is None:
        seen = set()

    try:
        key = (safe_str(vn.getAddress()), int(vn.getOffset()), int(vn.getSize()))
    except Exception:
        key = ("id", id(vn))
    if key in seen:
        if trace is not None:
            limit_append(trace, {"depth": depth, "event": "cycle", "varnode": describe_varnode(vn)}, 40)
        return None
    seen.add(key)

    try:
        if vn.isConstant():
            val = int(vn.getOffset())
            if trace is not None:
                limit_append(trace, {"depth": depth, "event": "constant", "value_hex": fmt_hex(val)}, 40)
            return val
    except Exception:
        pass

    direct_addr = try_direct_varnode_address(vn, trace=trace)
    if direct_addr is not None:
        return direct_addr

    try:
        defop = vn.getDef()
    except Exception:
        defop = None

    if defop is None:
        if trace is not None:
            limit_append(trace, {"depth": depth, "event": "no-def", "varnode": describe_varnode(vn)}, 40)
        return None

    opc = defop.getOpcode()
    try:
        mnemonic = defop.getMnemonic()
    except Exception:
        mnemonic = str(opc)
    if trace is not None:
        limit_append(trace, {"depth": depth, "event": "def", "opcode": mnemonic, "op": safe_str(defop)}, 40)

    def one(i):
        try:
            return resolve_const_varnode(defop.getInput(i), depth + 1, seen, trace)
        except Exception:
            return None

    # pass-through / cast-like
    if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE):
        return one(0)

    if opc == PcodeOp.INT_ADD:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a + b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.INT_SUB:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a - b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.INT_MULT:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a * b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.INT_OR:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a | b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.INT_AND:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a & b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.INT_XOR:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a ^ b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.INT_LEFT:
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a << b) & 0xFFFFFFFF
        return None

    if opc in (PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT):
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a >> b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.MULTIEQUAL:
        vals = []
        for i in range(defop.getNumInputs()):
            v = one(i)
            if v is None:
                return None
            vals.append(v)
        if vals and len(set(vals)) == 1:
            return vals[0]
        return None

    if opc == PcodeOp.PIECE:
        hi = one(0)
        lo = one(1)
        if hi is not None and lo is not None:
            try:
                lo_size = int(defop.getInput(1).getSize())
            except Exception:
                lo_size = 4
            return ((hi << (8 * lo_size)) | lo) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.PTRSUB:
        # Usually PTRSUB(base, const_off) => base + off
        a = one(0)
        b = one(1)
        if a is not None and b is not None:
            return (a + b) & 0xFFFFFFFF
        return None

    if opc == PcodeOp.PTRADD:
        # Usually PTRADD(base, index, stride) => base + index*stride
        base = one(0)
        idx = one(1)
        stride = one(2)
        if base is not None and idx is not None and stride is not None:
            return (base + (idx * stride)) & 0xFFFFFFFF
        return None

    return None


class MMIOCollector(object):
    def __init__(self, listing, ref_manager):
        self.listing = listing
        self.ref_manager = ref_manager
        self.aggregate_debug = {
            "functions_processed": 0,
            "functions_with_mmio": 0,
            "decompile_success": 0,
            "decompile_failure": 0,
            "reference": defaultdict(int),
            "ssa": defaultdict(int),
            "fallback": defaultdict(int),
            "access_sources": Counter(),
            "top_mmio_functions": [],
            "mmio_address_counter": Counter(),
            "sample_mmio_hits": [],
            "sample_unresolved_ssa": [],
            "log_lines": [],
        }

    def log(self, line):
        self.aggregate_debug["log_lines"].append(line)
        print(line)

    def _get_or_create_hit(self, hit_map, insn_addr, insn_text, kind, addr):
        key = (insn_addr, kind, int(addr))
        if key not in hit_map:
            hit_map[key] = {
                "instruction_address": insn_addr,
                "instruction_text": insn_text,
                "kind": kind,
                "address": int(addr),
                "address_hex": fmt_hex(addr),
                "evidence": [],
            }
        return hit_map[key]

    def _add_evidence(self, hit_map, func_debug, insn_addr, insn_text, kind, addr,
                      source, confidence, resolver, extra=None):
        if addr is None or not is_mmio_value(addr):
            return False

        item = self._get_or_create_hit(hit_map, insn_addr, insn_text, kind, addr)
        ev_key = (source, resolver)
        seen = item.setdefault("_seen_evidence", set())
        if ev_key in seen:
            return False
        seen.add(ev_key)

        ev = {
            "source": source,
            "confidence": confidence,
            "resolver": resolver,
        }
        if extra:
            for k, v in extra.items():
                if v is not None:
                    ev[k] = v
        item["evidence"].append(ev)

        self.aggregate_debug["access_sources"][source] += 1
        self.aggregate_debug["mmio_address_counter"][fmt_hex(addr)] += 1
        if len(self.aggregate_debug["sample_mmio_hits"]) < 20:
            self.aggregate_debug["sample_mmio_hits"].append({
                "function": func_debug["name"],
                "instruction_address": insn_addr,
                "instruction_text": insn_text,
                "kind": kind,
                "address_hex": fmt_hex(addr),
                "source": source,
                "resolver": resolver,
            })
        return True

    def collect_from_references(self, func, hit_map, func_debug):
        stats = func_debug["reference"]
        it = self.listing.getInstructions(func.getBody(), True)
        while it.hasNext():
            insn = it.next()
            stats["instructions_scanned"] += 1
            try:
                refs = self.ref_manager.getReferencesFrom(insn.getAddress())
            except Exception:
                refs = None
            if refs is None:
                continue
            for ref in jiter(refs):
                stats["references_seen"] += 1
                try:
                    to_addr = ref.getToAddress()
                    ref_type = ref.getReferenceType()
                except Exception:
                    continue
                if to_addr is None:
                    continue
                addr_val = to_int(to_addr.getOffset())
                if addr_val is None:
                    continue
                if not is_mmio_value(addr_val):
                    continue
                stats["mmio_refs"] += 1
                kind = classify_ref_kind(ref_type, classify_mnemonic_kind(insn))
                if self._add_evidence(
                    hit_map=hit_map,
                    func_debug=func_debug,
                    insn_addr=safe_str(insn.getAddress()),
                    insn_text=safe_str(insn),
                    kind=kind,
                    addr=addr_val,
                    source="reference",
                    confidence="high",
                    resolver="reference_manager",
                    extra={"reference_type": safe_str(ref_type)},
                ):
                    stats["hits_added"] += 1

    def collect_from_highfunction_ssa(self, func, high_func, hit_map, func_debug):
        stats = func_debug["ssa"]
        if high_func is None:
            stats["skipped_no_high_function"] += 1
            return

        for op in jiter(high_func.getPcodeOps()):
            stats["pcode_ops_seen"] += 1
            opc = op.getOpcode()
            if opc == PcodeOp.LOAD:
                stats["load_ops_seen"] += 1
                kind = "reads_mmio"
            elif opc == PcodeOp.STORE:
                stats["store_ops_seen"] += 1
                kind = "writes_mmio"
            else:
                continue

            try:
                seq = op.getSeqnum()
                insn_addr_obj = seq.getTarget()
                insn_addr = safe_str(insn_addr_obj)
            except Exception:
                insn_addr_obj = None
                insn_addr = None

            insn = None
            insn_text = safe_str(op)
            if insn_addr_obj is not None:
                try:
                    insn = self.listing.getInstructionAt(insn_addr_obj)
                    if insn is not None:
                        insn_text = safe_str(insn)
                except Exception:
                    pass

            try:
                addr_vn = op.getInput(1)
            except Exception:
                addr_vn = None

            trace = []
            addr_val = resolve_const_varnode(addr_vn, trace=trace)
            if addr_val is None:
                category = classify_non_mmio_unresolved(addr_vn)
                if category:
                    stats["pruned_" + category] += 1
                    continue

                stats["addr_unresolved"] += 1
                sample = {
                    "function": func_debug["name"],
                    "instruction_address": insn_addr,
                    "instruction_text": insn_text,
                    "opcode": safe_str(op.getMnemonic()),
                    "addr_varnode": describe_varnode(addr_vn),
                    "trace": trace[:10],
                }
                limit_append(stats["unresolved_samples"], sample, 12)
                limit_append(self.aggregate_debug["sample_unresolved_ssa"], sample, 20)
                continue

            stats["addr_resolved"] += 1
            if not is_mmio_value(addr_val):
                stats["addr_resolved_non_mmio"] += 1
                continue

            stats["addr_mmio"] += 1
            extra = {
                "pcode_op": safe_str(op),
                "pcode_opcode": safe_str(op.getMnemonic()),
            }
            if self._add_evidence(
                hit_map=hit_map,
                func_debug=func_debug,
                insn_addr=insn_addr,
                insn_text=insn_text,
                kind=kind,
                addr=addr_val,
                source="pcode_ssa",
                confidence="high",
                resolver="highfunction_load_store",
                extra=extra,
            ):
                stats["hits_added"] += 1
                limit_append(stats["resolved_mmio_samples"], {
                    "instruction_address": insn_addr,
                    "instruction_text": insn_text,
                    "opcode": safe_str(op.getMnemonic()),
                    "address_hex": fmt_hex(addr_val),
                    "trace": trace[:10],
                }, 12)

    def collect_from_constant_fallback(self, func, hit_map, func_debug):
        stats = func_debug["fallback"]
        it = self.listing.getInstructions(func.getBody(), True)
        while it.hasNext():
            insn = it.next()
            text = safe_str(insn)
            mnemonic = (insn.getMnemonicString() or "").lower()
            looks_like_mem = ("[" in text and "]" in text) or mnemonic.startswith("ldr") or mnemonic.startswith("str") or mnemonic.startswith("ld") or mnemonic.startswith("st")
            if not looks_like_mem:
                continue
            stats["mem_like_instructions_seen"] += 1
            num_ops = insn.getNumOperands()
            for i in range(num_ops):
                objs = insn.getOpObjects(i)
                if objs is None:
                    continue
                for obj in objs:
                    stats["operand_objects_seen"] += 1
                    value = None
                    if isinstance(obj, Scalar):
                        try:
                            value = obj.getUnsignedValue()
                        except Exception:
                            value = None
                    elif isinstance(obj, Address):
                        try:
                            value = obj.getOffset()
                        except Exception:
                            value = None
                    if value is None:
                        continue
                    stats["constant_candidates_seen"] += 1
                    if not is_mmio_value(value):
                        continue
                    stats["mmio_constants_seen"] += 1
                    if self._add_evidence(
                        hit_map=hit_map,
                        func_debug=func_debug,
                        insn_addr=safe_str(insn.getAddress()),
                        insn_text=text,
                        kind=classify_mnemonic_kind(insn),
                        addr=value,
                        source="operand_fallback",
                        confidence="low",
                        resolver="operand_constant_scan",
                    ):
                        stats["hits_added"] += 1

    def finalize_hits(self, hit_map):
        out = []
        for item in hit_map.values():
            item.pop("_seen_evidence", None)
            item["sources"] = sorted(list(set(ev.get("source") for ev in item.get("evidence", []) if ev.get("source"))))
            out.append(item)
        out.sort(key=lambda x: (x.get("instruction_address") or "", x.get("address") or 0, x.get("kind") or ""))
        return out

    def aggregate_function_debug(self, func_debug):
        self.aggregate_debug["functions_processed"] += 1
        if func_debug["decompile"]["completed"]:
            self.aggregate_debug["decompile_success"] += 1
        else:
            self.aggregate_debug["decompile_failure"] += 1

        if func_debug["mmio_summary"]["unique_accesses"] > 0:
            self.aggregate_debug["functions_with_mmio"] += 1
            limit_append(self.aggregate_debug["top_mmio_functions"], {
                "name": func_debug["name"],
                "unique_accesses": func_debug["mmio_summary"]["unique_accesses"],
                "sources": func_debug["mmio_summary"]["sources"],
            }, 40)

        for domain in ("reference", "ssa", "fallback"):
            for k, v in func_debug[domain].items():
                if isinstance(v, int):
                    self.aggregate_debug[domain][k] += v

        self.log(
            "[DEBUG][mmio] func=%s refs_added=%d ssa_added=%d fallback_added=%d unique=%d resolved_ssa=%d unresolved_ssa=%d" % (
                func_debug["name"],
                func_debug["reference"].get("hits_added", 0),
                func_debug["ssa"].get("hits_added", 0),
                func_debug["fallback"].get("hits_added", 0),
                func_debug["mmio_summary"].get("unique_accesses", 0),
                func_debug["ssa"].get("addr_resolved", 0),
                func_debug["ssa"].get("addr_unresolved", 0),
            )
        )


class DecompilerPool(object):
    def __init__(self, program):
        self.ifc = DecompInterface()
        self.ifc.toggleCCode(True)
        self.ifc.toggleSyntaxTree(True)
        self.ifc.openProgram(program)

    def decompile(self, func, timeout_secs):
        result = self.ifc.decompileFunction(func, timeout_secs, ConsoleTaskMonitor())
        info = {
            "completed": False,
            "error": None,
            "c": "",
            "high_function": None,
        }
        if result is None:
            info["error"] = "decompile returned None"
            return info
        info["completed"] = bool(result.decompileCompleted())
        try:
            info["error"] = result.getErrorMessage()
        except Exception:
            info["error"] = None
        try:
            dfunc = result.getDecompiledFunction()
            if dfunc is not None:
                info["c"] = dfunc.getC() or ""
        except Exception:
            pass
        try:
            info["high_function"] = result.getHighFunction()
        except Exception:
            info["high_function"] = None
        return info

    def dispose(self):
        try:
            self.ifc.dispose()
        except Exception:
            pass


def make_default_func_debug(func):
    ssa_stats = defaultdict(int)
    ssa_stats["unresolved_samples"] = []
    ssa_stats["resolved_mmio_samples"] = []
    reference_stats = defaultdict(int)
    fallback_stats = defaultdict(int)
    return {
        "name": func.getName(),
        "entry": safe_str(func.getEntryPoint()),
        "reference": reference_stats,
        "ssa": ssa_stats,
        "fallback": fallback_stats,
        "decompile": {
            "completed": False,
            "error": None,
            "high_function_available": False,
        },
        "mmio_summary": {
            "unique_accesses": 0,
            "sources": {},
        },
        "stage_errors": {},
    }


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def main():
    args = getScriptArgs()
    if len(args) < 1:
        raise RuntimeError("usage: export_binary_kg.py <out_json> [max_functions]")

    out_json = args[0]
    max_functions = 0
    if len(args) >= 2:
        try:
            max_functions = int(args[1])
        except Exception:
            max_functions = 0

    outdir = os.path.dirname(out_json) or "."
    debug_json = os.path.join(outdir, "ghidra_debug.json")
    debug_log = os.path.join(outdir, "ghidra_debug.log")

    listing = currentProgram.getListing()
    ref_manager = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    collector = MMIOCollector(listing, ref_manager)
    collector.log("[DEBUG][start] program=%s out_json=%s" % (currentProgram.getName(), out_json))

    out = {
        "program_name": currentProgram.getName(),
        "executable_path": currentProgram.getExecutablePath(),
        "language_id": safe_str(currentProgram.getLanguageID()),
        "compiler_spec": safe_str(currentProgram.getCompilerSpec().getCompilerSpecID()),
        "image_base": safe_str(currentProgram.getImageBase()),
        "functions": [],
        "debug_artifacts": {
            "ghidra_debug_json": debug_json,
            "ghidra_debug_log": debug_log,
        },
    }

    debug_out = {
        "program_name": currentProgram.getName(),
        "debug_json": debug_json,
        "debug_log": debug_log,
        "aggregate": None,
        "functions": [],
        "exceptions": [],
    }

    decompiler = DecompilerPool(currentProgram)

    try:
        count = 0
        while funcs.hasNext():
            func = funcs.next()
            count += 1
            if max_functions > 0 and count > max_functions:
                break

            func_debug = make_default_func_debug(func)

            try:
                decomp = decompiler.decompile(func, 15)
                func_debug["decompile"]["completed"] = bool(decomp["completed"])
                func_debug["decompile"]["error"] = decomp["error"]
                func_debug["decompile"]["high_function_available"] = bool(decomp["high_function"] is not None)

                hit_map = {}

                try:
                    collector.collect_from_references(func, hit_map, func_debug)
                except Exception as e:
                    func_debug["stage_errors"]["reference"] = safe_str(e)
                    collector.log("[DEBUG][stage-error] func=%s stage=reference error=%s" % (func.getName(), safe_str(e)))

                try:
                    collector.collect_from_highfunction_ssa(func, decomp["high_function"], hit_map, func_debug)
                except Exception as e:
                    func_debug["stage_errors"]["ssa"] = safe_str(e)
                    collector.log("[DEBUG][stage-error] func=%s stage=ssa error=%s" % (func.getName(), safe_str(e)))

                try:
                    collector.collect_from_constant_fallback(func, hit_map, func_debug)
                except Exception as e:
                    func_debug["stage_errors"]["fallback"] = safe_str(e)
                    collector.log("[DEBUG][stage-error] func=%s stage=fallback error=%s" % (func.getName(), safe_str(e)))

                mmio_accesses = collector.finalize_hits(hit_map)

                source_counter = Counter()
                for item in mmio_accesses:
                    for ev in item.get("evidence", []):
                        src = ev.get("source")
                        if src:
                            source_counter[src] += 1

                func_debug["mmio_summary"]["unique_accesses"] = len(mmio_accesses)
                func_debug["mmio_summary"]["sources"] = dict(source_counter)

                entry = func.getEntryPoint()
                item = {
                    "name": func.getName(),
                    "entry": safe_str(entry),
                    "entry_offset": int(entry.getOffset()),
                    "signature": safe_str(func.getSignature()),
                    "is_isr": bool(is_isr_like(func)),
                    "calls": collect_calls(func),
                    "disassembly": collect_disassembly(func, 120),
                    "mmio_accesses": mmio_accesses,
                    "decompile": decomp["c"],
                }
                out["functions"].append(item)

            except Exception as e:
                tb = traceback.format_exc()
                func_debug["exception"] = safe_str(e)
                debug_out["exceptions"].append({
                    "function": func.getName(),
                    "entry": safe_str(func.getEntryPoint()),
                    "error": safe_str(e),
                    "traceback": tb,
                })
                collector.log("[DEBUG][error] func=%s error=%s" % (func.getName(), safe_str(e)))
                # Keep partial item so debugging doesn't lose the function entirely.
                entry = func.getEntryPoint()
                out["functions"].append({
                    "name": func.getName(),
                    "entry": safe_str(entry),
                    "entry_offset": int(entry.getOffset()),
                    "signature": safe_str(func.getSignature()),
                    "is_isr": bool(is_isr_like(func)),
                    "calls": collect_calls(func),
                    "disassembly": collect_disassembly(func, 120),
                    "mmio_accesses": [],
                    "decompile": "",
                })

            collector.aggregate_function_debug(func_debug)
            debug_out["functions"].append(func_debug)

            if count % 25 == 0:
                collector.log("[DEBUG][progress] processed=%d functions_with_mmio=%d" % (
                    count,
                    collector.aggregate_debug["functions_with_mmio"],
                ))

    finally:
        decompiler.dispose()

    top_funcs_sorted = sorted(
        debug_out["functions"],
        key=lambda fd: fd.get("mmio_summary", {}).get("unique_accesses", 0),
        reverse=True,
    )
    collector.aggregate_debug["top_mmio_functions"] = [
        {
            "name": fd.get("name"),
            "unique_accesses": fd.get("mmio_summary", {}).get("unique_accesses", 0),
            "sources": fd.get("mmio_summary", {}).get("sources", {}),
        }
        for fd in top_funcs_sorted[:20]
        if fd.get("mmio_summary", {}).get("unique_accesses", 0) > 0
    ]
    collector.aggregate_debug["reference"] = dict(collector.aggregate_debug["reference"])
    collector.aggregate_debug["ssa"] = dict(collector.aggregate_debug["ssa"])
    collector.aggregate_debug["fallback"] = dict(collector.aggregate_debug["fallback"])
    collector.aggregate_debug["access_sources"] = dict(collector.aggregate_debug["access_sources"])
    collector.aggregate_debug["mmio_address_counter"] = dict(collector.aggregate_debug["mmio_address_counter"].most_common(50))
    debug_out["aggregate"] = collector.aggregate_debug

    write_json(out_json, out)
    write_json(debug_json, debug_out)
    with open(debug_log, "w", encoding="utf-8") as f:
        for line in collector.aggregate_debug["log_lines"]:
            f.write(line + "\n")

    collector.log(
        "[DEBUG][done] exported_functions=%d mmio_functions=%d access_sources=%s debug_json=%s" % (
            len(out["functions"]),
            collector.aggregate_debug["functions_with_mmio"],
            safe_str(collector.aggregate_debug["access_sources"]),
            debug_json,
        )
    )
    print("[ghidra_kg] exported %d functions to %s" % (len(out["functions"]), out_json))


main()
