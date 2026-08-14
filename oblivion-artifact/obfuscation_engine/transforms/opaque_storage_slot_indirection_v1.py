# obfuscation_engine/transforms/opaque_storage_slot_indirection_v1.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import re


@dataclass
class TransformResult:
    new_source: str
    details: Dict[str, Any]


def _find_contract_span(source: str, contract_name: str) -> Optional[Tuple[int, int]]:
    m = re.search(rf"\bcontract\s+{re.escape(contract_name)}\b", source)
    if not m:
        return None
    after = source[m.end():]
    m2 = re.search(r"\{", after)
    if not m2:
        return None
    lbrace = m.end() + m2.start()
    depth = 0
    rbrace = None
    for i in range(lbrace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                rbrace = i
                break
    if rbrace is None:
        return None
    return (lbrace, rbrace)


def _extract_state_var_block(contract_body: str) -> str:
    """
    Best-effort: take text from start of contract body until first function/modifier/constructor/event error.
    We'll parse state declarations inside this prefix.
    """
    # stop at first function/modifier/constructor to avoid local vars
    m = re.search(r"\b(function|modifier|constructor)\b", contract_body)
    return contract_body if not m else contract_body[: m.start()]


def _parse_mapping_decls(state_block: str) -> List[Dict[str, Any]]:
    """
    Parse mapping declarations:
      mapping(address => uint256) public deposits;
    Returns list of {name, key_type, val_type, full_decl}.
    """
    out: List[Dict[str, Any]] = []

    # simplistic mapping regex
    pat = re.compile(
        r"\bmapping\s*\(\s*([A-Za-z0-9_\[\]]+)\s*=>\s*([A-Za-z0-9_\[\]]+)\s*\)\s*(?:public|private|internal)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
        re.MULTILINE,
    )
    for m in pat.finditer(state_block):
        key_t = m.group(1).strip()
        val_t = m.group(2).strip()
        name = m.group(3).strip()
        out.append({"name": name, "key_type": key_t, "val_type": val_t, "full_decl": m.group(0)})

    return out


def _parse_storage_slots(state_block: str) -> Dict[str, int]:
    """
    Best-effort slot numbering: count non-constant state declarations in order.
    This is approximate but works for your style contracts (and LoopPlayground).
    """
    # Remove comments
    sb = re.sub(r"//.*?$", "", state_block, flags=re.MULTILINE)
    sb = re.sub(r"/\*.*?\*/", "", sb, flags=re.DOTALL)

    lines = [ln.strip() for ln in sb.splitlines() if ln.strip()]
    slots: Dict[str, int] = {}
    slot = 0

    # Very permissive var decl match; ignores function/event/etc due to state_block slicing
    var_pat = re.compile(r"^(?!event\b)(?!error\b)(?!using\b)(?!struct\b)(?!enum\b)(?!type\b)(?!mapping\b).*?\b([A-Za-z_][A-Za-z0-9_]*)\s*;$")
    mapping_pat = re.compile(r"^\bmapping\b.*?\b([A-Za-z_][A-Za-z0-9_]*)\s*;$")

    for ln in lines:
        if "constant" in ln:
            continue
        m_map = mapping_pat.search(ln)
        if m_map:
            name = m_map.group(1)
            slots[name] = slot
            slot += 1
            continue

        m_var = var_pat.search(ln)
        if m_var:
            name = m_var.group(1)
            # skip obvious keywords
            if name in ("public", "private", "internal", "external"):
                continue
            slots[name] = slot
            slot += 1

    return slots


def _inject_helpers_into_contract(contract_body: str, helpers_src: str) -> str:
    # Inject helpers just before the last '}' of the contract body.
    return contract_body.rstrip() + "\n\n" + helpers_src + "\n"


def apply_opaque_storage_slot_indirection_v1(
    *,
    source: str,
    contract_name: str,
    fn_name: str,
    seed: int = 1337,
    **params: Any,
) -> TransformResult:
    """
    Opaque storage indirection for mappings:
      mapping(K => uint256) name;

    Rewrites mapping reads/writes into helper calls that compute:
      slot = keccak256(abi.encode(key, uint256(SLOT_INDEX)))
      sload(slot) / sstore(slot)

    Limitations (best-effort):
    - Only targets mapping value type uint256 (safe cast for common cases).
    - Simple rewrite of `name[key]` and `name[key] = expr;` and `name[key] += expr;`
    """
    cspan = _find_contract_span(source, contract_name)
    if not cspan:
        return TransformResult(new_source=source, details={"note": "opaque_storage_slot_indirection_v1: contract not found"})

    cl, cr = cspan
    contract_body = source[cl + 1 : cr]
    state_block = _extract_state_var_block(contract_body)
    mappings = _parse_mapping_decls(state_block)
    if not mappings:
        return TransformResult(new_source=source, details={"note": "opaque_storage_slot_indirection_v1: no mappings found"})

    slots = _parse_storage_slots(state_block)

    # Choose mappings we can safely handle
    usable = []
    for mp in mappings:
        name = mp["name"]
        if mp["val_type"] != "uint256":
            continue
        if name not in slots:
            continue
        usable.append((mp, slots[name]))

    if not usable:
        return TransformResult(new_source=source, details={"note": "opaque_storage_slot_indirection_v1: no usable mappings (uint256) with slot index"})

    helpers = []
    for (mp, slot_idx) in usable:
        name = mp["name"]
        key_t = mp["key_type"]

        load_fn = f"__obf_map_load_{name}"
        store_fn = f"__obf_map_store_{name}"

        helpers.append(f"    function {load_fn}({key_t} k) internal view returns (uint256 v) {{")
        helpers.append(f"        bytes32 s = keccak256(abi.encode(k, uint256({slot_idx})));")
        helpers.append("        assembly { v := sload(s) }")
        helpers.append("    }")
        helpers.append("")
        helpers.append(f"    function {store_fn}({key_t} k, uint256 v) internal {{")
        helpers.append(f"        bytes32 s = keccak256(abi.encode(k, uint256({slot_idx})));")
        helpers.append("        assembly { sstore(s, v) }")
        helpers.append("    }")
        helpers.append("")

    helpers_src = "\n".join(helpers).rstrip()

    # Avoid duplicate helper injection
    if "__obf_map_load_" in contract_body and "__obf_map_store_" in contract_body:
        injected_body = contract_body
    else:
        injected_body = _inject_helpers_into_contract(contract_body, helpers_src)

    # Now rewrite mapping accesses in whole source (best-effort, but tries to avoid helper bodies)
    new_contract = injected_body

    for (mp, slot_idx) in usable:
        name = mp["name"]
        load_fn = f"__obf_map_load_{name}"
        store_fn = f"__obf_map_store_{name}"

        # Rewrite "+=" first (to avoid partial match with "=")
        # name[key] += expr;  ->  store(key, load(key) + (expr));
        pat_add = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<k>[^\]]+?)\s*\]\s*\+\=\s*(?P<e>[^;]+);")
        def repl_add(m):
            k = m.group("k").strip()
            e = m.group("e").strip()
            return f"{store_fn}({k}, {load_fn}({k}) + ({e}));"
        new_contract = pat_add.sub(repl_add, new_contract)

        # Rewrite direct assignment:
        # name[key] = expr; -> store(key, expr);
        pat_set = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<k>[^\]]+?)\s*\]\s*\=\s*(?P<e>[^;]+);")
        def repl_set(m):
            k = m.group("k").strip()
            e = m.group("e").strip()
            return f"{store_fn}({k}, ({e}));"
        new_contract = pat_set.sub(repl_set, new_contract)

        # Rewrite remaining reads:
        # name[key] -> load(key)
        # Avoid rewriting in the mapping declaration line by requiring a preceding non-word or whitespace
        pat_read = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<k>[^\]]+?)\s*\]")
        def repl_read(m):
            k = m.group("k").strip()
            return f"{load_fn}({k})"
        new_contract = pat_read.sub(repl_read, new_contract)

    new_source = source[:cl + 1] + new_contract + source[cr:]

    return TransformResult(
        new_source=new_source,
        details={
            "seed": seed,
            "note": "opaque_storage_slot_indirection_v1 injected slot-based mapping helpers and rewrote mapping accesses",
            "mappings": [{"name": mp["name"], "slot": slot_idx} for (mp, slot_idx) in usable],
        },
    )