# scorer/bytecode_scorer.py
from __future__ import annotations

import json
import math
import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# ----------------------------
# Small helpers
# ----------------------------

def _run(cmd: list[str], *, cwd: Path) -> Tuple[int, str]:
    res = subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return res.returncode, (res.stdout or "")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _hex_to_bytes_len(hexstr: str) -> int:
    """
    hexstr may be:
      - "" (empty)
      - "0x..."
      - "deadbeef..."
    Return number of bytes.
    """
    if not hexstr:
        return 0
    s = hexstr.strip()
    if s.startswith("0x"):
        s = s[2:]
    if not s:
        return 0
    # If odd length, ignore last nibble (shouldn't happen for EVM bytecode)
    if len(s) % 2 == 1:
        s = s[:-1]
    return len(s) // 2


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _signed_to_unit(x: float) -> float:
    """
    Map a score in [-1, 1] to [0, 1].
    Useful for existing proxy scores that can be negative.
    """
    return _clamp01((x + 1.0) / 2.0)


# ----------------------------
# Transform-map quality helpers
# ----------------------------

def _is_cosmetic_transform_id(tid: str) -> bool:
    return tid in {
        "rename_identifiers_v2_scoped",
        "rename_identifiers_sha1_v1",
        "rename_identifiers_v1",
        "layout_scramble_v1",
    }


def _classify_transform_family(tid: str) -> str:
    """
    Best-effort transform family classifier.
    Keeps scorer self-contained even if transform catalog isn't imported here.
    """
    t = (tid or "").strip().lower()

    if not t:
        return "unknown"

    if "rename" in t or "layout" in t or "whitespace" in t or "format" in t:
        return "cosmetic"

    if "opaque" in t or "flatten" in t or "branch" in t or "split" in t or "dispatcher" in t:
        return "control"

    if "constant" in t or "literal" in t or "encode" in t or "array" in t or "mapping" in t:
        return "data"

    if "inline" in t or "extract" in t or "outline" in t or "clone" in t or "helper" in t:
        return "structure"

    return "other"


def _extract_transform_quality(transform_map_json: Optional[Path]) -> Dict[str, Any]:
    if not transform_map_json or not Path(transform_map_json).exists():
        return {
            "selected": 0,
            "applied": 0,
            "selected_noop": 0,
            "distinct_ids": 0,
            "distinct_families": 0,
            "has_noncosmetic": False,
            "cosmetic_only": False,
            "families": [],
            "applied_ids": [],
        }

    try:
        tm = _read_json(Path(transform_map_json))
    except Exception:
        return {
            "selected": 0,
            "applied": 0,
            "selected_noop": 0,
            "distinct_ids": 0,
            "distinct_families": 0,
            "has_noncosmetic": False,
            "cosmetic_only": False,
            "families": [],
            "applied_ids": [],
        }

    selected = tm.get("selected") or []
    applied = tm.get("applied") or []

    selected_ids = set()
    applied_ids = set()
    families = set()
    selected_noop = 0

    for row in selected:
        if not isinstance(row, dict):
            continue
        tid = row.get("id") or row.get("transform_id")
        if isinstance(tid, str) and tid:
            selected_ids.add(tid)
        if str(row.get("final_outcome") or "").strip().lower() == "noop":
            selected_noop += 1

    for row in applied:
        if not isinstance(row, dict):
            continue
        tid = row.get("id") or row.get("transform_id")
        changed = row.get("changed")

        # If "changed" is explicitly False, count as noop-like
        if changed is False:
            selected_noop += 1
            continue

        if isinstance(tid, str) and tid:
            applied_ids.add(tid)
            families.add(_classify_transform_family(tid))

    has_noncosmetic = any(not _is_cosmetic_transform_id(tid) for tid in applied_ids)
    cosmetic_only = bool(applied_ids) and all(_is_cosmetic_transform_id(tid) for tid in applied_ids)

    return {
        "selected": len(selected),
        "applied": len(applied_ids),
        "selected_noop": int(selected_noop),
        "distinct_ids": len(applied_ids),
        "distinct_families": len(families),
        "has_noncosmetic": bool(has_noncosmetic),
        "cosmetic_only": bool(cosmetic_only),
        "families": sorted(families),
        "applied_ids": sorted(applied_ids),
    }


# ----------------------------
# Opcode parsing (cheap)
# ----------------------------

# EVM opcodes map for 0x00..0xff.
# Minimal: include names; unknown -> "INVALID_<hex>"
# This is enough for "unique opcode count" and entropy.
EVM_OPCODES: Dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",

    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",

    0x20: "SHA3",

    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",

    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "DIFFICULTY",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",

    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",

    0x60: "PUSH1",
    0x61: "PUSH2",
    0x62: "PUSH3",
    0x63: "PUSH4",
    0x64: "PUSH5",
    0x65: "PUSH6",
    0x66: "PUSH7",
    0x67: "PUSH8",
    0x68: "PUSH9",
    0x69: "PUSH10",
    0x6A: "PUSH11",
    0x6B: "PUSH12",
    0x6C: "PUSH13",
    0x6D: "PUSH14",
    0x6E: "PUSH15",
    0x6F: "PUSH16",
    0x70: "PUSH17",
    0x71: "PUSH18",
    0x72: "PUSH19",
    0x73: "PUSH20",
    0x74: "PUSH21",
    0x75: "PUSH22",
    0x76: "PUSH23",
    0x77: "PUSH24",
    0x78: "PUSH25",
    0x79: "PUSH26",
    0x7A: "PUSH27",
    0x7B: "PUSH28",
    0x7C: "PUSH29",
    0x7D: "PUSH30",
    0x7E: "PUSH31",
    0x7F: "PUSH32",

    0x80: "DUP1",
    0x81: "DUP2",
    0x82: "DUP3",
    0x83: "DUP4",
    0x84: "DUP5",
    0x85: "DUP6",
    0x86: "DUP7",
    0x87: "DUP8",
    0x88: "DUP9",
    0x89: "DUP10",
    0x8A: "DUP11",
    0x8B: "DUP12",
    0x8C: "DUP13",
    0x8D: "DUP14",
    0x8E: "DUP15",
    0x8F: "DUP16",

    0x90: "SWAP1",
    0x91: "SWAP2",
    0x92: "SWAP3",
    0x93: "SWAP4",
    0x94: "SWAP5",
    0x95: "SWAP6",
    0x96: "SWAP7",
    0x97: "SWAP8",
    0x98: "SWAP9",
    0x99: "SWAP10",
    0x9A: "SWAP11",
    0x9B: "SWAP12",
    0x9C: "SWAP13",
    0x9D: "SWAP14",
    0x9E: "SWAP15",
    0x9F: "SWAP16",

    0xA0: "LOG0",
    0xA1: "LOG1",
    0xA2: "LOG2",
    0xA3: "LOG3",
    0xA4: "LOG4",

    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

# Fill in ranges programmatically for completeness.
for i in range(0xB0, 0xC0):
    EVM_OPCODES.setdefault(i, f"UNKNOWN_{i:02x}")
for i in range(0xC0, 0xD0):
    EVM_OPCODES.setdefault(i, f"UNKNOWN_{i:02x}")
for i in range(0xD0, 0xE0):
    EVM_OPCODES.setdefault(i, f"UNKNOWN_{i:02x}")
for i in range(0xE0, 0xF0):
    EVM_OPCODES.setdefault(i, f"UNKNOWN_{i:02x}")
for i in range(0x60, 0x80):
    EVM_OPCODES[i] = f"PUSH{i - 0x5F}"
for i in range(0x80, 0x90):
    EVM_OPCODES[i] = f"DUP{i - 0x7F}"
for i in range(0x90, 0xA0):
    EVM_OPCODES[i] = f"SWAP{i - 0x8F}"


def _hex_to_bytes(hexstr: str) -> bytes:
    if not hexstr:
        return b""
    s = hexstr.strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 == 1:
        s = s[:-1]
    if not s:
        return b""
    try:
        return bytes.fromhex(s)
    except Exception:
        return b""


def _opcode_stream(bytecode_hex: str) -> list[str]:
    """
    Decode bytecode into opcode names. Handles PUSHn immediate skipping.
    This is NOT a full disassembler (no PC map), but enough for diversity/entropy.
    """
    b = _hex_to_bytes(bytecode_hex)
    out: list[str] = []
    i = 0
    n = len(b)
    while i < n:
        op = b[i]
        name = EVM_OPCODES.get(op, f"INVALID_{op:02x}")
        out.append(name)

        # PUSH1..PUSH32: skip immediate bytes
        if 0x60 <= op <= 0x7F:
            push_n = op - 0x5F
            i += 1 + push_n
        else:
            i += 1
    return out


def _opcode_stats(opcodes: list[str]) -> Dict[str, Any]:
    if not opcodes:
        return {
            "count": 0,
            "unique": 0,
            "entropy": 0.0,
            "top": [],
        }

    freq: Dict[str, int] = {}
    for op in opcodes:
        freq[op] = freq.get(op, 0) + 1

    total = len(opcodes)
    unique = len(freq)

    # Shannon entropy in bits
    entropy = 0.0
    for c in freq.values():
        p = c / total
        entropy -= p * math.log2(p)

    top = sorted(freq.items(), key=lambda kv: kv[1], reverse=True)[:15]
    return {
        "count": total,
        "unique": unique,
        "entropy": entropy,
        "top": [{"op": k, "count": v} for k, v in top],
    }


def _cfg_proxy_stats(opcodes: list[str]) -> Dict[str, Any]:
    total = len(opcodes)
    jump = sum(1 for op in opcodes if op == "JUMP")
    jumpi = sum(1 for op in opcodes if op == "JUMPI")
    jumpdest = sum(1 for op in opcodes if op == "JUMPDEST")

    basic_blocks_est = jumpdest
    cfg_edges_est = jump + (2 * jumpi)
    branch_density = ((jump + jumpi) / total) if total > 0 else 0.0

    return {
        "opcode_count": total,
        "jump_count": jump,
        "jumpi_count": jumpi,
        "jumpdest_count": jumpdest,
        "basic_blocks_est": basic_blocks_est,
        "cfg_edges_est": cfg_edges_est,
        "branch_density": branch_density,
    }


# ----------------------------
# Artifact resolution
# ----------------------------

def _find_forge_artifact(
    *,
    foundry_root: Path,
    contract_name: str,
    target_relpath: Optional[str] = None,
) -> Optional[Path]:
    """
    Foundry artifacts are typically:
      <foundry_root>/out/<File.sol>/<Contract>.json

    If target_relpath is known, we use it to reduce ambiguity:
      target_relpath = "src/LoopPlayground.sol" -> file = "LoopPlayground.sol"

    Otherwise, fall back to searching out/**/<contract_name>.json.
    """
    out_dir = Path(foundry_root) / "out"
    if not out_dir.exists():
        return None

    if target_relpath:
        file_name = Path(target_relpath).name
        cand = out_dir / file_name / f"{contract_name}.json"
        if cand.exists():
            return cand

    matches = list(out_dir.rglob(f"{contract_name}.json"))
    for m in matches:
        if m.parent.name.endswith(".sol"):
            return m
    return matches[0] if matches else None


def _extract_bytecode_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, str]:
    """
    Return (bytecode_hex, deployed_bytecode_hex).
    Prefer deployedBytecode.object for "size in the wild".
    """
    bytecode = ""
    deployed = ""

    try:
        bytecode = str(((artifact.get("bytecode") or {}).get("object")) or "")
    except Exception:
        bytecode = ""
    try:
        deployed = str(((artifact.get("deployedBytecode") or {}).get("object")) or "")
    except Exception:
        deployed = ""

    if not deployed:
        deployed = bytecode

    return bytecode, deployed


def _flatten_sec_issues(sec_advice: Dict[str, Any]) -> list[Dict[str, Any]]:
    if not isinstance(sec_advice, dict):
        return []

    if isinstance(sec_advice.get("issues"), list):
        return [x for x in sec_advice["issues"] if isinstance(x, dict)]

    out: list[Dict[str, Any]] = []
    funcs = sec_advice.get("functions") or []
    if isinstance(funcs, list):
        for f in funcs:
            if not isinstance(f, dict):
                continue
            issues = f.get("issues") or []
            if not isinstance(issues, list):
                continue
            for iss in issues:
                if isinstance(iss, dict):
                    out.append(iss)
    return out


def _detector_proxy_metrics(
    *,
    diff_report: Optional[Dict[str, Any]],
    baseline_sec: Optional[Dict[str, Any]],
    candidate_sec: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    baseline_issues = _flatten_sec_issues(baseline_sec or {})
    candidate_issues = _flatten_sec_issues(candidate_sec or {})

    baseline_count = len(baseline_issues)
    candidate_count = len(candidate_issues)

    counts = (diff_report or {}).get("counts") or {}
    removed = int(counts.get("removed", 0))
    added = int(counts.get("added", 0))
    new_high = int(counts.get("new_high_or_critical", 0))

    denom = max(baseline_count, 1)
    recall_drop_proxy = removed / denom
    added_penalty = added / denom
    new_high_penalty = min(new_high / 2.0, 1.0)

    raw_score = recall_drop_proxy - 0.75 * added_penalty - 1.0 * new_high_penalty
    bounded_score = max(min(raw_score, 1.0), -1.0)

    return {
        "baseline_issue_count": baseline_count,
        "candidate_issue_count": candidate_count,
        "removed_detector_findings": removed,
        "added_detector_findings": added,
        "new_high_or_critical": new_high,
        "detector_recall_drop_proxy": recall_drop_proxy,
        "detector_surface_penalty": added_penalty,
        "detector_proxy_score": bounded_score,
    }


@contextmanager
def _temporary_source_swap(target_path: Path, replacement_path: Path):
    target_path = Path(target_path).resolve()
    replacement_path = Path(replacement_path).resolve()

    same_file = False
    try:
        same_file = target_path.exists() and replacement_path.exists() and target_path.samefile(replacement_path)
    except Exception:
        same_file = (str(target_path) == str(replacement_path))

    had_original = target_path.exists()
    backup_bytes = None if same_file else (target_path.read_bytes() if had_original else None)

    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # If source and target are the same file, no swap is needed.
        if not same_file:
            shutil.copy2(replacement_path, target_path)

        yield
    finally:
        if same_file:
            return

        if had_original and backup_bytes is not None:
            target_path.write_bytes(backup_bytes)
        elif target_path.exists():
            target_path.unlink()


def _build_and_snapshot_artifact(
    *,
    foundry_root: Path,
    contract_name: str,
    target_relpath: str,
    out_json_log: Path,
    snapshot_artifact_path: Path,
) -> Dict[str, Any]:
    code, logs = _run(["forge", "build", "--silent"], cwd=foundry_root)
    out_json_log.write_text(logs, encoding="utf-8")

    if code != 0:
        raise RuntimeError(
            f"forge build failed while producing {snapshot_artifact_path.name}"
        )

    art_path = _find_forge_artifact(
        foundry_root=foundry_root,
        contract_name=contract_name,
        target_relpath=target_relpath,
    )
    if not art_path or not art_path.exists():
        raise RuntimeError(f"artifact not found for {contract_name} at {target_relpath}")

    snapshot_artifact_path.write_text(
        art_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return _read_json(snapshot_artifact_path)


# ----------------------------
# Public API
# ----------------------------

@dataclass(frozen=True)
class BytecodeScoreResult:
    ok: bool
    reason: str
    paths: Dict[str, str]
    bytecode: Dict[str, Any]
    opcodes: Dict[str, Any]
    score: float


def score_bytecode_delta(
    *,
    foundry_root: Path,
    contract_name: str,
    original_target_relpath: str,
    candidate_target_relpath: Optional[str] = None,
    out_json: Path,
) -> BytecodeScoreResult:
    """
    Compile with Foundry and compute candidate-only bytecode/opcode metrics for
    whatever is currently present in the Foundry project.
    """
    foundry_root = Path(foundry_root).resolve()
    out_json = Path(out_json).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    code, logs = _run(["forge", "build", "--silent"], cwd=foundry_root)
    build_log = out_json.with_suffix(out_json.suffix + ".forge_build.log.txt")
    build_log.write_text(logs, encoding="utf-8")

    if code != 0:
        res = BytecodeScoreResult(
            ok=False,
            reason=f"forge_build_failed(returncode={code})",
            paths={"out_json": str(out_json), "forge_build_log": str(build_log)},
            bytecode={},
            opcodes={},
            score=0.0,
        )
        out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
        return res

    art_path = _find_forge_artifact(
        foundry_root=foundry_root,
        contract_name=contract_name,
        target_relpath=(candidate_target_relpath or original_target_relpath),
    )
    if not art_path or not art_path.exists():
        res = BytecodeScoreResult(
            ok=False,
            reason="artifact_not_found",
            paths={
                "out_json": str(out_json),
                "forge_build_log": str(build_log),
            },
            bytecode={},
            opcodes={},
            score=0.0,
        )
        out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
        return res

    artifact = _read_json(art_path)
    bytecode_hex, deployed_hex = _extract_bytecode_from_artifact(artifact)

    deployed_bytes = _hex_to_bytes_len(deployed_hex)
    bytecode_bytes = _hex_to_bytes_len(bytecode_hex)

    ops = _opcode_stream(deployed_hex)
    ops_stats = _opcode_stats(ops)

    size_term = min(deployed_bytes / 50000.0, 1.0)
    uniq_term = min(ops_stats.get("unique", 0) / 100.0, 1.0)
    ent_term = min(float(ops_stats.get("entropy", 0.0)) / 6.0, 1.0)
    score = 0.6 * size_term + 0.3 * uniq_term + 0.1 * ent_term

    res = BytecodeScoreResult(
        ok=True,
        reason="ok",
        paths={
            "out_json": str(out_json),
            "forge_build_log": str(build_log),
            "artifact": str(art_path),
        },
        bytecode={
            "bytecode_bytes": bytecode_bytes,
            "deployed_bytes": deployed_bytes,
            "bytecode_hex_len": len(
                bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
            ),
            "deployed_hex_len": len(
                deployed_hex[2:] if deployed_hex.startswith("0x") else deployed_hex
            ),
        },
        opcodes=ops_stats,
        score=float(score),
    )
    out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
    return res


def score_pair(
    *,
    foundry_root: Path,
    contract_name: str,
    original_artifact_path: Path,
    candidate_artifact_path: Path,
    out_json: Path,
) -> BytecodeScoreResult:
    """
    Compare original vs candidate using two artifact JSON files that already exist.
    """
    out_json = Path(out_json).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    if not Path(original_artifact_path).exists() or not Path(candidate_artifact_path).exists():
        res = BytecodeScoreResult(
            ok=False,
            reason="missing_artifact_json",
            paths={
                "out_json": str(out_json),
                "original_artifact": str(original_artifact_path),
                "candidate_artifact": str(candidate_artifact_path),
            },
            bytecode={},
            opcodes={},
            score=0.0,
        )
        out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
        return res

    orig_art = _read_json(Path(original_artifact_path))
    cand_art = _read_json(Path(candidate_artifact_path))

    _, orig_dep = _extract_bytecode_from_artifact(orig_art)
    _, cand_dep = _extract_bytecode_from_artifact(cand_art)

    orig_bytes = _hex_to_bytes_len(orig_dep)
    cand_bytes = _hex_to_bytes_len(cand_dep)

    delta_pct = 0.0
    if orig_bytes > 0:
        delta_pct = ((cand_bytes - orig_bytes) / orig_bytes) * 100.0

    orig_ops = _opcode_stream(orig_dep)
    cand_ops = _opcode_stream(cand_dep)

    orig_stats = _opcode_stats(orig_ops)
    cand_stats = _opcode_stats(cand_ops)

    uniq_delta = int(cand_stats.get("unique", 0)) - int(orig_stats.get("unique", 0))
    ent_delta = float(cand_stats.get("entropy", 0.0)) - float(orig_stats.get("entropy", 0.0))

    size_term = max(min(delta_pct / 50.0, 1.0), -1.0)
    uniq_term = max(min(uniq_delta / 40.0, 1.0), -1.0)
    ent_term = max(min(ent_delta / 2.0, 1.0), -1.0)
    score = 0.6 * size_term + 0.3 * uniq_term + 0.1 * ent_term

    res = BytecodeScoreResult(
        ok=True,
        reason="ok",
        paths={
            "out_json": str(out_json),
            "original_artifact": str(original_artifact_path),
            "candidate_artifact": str(candidate_artifact_path),
        },
        bytecode={
            "orig_deployed_bytes": orig_bytes,
            "cand_deployed_bytes": cand_bytes,
            "delta_bytes": cand_bytes - orig_bytes,
            "delta_pct": delta_pct,
        },
        opcodes={
            "orig": orig_stats,
            "cand": cand_stats,
            "unique_delta": uniq_delta,
            "entropy_delta": ent_delta,
        },
        score=float(score),
    )
    out_json.write_text(json.dumps(res.__dict__, indent=2), encoding="utf-8")
    return res


def score_contract(
    *,
    foundry_root: Path,
    out_dir: Path,
    contract_name: Optional[str] = None,
    target_relpath: Optional[str] = None,
    original_sol: Optional[Path] = None,
    candidate_sol: Optional[Path] = None,
    validator_dir: Optional[Path] = None,
    baseline_sec_advice_json: Optional[Path] = None,
    transform_map_json: Optional[Path] = None,
    **_: Any,
) -> Dict[str, Any]:
    """
    Differential adversarial proxy scorer.

    This builds and snapshots:
      - original artifact
      - candidate artifact

    Then combines:
      - bytecode/opcode delta score
      - CFG-ish structural proxy score
      - detector-facing proxy score from validator/security diff artifacts
      - transform realization quality bonus/penalty
    """
    foundry_root = Path(foundry_root).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not contract_name:
        if original_sol is not None:
            contract_name = Path(original_sol).stem
        elif candidate_sol is not None:
            contract_name = Path(candidate_sol).stem
        else:
            raise RuntimeError("score_contract requires contract_name or source path")

    if not target_relpath:
        if original_sol is not None:
            target_relpath = f"src/{Path(original_sol).name}"
        elif candidate_sol is not None:
            target_relpath = f"src/{Path(candidate_sol).name}"
        else:
            target_relpath = f"src/{contract_name}.sol"

    if original_sol is None or candidate_sol is None:
        raise RuntimeError("score_contract now requires both original_sol and candidate_sol")

    target_path = foundry_root / target_relpath
    original_artifact_path = out_dir / "original_artifact.json"
    candidate_artifact_path = out_dir / "candidate_artifact.json"

    original_build_log = out_dir / "original_build.log.txt"
    candidate_build_log = out_dir / "candidate_build.log.txt"

    with _temporary_source_swap(target_path, original_sol):
        _build_and_snapshot_artifact(
            foundry_root=foundry_root,
            contract_name=contract_name,
            target_relpath=target_relpath,
            out_json_log=original_build_log,
            snapshot_artifact_path=original_artifact_path,
        )

    with _temporary_source_swap(target_path, candidate_sol):
        _build_and_snapshot_artifact(
            foundry_root=foundry_root,
            contract_name=contract_name,
            target_relpath=target_relpath,
            out_json_log=candidate_build_log,
            snapshot_artifact_path=candidate_artifact_path,
        )

    pair_out_json = out_dir / "adversarial_proxy_score.json"
    pair_res = score_pair(
        foundry_root=foundry_root,
        contract_name=contract_name,
        original_artifact_path=original_artifact_path,
        candidate_artifact_path=candidate_artifact_path,
        out_json=pair_out_json,
    )

    orig_art = _read_json(original_artifact_path)
    cand_art = _read_json(candidate_artifact_path)

    _, orig_dep = _extract_bytecode_from_artifact(orig_art)
    _, cand_dep = _extract_bytecode_from_artifact(cand_art)

    orig_cfg = _cfg_proxy_stats(_opcode_stream(orig_dep))
    cand_cfg = _cfg_proxy_stats(_opcode_stream(cand_dep))

    cfg_delta = {
        "basic_blocks_delta": cand_cfg["basic_blocks_est"] - orig_cfg["basic_blocks_est"],
        "cfg_edges_delta": cand_cfg["cfg_edges_est"] - orig_cfg["cfg_edges_est"],
        "jump_delta": cand_cfg["jump_count"] - orig_cfg["jump_count"],
        "jumpi_delta": cand_cfg["jumpi_count"] - orig_cfg["jumpi_count"],
        "jumpdest_delta": cand_cfg["jumpdest_count"] - orig_cfg["jumpdest_count"],
        "branch_density_delta": cand_cfg["branch_density"] - orig_cfg["branch_density"],
    }

    cfg_growth_score = (
        0.40 * max(min(cfg_delta["basic_blocks_delta"] / 50.0, 1.0), -1.0)
        + 0.40 * max(min(cfg_delta["cfg_edges_delta"] / 80.0, 1.0), -1.0)
        + 0.20 * max(min(cfg_delta["branch_density_delta"] / 0.08, 1.0), -1.0)
    )

    diff_report: Dict[str, Any] = {}
    baseline_sec: Dict[str, Any] = {}
    candidate_sec: Dict[str, Any] = {}
    gas_diff_report: Dict[str, Any] = {}

    if validator_dir:
        validator_dir = Path(validator_dir)
        diff_path = validator_dir / "diff_report.json"
        candidate_sec_path = validator_dir / "candidate_sec_advice.json"
        gas_diff_path = validator_dir / "gas_diff.json"

        if diff_path.exists():
            diff_report = _read_json(diff_path)
        if candidate_sec_path.exists():
            candidate_sec = _read_json(candidate_sec_path)
        if gas_diff_path.exists():
            gas_diff_report = _read_json(gas_diff_path)

    if baseline_sec_advice_json and Path(baseline_sec_advice_json).exists():
        baseline_sec = _read_json(Path(baseline_sec_advice_json))

    detector_metrics = _detector_proxy_metrics(
        diff_report=diff_report,
        baseline_sec=baseline_sec,
        candidate_sec=candidate_sec,
    )

    # -----------------------------------------
    # Explicit multi-objective decomposition
    # -----------------------------------------

    # 1) Potency score: how much harder / richer the obfuscation appears
    bytecode_proxy_unit = _signed_to_unit(float(pair_res.score))
    cfg_proxy_unit = _signed_to_unit(float(cfg_growth_score))

    potency_score = _clamp01(
        0.60 * bytecode_proxy_unit
        + 0.40 * cfg_proxy_unit
    )

    # 2) Overhead score: penalize size + gas overhead
    bytecode_delta_pct = float(((pair_res.bytecode or {}).get("delta_pct")) or 0.0)
    bytecode_overhead_unit = _clamp01(max(bytecode_delta_pct, 0.0) / 50.0)

    gas_metric = (gas_diff_report.get("metric") or {})
    gas_used_value = float(gas_metric.get("used_value") or 0.0)
    gas_overhead_unit = _clamp01(max(gas_used_value, 0.0) / 25.0)

    overhead_score = _clamp01(
        0.50 * bytecode_overhead_unit
        + 0.50 * gas_overhead_unit
    )

    # 3) Risk score: penalize detector surface increase / new serious issues
    added_penalty = float(detector_metrics.get("detector_surface_penalty") or 0.0)
    new_high_count = int(detector_metrics.get("new_high_or_critical") or 0)
    new_high_penalty = _clamp01(new_high_count / 1.0)

    risk_score = _clamp01(
        0.70 * new_high_penalty
        + 0.30 * _clamp01(added_penalty)
    )

    # 4) Transform realization quality
    transform_quality = _extract_transform_quality(transform_map_json)

    transform_bonus = 0.0
    noop_penalty = 0.0

    distinct_families = int(transform_quality.get("distinct_families", 0))
    has_noncosmetic = bool(transform_quality.get("has_noncosmetic", False))
    cosmetic_only = bool(transform_quality.get("cosmetic_only", False))
    selected_noop = int(transform_quality.get("selected_noop", 0))

    # Reward diversity of realized transform families
    transform_bonus += min(0.10, 0.03 * distinct_families)

    # Reward at least one non-cosmetic realized transform
    if has_noncosmetic:
        transform_bonus += 0.08

    # Extra reward if control/data family appears
    fams = set(transform_quality.get("families") or [])
    if "control" in fams or "data" in fams:
        transform_bonus += 0.06

    # Penalize selected-but-noop transforms
    noop_penalty += min(0.20, 0.04 * selected_noop)

    # Penalize cosmetic-only outcome
    if cosmetic_only:
        noop_penalty += 0.12

    # 5) Explicit weighted objective
    weights = {
        "w1_potency": 0.50,
        "w2_overhead": 0.25,
        "w3_risk": 0.25,
    }

    objective_score = (
        weights["w1_potency"] * potency_score
        - weights["w2_overhead"] * overhead_score
        - weights["w3_risk"] * risk_score
        + transform_bonus
        - noop_penalty
    )

    payload = {
        "ok": True,
        "skipped": False,
        "reason": "ok",
        "scorer_kind": "adversarial_proxy_score",
        "scorer_version": "v3_multi_objective_transform_quality",
        "score": float(objective_score),  # legacy compatibility
        "objective_score": float(objective_score),
        "potency_score": float(potency_score),
        "overhead_score": float(overhead_score),
        "risk_score": float(risk_score),
        "transform_bonus": float(transform_bonus),
        "noop_penalty": float(noop_penalty),
        "weights": weights,
        "paths": {
            "out_json": str(pair_out_json),
            "original_artifact": str(original_artifact_path),
            "candidate_artifact": str(candidate_artifact_path),
            "original_build_log": str(original_build_log),
            "candidate_build_log": str(candidate_build_log),
            "validator_dir": str(validator_dir) if validator_dir else None,
            "transform_map_json": str(transform_map_json) if transform_map_json else None,
        },
        "bytecode": pair_res.bytecode,
        "opcodes": pair_res.opcodes,
        "cfg_proxy": {
            "orig": orig_cfg,
            "cand": cand_cfg,
            "delta": cfg_delta,
            "cfg_growth_score": float(cfg_growth_score),
        },
        "detector_proxy": detector_metrics,
        "transform_quality": transform_quality,
        "overhead_inputs": {
            "bytecode_delta_pct": float(bytecode_delta_pct),
            "gas_used_metric": str(gas_metric.get("used_metric") or ""),
            "gas_used_value_pct": float(gas_used_value),
        },
        "components": {
            "bytecode_proxy_score": float(pair_res.score),
            "cfg_proxy_score": float(cfg_growth_score),
            "detector_proxy_score": float(detector_metrics["detector_proxy_score"]),
        },
    }

    pair_out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload