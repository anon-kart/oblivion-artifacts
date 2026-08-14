# scorer/opcode_tools.py
"""
Opcode / bytecode utilities for Oblivion's adversarial scorer.

This module is intentionally dependency-light and works with:
  - raw EVM bytecode hex strings (with/without 0x)
  - Foundry/forge JSON artifacts containing "bytecode.object" or
    "deployedBytecode.object"

What we provide (v1):
  - hex normalization + decode
  - opcode disassembly (minimal but correct for PUSH/DATA)
  - opcode histogram + diversity metrics
  - bytecode size metrics
  - simple entropy metric over opcode stream
  - (optional) strip swarm/CBOR metadata for fairer comparisons

Notes:
  - EVM uses 1-byte opcodes.
  - PUSH1..PUSH32 are 0x60..0x7f and consume immediate data bytes.
  - We count opcodes as encountered in execution order (static stream),
    not runtime frequency.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional


# -----------------------------
# Hex / bytecode normalization
# -----------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def normalize_hex_bytecode(hex_str: str) -> str:
    """
    Normalize a bytecode hex string:
      - accept with/without 0x prefix
      - strip whitespace/newlines
      - validate hex characters
      - ensure even length (pad left with 0 if needed)
    Returns lowercase hex WITHOUT 0x.
    """
    if hex_str is None:
        return ""

    s = str(hex_str).strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    s = re.sub(r"\s+", "", s)

    if not s:
        return ""

    if not _HEX_RE.match(s):
        raise ValueError("bytecode contains non-hex characters")

    if len(s) % 2 == 1:
        # odd number of nibbles -> pad on the left
        s = "0" + s

    return s.lower()


def hex_to_bytes(hex_str: str) -> bytes:
    s = normalize_hex_bytecode(hex_str)
    return bytes.fromhex(s) if s else b""


# -----------------------------
# (Optional) metadata stripping
# -----------------------------

def strip_solc_metadata(bytecode: bytes) -> bytes:
    """
    Best-effort removal of Solidity compiler metadata tail (CBOR).

    Solidity appends CBOR metadata with a 2-byte length field at the very end.
    The last 2 bytes are the metadata length in bytes (big-endian).
    Many tools strip this before bytecode comparison to reduce noise.

    If it doesn't look like valid metadata, returns original bytecode.
    """
    if not bytecode or len(bytecode) < 2:
        return bytecode

    mlen = int.from_bytes(bytecode[-2:], "big")
    if mlen <= 0:
        return bytecode

    # total tail includes the length field itself
    total_tail = mlen + 2
    if total_tail >= len(bytecode):
        return bytecode

    # Heuristic: CBOR often begins with 0xa1 / 0xa2 etc (map) but not guaranteed.
    # We'll just trust the length field if it yields a plausible cut.
    return bytecode[: len(bytecode) - total_tail]


# -----------------------------
# Opcode table
# -----------------------------

# Minimal EVM opcode name map. Includes common opcodes + all PUSH/DUP/SWAP/LOG.
# Unknown opcodes are labeled "UNKNOWN_0x??".
OPCODES: Dict[int, str] = {
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
    0x44: "PREVRANDAO",  # formerly DIFFICULTY
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

# Generate PUSH1..PUSH32
for i in range(1, 33):
    OPCODES[0x5F + i] = f"PUSH{i}"

# Generate DUP1..DUP16
for i in range(1, 17):
    OPCODES[0x7F + i] = f"DUP{i}"

# Generate SWAP1..SWAP16
for i in range(1, 17):
    OPCODES[0x8F + i] = f"SWAP{i}"


def opcode_name(op: int) -> str:
    return OPCODES.get(op, f"UNKNOWN_0x{op:02x}")


def is_push(op: int) -> bool:
    return 0x60 <= op <= 0x7F


def push_immediate_len(op: int) -> int:
    # PUSH1=0x60 -> 1 byte, PUSH32=0x7f -> 32 bytes
    if not is_push(op):
        return 0
    return op - 0x5F


# -----------------------------
# Disassembly
# -----------------------------

@dataclass(frozen=True)
class Op:
    pc: int
    opcode: int
    name: str
    imm: bytes  # PUSH immediate, empty otherwise


def disassemble(bytecode: bytes) -> List[Op]:
    """
    Disassemble byte stream into Op entries.

    For PUSHn, captures immediate bytes (may be shorter if bytecode ends).
    """
    ops: List[Op] = []
    i = 0
    n = len(bytecode)

    while i < n:
        op = bytecode[i]
        name = opcode_name(op)
        imm = b""

        if is_push(op):
            k = push_immediate_len(op)
            start = i + 1
            end = min(start + k, n)
            imm = bytecode[start:end]
            ops.append(Op(pc=i, opcode=op, name=name, imm=imm))
            i = end
            continue

        ops.append(Op(pc=i, opcode=op, name=name, imm=imm))
        i += 1

    return ops


# -----------------------------
# Metrics
# -----------------------------

def opcode_histogram(ops: List[Op], *, normalize_push: bool = False) -> Dict[str, int]:
    """
    Count opcode names.

    If normalize_push=True, treat PUSH1..PUSH32 as a single bucket "PUSH".
    This can be helpful to compare patterns across compiler versions.
    """
    hist: Dict[str, int] = {}
    for o in ops:
        nm = o.name
        if normalize_push and nm.startswith("PUSH"):
            nm = "PUSH"
        hist[nm] = hist.get(nm, 0) + 1
    return hist


def opcode_diversity(hist: Dict[str, int]) -> int:
    """Number of distinct opcode buckets."""
    return len([k for k, v in hist.items() if v > 0])


def shannon_entropy_from_hist(hist: Dict[str, int]) -> float:
    """
    Shannon entropy over opcode distribution (base 2).
    Higher can indicate less repetitive opcode patterns.
    """
    total = sum(hist.values())
    if total <= 0:
        return 0.0

    ent = 0.0
    for c in hist.values():
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log(p, 2)
    return ent


def bytecode_size_metrics(bytecode: bytes) -> Dict[str, int]:
    """
    Size metrics in bytes.
      - total_bytes: length of bytecode
      - nonzero_bytes: count of bytes != 0x00
      - zero_bytes: count of bytes == 0x00
    """
    total = len(bytecode)
    zeros = bytecode.count(0)
    return {
        "total_bytes": total,
        "nonzero_bytes": total - zeros,
        "zero_bytes": zeros,
    }


def opcode_stream(bytecode: bytes, *, strip_metadata: bool = True) -> List[int]:
    """
    Return the opcode byte stream (including PUSHn opcodes themselves,
    but excluding PUSH immediate bytes).

    This is often what you want for opcode-level statistics.
    """
    b = strip_solc_metadata(bytecode) if strip_metadata else bytecode
    ops = disassemble(b)
    return [o.opcode for o in ops]


def opcode_histogram_from_bytecode(
    bytecode: bytes,
    *,
    strip_metadata: bool = True,
    normalize_push: bool = False,
) -> Dict[str, int]:
    b = strip_solc_metadata(bytecode) if strip_metadata else bytecode
    ops = disassemble(b)
    return opcode_histogram(ops, normalize_push=normalize_push)


def summarize_opcodes(
    bytecode: bytes,
    *,
    strip_metadata: bool = True,
    normalize_push: bool = False,
) -> Dict[str, object]:
    """
    Convenience one-shot summary used by the scorer.

    Returns:
      {
        "size": {...},
        "diversity": int,
        "entropy": float,
        "hist": {opcode: count, ...}
      }
    """
    b = strip_solc_metadata(bytecode) if strip_metadata else bytecode
    ops = disassemble(b)
    hist = opcode_histogram(ops, normalize_push=normalize_push)
    return {
        "size": bytecode_size_metrics(b),
        "diversity": opcode_diversity(hist),
        "entropy": shannon_entropy_from_hist(hist),
        "hist": hist,
    }


# -----------------------------
# Deltas
# -----------------------------

@dataclass(frozen=True)
class OpcodeDelta:
    size_delta_bytes: int
    size_delta_pct: float
    diversity_delta: int
    entropy_delta: float
    added_opcodes: Tuple[str, ...]
    removed_opcodes: Tuple[str, ...]


def compare_opcode_summaries(
    base: Dict[str, object],
    cand: Dict[str, object],
) -> OpcodeDelta:
    """
    Compare two summaries returned by summarize_opcodes.
    """
    bsz = int(((base.get("size") or {}).get("total_bytes")) or 0)
    csz = int(((cand.get("size") or {}).get("total_bytes")) or 0)

    size_delta = csz - bsz
    size_pct = 0.0 if bsz <= 0 else (size_delta / bsz) * 100.0

    bdiv = int(base.get("diversity") or 0)
    cdiv = int(cand.get("diversity") or 0)

    bent = float(base.get("entropy") or 0.0)
    cent = float(cand.get("entropy") or 0.0)

    bh = base.get("hist") or {}
    ch = cand.get("hist") or {}
    if not isinstance(bh, dict):
        bh = {}
    if not isinstance(ch, dict):
        ch = {}

    bset = {k for k, v in bh.items() if int(v) > 0}
    cset = {k for k, v in ch.items() if int(v) > 0}

    added = tuple(sorted(cset - bset))
    removed = tuple(sorted(bset - cset))

    return OpcodeDelta(
        size_delta_bytes=size_delta,
        size_delta_pct=size_pct,
        diversity_delta=cdiv - bdiv,
        entropy_delta=cent - bent,
        added_opcodes=added,
        removed_opcodes=removed,
    )
