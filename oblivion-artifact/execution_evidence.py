#!/usr/bin/env python3
"""
ExecutionEvidence

Parses:
  - forge test -vvvv stdout  →  test_summary.json, test_results.json, traces.json, traces/
  - forge coverage --report lcov → coverage.json

Now includes internal call entries like:

  { "type": "call", "contract": "LoopPlayground", "function": "sumGridDots", "gas": 61559, "raw": "..." }

in addition to the harness-level call and events you already had.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional


# -----------------------------
# Data container
# -----------------------------


@dataclass
class ExecutionEvidence:
    tests: Dict[str, Dict[str, Any]]
    traces: Dict[str, List[Dict[str, Any]]]
    coverage: Dict[str, Any]

    # ----- construction from raw artifacts -----

    @classmethod
    def from_paths(cls, test_stdout: Path, coverage_lcov: Path) -> "ExecutionEvidence":
        tests, traces = parse_forge_test_stdout(test_stdout)
        coverage = parse_lcov(coverage_lcov) if coverage_lcov and coverage_lcov.exists() else {}
        return cls(tests=tests, traces=traces, coverage=coverage)

    @classmethod
    def from_run_dir(cls, run_dir: Path) -> "ExecutionEvidence":
        run_dir = run_dir.resolve()

        test_results_path = run_dir / "test_results.json"
        test_summary_path = run_dir / "test_summary.json"
        traces_path = run_dir / "traces.json"
        coverage_path = run_dir / "coverage.json"

        tests: Dict[str, Dict[str, Any]] = {}
        traces: Dict[str, List[Dict[str, Any]]] = {}
        coverage: Dict[str, Any] = {}

        if test_results_path.exists():
            tests = json.loads(test_results_path.read_text(encoding="utf-8"))
        elif test_summary_path.exists():
            tests = json.loads(test_summary_path.read_text(encoding="utf-8"))

        if traces_path.exists():
            traces = json.loads(traces_path.read_text(encoding="utf-8"))
        else:
            traces_dir = run_dir / "traces"
            if traces_dir.exists() and traces_dir.is_dir():
                for trace_file in sorted(traces_dir.glob("*.json")):
                    try:
                        payload = json.loads(trace_file.read_text(encoding="utf-8"))
                        if isinstance(payload, list):
                            traces[trace_file.stem] = payload
                    except Exception:
                        continue

        if coverage_path.exists():
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))

        return cls(tests=tests, traces=traces, coverage=coverage)

    # ----- export to JSON files -----

    def to_json_files(self, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)

        (out_dir / "test_summary.json").write_text(
            json.dumps(self.tests, indent=2), encoding="utf-8"
        )
        (out_dir / "test_results.json").write_text(
            json.dumps(self.tests, indent=2), encoding="utf-8"
        )
        (out_dir / "traces.json").write_text(
            json.dumps(self.traces, indent=2), encoding="utf-8"
        )
        (out_dir / "coverage.json").write_text(
            json.dumps(self.coverage, indent=2), encoding="utf-8"
        )

        traces_dir = out_dir / "traces"
        traces_dir.mkdir(parents=True, exist_ok=True)
        for test_name, entries in self.traces.items():
            safe_name = sanitize_trace_filename(test_name)
            (traces_dir / f"{safe_name}.json").write_text(
                json.dumps(entries, indent=2),
                encoding="utf-8",
            )


# -----------------------------
# forge test stdout parsing
# -----------------------------


# Example lines we want to parse:
#
# [PASS] test_sumGridDots_basic() (gas: 80842)
# [FAIL] test_something() (gas: 12345)
#
TEST_HEADER_RE = re.compile(
    r"^\[(PASS|FAIL)\]\s+([A-Za-z0-9_]+)\(\)\s+\(gas:\s*([0-9]+)\)"
)

# Example trace lines:
#
# Traces:
#   [80842] LoopPlayground_Harness::test_sumGridDots_basic()
#     ├─ [61559] LoopPlayground::sumGridDots()
#     ├─ emit MatrixDot(row: 0, col: 0, val: 1)
#     ├─ emit SumResult(sum: 228)
#
CALL_LINE_RE = re.compile(
    r"\[\s*(\d+)\]\s+([A-Za-z0-9_]+)::([A-Za-z0-9_]+)\("
)

EMIT_EVENT_RE = re.compile(
    r"emit\s+([A-Za-z0-9_]+)"
)


def parse_forge_test_stdout(
    path: Path,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """
    Parse forge -vvvv test stdout to:

      tests[name] = { "status": "PASS"/"FAIL", "gas": int }
      traces[name] = [ {type, ...}, ... ]

    We:
      - detect each test header line ([PASS]/[FAIL])
      - then find the "Traces:" block for that test
      - inside traces, we parse:
          * top-level harness call line ([gas] Harness::test_...)
          * internal calls ([gas] Contract::fn(...))
          * emit lines (events and log_*)
    """
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()

    tests: Dict[str, Dict[str, Any]] = {}
    traces: Dict[str, List[Dict[str, Any]]] = {}

    current_test: Optional[str] = None
    in_traces: bool = False

    for _, line in enumerate(text):
        stripped = line.strip()

        # 1) Detect test header
        m = TEST_HEADER_RE.match(stripped)
        if m:
            status, name, gas_str = m.groups()
            gas = int(gas_str)
            tests[name] = {"status": status, "gas": gas}
            current_test = name
            in_traces = False
            continue

        # 2) Enter Traces: block
        if stripped.startswith("Traces:"):
            if current_test is not None:
                in_traces = True
                traces.setdefault(current_test, [])
            continue

        # 3) If we hit a new test header or suite summary, stop traces for current test
        if in_traces:
            if TEST_HEADER_RE.match(stripped) or stripped.startswith("Suite result"):
                in_traces = False
                current_test = None
                continue

            if not stripped:
                continue

            # 3a) parse call lines: [gas] Contract::function(...)
            cm = CALL_LINE_RE.search(stripped)
            if cm:
                gas_str, contract, fn = cm.groups()
                try:
                    gas = int(gas_str)
                except ValueError:
                    gas = None

                entry = {
                    "type": "call",
                    "contract": contract,
                    "function": fn,
                    "gas": gas,
                    "raw": stripped,
                }
                traces[current_test].append(entry)
                continue

            # 3b) parse emit lines (events / logs)
            if "emit " in stripped:
                em = EMIT_EVENT_RE.search(stripped)
                if em:
                    event_name = em.group(1)
                else:
                    event_name = "unknown"

                entry = {
                    "type": "event",
                    "event": event_name,
                    "raw": stripped,
                }
                traces[current_test].append(entry)
                continue

            # Other trace lines are ignored to keep JSON compact.

    return tests, traces


# -----------------------------
# LCOV coverage parsing
# -----------------------------


def normalize_source_path(sf_line: str) -> str:
    """
    Normalize an SF: path to something like 'src/LoopPlayground.sol'.

    Forge LCOV SF lines are usually absolute paths; we want stable keys.
    """
    p = Path(sf_line).resolve()
    parts = p.parts

    if "src" in parts:
        idx = parts.index("src")
        return "/".join(parts[idx:])
    return p.name


def parse_lcov(path: Path) -> Dict[str, Any]:
    """
    Parse LCOV file to:

      {
        "src/LoopPlayground.sol": {
          "functions": { "LoopPlayground.sumGridDots": 1, ... },
          "lines": { "169": 5050, ... }
        },
        ...
      }
    """
    coverage: Dict[str, Any] = {}

    if not path.exists():
        return coverage

    current_file: Optional[str] = None
    fn_hits: Dict[str, int] = {}
    line_hits: Dict[str, int] = {}

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()

            if line.startswith("SF:"):
                if current_file is not None:
                    coverage[current_file] = {
                        "functions": dict(fn_hits),
                        "lines": dict(line_hits),
                    }
                sf = line[3:]
                current_file = normalize_source_path(sf)
                fn_hits = {}
                line_hits = {}
                continue

            if line.startswith("FNDA:"):
                rest = line[len("FNDA:") :]
                try:
                    count_str, fn_name = rest.split(",", 1)
                    count = int(count_str)
                    fn_hits[fn_name] = fn_hits.get(fn_name, 0) + count
                except ValueError:
                    continue
                continue

            if line.startswith("DA:"):
                rest = line[len("DA:") :]
                try:
                    line_no_str, cnt_str = rest.split(",", 1)
                    ln = int(line_no_str)
                    cnt = int(cnt_str)
                    line_hits[str(ln)] = line_hits.get(str(ln), 0) + cnt
                except ValueError:
                    continue
                continue

            if line.startswith("end_of_record"):
                if current_file is not None:
                    coverage[current_file] = {
                        "functions": dict(fn_hits),
                        "lines": dict(line_hits),
                    }
                    current_file = None
                    fn_hits = {}
                    line_hits = {}
                continue

    if current_file is not None:
        coverage[current_file] = {
            "functions": dict(fn_hits),
            "lines": dict(line_hits),
        }

    return coverage


# -----------------------------
# Helpers
# -----------------------------


_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_]+")


def sanitize_trace_filename(name: str) -> str:
    out = _SANITIZE_RE.sub("_", (name or "").strip())
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        out = "trace"
    if out[0].isdigit():
        out = f"t_{out}"
    return out