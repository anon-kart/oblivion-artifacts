# obfuscation_advisor/cli.py

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .advisor import build_contract_advice


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Obfuscation Advisor v0 - analyze IR + execution evidence and suggest obfuscation targets."
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Path to an oblivion run directory (e.g. artifacts/oblivion_runs/LoopPlayground).",
    )
    parser.add_argument(
        "--contract-name",
        help="Contract name; defaults to the run directory name (overrides IR contract name).",
    )
    parser.add_argument(
        "--source-relpath",
        help="Contract import path used by Foundry (e.g. src/LoopPlayground.sol). "
             "Default: tries src/<contract-name>.sol.",
    )
    parser.add_argument(
        "--out-json",
        help="Output path for advice JSON (default: <run-dir>/obfuscation_advice.json).",
    )

    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    contract_name = args.contract_name or run_dir.name

    # Default source relpath guess (can be overridden)
    source_relpath = args.source_relpath or f"src/{contract_name}.sol"

    # Expected artifact paths produced by oblivion_run.py
    ir_json = run_dir / f"{contract_name}_ir.json"
    coverage_json = run_dir / "coverage.json"
    traces_json = run_dir / "traces.json"
    test_summary_json = run_dir / "test_summary.json"

    missing = [p for p in [ir_json, coverage_json, traces_json, test_summary_json] if not p.exists()]
    if missing:
        print("[OBF-ADVISOR] ERROR: missing required files in run directory:")
        for p in missing:
            print(f"  - {p}")
        print("\nMake sure you ran `oblivion_run.py` first (or generated these artifacts).")
        raise SystemExit(1)

    advice_dict = build_contract_advice(
        ir_json=ir_json,
        coverage_json=coverage_json,
        test_summary_json=test_summary_json,
        traces_json=traces_json,
        contract_name=contract_name,
        source_relpath=source_relpath,
    )

    out_path = Path(args.out_json).resolve() if args.out_json else (run_dir / "obfuscation_advice.json")
    out_path.write_text(json.dumps(advice_dict, indent=2), encoding="utf-8")

    print(f"[OBF-ADVISOR] Wrote obfuscation advice to {out_path}")


if __name__ == "__main__":
    main()

