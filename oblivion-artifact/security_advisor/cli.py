from __future__ import annotations

import argparse
from pathlib import Path
from .advisor import build_sec_advice

def main(argv=None):
    p = argparse.ArgumentParser(description="Security Advisor: run Slither and emit sec_advice.json")
    p.add_argument("--contract-name", required=True)
    p.add_argument("--source-relpath", required=True, help="e.g. src/LoopPlayground.sol")
    p.add_argument("--target-sol", required=True, help="path to Solidity file to analyze")
    p.add_argument("--out-json", required=True, help="output sec_advice.json path")
    p.add_argument("--cwd", default=None, help="optional cwd for slither run")
    p.add_argument("--coverage-json", default=None)
    p.add_argument("--traces-json", default=None)
    args = p.parse_args(argv)

    cwd = Path(args.cwd).resolve() if args.cwd else None

    build_sec_advice(
        contract_name=args.contract_name,
        source_relpath=args.source_relpath,
        target_sol=Path(args.target_sol).resolve(),
        out_json=Path(args.out_json).resolve(),
        cwd=cwd,
        coverage_json=Path(args.coverage_json).resolve() if args.coverage_json else None,
        traces_json=Path(args.traces_json).resolve() if args.traces_json else None,
    )
    print(f"[SEC-ADVISOR] wrote {args.out_json}")

if __name__ == "__main__":
    main()