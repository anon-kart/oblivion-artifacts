# decision_planner/cli.py
from __future__ import annotations

import argparse
from pathlib import Path

from .planner import build_variants_plan


def main(argv=None):
    p = argparse.ArgumentParser(description="Decision/Planner: obfuscation_advice.json -> variants_plan.json")
    p.add_argument("--run-dir", required=True, help="artifacts/oblivion_runs/<ContractName>")
    p.add_argument("--advice", default="obfuscation_advice.json")
    p.add_argument("--out", default="variants_plan.json")
    p.add_argument("--policy", default=None, help="Optional policy.json path")
    args = p.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    advice_json = run_dir / args.advice
    out_json = run_dir / args.out
    policy_json = Path(args.policy).resolve() if args.policy else None

    build_variants_plan(advice_json=advice_json, out_json=out_json, policy_json=policy_json)
    print(f"[PLANNER] Wrote variants plan to {out_json}")


if __name__ == "__main__":
    main()

