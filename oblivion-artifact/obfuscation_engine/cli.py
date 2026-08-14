# obfuscation_engine/cli.py
from __future__ import annotations

import argparse
from pathlib import Path

from .engine import apply_variants_plan


def main(argv=None):
    p = argparse.ArgumentParser(description="Obfuscation Engine: apply variants_plan.json to Solidity source.")
    p.add_argument("--run-dir", required=True, help="artifacts/oblivion_runs/<ContractName>")
    p.add_argument("--foundry-root", required=True, help="Path to foundry_project root")
    p.add_argument("--plan", default="variants_plan.json")
    args = p.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    foundry_root = Path(args.foundry_root).resolve()
    plan_json = run_dir / args.plan

    obf_path, map_path = apply_variants_plan(plan_json=plan_json, foundry_root=foundry_root, out_dir=run_dir)
    print(f"[OBF-ENGINE] Wrote obfuscated source to: {obf_path}")
    print(f"[OBF-ENGINE] Wrote transform map to:    {map_path}")


if __name__ == "__main__":
    main()

