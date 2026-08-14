#!/usr/bin/env bash
# Runs every behavioural oracle and prints a per-class induction count.
set -u
forge build || { echo "build failed - fix compilation before reading results"; exit 1; }
forge test --json > /tmp/oblivion_oracles.json 2>/dev/null
python3 - <<'PY'
import json, collections
d = json.load(open("/tmp/oblivion_oracles.json"))
c = collections.Counter()
for suite in d.values():
    for name, r in suite["test_results"].items():
        cls = name.split("_")[1] if name.startswith("test_D") else "?"
        cls = name[5:7]
        variant = "obfuscated" if name.endswith("obfuscated") else ("original" if name.endswith("original") else "diff")
        c[(cls, variant, r["status"])] += 1
for k in sorted(c):
    print("%-4s %-9s %-8s %d" % (k[0], k[1], k[2], c[k]))
induced = sum(v for k, v in c.items() if k[1] == "obfuscated" and k[2] == "Failure")
print("\ncontracts whose oracle fails after obfuscation:", induced)
PY
