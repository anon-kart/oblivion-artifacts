TestCrafter-mini — quick run guide

Generate a Foundry test harness from an AST JSON, then run it with forge.

tl;dr — the exact commands I use
cd ~/Desktop/InvSol/testcrafter-mini
source .venv/bin/activate
python -m testcrafter.c  forge test -vvvv


If you only want the generated harness file:

forge test --match-path test/SimpleToken_Harness.t.sol -vvvv

What the CLI expects (AST JSON location)

testcrafter.cli looks for the AST Analyzer’s JSON in this order:

CLI flag --ast-json <path>

Env var AST_JSON_PATH

Default relative path (from repo root):

../invsol_ast_analyzer/examples/outputs/output.json


Fallback relative path:

../invsol_ast_analyzer/examples/outputs/asset_ir.json


👉 So the easiest path is to save the AST analyzer output as:

../invsol_ast_analyzer/examples/outputs/output.json


relative to testcrafter-mini/.

Or, override at run time:

python -m testcrafter.cli --ast-json /full/path/to/output.json
# or
export AST_JSON_PATH=/full/path/to/output.json
python -m testcrafter.cli


If none of these exist, the CLI exits with “AST JSON not found…”

Running the generator

From the repo root, with your venv active:

python -m testcrafter.cli


You should see something like:

Using AST JSON: ../invsol_ast_analyzer/examples/outputs/output.json
Generated harness: artifacts/foundry_project/test/SimpleToken_Harness.t.sol
Import mode: import | path=src/SimpleToken.sol
Verbose logs: on

Useful flags

--config data/config.json — optional config file (default shown)

--out <dir> — override output dir (default is set in config)

--verbose-logs / --no-verbose-logs — turn detailed ENTER/EXIT + context logs on/off

--inline-uut — use an inline minimal demo contract instead of importing

--contract-import-path <path> — where the harness should import your contract (e.g. src/SimpleToken.sol)

Examples:

python -m testcrafter.cli --verbose-logs
python -m testcrafter.cli --ast-json ../invsol_ast_analyzer/examples/outputs/output.json --contract-import-path src/SimpleToken.sol

Where files are written

After generation:

artifacts/foundry_project/
├── src/                # your contract import target (or inline demo if --inline-uut)
├── test/
│   └── SimpleToken_Harness.t.sol   # the generated harness
└── foundry.toml

Running with Foundry

From the generated project:

cd artifacts/foundry_project
forge test -vvvv               # run entire suite with detailed traces
# or just the harness file:
forge test --match-path test/SimpleToken_Harness.t.sol -vvvv

What to expect in traces

ENTER/EXIT banners

vm.assume, vm.prank, vm.expectRevert steps

Context info (contract address, totalSupply)

Calls + return values (mint, burn, transfer)

Pre/post reads (balanceOf, totalSupply)

Event introspection via recordLogs()/getRecordedLogs() (topics + data)

Fuzz input dumps with bound values

These are at least as detailed as the manual sample you shared (often more detailed due to full event topic/data dumps).

Tips & troubleshooting

AST not found: confirm your JSON is at one of the searched paths, or pass --ast-json / set AST_JSON_PATH.

Changed AST? Re-run python -m testcrafter.cli to regenerate the harness before forge test.

Foundry: ensure forge --version works. If not, install Foundry and run foundryup.

One-week-later checklist ✅

cd ~/Desktop/InvSol/testcrafter-mini

source .venv/bin/activate

Make sure AST JSON exists at:
../invsol_ast_analyzer/examples/outputs/output.json
(or pass --ast-json / set AST_JSON_PATH)

python -m testcrafter.cli

cd artifacts/foundry_project

forge test -vvvv (or --match-path test/SimpleToken_Harness.t.sol)
