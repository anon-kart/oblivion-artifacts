from adapter import load_contract_model
from harness import generate_harness

AST = "examples/outputs/output.json"
model = load_contract_model(AST)

cfg = {
    "foundry_project_dir": "artifacts/foundry_project",
    "contract_import_path": "src/LoopPlayground.sol",
    "inline_uut": False,
    "verbose_logs": True,
    "mapping_snapshot_n": 10,
    # constructor expects uint256[] so we pass an inline array literal
    "constructor_args": "],
}

out = generate_harness(model, cfg)
print("Wrote:", out)
