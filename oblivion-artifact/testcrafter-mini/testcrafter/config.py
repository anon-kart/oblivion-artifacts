
import json, os

DEFAULTS = {
    "output_dir": "outputs",
    "foundry_project_dir": "artifacts/foundry_project",
    "templates_dir": "templates",
    "verbosity": 4,
    "inline_uut": False,
    "contract_import_path": "src/AssetTransfer.sol"
}

def load_config(user_cfg_path: str | None = None):
    cfg = dict(DEFAULTS)
    if user_cfg_path and os.path.exists(user_cfg_path):
        with open(user_cfg_path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg
