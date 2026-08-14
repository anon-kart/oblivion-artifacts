
import json, os
from typing import Any, Dict

def write_json(ir: Dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(ir, f, indent=2, ensure_ascii=False)
