import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import SolcNotFound, SolcRunError


def find_solc(explicit_path: Optional[str] = None) -> str:
    """
    Returns a path to `solc` or raises SolcNotFound.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            return str(p)
    solc = shutil.which("solc")
    if not solc:
        raise SolcNotFound(
            "`solc` not found on PATH. Install solc or provide an explicit path."
        )
    return solc


def run_solc(args: list[str], *, input_data: Optional[str] = None, solc_path: Optional[str] = None) -> str:
    """
    Runs solc with args and optional stdin input; returns stdout as text.
    Raises SolcRunError on failure.
    """
    solc = find_solc(solc_path)
    try:
        out = subprocess.check_output(
            [solc] + args,
            input=(input_data.encode() if input_data is not None else None),
            stderr=subprocess.STDOUT,
        )
        return out.decode()
    except subprocess.CalledProcessError as e:
        raise SolcRunError(e.output.decode()) from e


def get_solc_version(solc_path: Optional[str] = None) -> str:
    """
    Returns the semantic version like '0.8.26' from `solc --version`.
    """
    import re
    try:
        out = run_solc(["--version"], solc_path=solc_path)
        # Typical output:
        # solc, the solidity compiler commandline interface
        # Version: 0.8.26+commit.XXXXX.Linux.g++
        m = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", out)
        return m.group(1) if m else out.splitlines()[0].strip()
    except SolcRunError:
        return "unknown"


def ast_compact_json(file_path: str, solc_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Returns the JSON produced by `solc --ast-compact-json file.sol`.
    Some solc versions wrap the AST under 'sources'.
    """
    out = run_solc(["--ast-compact-json", str(file_path)], solc_path=solc_path)
    data = json.loads(out)
    if isinstance(data, dict) and "sources" in data:
        for _, v in data["sources"].items():
            return v.get("ast", v)  # best-effort
    return data


def standard_json_ast(file_path: str, solc_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Uses `--standard-json` to request AST. More consistent across versions.
    """
    std_input = {
        "language": "Solidity",
        "sources": {Path(file_path).name: {"urls": [str(Path(file_path).resolve())]}},
        "settings": {"outputSelection": {"*": {"*": ["*"], "": ["ast"]}}},
    }
    out = run_solc(["--standard-json"], input_data=json.dumps(std_input), solc_path=solc_path)
    data = json.loads(out)
    sources = data.get("sources") or {}
    for _, src in sources.items():
        if "ast" in src:
            return src["ast"]
    # Fallback
    return {"nodes": [], "note": "no ast found from --standard-json"}


def get_ast_best_effort(file_path: str, solc_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Tries compact JSON first, then standard-json; returns an AST-like dict.
    """
    try:
        return ast_compact_json(file_path, solc_path=solc_path)
    except (SolcRunError, json.JSONDecodeError):
        pass
    try:
        return standard_json_ast(file_path, solc_path=solc_path)
    except (SolcRunError, json.JSONDecodeError):
        return {"nodes": [], "note": "failed to obtain AST"}
