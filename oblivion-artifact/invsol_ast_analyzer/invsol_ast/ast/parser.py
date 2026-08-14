import json
import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict


# Proper error types
class SolcNotFound(Exception):
    pass


class SolcRunError(Exception):
    pass


class ParseError(Exception):
    pass


def _run(cmd: list) -> str:
    """
    Run a solc command and return stdout text.

    IMPORTANT:
    - We must NOT merge stderr into stdout for JSON-producing commands,
      because solc prints warnings to stderr and that breaks json.loads().
    - So we capture stdout/stderr separately and only return stdout.
    """
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as e:
        raise SolcNotFound("`solc` not found on PATH. Install solc or set SOLC_PATH.") from e

    stdout = (res.stdout or b"").decode(errors="replace")
    stderr = (res.stderr or b"").decode(errors="replace")

    if res.returncode != 0:
        raise SolcRunError(
            "solc failed:\n"
            f"exit_code={res.returncode}\n"
            f"--- stdout ---\n{stdout}\n"
            f"--- stderr ---\n{stderr}\n"
        )

    return stdout


def _strip_solc_header(output: str) -> str:
    """
    Some solc versions print a human header like:

        JSON AST (compact format):


        ======= /path/to/file.sol =======
        { ... JSON ... }

    This helper strips everything before the first '{' so we can parse pure JSON.
    If no '{' is found, returns the original string.
    """
    text = output.lstrip()
    if text.startswith("{") or text.startswith("["):
        return text

    idx = text.find("{")
    if idx != -1:
        return text[idx:]

    return text


def parse_solidity_to_ast(path: str) -> Dict[str, Any]:
    """
    Obtain AST JSON via solc.

    1. Try `solc --ast-compact-json file.sol`
       - Handles both pure JSON and the "JSON AST (compact format)" header output.
       - Warnings are printed on stderr and will NOT break JSON parsing.
    2. If that fails, try `solc --standard-json`
    3. No silent fallback — raise errors if AST cannot be retrieved.

    Returns:
        {
            "source": "<path>",
            "ast": <solc AST dictionary>
        }
    """
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Solidity file not found: {path}")

    solc = shutil.which("solc")
    if solc is None:
        raise SolcNotFound("`solc` not found on PATH. Install solc or set SOLC_PATH.")

    # ---------------------------------------------------------
    # 1) Try compact AST first
    # ---------------------------------------------------------
    try:
        output = _run([solc, "--ast-compact-json", str(p)])
        text = _strip_solc_header(output)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ParseError(
                f"Could not decode solc --ast-compact-json output: {e}\n"
                f"Raw output (first 500 chars):\n{output[:500]}"
            )

        if isinstance(data, dict) and "sources" in data:
            for _, v in data["sources"].items():
                ast = v.get("ast", v)
                return {"source": str(p), "ast": ast}

        return {"source": str(p), "ast": data}

    except SolcRunError:
        pass

    # ---------------------------------------------------------
    # 2) Fallback to --standard-json
    # IMPORTANT:
    # Use inline "content" instead of "urls" so solc does not reject
    # absolute paths outside allowed directories.
    # ---------------------------------------------------------
    try:
        source_text = p.read_text(encoding="utf-8")
    except Exception as e:
        raise ParseError(f"Failed to read Solidity source for AST parsing: {p}\n{e}") from e

    std_input = {
        "language": "Solidity",
        "sources": {
            p.name: {
                "content": source_text
            }
        },
        "settings": {
            "outputSelection": {"*": {"*": ["*"], "": ["ast"]}}
        },
    }

    try:
        res = subprocess.run(
            [solc, "--standard-json"],
            input=json.dumps(std_input).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as e:
        raise SolcNotFound("`solc` not found on PATH. Install solc or set SOLC_PATH.") from e

    out_text = (res.stdout or b"").decode(errors="replace")
    err_text = (res.stderr or b"").decode(errors="replace")

    if res.returncode != 0:
        raise SolcRunError(
            "solc --standard-json failed:\n"
            f"exit_code={res.returncode}\n"
            f"--- stdout ---\n{out_text}\n"
            f"--- stderr ---\n{err_text}\n"
        )

    try:
        data = json.loads(out_text)
    except json.JSONDecodeError as e:
        raise ParseError(
            f"Could not decode solc --standard-json output: {e}\n"
            f"Raw output (first 500 chars):\n{out_text[:500]}"
        )

    sources = data.get("sources") or {}
    for _, src in sources.items():
        if isinstance(src, dict) and "ast" in src:
            return {"source": str(p), "ast": src["ast"]}

    raise ParseError(
        "No AST found in solc --standard-json output.\n"
        "This usually means solc failed silently or the input file is invalid.\n"
        f"solc stderr:\n{err_text}\n"
        f"solc stdout (first 2000 chars):\n{out_text[:2000]}"
    )