import json
import typer
from typing import Optional

from .pipeline import run_pipeline
from .config import STRICT_VALIDATION_DEFAULT

app = typer.Typer(help="InvSol AST Analyzer CLI")

@app.command()
def main(
    path: str = typer.Argument(..., help="Path to a Solidity file (.sol)"),
    out: str = typer.Option("ir.json", "--out", "-o", help="Output IR JSON path"),
    solc_path: Optional[str] = typer.Option(None, "--solc-path", help="Explicit path to `solc` binary"),
    strict: bool = typer.Option(STRICT_VALIDATION_DEFAULT, "--strict", help="Fail on validation issues"),
    no_validate: bool = typer.Option(False, "--no-validate", help="Skip schema + consistency checks"),
    print_ir: bool = typer.Option(False, "--print", help="Print IR to stdout after writing"),
    dump_ast: Optional[str] = typer.Option(None, "--dump-ast", help="Also write normalized analyzer JSON here"),
):
    ir = run_pipeline(
        path=path,
        out=out,
        solc_path=solc_path,
        validate=not no_validate,
        strict=strict,
        dump_ast=dump_ast,
    )
    if print_ir:
        typer.echo(json.dumps(ir, indent=2))

if __name__ == "__main__":
    app()
