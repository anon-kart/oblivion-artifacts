import argparse, os, sys
from rich import print
from .config import load_config
from .ast_bridge.adapter import load_contract_model
from .synthesis.harness_generator import generate_harness

DEFAULT_RELATIVE = os.path.join("..","invsol_ast_analyzer","examples","outputs","output.json")
FALLBACK_RELATIVE = os.path.join("..","invsol_ast_analyzer","examples","outputs","asset_ir.json")

def discover_ast_json(cmd_arg: str | None) -> str:
    # 1) explicit
    if cmd_arg and os.path.exists(cmd_arg):
        return cmd_arg
    # 2) env
    envp = os.getenv("AST_JSON_PATH")
    if envp and os.path.exists(envp):
        return envp
    # 3) default relative
    if os.path.exists(DEFAULT_RELATIVE):
        return DEFAULT_RELATIVE
    # 4) fallback if the asset_ir.json is directly the file
    if os.path.exists(FALLBACK_RELATIVE) and os.path.isfile(FALLBACK_RELATIVE):
        return FALLBACK_RELATIVE
    raise FileNotFoundError(
        f"AST JSON not found. Tried: {cmd_arg or '(none)'} | $AST_JSON_PATH | "
        f"{DEFAULT_RELATIVE} | {FALLBACK_RELATIVE}"
    )

def main():
    ap = argparse.ArgumentParser(description="TestCrafter v4 (auto-ast)")
    ap.add_argument("--ast-json", help="Override path to AST Analyzer JSON")
    ap.add_argument("--config", default="data/config.json", help="Optional JSON config file")
    ap.add_argument("--out", default=None, help="Output dir override")

    # NEW: verbosity & import/inline overrides
    ap.add_argument("--verbose-logs", action="store_true",
                    help="Emit detailed ENTER/EXIT + context logs in the harness")
    ap.add_argument("--no-verbose-logs", action="store_true",
                    help="Disable detailed logs even if enabled in config")
    ap.add_argument("--inline-uut", action="store_true",
                    help="Inline a minimal demo contract instead of importing the real one")
    ap.add_argument("--contract-import-path", default=None,
                    help='Path used by `import "<path>"` in the harness (e.g., src/AssetTransfer.sol)')

    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.out:
        cfg["output_dir"] = args.out

    # Apply CLI overrides to config
    if args.inline_uut:
        cfg["inline_uut"] = True
    if args.contract_import_path:
        cfg["contract_import_path"] = args.contract_import_path
    if args.verbose_logs and args.no_verbose_logs:
        print("[yellow]Both --verbose-logs and --no-verbose-logs were provided; defaulting to verbose on.[/]")
        cfg["verbose_logs"] = True
    elif args.verbose_logs:
        cfg["verbose_logs"] = True
    elif args.no_verbose_logs:
        cfg["verbose_logs"] = False
    else:
        # leave cfg['verbose_logs'] as-is (defaults to True in generator/config)
        pass

    try:
        ast_path = discover_ast_json(args.ast_json)
    except FileNotFoundError as e:
        print(f"[red]{e}[/]")
        sys.exit(1)

    print(f"[bold cyan]Using AST JSON:[/] {ast_path}")
    model = load_contract_model(ast_path)
    out_path = generate_harness(model, cfg)

    mode = "inline" if cfg.get("inline_uut") else "import"
    vlogs = cfg.get("verbose_logs", True)
    print(f"[green]Generated harness[/]: {out_path}")
    print(f"[dim]Import mode:[/] {mode} | path={cfg.get('contract_import_path')}")
    print(f"[dim]Verbose logs:[/] {'on' if vlogs else 'off'}")

if __name__ == "__main__":
    main()
