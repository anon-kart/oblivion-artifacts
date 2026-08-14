import os
from typing import Dict, List, Optional, Tuple

from .logging_templates import (
    enter_log, exit_log, log_string, log_address, log_uint, log_bytes, log_bytes32, indent,
)

# ---------------------------
# Small helpers
# ---------------------------
def _is_scalar_type(typ: str) -> bool:
    """True only for non-array, non-mapping simple types we can read via () getter."""
    t = (typ or "").strip()
    if not t:
        return False
    if "mapping" in t:
        return False
    if "[" in t or "]" in t:
        return False
    return t.startswith(("address", "uint", "int")) or t == "bool"


def _constructor_params_from_model(model: Dict, functions: List[Dict]) -> List[Dict]:
    """Return constructor params (list of {name,type}), from model or functions."""
    ctor = (model.get("constructor") or {})
    params = ctor.get("params")
    if params:
        return params
    for f in functions or []:
        if f.get("name") == "constructor":
            return f.get("params", []) or []
    return []


def _needs_owner_prank(fn: Dict, access_deps: List[Dict]) -> bool:
    """
    Heuristic: if function has onlyOwner modifier OR requires has (msg.sender == owner)
    OR access_dependencies say role=owner, we prank as OWNER.
    """
    mods = set(fn.get("modifiers", []) or [])
    reqs = " ".join(fn.get("requires", []) or [])
    if "onlyOwner" in mods:
        return True
    if "msg.sender" in reqs and "owner" in reqs:
        return True
    for dep in access_deps or []:
        if dep.get("function") == fn.get("name") and (dep.get("role") == "owner"):
            return True
    return False


def _dummy_arg_for_type(sol_type: str, idx: int) -> str:
    """
    Return a compilable default literal/expression for the given Solidity type.
    Supports dynamic/fixed arrays by allocating a memory array.
    """
    t = (sol_type or "").strip()
    if not t:
        return "0"

    # Arrays (dynamic or fixed, incl. multi-dim)
    if "[" in t and "]" in t:
        base = t.split("[", 1)[0].strip()         # e.g. "uint256" from "uint256[]" / "uint256[][]"
        dims = t.count("[")                        # number of dimensions
        bracket_suffix = "[]" * dims               # "[]", "[][]", ...
        length = max(2, idx + 1)                   # small non-zero length
        return f"new {base}{bracket_suffix}({length})"

    # Scalars
    if t == "address":
        return "address(0xC0FFEE)"
    if t.startswith("uint") or t.startswith("int"):
        return str(100 * (idx + 1))
    if t == "bool":
        return "true"
    if t.startswith("bytes"):
        return 'hex""'
    if t.startswith("string"):
        return '"test"'
    return "0"



def _build_args(fn: Dict) -> List[str]:
    params = fn.get("params", []) or []
    return [_dummy_arg_for_type(p.get("type", ""), i) for i, p in enumerate(params)]


def _first_address_param(fn: Dict) -> Optional[Tuple[int, str]]:
    """Return (index, nameOrDefault) of the first address parameter, or None."""
    params = fn.get("params", []) or []
    for i, p in enumerate(params):
        if (p.get("type") or "").strip() == "address":
            name = p.get("name") or f"arg{i}"
            return i, name
    return None


def _has_fn(functions: List[Dict], name: str, param_types: List[str]) -> bool:
    for f in functions or []:
        if f.get("name") != name:
            continue
        params = f.get("params", []) or []
        if len(params) != len(param_types):
            continue
        if all((params[i].get("type") or "").strip() == param_types[i] for i in range(len(param_types))):
            return True
    return False


def _has_total_supply(functions: List[Dict]) -> bool:
    for f in functions or []:
        if f.get("name") == "totalSupply" and len(f.get("params", []) or []) == 0:
            return True
    return False


def _has_balance_getter(functions: List[Dict]) -> bool:
    return _has_fn(functions, "balanceOf", ["address"])


def _log_params(fn: Dict, args: List[str]) -> List[str]:
    """
    Emit lines that log each parameter's label (name + type) and the value being used.
    Arrays/mappings are logged as strings (their literal expressions), not as uint.
    """
    lines: List[str] = []
    params = fn.get("params", []) or []
    for i, p in enumerate(params):
        ptype = (p.get("type") or "").strip()
        pname = p.get("name") or f"arg{i}"
        lines.append(log_string(f"{pname}: ({ptype})"))

        is_array_or_mapping = ("[" in ptype) or ("]" in ptype) or ("mapping" in ptype)
        if is_array_or_mapping:
            # Don't try to use log_uint/log_address on arrays/mappings
            lines.append(log_string(args[i]))
        elif ptype.startswith("address"):
            lines.append(log_address(args[i]))
        elif ptype == "bool" or ptype.startswith("uint") or ptype.startswith("int"):
            lines.append(log_uint(args[i]))
        elif ptype == "bytes32":
            lines.append(log_bytes32(args[i]))
        elif ptype.startswith("bytes"):
            lines.append(log_bytes(args[i]))
        else:
            lines.append(log_string(args[i]))
    return lines



def _log_basic_context(contract_var: str, state_vars: List[Dict], header: str = "Context Info:") -> List[str]:
    """
    Emit generic context logs: header + contract address + simple state getters.
    Only logs primitive-like state vars (address/uint*/bool).
    """
    lines: List[str] = []
    lines.append(log_string(header))
    lines.append(log_string("Address of Contract: (address)"))
    lines.append(log_address(f"address({contract_var})"))

    for sv in state_vars or []:
        name = sv.get("name")
        typ = (sv.get("type") or "").strip()
        if not name:
            continue

        # only log simple scalar-like vars; skip arrays/mappings/etc.
        if not _is_scalar_type(typ):
            continue

        lines.append(log_string(f"{name}: ({typ})"))
        getter_expr = f"{contract_var}.{name}()"
        if typ.startswith("address"):
            lines.append(log_address(getter_expr))
        elif typ.startswith(("uint", "int")):
            lines.append(log_uint(getter_expr))
        elif typ == "bool":
            lines.append(log_uint(f"{getter_expr} ? 1 : 0"))  # cast to 0/1

    return lines


def _log_mapping_snapshots(contract_var: str, functions: List[Dict], n: int) -> List[str]:
    """
    If we detect an ERC20-like balanceOf(address), emit sample reads for the first N addresses.
    """
    if not _has_balance_getter(functions):
        return []
    lines: List[str] = []
    lines.append(log_string("Balances Mapping: (address => uint256)"))
    for i in range(1, n + 1):
        addr_expr = f"address(0x{i:X})"
        lines.append(log_address(addr_expr))
        lines.append(log_uint(f"{contract_var}.balanceOf({addr_expr})"))
    return lines


def _emit_event_dump_block() -> List[str]:
    """
    Returns Solidity lines for a helper that prints recorded logs.
    """
    block: List[str] = []
    block.append("    function _printRecordedLogs() internal {")
    block.append("        Vm.Log[] memory entries = vm.getRecordedLogs();")
    block.append("        for (uint256 i = 0; i < entries.length; i++) {")
    block.append('            emit log_string("Event:");')
    block.append("            emit log_address(entries[i].emitter);")
    block.append("            for (uint256 t = 0; t < entries[i].topics.length; t++) {")
    block.append("                emit log_bytes32(entries[i].topics[t]);")
    block.append("            }")
    block.append("            emit log_bytes(entries[i].data);")
    block.append("        }")
    block.append("    }")
    block.append("")
    return block


# ---------------------------
# Main generator
# ---------------------------

def generate_harness(model: Dict, cfg: Dict) -> str:
    """
    Build a verbose, log-rich Foundry harness .t.sol based on the AST model.
    Writes and returns the path to {foundry_project_dir}/test/<ContractName>_Harness.t.sol
    """

    # ---- local helpers (scoped to this function) -----------------------------
    def _is_scalar_type_local(typ: str) -> bool:
        t = (typ or "").strip()
        if not t:
            return False
        if "mapping" in t:
            return False
        if "[" in t or "]" in t:
            return False
        return t.startswith(("address", "uint", "int")) or t == "bool"

    def _constructor_params_from_model_local(m: Dict, fns: List[Dict]) -> List[Dict]:
        ctor = (m.get("constructor") or {})
        params = ctor.get("params")
        if params:
            return params
        for f in fns or []:
            if f.get("name") == "constructor":
                return f.get("params", []) or []
        return []

    # ---- normalize IR shapes -------------------------------------------------
    state_vars: List[Dict] = model.get("state_variables", []) or (model.get("state", {}).get("variables", []) or [])
    functions: List[Dict] = model.get("functions", []) or []
    access_deps: List[Dict] = model.get("access_dependencies", []) or []
    contract_name: str = model.get("name", model.get("contract", {}).get("name", "Contract"))

    # map of state var name -> type (used to detect public getters)
    sv_types = {sv.get("name"): (sv.get("type") or "") for sv in state_vars if sv.get("name")}
    # only scalar vars are safe to auto-log via .name()
    scalar_state_vars = [sv for sv in state_vars if _is_scalar_type_local(sv.get("type", ""))]

    # ---- Config --------------------------------------------------------------
    foundry_root = cfg.get("foundry_project_dir", "artifacts/foundry_project")
    test_dir = os.path.join(foundry_root, "test")
    os.makedirs(test_dir, exist_ok=True)

    inline_uut = cfg.get("inline_uut", False)
    import_path = cfg.get("contract_import_path", f"src/{contract_name}.sol")
    verbose = cfg.get("verbose_logs", True)
    snapshot_n = int(cfg.get("mapping_snapshot_n", 3))

    # constructor args (from config or dummy defaults)
    ctor_params = _constructor_params_from_model_local(model, functions)
    ctor_args_cfg = cfg.get("constructor_args", []) or []
    ctor_args_built: List[str] = []
    for i, p in enumerate(ctor_params):
        ptype = (p.get("type") or "").strip()
        if i < len(ctor_args_cfg) and str(ctor_args_cfg[i]).strip() != "":
            ctor_args_built.append(ctor_args_cfg[i])
        else:
            ctor_args_built.append(_dummy_arg_for_type(ptype, i))
    ctor_arg_str = ", ".join(ctor_args_built)

    # ---- ERC20-ish detection -------------------------------------------------
    has_mint = _has_fn(functions, "mint", ["address", "uint256"])
    has_burn = _has_fn(functions, "burn", ["uint256"])
    has_transfer = _has_fn(functions, "transfer", ["address", "uint256"])
    has_balanceOf = _has_balance_getter(functions)
    has_totalSupply = _has_total_supply(functions)

    # ---- Assemble source lines ----------------------------------------------
    L: List[str] = []
    L.append("// SPDX-License-Identifier: MIT")
    # Use the same Solidity version as the contract model, or default
    sol_version = str(model.get("solidity_version") or "0.8.19")
    L.append(f"pragma solidity ^{sol_version};")
    L.append("")
    L.append('import "forge-std/Test.sol";')
    L.append("")

    if inline_uut:
        L.extend([
            f"contract {contract_name} {{",
            "    address public owner;",
            "    constructor() { owner = msg.sender; }",
            '    modifier onlyOwner() { require(msg.sender == owner, "Only owner"); _; }',
            "    function transferOwnership(address newOwner) public onlyOwner { owner = newOwner; }",
            "}",
            "",
        ])
    else:
        L.append(f'import "{import_path}";')
        L.append("")

    harness_name = f"{contract_name}_Harness"
    uut = "uut"

    L.append(f"contract {harness_name} is Test {{")
    # helper to dump events
    L.extend(_emit_event_dump_block())

    # Fields
    L.append(f"    {contract_name} internal {uut};")
    L.append("    address internal OWNER = address(0xA11CE);")
    L.append("    address internal BOB   = address(0xB0B);")
    L.append("")

    # setUp
    L.append("    function setUp() public {")
    L.append("        vm.prank(OWNER);")
    if ctor_params:
        L.append(f"        {uut} = new {contract_name}({ctor_arg_str});")
    else:
        L.append(f"        {uut} = new {contract_name}();")
    L.append("    }")
    L.append("")

    # --- Constructor sanity test (if 'owner' exists) ---
    if any(sv.get("name") == "owner" for sv in scalar_state_vars):
        fn_name = "test_constructor_setsOwner"
        L.append(f"    function {fn_name}() public {{")
        if verbose:
            L.append(indent(enter_log(fn_name)))
            for line in _log_basic_context(uut, scalar_state_vars, header="Context Info:"):
                L.append(indent(line))
        L.append(f"        assertEq({uut}.owner(), OWNER);")
        if verbose:
            for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                L.append(indent(line))
            for line in _log_mapping_snapshots(uut, functions, snapshot_n):
                L.append(indent(line))
            L.append(indent(exit_log(fn_name)))
        L.append("    }")
        L.append("")

    # --- Per-function single-call tests ---
    for fn in functions:
        name = fn.get("name")
        if not name or name == "constructor":
            continue

        # Skip internal/private and underscore helpers
        visibility = (fn.get("visibility") or "public").lower()
        if visibility in ("internal", "private") or name.startswith("_"):
            continue

        # If this is a public getter backed by a non-scalar state var (array/mapping), skip
        svt = sv_types.get(name)
        if svt and not _is_scalar_type_local(svt):
            continue

        pos_name = f"test_{name}_byOwner_succeeds" if _needs_owner_prank(fn, access_deps) else f"test_{name}_basic"
        L.append(f"    function {pos_name}() public {{")
        if verbose:
            L.append(indent(enter_log(pos_name)))

        args = _build_args(fn)

        if verbose and args:
            for line in _log_params(fn, args):
                L.append(indent(line))

        if verbose:
            for line in _log_basic_context(uut, scalar_state_vars, header="Context Info:"):
                L.append(indent(line))

        # --- special cases for ERC20-ish "basic" calls that should revert ---
        special_handled = False

        # burn(uint256): with zero balance, expect revert
        if has_burn and name == "burn" and not _needs_owner_prank(fn, access_deps):
            L.append("        vm.expectRevert();")
            L.append("        vm.prank(address(0xDEAD));")
            if args:
                L.append(f"        {uut}.{name}({', '.join(args)});")
            else:
                L.append(f"        {uut}.{name}();")
            special_handled = True

        # transfer(address,uint256): sender has zero balance, expect revert
        if not special_handled and has_transfer and name == "transfer" and not _needs_owner_prank(fn, access_deps):
            L.append("        vm.expectRevert();")
            L.append("        vm.prank(address(0xFEE1));")
            if args:
                L.append(f"        {uut}.{name}({', '.join(args)});")
            else:
                L.append(f"        {uut}.{name}();")
            special_handled = True

        # default path (owner prank if needed, and do the call)
        if not special_handled:
            if _needs_owner_prank(fn, access_deps):
                L.append("        vm.prank(OWNER);")
            if args:
                L.append(f"        {uut}.{name}({', '.join(args)});")
            else:
                L.append(f"        {uut}.{name}();")
            if name == "transferOwnership":
                L.append(f"        assertEq({uut}.owner(), address(0xC0FFEE));")

        if verbose:
            for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                L.append(indent(line))
            for line in _log_mapping_snapshots(uut, functions, snapshot_n):
                L.append(indent(line))
            L.append(indent(exit_log(pos_name)))
        L.append("    }")
        L.append("")

        # Negative path for access-controlled functions
        if _needs_owner_prank(fn, access_deps):
            neg_name = f"test_{name}_byNonOwner_reverts"
            L.append(f"    function {neg_name}() public {{")
            if verbose:
                L.append(indent(enter_log(neg_name)))
                if args:
                    for line in _log_params(fn, args):
                        L.append(indent(line))
                for line in _log_basic_context(uut, scalar_state_vars, header="Context Info:"):
                    L.append(indent(line))
            L.append("        vm.prank(BOB);")
            if "onlyOwner" in (set(fn.get("modifiers", []) or [])):
                L.append('        vm.expectRevert(bytes("Only owner"));')
            else:
                L.append("        vm.expectRevert();")
            if args:
                L.append(f"        {uut}.{name}({', '.join(args)});")
            else:
                L.append(f"        {uut}.{name}();")
            if verbose:
                for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                    L.append(indent(line))
                for line in _log_mapping_snapshots(uut, functions, snapshot_n):
                    L.append(indent(line))
                L.append(indent(exit_log(neg_name)))
            L.append("    }")
            L.append("")

        # --- Optional fuzz test for address params with OWNER access ---
        addr_meta = _first_address_param(fn)
        if addr_meta and _needs_owner_prank(fn, access_deps):
            addr_idx, addr_name = addr_meta
            fuzz_name = f"testFuzz_{name}"
            fuzz_param_name = addr_name if addr_name not in ("OWNER", "BOB") else f"{addr_name}_fuzz"
            fuzz_args = _build_args(fn)
            if addr_idx < len(fuzz_args):
                fuzz_args[addr_idx] = fuzz_param_name
            else:
                fuzz_args.append(fuzz_param_name)

            L.append(f"    function {fuzz_name}(address {fuzz_param_name}) public {{")
            if verbose:
                L.append(indent(enter_log(fuzz_name)))
                L.append(indent(log_string("Fuzz Input:")))
                L.append(indent(log_string(f"{fuzz_param_name}: (address)")))
                L.append(indent(log_address(fuzz_param_name)))
                for line in _log_basic_context(uut, scalar_state_vars, header="Context Info:"):
                    L.append(indent(line))
            L.append(f"        vm.assume({fuzz_param_name} != address(0));")
            L.append("        vm.prank(OWNER);")
            if fuzz_args:
                L.append(f"        {uut}.{name}({', '.join(fuzz_args)});")
            else:
                L.append(f"        {uut}.{name}();")
            if name == "transferOwnership":
                L.append(f"        assertEq({uut}.owner(), {fuzz_param_name});")
            if verbose:
                for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                    L.append(indent(line))
                for line in _log_mapping_snapshots(uut, functions, snapshot_n):
                    L.append(indent(line))
                L.append(indent(exit_log(fuzz_name)))
            L.append("    }")
            L.append("")

    # --- ERC20-like multi-step scenario tests & multi-param fuzzers ---
    if has_mint and has_balanceOf and has_totalSupply:
        # Scenario: Mint -> Burn
        if has_burn:
            L.append("    function testScenario_MintThenBurn() public {")
            if verbose:
                L.append(indent(enter_log("testScenario_MintThenBurn")))
                for line in _log_basic_context(uut, scalar_state_vars, header="Context Info:"):
                    L.append(indent(line))
            L.append("        address user = address(0x0123);")
            L.append("        uint256 amountMint = 1000;")
            L.append("        uint256 amountBurn = 200;")
            L.append("        vm.recordLogs();")
            L.append(f"        {uut}.mint(user, amountMint);")
            if verbose:
                L.append(indent(log_string("Intermediate State: After Mint")))
                L.append(indent(log_string("Initial Balance: (uint256)")))
                L.append(indent(log_uint(f"{uut}.balanceOf(user)")))
            L.append("        vm.prank(user);")
            L.append(f"        {uut}.burn(amountBurn);")
            if verbose:
                L.append(indent(log_string("Final State:")))
            L.append(f"        assertEq({uut}.balanceOf(user), amountMint - amountBurn);")
            L.append(f"        assertEq({uut}.totalSupply(), amountMint - amountBurn);")
            if verbose:
                for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                    L.append(indent(line))
                for line in _log_mapping_snapshots(uut, functions, snapshot_n):
                    L.append(indent(line))
                L.append("        _printRecordedLogs();")
                L.append(indent(exit_log("testScenario_MintThenBurn")))
            L.append("    }")
            L.append("")

            # Fuzz version: (address,uint256,uint256)
            L.append("    function testFuzz_BurnFlow(address user, uint256 mintAmt, uint256 burnAmt) public {")
            if verbose:
                L.append(indent(enter_log("testFuzz_BurnFlow")))
                L.append(indent(log_string("Fuzz Inputs:")))
                L.append(indent(log_string("user: (address)")))
                L.append(indent(log_address("user")))
                L.append(indent(log_string("mintAmt: (uint256)")))
                L.append(indent(log_uint("mintAmt")))
                L.append(indent(log_string("burnAmt: (uint256)")))
                L.append(indent(log_uint("burnAmt")))
            L.append("        vm.assume(user != address(0));")
            L.append("        mintAmt = bound(mintAmt, 1, type(uint256).max/2);")
            L.append("        burnAmt = bound(burnAmt, 0, mintAmt);")
            L.append("        vm.recordLogs();")
            L.append(f"        {uut}.mint(user, mintAmt);")
            L.append("        vm.prank(user);")
            L.append(f"        {uut}.burn(burnAmt);")
            L.append(f"        assertEq({uut}.balanceOf(user), mintAmt - burnAmt);")
            L.append(f"        assertEq({uut}.totalSupply(), mintAmt - burnAmt);")
            if verbose:
                L.append("        _printRecordedLogs();")
                for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                    L.append(indent(line))
                L.append(indent(exit_log("testFuzz_BurnFlow")))
            L.append("    }")
            L.append("")

        # Scenario: Mint -> Transfer
        if has_transfer:
            L.append("    function testScenario_MintThenTransfer() public {")
            if verbose:
                L.append(indent(enter_log("testScenario_MintThenTransfer")))
                for line in _log_basic_context(uut, scalar_state_vars, header="Context Info:"):
                    L.append(indent(line))
            L.append("        address from = address(0x0123);")
            L.append("        address to = address(0x0456);")
            L.append("        uint256 amountMint = 1000;")
            L.append("        uint256 amountXfer = 300;")
            L.append("        vm.recordLogs();")
            L.append(f"        {uut}.mint(from, amountMint);")
            if verbose:
                L.append(indent(log_string("Intermediate State: After Mint")))
                L.append(indent(log_string("Initial Balance (from): (uint256)")))
                L.append(indent(log_uint(f"{uut}.balanceOf(from)")))
            L.append("        vm.prank(from);")
            L.append(f"        {uut}.transfer(to, amountXfer);")
            L.append(f"        assertEq({uut}.balanceOf(from), amountMint - amountXfer);")
            L.append(f"        assertEq({uut}.balanceOf(to), amountXfer);")
            L.append(f"        assertEq({uut}.totalSupply(), amountMint);")
            if verbose:
                for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                    L.append(indent(line))
                for line in _log_mapping_snapshots(uut, functions, snapshot_n):
                    L.append(indent(line))
                L.append("        _printRecordedLogs();")
                L.append(indent(exit_log("testScenario_MintThenTransfer")))
            L.append("    }")
            L.append("")

            # Fuzz: (address,address,uint256,uint256)
            L.append("    function testFuzz_TransferFlow(address from, address to, uint256 mintAmt, uint256 xferAmt) public {")
            if verbose:
                L.append(indent(enter_log("testFuzz_TransferFlow")))
                L.append(indent(log_string("Fuzz Inputs:")))
                L.append(indent(log_string("from: (address)"))); L.append(indent(log_address("from")))
                L.append(indent(log_string("to: (address)")));   L.append(indent(log_address("to")))
                L.append(indent(log_string("mintAmt: (uint256)"))); L.append(indent(log_uint("mintAmt")))
                L.append(indent(log_string("xferAmt: (uint256)"))); L.append(indent(log_uint("xferAmt")))
            L.append("        vm.assume(from != address(0));")
            L.append("        vm.assume(to != address(0));")
            L.append("        vm.assume(to != from);")
            L.append("        mintAmt = bound(mintAmt, 1, type(uint256).max/2);")
            L.append("        xferAmt = bound(xferAmt, 0, mintAmt);")
            L.append("        vm.recordLogs();")
            L.append(f"        {uut}.mint(from, mintAmt);")
            L.append("        vm.prank(from);")
            L.append(f"        {uut}.transfer(to, xferAmt);")
            L.append(f"        assertEq({uut}.balanceOf(from), mintAmt - xferAmt);")
            L.append(f"        assertEq({uut}.balanceOf(to), xferAmt);")
            L.append(f"        assertEq({uut}.totalSupply(), mintAmt);")
            if verbose:
                L.append("        _printRecordedLogs();")
                for line in _log_basic_context(uut, scalar_state_vars, header="Final State:"):
                    L.append(indent(line))
                L.append(indent(exit_log("testFuzz_TransferFlow")))
            L.append("    }")
            L.append("")

    L.append("}")  # end contract

    # Write file
    out_path = os.path.join(test_dir, f"{contract_name}_Harness.t.sol")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    return out_path
