# Minimal logging helpers used by the generator to keep the Solidity pretty.
# These return raw Solidity lines like `emit log_string("...");`

def indent(line: str, n: int = 8) -> str:
    return " " * n + line

def enter_log(name: str) -> str:
    return f'emit log_string(":::ENTER - {name}");'

def exit_log(name: str) -> str:
    return f'emit log_string(":::EXIT - {name}");'

def log_string(s: str) -> str:
    # s should already be a literal, NOT quoted by caller
    return f'emit log_string("{s}");'

def log_address(expr: str) -> str:
    # expr is a Solidity expression evaluating to address
    return f"emit log_address({expr});"

def log_uint(expr: str) -> str:
    # expr is a Solidity expression evaluating to uint256
    return f"emit log_uint({expr});"

# New: event introspection helpers
def log_bytes(expr: str) -> str:
    return f"emit log_bytes({expr});"

def log_bytes32(expr: str) -> str:
    return f"emit log_bytes32({expr});"
