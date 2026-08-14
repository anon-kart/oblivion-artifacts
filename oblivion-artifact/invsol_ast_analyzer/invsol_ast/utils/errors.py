# Centralized exception hierarchy for the AST Analyzer.

class InvSolAstError(Exception):
    """Base error for InvSol AST Analyzer."""


class ParseError(InvSolAstError):
    """Raised when Solidity parsing or AST decoding fails."""


class NormalizationError(InvSolAstError):
    """Raised when AST cannot be normalized into the expected shape."""


class ExtractionError(InvSolAstError):
    """Raised when semantic extraction (functions/loops/req/state) fails."""


class IRBuildError(InvSolAstError):
    """Raised when building the IR from extracted artifacts fails."""


class ValidationError(InvSolAstError):
    """Raised when IR schema/consistency validation fails."""


class SolcNotFound(InvSolAstError):
    """Raised when `solc` binary is not available on PATH."""


class SolcRunError(InvSolAstError):
    """Raised when `solc` returns a non-zero exit code or bad output."""
