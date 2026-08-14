"""
Global configuration and env overrides for the AST Analyzer.
"""
import os

# IR versioning
IR_VERSION = os.getenv("INVSOL_IR_VERSION", "0.1")

# solc configuration (optional override)
SOLC_PATH = os.getenv("INVSOL_SOLC_PATH")  # None means: discover via PATH

# Validation behavior
STRICT_VALIDATION_DEFAULT = os.getenv("INVSOL_STRICT", "0").strip() in {"1", "true", "True"}
