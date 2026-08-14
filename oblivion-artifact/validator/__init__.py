"""OBLIVION Validator package (MVP).

This module validates an obfuscated Solidity candidate by enforcing:
  - compile success (forge build)
  - test success (forge test; optionally targeted tests)
Optional stubs (to be upgraded):
  - coverage diff gate
  - security diff gate
  - gas delta gate
"""

from .validator import validate_candidate

__all__ = ["validate_candidate"]
