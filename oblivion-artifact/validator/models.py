from dataclasses import dataclass, asdict
from typing import Any, Dict, List

@dataclass
class ValidationResult:
    accepted: bool
    compile: Dict[str, Any]
    tests: Dict[str, Any]
    fuzz: Dict[str, Any]
    semantic: Dict[str, Any]
    coverage: Dict[str, Any]
    security: Dict[str, Any]
    gas: Dict[str, Any]
    notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
