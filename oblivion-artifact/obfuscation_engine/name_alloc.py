from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Set

_OBF_NAME_RE = re.compile(r"\b(v_\d+_\d+|__obf_[A-Za-z0-9_]+)\b")

def collect_identifiers(text: str) -> Set[str]:
    """
    Conservative identifier collector. Enough to prevent collisions.
    """
    ids = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
    # Keep already-obfuscated names too
    ids |= set(m.group(1) for m in _OBF_NAME_RE.finditer(text))
    return ids

@dataclass
class NameAllocator:
    seed: int
    used: Set[str]
    counter: int = 0

    def fresh(self, hint: str = "t") -> str:
        while True:
            name = f"__obf_{hint}_{self.seed}_{self.counter}"
            self.counter += 1
            if name not in self.used:
                self.used.add(name)
                return name
