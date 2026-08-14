from __future__ import annotations
from typing import Any, Dict, List, TypedDict, Literal, Optional


JSON = Dict[str, Any]


class FunctionRecord(TypedDict, total=False):
    contract: str
    name: str
    visibility: str           # public|external|internal|private
    mutability: str           # nonpayable|payable|view|pure
    modifiers: List[str]
    params: List[Dict[str, str]]
    node_id: Optional[int]


class LoopSignatureRecord(TypedDict, total=False):
    type: Literal["for", "while", "loop"]
    init: str
    guard: str
    update: str


class LoopRecord(TypedDict, total=False):
    contract: str
    function: str
    signature: LoopSignatureRecord
    node_id: Optional[int]


class RequireRecord(TypedDict, total=False):
    contract: str
    function: str
    condition: str
    node_id: Optional[int]


class StateVarRecord(TypedDict, total=False):
    contract: str
    name: str
    type: str


class MappingRecord(TypedDict, total=False):
    contract: str
    name: str
    key: str
    value: str


class AccessEdgeRecord(TypedDict, total=False):
    contract: str
    function: str
    modifier: str
    role: str
