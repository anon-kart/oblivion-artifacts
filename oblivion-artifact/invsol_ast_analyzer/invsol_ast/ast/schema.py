from typing import List, Optional
from pydantic import BaseModel

class FunctionParam(BaseModel):
    name: str
    type: str

class LoopSignature(BaseModel):
    type: str
    init: Optional[str] = ""
    guard: Optional[str] = ""
    update: Optional[str] = ""

class FunctionIR(BaseModel):
    contract: str
    name: str
    visibility: str
    mutability: str
    modifiers: List[str] = []
    params: List[FunctionParam] = []

class MappingIR(BaseModel):
    contract: str
    name: str
    key: str
    value: str

class StateIR(BaseModel):
    variables: List[dict] = []
    mappings: List[MappingIR] = []

# Optional helpers for future validation.
