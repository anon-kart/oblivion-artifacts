# InvSol AST Analyzer (Mini-Project)

This is a standalone AST Analyzer module matching the architecture in your paper.
It parses Solidity contracts with `solc`, normalizes the AST, extracts semantic info
(functions, requires, state/storage, loops, access control), and emits a loop-aware JSON IR.

## Quick start
```bash
pip install -e .
invsol-ast analyze examples/contracts/AssetTransfer.sol --out examples/outputs/sample_ir.json
```

*Note:* Files contain placeholders; fill in logic as you build.