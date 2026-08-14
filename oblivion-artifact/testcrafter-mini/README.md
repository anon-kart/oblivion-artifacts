# TestCrafter (MVP)

An MVP that consumes your AST Analyzer JSON (schema you provided) and generates a fuzzable Foundry `.t.sol` harness.

## Usage

```bash
python -m testcrafter.cli --ast-json data/sample_ast.json --out outputs
```

This will render a test harness into `artifacts/foundry_project/test/<ContractName>_Harness.t.sol`.
