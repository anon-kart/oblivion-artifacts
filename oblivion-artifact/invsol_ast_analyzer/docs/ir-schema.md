# IR Schema (Draft)
Minimal, versioned JSON structure emitted by the analyzer.

```json
{
  "ir_version": "0.1",
  "contract": {
    "name": "ContractName",
    "solidity_version": "0.8.x",
    "functions": [{
      "name": "transferOwnership",
      "visibility": "public",
      "mutability": "nonpayable",
      "modifiers": ["onlyOwner"],
      "params": [{"name":"newOwner","type":"address"}],
      "requires": ["msg.sender == owner"],
      "loops": [{
        "type": "for",
        "init": "uint i = 0",
        "guard": "i < payees.length",
        "update": "i++",
        "body_summary": ["transfer(payee, payment)"],
        "accumulators": ["sumSoFar"],
        "indices": ["i"]
      }]
    }],
    "state": {
      "variables": [{"name":"owner","type":"address"}],
      "mappings": [{"name":"balances","key":"address","value":"uint256"}]
    },
    "access_control": [{"modifier":"onlyOwner","role":"owner"}]
  }
}
```