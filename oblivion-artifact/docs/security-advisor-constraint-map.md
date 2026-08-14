# OBLIVION Security Advisor: Constraint Map

This artifact documents the principal security signals, protected-region tags, sensitivity scoring, and transformation restrictions implemented by the Security Advisor.

## 1. Security-policy signals

| Signal | Evidence used by the implementation | Sensitivity contribution |
|---|---|---:|
| `access_control_sensitive` | Access-control edges, authorization-like `require` conditions, ownership/role modifiers, and analyzer findings related to access control | +0.35 |
| `external_call_sensitive` | External interactions including `call`, `delegatecall`, `staticcall`, `send`, and `transfer` | +0.25 |
| `reentrancy_sensitive` | Presence of both external calls and storage writes, augmented by analyzer findings | +0.20 |
| `arithmetic_sensitive` | Arithmetic operators, unchecked blocks, and arithmetic/overflow/underflow findings | +0.12 |
| `revert_semantics_sensitive` | `require`, `assert`, `revert`, and related analyzer findings | +0.12 |
| `loop_gas_sensitive` | `for`, `while`, and `do-while` loops and loop-related analyzer findings | +0.08 |

The Security Advisor merges analyzer-derived and semantic signals: a signal is active if either evidence source identifies it.

## 2. Protected-region tags

| Protected-region tag | Typical source construct | Purpose |
|---|---|---|
| `access_control_guard` | Authorization `require`/`if` conditions and modifier invocations/definitions | Preserve authorization semantics and guard structure |
| `external_call_site` | `call`, `delegatecall`, `staticcall`, `send`, `transfer`; also a nearby state write when ordering is sensitive | Preserve interaction boundaries and state-update/external-call ordering |
| `revert_semantics_region` | Non-authorization `require`, `assert`, or `revert` | Preserve revert behavior and failure conditions |
| `loop_region` | `for`, `while`, and `do-while` statements | Preserve loop behavior and avoid unsafe loop expansion/restructuring |
| `arithmetic_region` | Arithmetic/bit-shift expressions and unchecked blocks | Preserve arithmetic meaning and guard against unsafe data-flow rewrites |
| `state_write_region` | Statements that write contract storage | Preserve state effects and expose writes to downstream tiering/constraint logic |

## 3. Additional sensitivity contributions

Protected regions further increase the normalized policy-sensitivity score:

| Condition | Additional contribution |
|---|---:|
| `access_control_guard` present | +0.12 |
| `external_call_site` present | +0.12 |
| `revert_semantics_region` present | +0.08 |
| `arithmetic_region` present | +0.06 |
| Runtime relevance >= 0.50 and access-control/external-call/reentrancy sensitivity is active | +0.05 |

The final score is clamped to the interval [0, 1].

## 4. Sensitivity bands

| Band | Score range |
|---|---|
| `HIGH` | >= 0.75 |
| `MEDIUM` | >= 0.40 and < 0.75 |
| `LOW` | >= 0.15 and < 0.40 |
| `INFO` | < 0.15 |

## 5. Constraint templates

| Security condition | Representative transformations forbidden by the Security Advisor | Risk tags blocked |
|---|---|---|
| Access-control sensitive | modifier expansion, predicate masking, opaque predicates, CFG flattening, dispatcher virtualization, dead-code insertion, internal inlining | `touches_access_control`, `touches_reverts` |
| External-call or reentrancy sensitive | local-to-state lifting, CFG flattening, dispatcher virtualization, opaque storage-slot indirection, predicate masking, opaque predicates, loop rewriting, dead-code insertion, internal inlining | `touches_storage`, `touches_external_calls` |
| Arithmetic sensitive | constant encoding, dynamic constants, boolean splitting, predicate masking | `touches_data_flow` |
| Revert-semantics sensitive | predicate masking, opaque predicates, dead-code insertion | `touches_reverts` |
| Loop sensitive | loop rewriting, dead-code insertion, CFG flattening | — |

## 6. Downstream use

The advisor emits, per function:

- normalized security score and severity,
- runtime relevance,
- merged policy signals,
- normalized policy-sensitivity score and band,
- protected source regions,
- forbidden transformation IDs,
- forbidden risk tags,
- and transformation hints derived from analyzer findings.

These outputs are consumed by the obfuscation advisor, plan synthesizer, semantic-contract construction, candidate filtering, tier selection, and validation stages. The result is a constraint source rather than a vulnerability report: security evidence directly narrows the transformation space before code is modified.

## Implementation locations

The primary implementation is in:

- `oblivion-artifact/security_advisor/advisor.py`
- `oblivion-artifact/decision/semantic_rules.py`
- `oblivion-artifact/obfuscation_advisor/tiering.py`
- `oblivion-artifact/configs/policy.json`
- `oblivion-artifact/validator/security_check.py`
