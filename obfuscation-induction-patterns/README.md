# Obfuscation-Induced Vulnerability Patterns — 50 Solidity Contracts

A catalogue of source-level obfuscation transformations that can change the behaviour of a Solidity contract, together with transformations that do not induce a defect under the tested conditions.

The dataset contains fifty security-sensitive but initially clean contracts, each paired with an obfuscated counterpart and each carrying a behavioural oracle expressed as a Foundry differential test.

The question the set answers is:

**Which source-level obfuscation transformations actually induce a defect, and under what conditions?**

The answer is narrower than one might expect, and the negative results are an important part of the evidence.

**Read “What this is not” before using any of this in a paper.**

## Layout

```text
contracts/
  D1/original/  D1/obfuscated/   13 contracts  lift of a local whose per-call reinit is lost
  D2/original/  D2/obfuscated/   10 contracts  merge of same-named locals across functions
  D3/original/  D3/obfuscated/   10 contracts  storage-slot displacement (proxy logic)
  D4/original/  D4/obfuscated/   10 contracts  constant-to-expression rewrite
  D5/original/  D5/obfuscated/    7 contracts  loop-body local hoisting
test/
  D1_Oracle.t.sol  ...           one test per contract per variant
manifest.csv                     class, name, expected outcome, paths
foundry.toml
```

## The Five Patterns

| Class | #C | Mechanism                                                                                                                                                                        |
| ----- | -- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1    | 13 | An accumulator is lifted from function scope to contract scope; its initializer then runs once at construction rather than on each call, so residue carries across transactions. |
| D2    | 10 | Two functions declare identically named locals; lifting collapses them into one state variable, and the second call observes the first call's residue.                           |
| D3    | 10 | The introduced aggregate is appended after the existing declarations, so slots `0..n-1` are unchanged and `delegatecall` still resolves correctly.                               |
| D4    | 10 | Constants are left intact; only scoped renaming of non-ABI identifiers is applied.                                                                                               |
| D5    | 7  | The hoisted declaration remains at function scope rather than contract scope, so no cross-call persistence arises.                                                               |

Across the 50 contracts, **23 induce a defect after obfuscation**. These are the 13 D1 contracts and the 10 D2 contracts.

D3, D4, and D5 are **negative controls**, and they are essential to interpreting the positive cases. They bound the claim: defect induction follows from a specific interaction—lifting a local whose per-call reinitialization is lost—rather than from obfuscation in general.

D3 in particular acts as the control for the `delegatecall` storage-layout hazard. Altering storage layout can be dangerous in principle, but the transformation represented here appends new state rather than displacing existing slots, so the tested proxy invariant remains intact.

Reporting these negative results is important because they distinguish a reproducible transformation-specific failure mechanism from a broad claim that source-level obfuscation is inherently unsafe.

## The Oracles

Each oracle is a **differential transaction sequence**, not an analyzer comparison.

A contract counts as having an induced defect when:

1. the oracle passes on the original contract; and
2. the same oracle fails on the transformed version.

Every original contract passes its behavioural oracle before obfuscation.

### D1 — Lost Per-Call Reinitialization

**Oracle sequence:** Alice claims her entitlement, then Bob claims his.

**Invariant:** Bob must receive exactly `entitlement(bob)` and must not receive any value left over from Alice's previous call.

In the transformed version, the accumulator has been lifted to contract storage. Its value therefore survives across transactions, causing Bob's payout to include residue from Alice's earlier claim.

### D2 — Same-Named Local Merge

**Oracle sequence:** A user withdraws from stream A and then withdraws from stream B.

**Invariant:** The second withdrawal must pay exactly the amount belonging to stream B and must be independent of the previous withdrawal from stream A.

After lifting, identically named locals originating in separate functions can collapse into the same persistent state variable. The second operation therefore observes residue written by the first.

### D3 — Proxy Storage-Layout Control

**Oracle sequence:** The logic contract is executed through `delegatecall` from a minimal proxy after initialization.

**Invariant:** Slot `0` must continue to contain the address supplied during `initialize()`, and access control must continue to resolve against that same slot.

The transformation used in this class appends the introduced state after the existing declarations. Because the original slots are not displaced, the tested proxy-storage assumption remains valid.

### D4 — Constant-Rewrite Control

**Oracle sequence:** Execute the pure entry point on fixed inputs before and after transformation.

**Invariant:** The transformed contract must return exactly the same output as the original contract for every tested input.

In the provided transformed variants, the constants relevant to the computation are left intact and only scoped renaming of non-ABI identifiers is applied. The oracle therefore continues to pass.

### D5 — Loop-Local Hoisting Control

**Oracle sequence:** Execute the relevant entry point on fixed inputs before and after transformation.

**Invariant:** The transformed contract must preserve the original result and must not carry the loop-local value across independent calls.

The declaration is hoisted within the function but is not promoted to contract state. Its lifetime therefore remains per-call, so the cross-transaction persistence defect observed in D1 does not arise.

## Interpreting the Results

The central result is not that source-level obfuscation generally creates vulnerabilities.

Instead, the dataset isolates a narrower mechanism:

**A defect is induced when a transformation changes a value's lifetime from per-call local state to persistent contract state in a context where correctness depends on reinitialization between calls.**

D1 demonstrates this mechanism directly.

D2 demonstrates a related form in which two independent local variables become unintentionally coupled through shared persistent storage.

The three negative-control classes establish important boundaries:

* D3 shows that merely introducing new storage does not necessarily break proxy semantics when existing slots are not displaced.
* D4 shows that transformations that leave the relevant computation intact do not produce the targeted constant-rewrite defect.
* D5 shows that moving a declaration within function scope is materially different from promoting it to contract scope.

The zeros in these classes are therefore not failed attempts to find vulnerabilities. They are evidence about the conditions under which the transformation-induced defect does and does not occur.

## Running

```bash
forge init --no-git --no-commit .    # if you do not already have forge-std
forge test -vv
```

Expected outcome:

* all `*_original` tests pass;
* all 13 D1 `*_obfuscated` tests fail;
* all 10 D2 `*_obfuscated` tests fail;
* all D3, D4, and D5 tests pass on both original and transformed variants.

In total, **23 of the 50 transformed contracts fail their behavioural oracle**.

`scripts/run_oracles.sh` runs the complete suite and prints a per-class induction count.

## What the Invariants Establish

Each contract should expose, alongside its oracle, a one-line statement of the invariant being checked.

This makes the intended security or behavioural property directly inspectable rather than requiring the reader to infer it from the test implementation.

For example:

```text
D1 invariant: a claimant's payout depends only on that claimant's entitlement in the current invocation.

D2 invariant: withdrawals from independent streams must not share transient accounting state.

D3 invariant: proxy-visible storage slots used for initialization and access control remain unchanged.

D4 invariant: the transformed pure computation is extensionally equivalent to the original on the tested inputs.

D5 invariant: loop-local intermediate values remain scoped to the current function invocation.
```

Stating the invariant explicitly closes the gap between describing the examples as being distilled from security-sensitive or real-world patterns and providing a property that a reader can independently inspect and verify against the accompanying Foundry oracle.
