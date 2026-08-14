# Obfuscation-Induced Vulnerability Patterns — 50 Solidity contracts

A catalogue of source-level obfuscation transformations that can change the
behaviour of a Solidity contract, together with the transformations that cannot.
Fifty security-sensitive but initially clean contracts, each paired with an
obfuscated counterpart, each carrying a behavioural oracle expressed as a
Foundry differential test.

The question the set answers: **which source-level obfuscation transformations
actually induce a defect, and under what conditions?** The answer is narrower
than one might expect, and the negative results are the point.

**Read "What this is not" before using any of this in a paper.**

## Layout

```
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

## The five patterns

| Class | #C | Oracle fails after obfuscation? | Mechanism |
|-------|----|----------------------------------|-----------|
| D1 | 13 | **yes** | an accumulator is lifted from function scope to contract scope; its initializer then runs once at construction rather than on each call, so residue carries across transactions |
| D2 | 10 | **yes** | two functions declare identically named locals; lifting collapses them into one state variable, and the second call observes the first's residue |
| D3 | 10 | no  | the introduced aggregate is appended after the existing declarations, so slots 0..n-1 are unchanged and delegatecall still resolves correctly |
| D4 | 10 | no  | constants are left intact; only scoped renaming of non-ABI identifiers is applied |
| D5 |  7 | no  | the hoisted declaration stays at function scope, not contract scope, so no cross-call persistence arises |

23 of 50 induce a defect.

D3, D4 and D5 are **negative controls**, and they carry more weight than the
positive cases. They bound the claim: induction follows from one specific
interaction — lifting a local whose per-call reinitialization is lost — not from
obfuscation in general. D3 in particular is the control for the delegatecall
storage-layout hazard: the hazard is real in principle, but a transformation that
appends rather than displaces does not trigger it. Reporting the zeros is what
makes the non-zeros credible.

## The oracles

Each oracle is a differential transaction sequence, not an analyzer comparison.
A contract counts as induced when the oracle passes on the original and fails on
the transformed version. Every contract passes its oracle before obfuscation.

- **D1** — Alice claims her entitlement, then Bob claims his. Bob must receive
  exactly `entitlement(bob)`. Under the lifted accumulator he receives Alice's
  residue as well.
- **D2** — the user withdraws from stream A, then from stream B. The second
  withdrawal must pay exactly stream B.
- **D3** — the logic contract runs under `delegatecall` from a minimal proxy;
  slot 0 must still hold the address that called `initialize()`, and access
  control must still bind to that slot.
- **D4, D5** — differential equivalence of the pure entry point on fixed inputs.

## Running

```bash
forge init --no-git --no-commit .    # if you do not already have forge-std
forge test -vv
```

Expected: all `*_original` tests pass; the 23 D1/D2 `*_obfuscated` tests fail;
all D3/D4/D5 tests pass on both variants.

`scripts/run_oracles.sh` runs the suite and prints a per-class induction count.

## What this is not

Three limitations, in order of how badly they would hurt you if ignored.

1. **The obfuscated versions were hand-constructed, not tool-generated.** They
   apply the transformation semantics described in the source-level obfuscation
   literature — local-to-state lifting, struct-based storage packing, constant
   encoding, control-flow flattening, scoped renaming — but no obfuscator was
   executed to produce them. If your write-up claims a particular tool produced
   these outputs, you must run that tool and regenerate the `obfuscated/`
   directories from its output. Shipping these as-is would misdescribe the
   method.

2. **Nothing here has been compiled.** No `solc` was available in the generating
   environment. The files pass structural checks (balanced delimiters, pragma,
   declared-name agreement, and a per-class invariant check) but compilation and
   test execution are unverified. Run `forge build` first and expect to fix a few
   things — the aliased imports across same-named contracts and the D3 proxy
   assembly block are the likeliest spots.

3. **These are synthetic.** They are distilled from common patterns — reward
   vaults, escrow, staking, payroll, proxy logic — but no contract here is drawn
   from a deployed system. If you want a provenance column, you will need to
   trace each pattern back to a real contract or incident and record it.

Two smaller notes. The D1 setter signatures deliberately vary across contracts
(`grant`, `fund`, `enqueue`, `assign`, `record`, ...) so the set is not thirteen
copies of one template with renamed variables; a reader who opens three files
should see three different contracts. And `entitlement(address)` exists on every
D1 contract purely so the oracle can compute the expected payout without
hard-coding it — if that helper is an artifact you do not want in a released
version, inline the expected values in the tests instead.

## Suggested provenance work

`manifest.csv` records the expected outcome but not provenance. For a released
artifact you will want to add, per contract: the vulnerability class it derives
from (DASP / SWC id), the real contract or incident the pattern came from, and
the invariant the oracle checks stated in one line. That closes the gap between
"distilled from real-world patterns" and something a reader can verify.
