# fix(claim): reject unbounded field-element truncation in proof signals

## Summary

- `claim_payout` converted 32-byte BN254 public signals (`payrollEpoch`, `amount`) to `u64`/`i128` by slicing off the low 8/16 bytes and discarding the rest, without checking that the discarded high-order bytes were actually zero.
- Since the claim circuit does not range-constrain these signals to fit in 64/128 bits, a prover could supply a field element whose low bytes decode to any desired epoch/amount while the true field value is unrelated — letting the on-chain integer the contract acts on diverge from what the SNARK proof actually authenticated.
- `bytes_to_u64` / `bytes_to_i128` now return a `Result` and reject any signal with non-zero high-order bytes, propagating `ClaimError::SignalMismatch` instead of silently truncating.

## Why

Found during a security review of the claim/payroll/verifier contracts and circuits. This is a self-contained, contract-level fix that closes off field-wraparound truncation regardless of circuit behavior.

Two deeper issues were also identified but are **not** addressed in this PR because fixing them requires a circuit redesign and a new trusted-setup ceremony:

1. **Claim amount not bound to the payroll batch** — `claim.circom`'s `nullifier` only hashes `employeeId, payrollEpoch, salt`; `baseSalary`/`hoursWorked`/`salesFlag` are freely chosen by the prover and never checked against what `payroll_aggregator.circom` actually computed for that employee. A dishonest employee with a spent nullifier can claim an arbitrary amount up to the pool balance.
2. **Claim proof not bound to a recipient** — the public signals `[nullifier, payrollEpoch, amount]` don't include the recipient address, so a valid proof can be front-run: anyone who observes it pre-confirmation can resubmit it with themselves as recipient.

Both should be tracked as follow-up work requiring a Merkle/commitment link between the aggregator and claim circuits, plus recipient binding in the claim circuit's public inputs.

## Test plan

- [x] `cargo test -p claim` — compiles cleanly, existing `test_claim_payout_happy_path` passes
- [ ] Add a regression test asserting `claim_payout` rejects a `payrollEpoch`/`amount` signal with non-zero high-order bytes
