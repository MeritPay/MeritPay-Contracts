pragma circom 2.0.0;

// circomlib imports
include "node_modules/circomlib/circuits/comparators.circom";

/*
 * AuditorDisclosure(n)
 *
 * Proves that the total payroll is within an agreed budget without
 * revealing any individual employee's payout.
 *
 * This circuit is intentionally minimal — it gives an auditor
 * exactly what they need (budget compliance) without disclosing
 * salary or bonus details for any individual.
 *
 * Constraints verified:
 *   1. sum(individualPayouts) === totalPayroll   — totals are consistent
 *   2. totalPayroll <= budget                    — budget is not exceeded
 *   3. Each individualPayout >= 0               — no negative payouts
 *      (implicitly enforced by the field; explicit range check added
 *       using LessThan to keep values within 64-bit range)
 *
 * Note on negative values:
 *   Circom arithmetic is over a large prime field Fp. A "negative"
 *   value would wrap around to a very large field element. We guard
 *   against this by requiring each payout fits in 64 bits.
 */
template AuditorDisclosure(n) {

    // ---------------------------------------------------------------
    // Private inputs
    // ---------------------------------------------------------------
    signal input individualPayouts[n];  // each employee's payout (in stroops)

    // ---------------------------------------------------------------
    // Public inputs
    // ---------------------------------------------------------------
    signal input totalPayroll;  // claimed total; must equal sum of payouts
    signal input budget;        // maximum allowed payroll for this epoch

    // ---------------------------------------------------------------
    // Internal signals
    // ---------------------------------------------------------------
    signal runningSum[n+1];   // partial sums of individualPayouts

    // ---------------------------------------------------------------
    // Component arrays (declared at template scope)
    // ---------------------------------------------------------------
    component ltPayout[n];    // range-check each payout fits in 64 bits
    component leBudget;       // totalPayroll <= budget

    // ---------------------------------------------------------------
    // 1. Accumulate sum of individual payouts
    // ---------------------------------------------------------------
    runningSum[0] <== 0;

    for (var i = 0; i < n; i++) {

        // -----------------------------------------------------------
        // A. Range-check: ensure individualPayouts[i] is non-negative
        //    and fits within 64 bits (< 2^64).
        //
        //    LessThan(64) checks in[0] < in[1] over 64-bit integers.
        //    We verify:  0 <= individualPayouts[i] < 2^64
        //
        //    The lower bound (>= 0) is handled implicitly because a
        //    value that wrapped negative would be enormous in Fp and
        //    would fail the upper-bound check.
        //
        //    2^64 = 18446744073709551616
        // -----------------------------------------------------------
        ltPayout[i] = LessThan(64);
        ltPayout[i].in[0] <== individualPayouts[i];
        ltPayout[i].in[1] <== 18446744073709551616;
        ltPayout[i].out === 1;

        // -----------------------------------------------------------
        // B. Add to running total
        // -----------------------------------------------------------
        runningSum[i+1] <== runningSum[i] + individualPayouts[i];
    }

    // ---------------------------------------------------------------
    // 2. Enforce sum === totalPayroll
    //    The prover cannot claim a different total than the actual sum.
    // ---------------------------------------------------------------
    totalPayroll === runningSum[n];

    // ---------------------------------------------------------------
    // 3. Enforce totalPayroll <= budget
    //
    //    LessEqThan(a, b) is equivalent to LessThan(a, b+1).
    //    circomlib provides LessEqThan(n) which checks in[0] <= in[1].
    //    We use 64 bits since both totalPayroll and budget are u64.
    //
    //    Include comparators.circom provides: LessThan, LessEqThan,
    //    GreaterThan, GreaterEqThan.
    // ---------------------------------------------------------------
    leBudget = LessEqThan(64);
    leBudget.in[0] <== totalPayroll;
    leBudget.in[1] <== budget;
    leBudget.out === 1;
}

// ---------------------------------------------------------------
// Instantiate for n = 5 employees.
// Public signals: totalPayroll, budget
// ---------------------------------------------------------------
component main {public [totalPayroll, budget]} = AuditorDisclosure(5);
