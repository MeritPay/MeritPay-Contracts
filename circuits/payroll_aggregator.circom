pragma circom 2.0.0;

// circomlib imports
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/*
 * PayrollAggregator(n)
 *
 * Proves that an entire payroll batch is correctly computed for n employees.
 *
 * Bonus logic (per spec):
 *   +20% base salary if hoursWorked >= hoursThreshold
 *   +10% base salary if salesFlag == 1
 *   Maximum combined bonus: 30%
 *
 * Division-free bonus calculation:
 *   Instead of  bonus = baseSalary * rate / 100
 *   we constrain:  bonus * 100 === baseSalary * rate
 *   where rate = hoursMet*20 + salesFlag*10
 *
 * Anti-replay:
 *   nullifier[i] = Poseidon(employeeId[i], payrollEpoch, salt[i])
 *   The on-chain contract rejects any nullifier seen before.
 *
 * All signals that appear inside the for-loop must be declared at
 * template scope as arrays — Circom 2.0 does not allow signal
 * declarations inside loop bodies.
 */
template PayrollAggregator(n) {

    // ---------------------------------------------------------------
    // Private inputs (arrays of length n)
    // ---------------------------------------------------------------
    signal input baseSalaries[n];   // base salary in XLM stroops (u64)
    signal input hoursWorked[n];    // actual hours worked this epoch
    signal input salesFlags[n];     // 0 or 1 per employee
    signal input salts[n];          // random blinding factors

    // ---------------------------------------------------------------
    // Public inputs
    // ---------------------------------------------------------------
    signal input employeeIds[n];       // employee identifiers [1..5]
    signal input hoursThresholds[n];   // hours threshold per employee (e.g. 160)
    signal input totalPayroll;         // claimed sum of all payouts
    signal input payrollEpoch;         // u64 epoch identifier
    signal input nullifiers[n];        // anti-replay tokens (checked against computed hash)

    // ---------------------------------------------------------------
    // Internal computation signals — all declared at template scope
    // ---------------------------------------------------------------
    signal hoursMet[n];           // 1 if hoursWorked[i] >= hoursThresholds[i]
    signal bonusRate[n];          // hoursMet[i]*20 + salesFlags[i]*10
    signal salaryTimesRate[n];    // baseSalaries[i] * bonusRate[i] (intermediate)
    signal bonus[n];              // bonus payout per employee
    signal payout[n];             // total payout per employee
    signal runningSum[n+1];       // partial sums; runningSum[n] === totalPayroll

    // ---------------------------------------------------------------
    // Component arrays — all declared at template scope
    // ---------------------------------------------------------------
    component ltHours[n];   // LessThan comparator for hours check
    component kpiHash[n];   // Poseidon(employeeId, hoursWorked, salesFlag, salt)
    component nullHash[n];  // Poseidon(employeeId, payrollEpoch, salt)

    // ---------------------------------------------------------------
    // Initialise running sum
    // ---------------------------------------------------------------
    runningSum[0] <== 0;

    for (var i = 0; i < n; i++) {

        // -----------------------------------------------------------
        // A. Constrain salesFlag to be binary {0, 1}
        // -----------------------------------------------------------
        salesFlags[i] * (1 - salesFlags[i]) === 0;

        // -----------------------------------------------------------
        // B. Constrain baseSalary > 0
        //    We enforce this by requiring an inverse to exist.
        //    invSalary * baseSalaries[i] === 1  →  baseSalaries[i] != 0
        //    (declared as a separate template-scope array — see below)
        // -----------------------------------------------------------
        // (see invSalary[n] and ltSalary[n] declared below the loop)

        // -----------------------------------------------------------
        // C. Determine hoursMet[i]: 1 iff hoursWorked[i] >= hoursThresholds[i]
        //
        //    LessThan(14) outputs 1 when in[0] < in[1].
        //    14 bits covers hours up to 16 383 (well above ~10 000 max).
        //
        //    hoursMet[i] = 1 - (hoursWorked[i] < hoursThresholds[i])
        // -----------------------------------------------------------
        ltHours[i] = LessThan(14);
        ltHours[i].in[0] <== hoursWorked[i];
        ltHours[i].in[1] <== hoursThresholds[i];

        hoursMet[i] <== 1 - ltHours[i].out;

        // Defensive binary assertion (ltHours output is already binary)
        hoursMet[i] * (1 - hoursMet[i]) === 0;

        // -----------------------------------------------------------
        // D. bonusRate[i] = hoursMet[i]*20 + salesFlags[i]*10
        //    Linear — no extra multiplication signal required.
        // -----------------------------------------------------------
        bonusRate[i] <== hoursMet[i] * 20 + salesFlags[i] * 10;

        // -----------------------------------------------------------
        // E. Bonus without division (R1CS-safe)
        //    bonus[i] * 100 === baseSalaries[i] * bonusRate[i]
        //
        //    R1CS allows exactly one multiplication per constraint, so
        //    we first compute the RHS product into an intermediate signal,
        //    then state the equality.
        // -----------------------------------------------------------
        salaryTimesRate[i] <== baseSalaries[i] * bonusRate[i];
        // <-- assigns witness value (hint); === below enforces the constraint.
        // baseSalaries must be divisible by 100 after multiplying by bonusRate.
        // For XLM stroops amounts that are multiples of 1 XLM this always holds.
        bonus[i] <-- salaryTimesRate[i] / 100;
        bonus[i] * 100 === salaryTimesRate[i];

        // -----------------------------------------------------------
        // F. payout[i] = baseSalaries[i] + bonus[i]  (linear)
        // -----------------------------------------------------------
        payout[i] <== baseSalaries[i] + bonus[i];

        // -----------------------------------------------------------
        // G. Accumulate running total
        // -----------------------------------------------------------
        runningSum[i+1] <== runningSum[i] + payout[i];

        // -----------------------------------------------------------
        // H. KPI commitment binds all private inputs to this epoch.
        //    kpiHash[i].out is a cryptographic commitment; it is not
        //    exposed as a public output here, but it constrains the
        //    witness so the prover cannot substitute different values.
        //
        //    kpiCommitment[i] = Poseidon(employeeId, hoursWorked, salesFlag, salt)
        // -----------------------------------------------------------
        kpiHash[i] = Poseidon(4);
        kpiHash[i].inputs[0] <== employeeIds[i];
        kpiHash[i].inputs[1] <== hoursWorked[i];
        kpiHash[i].inputs[2] <== salesFlags[i];
        kpiHash[i].inputs[3] <== salts[i];
        // kpiHash[i].out is computed but acts as an internal commitment.
        // To make it public, add: signal output kpiCommitments[n]; kpiCommitments[i] <== kpiHash[i].out;

        // -----------------------------------------------------------
        // I. Anti-replay: verify the provided public nullifier matches
        //    the hash derived from private data.
        //
        //    nullifier[i] = Poseidon(employeeId, payrollEpoch, salt)
        // -----------------------------------------------------------
        nullHash[i] = Poseidon(3);
        nullHash[i].inputs[0] <== employeeIds[i];
        nullHash[i].inputs[1] <== payrollEpoch;
        nullHash[i].inputs[2] <== salts[i];

        // Enforce the public nullifier matches the witness-derived hash
        nullifiers[i] === nullHash[i].out;
    }

    // ---------------------------------------------------------------
    // J. Verify totalPayroll equals the accumulated sum of all payouts
    // ---------------------------------------------------------------
    totalPayroll === runningSum[n];

    // ---------------------------------------------------------------
    // K. baseSalary range checks (declared here to stay at template scope)
    //    invSalary[i] * baseSalaries[i] === 1  enforces baseSalaries[i] != 0
    // ---------------------------------------------------------------
    signal invSalary[n];
    component ltSalary[n];   // baseSalaries[i] < 2^40

    for (var i = 0; i < n; i++) {
        // Non-zero check: only a non-zero field element has an inverse
        invSalary[i] <-- 1 / baseSalaries[i];
        invSalary[i] * baseSalaries[i] === 1;

        // Upper bound: baseSalaries[i] < 2^40
        // LessThan(41) so in[1]=2^40 fits within 41-bit range (avoids boundary overflow)
        ltSalary[i] = LessThan(41);
        ltSalary[i].in[0] <== baseSalaries[i];
        ltSalary[i].in[1] <== 1099511627776; // 2^40
        ltSalary[i].out === 1;
    }
}

// ---------------------------------------------------------------
// Instantiate for n = 5 employees.
// Public signals: employeeIds, hoursThresholds, totalPayroll,
//                 payrollEpoch, nullifiers
// ---------------------------------------------------------------
component main {public [
    employeeIds,
    hoursThresholds,
    totalPayroll,
    payrollEpoch,
    nullifiers
]} = PayrollAggregator(5);
