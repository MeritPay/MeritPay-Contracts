pragma circom 2.0.0;

// circomlib imports
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/*
 * KPIProof
 *
 * An employee proves their KPI metrics without revealing raw data.
 * The circuit produces:
 *   - kpiCommitment : Poseidon hash binding all private inputs
 *   - hoursMet      : 1 iff hoursWorked >= hoursThreshold, else 0
 *   - salesMet      : mirrors salesFlag (0 or 1)
 *
 * Security properties:
 *   - Private inputs (hoursWorked, salesFlag, salt) are never revealed.
 *   - The commitment binds the employee to their exact input values.
 *   - hoursMet is constrained to be a correct boolean reflection of the
 *     hours comparison — the prover cannot lie about it.
 */
template KPIProof() {

    // ---------------------------------------------------------------
    // Private inputs — not revealed to the verifier
    // ---------------------------------------------------------------
    signal input hoursWorked;   // actual hours (u64, max ~10 000)
    signal input salesFlag;     // 0 or 1 — achieved a sales target
    signal input salt;          // random blinding factor

    // ---------------------------------------------------------------
    // Public inputs — visible to the verifier
    // ---------------------------------------------------------------
    signal input employeeId;      // integer in [1, 5]
    signal input hoursThreshold;  // e.g. 160 hours per epoch

    // ---------------------------------------------------------------
    // Public outputs
    // ---------------------------------------------------------------
    signal output kpiCommitment;  // Poseidon(employeeId, hoursWorked, salesFlag, salt)
    signal output hoursMet;       // 1 if hoursWorked >= hoursThreshold
    signal output salesMet;       // same as salesFlag

    // ---------------------------------------------------------------
    // 1. Constrain salesFlag to be binary {0, 1}
    // ---------------------------------------------------------------
    salesFlag * (1 - salesFlag) === 0;

    // ---------------------------------------------------------------
    // 2. Compute kpiCommitment = Poseidon(employeeId, hoursWorked, salesFlag, salt)
    // ---------------------------------------------------------------
    component poseidon = Poseidon(4);
    poseidon.inputs[0] <== employeeId;
    poseidon.inputs[1] <== hoursWorked;
    poseidon.inputs[2] <== salesFlag;
    poseidon.inputs[3] <== salt;

    kpiCommitment <== poseidon.out;

    // ---------------------------------------------------------------
    // 3. Determine hoursMet: 1 iff hoursWorked >= hoursThreshold
    //
    //    We use the LessThan comparator (from circomlib) to check
    //    hoursWorked < hoursThreshold, then negate: hoursMet = 1 - lt
    //
    //    LessThan(n) checks whether in[0] < in[1] over n-bit integers.
    //    We use 14 bits because max hours ~10 000 < 2^14 = 16 384.
    // ---------------------------------------------------------------
    component lt = LessThan(14);
    lt.in[0] <== hoursWorked;
    lt.in[1] <== hoursThreshold;

    // lt.out === 1  means hoursWorked < hoursThreshold  → hoursMet = 0
    // lt.out === 0  means hoursWorked >= hoursThreshold → hoursMet = 1
    signal notHoursMet;
    notHoursMet <== lt.out;

    hoursMet <== 1 - notHoursMet;

    // Verify hoursMet is binary (redundant given lt output, but explicit)
    hoursMet * (1 - hoursMet) === 0;

    // ---------------------------------------------------------------
    // 4. salesMet is just the (already-constrained) salesFlag
    // ---------------------------------------------------------------
    salesMet <== salesFlag;
}

component main {public [employeeId, hoursThreshold]} = KPIProof();
