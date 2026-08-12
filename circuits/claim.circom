pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/*
 * ClaimPayout
 *
 * Proves an employee is entitled to withdraw a specific payout amount
 * without revealing their full KPI data on-chain.
 *
 * Public:  nullifier, payrollEpoch, amount
 * Private: employeeId, salt, baseSalary, hoursWorked, salesFlag, hoursThreshold
 *
 * nullifier = Poseidon(employeeId, payrollEpoch, salt)
 * amount    = baseSalary + bonus (same bonus rules as PayrollAggregator)
 */
template ClaimPayout() {
    signal input employeeId;
    signal input salt;
    signal input baseSalary;
    signal input hoursWorked;
    signal input salesFlag;
    signal input hoursThreshold;

    signal input nullifier;
    signal input payrollEpoch;
    signal input amount;

    salesFlag * (1 - salesFlag) === 0;

    component nullHash = Poseidon(3);
    nullHash.inputs[0] <== employeeId;
    nullHash.inputs[1] <== payrollEpoch;
    nullHash.inputs[2] <== salt;
    nullifier === nullHash.out;

    component ltHours = LessThan(14);
    ltHours.in[0] <== hoursWorked;
    ltHours.in[1] <== hoursThreshold;

    signal hoursMet;
    hoursMet <== 1 - ltHours.out;
    hoursMet * (1 - hoursMet) === 0;

    signal bonusRate;
    bonusRate <== hoursMet * 20 + salesFlag * 10;

    signal salaryTimesRate;
    salaryTimesRate <== baseSalary * bonusRate;

    signal bonus;
    bonus <-- salaryTimesRate / 100;
    bonus * 100 === salaryTimesRate;

    signal payout;
    payout <== baseSalary + bonus;
    amount === payout;

    signal invSalary;
    invSalary <-- 1 / baseSalary;
    invSalary * baseSalary === 1;
}

component main {public [nullifier, payrollEpoch, amount]} = ClaimPayout();
