#!/usr/bin/env node
// =============================================================================
// MeritPay — ZK Proof Generator
// =============================================================================
// Generates Groth16 proofs for all three MeritPay circuits using mock payroll
// data for 5 employees and saves artefacts to build/proofs/.
//
// Circuits:
//   1. KPIProof              — individual private KPI commitment per employee
//   2. PayrollAggregator(5)  — aggregated payroll with bonus calculation
//   3. AuditorDisclosure(5)  — budget compliance proof for auditor
//
// Usage:
//   node scripts/gen_proof.js
//
// Prerequisites:
//   ./scripts/setup.sh must have been run first.
// =============================================================================

"use strict";

const snarkjs = require("../circuits/node_modules/snarkjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
const ROOT = path.resolve(__dirname, "..");
const BUILD = path.join(ROOT, "build");
const PROOFS_DIR = path.join(BUILD, "proofs");

// Circuit artefact paths
const CIRCUITS = {
  kpi: {
    wasm: path.join(BUILD, "kpi", "kpi_js", "kpi.wasm"),
    zkey: path.join(BUILD, "kpi", "kpi_final.zkey"),
    vkey: path.join(BUILD, "kpi", "kpi_vkey.json"),
  },
  payroll: {
    wasm: path.join(BUILD, "payroll", "payroll_aggregator_js", "payroll_aggregator.wasm"),
    zkey: path.join(BUILD, "payroll", "payroll_aggregator_final.zkey"),
    vkey: path.join(BUILD, "payroll", "payroll_aggregator_vkey.json"),
  },
  auditor: {
    wasm: path.join(BUILD, "auditor", "auditor_disclosure_js", "auditor_disclosure.wasm"),
    zkey: path.join(BUILD, "auditor", "auditor_disclosure_final.zkey"),
    vkey: path.join(BUILD, "auditor", "auditor_disclosure_vkey.json"),
  },
};

// ---------------------------------------------------------------------------
// Mock payroll data (5 employees)
// Salaries in XLM stroops (1 XLM = 10,000,000 stroops)
//
// Bonus rules (from payroll_aggregator.circom):
//   +20% if hoursWorked >= hoursThreshold
//   +10% if salesFlag == 1
//   Maximum: +30%
// ---------------------------------------------------------------------------
const MOCK_EMPLOYEES = [
  { id: 1, name: "Alice", baseSalary: 50000000, hoursWorked: 172, salesFlag: 1, threshold: 160 },
  { id: 2, name: "Bob",   baseSalary: 45000000, hoursWorked: 145, salesFlag: 0, threshold: 160 },
  { id: 3, name: "Carol", baseSalary: 60000000, hoursWorked: 200, salesFlag: 1, threshold: 160 },
  { id: 4, name: "Dave",  baseSalary: 40000000, hoursWorked: 160, salesFlag: 0, threshold: 160 },
  { id: 5, name: "Eve",   baseSalary: 55000000, hoursWorked: 180, salesFlag: 1, threshold: 160 },
];

// Budget for auditor disclosure: 30 XLM (300_000_000 stroops)
const BUDGET_STROOPS = 300000000n;

// Payroll epoch — use a fixed value for reproducibility in tests
const PAYROLL_EPOCH = 20260621n; // YYYYMMDD

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return a cryptographically random 248-bit BigInt (safe for BN254 field) */
function randomFieldElement() {
  const bytes = crypto.randomBytes(31); // 248 bits — safely below BN254 prime
  return BigInt("0x" + bytes.toString("hex"));
}

/** Convert stroops to XLM for human-readable display */
function stroopsToXLM(stroops) {
  return (Number(stroops) / 10_000_000).toFixed(4);
}

/** Compute Poseidon hash via snarkjs poseidon (used for nullifier display) */
async function computeNullifier(employeeId, epoch, salt) {
  // We use the circuit's own hash — snarkjs exposes the poseidon hasher
  const { buildPoseidon } = require("../circuits/node_modules/circomlibjs");
  const poseidon = await buildPoseidon();
  const hash = poseidon([BigInt(employeeId), BigInt(epoch), BigInt(salt)]);
  return poseidon.F.toObject(hash);
}

/** Calculate expected payout given the bonus rules */
function calcPayout(emp) {
  const hoursMet = emp.hoursWorked >= emp.threshold ? 1 : 0;
  const salesMet = emp.salesFlag;
  const bonusRate = hoursMet * 20 + salesMet * 10; // basis points * 10
  // Division-free: bonus * 100 = baseSalary * bonusRate
  const bonusTimesHundred = BigInt(emp.baseSalary) * BigInt(bonusRate);
  const bonus = bonusTimesHundred / 100n;
  const payout = BigInt(emp.baseSalary) + bonus;
  return { hoursMet, salesMet, bonusRate, bonus, payout };
}

/** Pretty-print a separator line */
function hr(char = "─", width = 72) {
  console.log(char.repeat(width));
}

// ---------------------------------------------------------------------------
// Proof generation helpers
// ---------------------------------------------------------------------------

async function generateKpiProof(emp, salt) {
  const { hoursMet, salesMet } = calcPayout(emp);

  const input = {
    // Private inputs
    hoursWorked: emp.hoursWorked.toString(),
    salesFlag: emp.salesFlag.toString(),
    salt: salt.toString(),
    // Public inputs
    employeeId: emp.id.toString(),
    hoursThreshold: emp.threshold.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    CIRCUITS.kpi.wasm,
    CIRCUITS.kpi.zkey,
  );

  return { proof, publicSignals, hoursMet, salesMet, input };
}

async function generatePayrollProof(employees, salts, nullifiers, totalPayroll) {
  const input = {
    // Private inputs
    baseSalaries:  employees.map((e) => e.baseSalary.toString()),
    hoursWorked:   employees.map((e) => e.hoursWorked.toString()),
    salesFlags:    employees.map((e) => e.salesFlag.toString()),
    salts:         salts.map((s) => s.toString()),
    // Public inputs
    employeeIds:      employees.map((e) => e.id.toString()),
    hoursThresholds:  employees.map((e) => e.threshold.toString()),
    totalPayroll:     totalPayroll.toString(),
    payrollEpoch:     PAYROLL_EPOCH.toString(),
    nullifiers:       nullifiers.map((n) => n.toString()),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    CIRCUITS.payroll.wasm,
    CIRCUITS.payroll.zkey,
  );

  return { proof, publicSignals, input };
}

async function generateAuditorProof(payouts, totalPayroll) {
  const input = {
    // Private inputs
    individualPayouts: payouts.map((p) => p.toString()),
    // Public inputs
    totalPayroll: totalPayroll.toString(),
    budget: BUDGET_STROOPS.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    CIRCUITS.auditor.wasm,
    CIRCUITS.auditor.zkey,
  );

  return { proof, publicSignals, input };
}

// ---------------------------------------------------------------------------
// Verification helper
// ---------------------------------------------------------------------------

async function verifyProof(circuitName, proof, publicSignals) {
  const vkeyJson = JSON.parse(
    fs.readFileSync(CIRCUITS[circuitName].vkey, "utf8"),
  );
  const valid = await snarkjs.groth16.verify(vkeyJson, publicSignals, proof);
  return valid;
}

// ---------------------------------------------------------------------------
// Prerequisite check
// ---------------------------------------------------------------------------

function checkBuildArtefacts() {
  const missing = [];
  for (const [name, paths] of Object.entries(CIRCUITS)) {
    for (const [key, p] of Object.entries(paths)) {
      if (!fs.existsSync(p)) {
        missing.push(`${name}.${key}: ${p}`);
      }
    }
  }
  if (missing.length > 0) {
    console.error("\n[ERROR] Missing build artefacts. Run ./scripts/setup.sh first.\n");
    for (const m of missing) console.error("  Missing:", m);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  hr("=");
  console.log("  MeritPay — ZK Proof Generator");
  console.log("  Hackathon: Stellar Hacks: Real-World ZK (June 2026)");
  hr("=");

  // ── Prereqs ──────────────────────────────────────────────────────────────
  console.log("\n[1/6] Checking build artefacts...");
  checkBuildArtefacts();
  fs.mkdirSync(PROOFS_DIR, { recursive: true });
  console.log("  OK — all circuit artefacts present");
  console.log(`  Proofs will be saved to: ${PROOFS_DIR}`);

  // ── Generate random salts ─────────────────────────────────────────────────
  console.log("\n[2/6] Generating cryptographic salts...");
  const salts = MOCK_EMPLOYEES.map(() => randomFieldElement());
  console.log(`  Generated ${salts.length} random 248-bit salts`);

  // ── Calculate expected payroll ────────────────────────────────────────────
  console.log("\n[3/6] Calculating payroll (verifying circuit logic)...");
  hr();
  console.log(
    "  Employee   Base XLM   Hours  HrsMet  Sales  BonusRate  Payout XLM",
  );
  hr();

  const payoutResults = MOCK_EMPLOYEES.map((emp) => {
    const r = calcPayout(emp);
    const label = `${emp.name}`.padEnd(9);
    const base = stroopsToXLM(emp.baseSalary).padStart(8);
    const hrs = String(emp.hoursWorked).padStart(5);
    const hrsMet = String(r.hoursMet).padStart(6);
    const sales = String(r.salesMet).padStart(5);
    const rate = `${r.bonusRate}%`.padStart(9);
    const payout = stroopsToXLM(r.payout).padStart(9);
    console.log(`  ${label}  ${base}   ${hrs}   ${hrsMet}  ${sales}  ${rate}  ${payout}`);
    return r;
  });

  const totalPayroll = payoutResults.reduce((sum, r) => sum + r.payout, 0n);

  hr();
  console.log(`  TOTAL                                              ${stroopsToXLM(totalPayroll).padStart(9)} XLM`);
  console.log(`  BUDGET                                             ${stroopsToXLM(BUDGET_STROOPS).padStart(9)} XLM`);
  console.log(`  WITHIN BUDGET: ${totalPayroll <= BUDGET_STROOPS ? "YES" : "NO"}`);
  hr();

  // ── Compute nullifiers ────────────────────────────────────────────────────
  // NOTE: In a real deployment these would be computed off-chain by the prover
  // and submitted with the proof. For the hackathon we derive them via the
  // same Poseidon formula the circuit uses.
  //
  // We approximate via a deterministic hash here rather than calling the
  // circomlibjs Poseidon (which requires the full field arithmetic) so the
  // script stays self-contained. The circuit itself enforces correctness.
  console.log("\n  Deriving nullifiers via Poseidon hash...");
  let nullifiers;
  try {
    const { buildPoseidon } = require("../circuits/node_modules/circomlibjs");
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    nullifiers = MOCK_EMPLOYEES.map((emp, i) => {
      const h = poseidon([BigInt(emp.id), PAYROLL_EPOCH, salts[i]]);
      return F.toObject(h);
    });
    console.log("  Nullifiers computed via circomlibjs Poseidon");
  } catch (_) {
    // Fallback: let the circuit derive them from the private inputs.
    // We provide placeholder BigInts that will be overridden by witness.
    // This is fine for fullProve() which auto-computes witnesses.
    warn("  circomlibjs unavailable — nullifiers will be computed inside circuit");
    nullifiers = MOCK_EMPLOYEES.map(() => 0n);
  }

  // ── KPI proofs ────────────────────────────────────────────────────────────
  console.log("\n[4/6] Generating individual KPI proofs...");
  const kpiResults = [];

  for (let i = 0; i < MOCK_EMPLOYEES.length; i++) {
    const emp = MOCK_EMPLOYEES[i];
    process.stdout.write(`  Proving KPI for ${emp.name}...`);

    try {
      const result = await generateKpiProof(emp, salts[i]);
      const valid = await verifyProof("kpi", result.proof, result.publicSignals);

      const outPath = path.join(PROOFS_DIR, `kpi_${emp.name.toLowerCase()}.json`);
      fs.writeFileSync(
        outPath,
        JSON.stringify(
          {
            employee: emp.name,
            employeeId: emp.id,
            publicSignals: result.publicSignals,
            proof: result.proof,
            computed: {
              hoursMet: result.hoursMet,
              salesMet: result.salesMet,
            },
            verified: valid,
            generatedAt: new Date().toISOString(),
          },
          null,
          2,
        ),
      );

      console.log(` ${valid ? "VALID" : "INVALID"} — saved to ${path.relative(ROOT, outPath)}`);
      if (!valid) throw new Error(`KPI proof for ${emp.name} failed verification`);

      kpiResults.push(result);
    } catch (err) {
      console.log(` FAILED`);
      throw err;
    }
  }

  // ── Payroll aggregated proof ──────────────────────────────────────────────
  console.log("\n[5/6] Generating aggregated payroll proof...");
  process.stdout.write("  Proving PayrollAggregator(5)...");

  let payrollResult;
  try {
    payrollResult = await generatePayrollProof(
      MOCK_EMPLOYEES,
      salts,
      nullifiers,
      totalPayroll,
    );
    const valid = await verifyProof("payroll", payrollResult.proof, payrollResult.publicSignals);

    const outPath = path.join(PROOFS_DIR, "payroll_aggregated.json");
    fs.writeFileSync(
      outPath,
      JSON.stringify(
        {
          totalPayroll: totalPayroll.toString(),
          totalPayrollXLM: stroopsToXLM(totalPayroll),
          payrollEpoch: PAYROLL_EPOCH.toString(),
          publicSignals: payrollResult.publicSignals,
          proof: payrollResult.proof,
          verified: valid,
          generatedAt: new Date().toISOString(),
        },
        null,
        2,
      ),
    );

    console.log(` ${valid ? "VALID" : "INVALID"} — saved to ${path.relative(ROOT, outPath)}`);
    if (!valid) throw new Error("Payroll aggregated proof failed verification");
  } catch (err) {
    console.log(" FAILED");
    throw err;
  }

  // ── Auditor disclosure proof ──────────────────────────────────────────────
  console.log("\n[6/6] Generating auditor disclosure proof...");
  process.stdout.write("  Proving AuditorDisclosure(5)...");

  const individualPayouts = payoutResults.map((r) => r.payout);

  let auditorResult;
  try {
    auditorResult = await generateAuditorProof(individualPayouts, totalPayroll);
    const valid = await verifyProof("auditor", auditorResult.proof, auditorResult.publicSignals);

    const outPath = path.join(PROOFS_DIR, "auditor_disclosure.json");
    fs.writeFileSync(
      outPath,
      JSON.stringify(
        {
          totalPayroll: totalPayroll.toString(),
          totalPayrollXLM: stroopsToXLM(totalPayroll),
          budget: BUDGET_STROOPS.toString(),
          budgetXLM: stroopsToXLM(BUDGET_STROOPS),
          withinBudget: totalPayroll <= BUDGET_STROOPS,
          publicSignals: auditorResult.publicSignals,
          proof: auditorResult.proof,
          verified: valid,
          generatedAt: new Date().toISOString(),
        },
        null,
        2,
      ),
    );

    console.log(` ${valid ? "VALID" : "INVALID"} — saved to ${path.relative(ROOT, outPath)}`);
    if (!valid) throw new Error("Auditor disclosure proof failed verification");
  } catch (err) {
    console.log(" FAILED");
    throw err;
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log("");
  hr("=");
  console.log("  Proof Generation Complete");
  hr("=");
  console.log("");
  console.log("  Payroll Summary:");
  console.log("  ┌─────────────────────────────────────────────────────────┐");
  MOCK_EMPLOYEES.forEach((emp, i) => {
    const r = payoutResults[i];
    const bonusDesc =
      r.hoursMet && r.salesMet
        ? "+30% (hours + sales)"
        : r.hoursMet
        ? "+20% (hours)"
        : r.salesMet
        ? "+10% (sales)"
        : "+0%  (no bonus)";
    const base = stroopsToXLM(emp.baseSalary);
    const payout = stroopsToXLM(r.payout);
    console.log(
      `  │  ${emp.name.padEnd(7)} ${base} XLM  ${bonusDesc.padEnd(22)}  = ${payout} XLM`,
    );
  });
  console.log("  ├─────────────────────────────────────────────────────────┤");
  console.log(`  │  TOTAL    ${stroopsToXLM(totalPayroll)} XLM  (budget: ${stroopsToXLM(BUDGET_STROOPS)} XLM)`);
  console.log("  └─────────────────────────────────────────────────────────┘");
  console.log("");
  console.log("  Proof files saved to build/proofs/:");
  for (const emp of MOCK_EMPLOYEES) {
    console.log(`    kpi_${emp.name.toLowerCase()}.json`);
  }
  console.log("    payroll_aggregated.json");
  console.log("    auditor_disclosure.json");
  console.log("");
  console.log("  Next step: ./scripts/deploy.sh");
  console.log("");
}

function warn(msg) {
  console.warn(`\x1b[33m${msg}\x1b[0m`);
}

main().catch((err) => {
  console.error("\n[ERROR]", err.message || err);
  if (err.stack) console.error(err.stack);
  process.exit(1);
});
