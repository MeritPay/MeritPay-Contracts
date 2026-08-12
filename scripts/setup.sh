#!/usr/bin/env bash
# =============================================================================
# MeritPay ZK Setup Script
# =============================================================================
# Compiles all three Circom circuits and runs the Groth16 trusted setup for each.
#
# Circuits compiled:
#   - circuits/kpi.circom               → build/kpi/
#   - circuits/payroll_aggregator.circom → build/payroll/
#   - circuits/auditor_disclosure.circom → build/auditor/
#   - circuits/claim.circom              → build/claim/
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh
#
# Environment variables (optional):
#   ENTROPY      Override the random entropy string for Phase 2 contribution
#   SKIP_PTAU    Set to "1" to skip re-downloading the powers-of-tau file
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${NC}"; }

# ---------------------------------------------------------------------------
# Resolve project root (script may be called from any directory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"
info "Project root: $PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Phase 2 entropy — override with ENTROPY env var for reproducibility
# ---------------------------------------------------------------------------
ENTROPY="${ENTROPY:-MeritPay-Hackathon-2026-$(date +%s)-$RANDOM}"

# Powers-of-tau files (Phase 1)
# pot12: covers up to 2^12=4096 constraints  — used by kpi, auditor, claim
# pot14: covers up to 2^14=16384 constraints — required by payroll_aggregator (7065 constraints)
PTAU12_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_12.ptau"
PTAU12_FILE="$PROJECT_ROOT/build/pot12_final.ptau"
PTAU14_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau"
PTAU14_FILE="$PROJECT_ROOT/build/pot14_final.ptau"

# Back-compat alias (used in section 5 messaging)
PTAU_FILE="$PTAU12_FILE"

# =============================================================================
# 1. Prerequisite checks
# =============================================================================
section "1 / 7  Checking prerequisites"

check_cmd() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" &>/dev/null; then
        error "'$cmd' not found. $hint"
    fi
    success "$cmd  $(${cmd} --version 2>&1 | head -1)"
}

check_cmd node  "Install Node.js 18+ from https://nodejs.org"
check_cmd npm   "Install Node.js 18+ from https://nodejs.org"

# Circom version check — binary may print to stderr
CIRCOM_VER=$(circom --version 2>&1 || true)
if [[ "$CIRCOM_VER" != *"circom"* ]]; then
    error "'circom' not found. Install via: cargo install circom\n  Or from: https://docs.circom.io/getting-started/installation/"
fi
success "circom  $CIRCOM_VER"

SNARKJS_VER=$(node -e "console.log(require('./circuits/node_modules/snarkjs/package.json').version)" 2>/dev/null || echo "not installed")
if [[ "$SNARKJS_VER" == "not installed" ]]; then
    warn "snarkjs not yet installed — will be installed in next step"
else
    success "snarkjs  $SNARKJS_VER"
fi

# Check for curl or wget to download ptau
if command -v curl &>/dev/null; then
    DOWNLOADER="curl"
elif command -v wget &>/dev/null; then
    DOWNLOADER="wget"
else
    error "Neither 'curl' nor 'wget' found. Cannot download powers-of-tau file."
fi

# =============================================================================
# 2. Install npm dependencies in circuits/
# =============================================================================
section "2 / 7  Installing circuit npm dependencies"

cd "$PROJECT_ROOT/circuits"
npm install --silent
success "circomlib and snarkjs installed"
cd "$PROJECT_ROOT"

# Expose snarkjs via npx shorthand for the rest of the script
SNARKJS="node $PROJECT_ROOT/circuits/node_modules/.bin/snarkjs"

# =============================================================================
# 3. Create build directories
# =============================================================================
section "3 / 7  Creating build directories"

mkdir -p build/kpi
mkdir -p build/payroll
mkdir -p build/auditor
mkdir -p build/proofs
success "build/{kpi,payroll,auditor,proofs} created"

# =============================================================================
# 4. Compile circuits
# =============================================================================
section "4 / 7  Compiling Circom circuits"

compile_circuit() {
    local name="$1"      # e.g. "kpi"
    local src="$2"       # path to .circom file
    local outdir="$3"    # output directory

    info "Compiling $name circuit..."
    circom "$src" \
        --r1cs \
        --wasm \
        --sym \
        -o "$outdir" \
        2>&1

    # Verify expected artefacts were generated
    local wasm_dir="$outdir/${name}_js"
    [[ -f "$outdir/${name}.r1cs" ]] || error "Missing ${name}.r1cs after compilation"
    [[ -d "$wasm_dir" ]] || error "Missing ${name}_js/ directory after compilation"

    local constraints
    constraints=$(${SNARKJS} r1cs info "$outdir/${name}.r1cs" 2>&1 | grep -i "# of Constraints" | awk '{print $NF}' || echo "?")
    success "$name compiled  ($constraints constraints)"
}

compile_circuit "kpi"              "circuits/kpi.circom"               "build/kpi"
compile_circuit "payroll_aggregator" "circuits/payroll_aggregator.circom" "build/payroll"
compile_circuit "auditor_disclosure" "circuits/auditor_disclosure.circom" "build/auditor"
compile_circuit "claim"              "circuits/claim.circom"               "build/claim"

# =============================================================================
# 5. Download Powers of Tau (Phase 1)
# =============================================================================
section "5 / 7  Powers of Tau (Phase 1)"

download_ptau() {
    local url="$1"
    local file="$2"
    local label="$3"
    local size="$4"

    if [[ "${SKIP_PTAU:-0}" == "1" ]] && [[ -f "$file" ]]; then
        warn "SKIP_PTAU=1 — using existing $file"
    elif [[ -f "$file" ]]; then
        success "$label already present — skipping download"
    else
        info "Downloading Powers of Tau ($label — $size)..."
        info "Source: $url"
        if [[ "$DOWNLOADER" == "curl" ]]; then
            curl -L --progress-bar "$url" -o "$file"
        else
            wget -q --show-progress "$url" -O "$file"
        fi
        success "Downloaded $label"
    fi
}

download_ptau "$PTAU12_URL" "$PTAU12_FILE" "pot12_final.ptau" "~54 MB"
download_ptau "$PTAU14_URL" "$PTAU14_FILE" "pot14_final.ptau" "~220 MB"

# =============================================================================
# 6. Phase 2 setup per circuit
# =============================================================================
section "6 / 7  Groth16 Phase 2 trusted setup"

phase2_setup() {
    local name="$1"
    local r1cs="$2"
    local outdir="$3"
    local ptau="$4"   # path to the correct powers-of-tau file for this circuit

    info "[$name] groth16 setup..."
    ${SNARKJS} groth16 setup \
        "$r1cs" \
        "$ptau" \
        "$outdir/${name}_0000.zkey" \
        2>&1

    info "[$name] Phase 2 contribution (hackathon entropy)..."
    ${SNARKJS} zkey contribute \
        "$outdir/${name}_0000.zkey" \
        "$outdir/${name}_final.zkey" \
        --name="MeritPay Hackathon Contributor" \
        -e="$ENTROPY" \
        2>&1

    info "[$name] Exporting verification key..."
    ${SNARKJS} zkey export verificationkey \
        "$outdir/${name}_final.zkey" \
        "$outdir/${name}_vkey.json" \
        2>&1

    # Verify the final zkey is valid
    ${SNARKJS} zkey verify \
        "$r1cs" \
        "$ptau" \
        "$outdir/${name}_final.zkey" \
        2>&1 | tail -3

    success "[$name] Phase 2 complete: ${name}_final.zkey + ${name}_vkey.json"
}

# payroll_aggregator has 7065 constraints (7065×2=14130 > 2^12), requires pot14
phase2_setup "kpi"               "build/kpi/kpi.r1cs"                       "build/kpi"     "$PTAU12_FILE"
phase2_setup "payroll_aggregator" "build/payroll/payroll_aggregator.r1cs"    "build/payroll" "$PTAU14_FILE"
phase2_setup "auditor_disclosure" "build/auditor/auditor_disclosure.r1cs"    "build/auditor" "$PTAU12_FILE"
phase2_setup "claim"              "build/claim/claim.r1cs"                   "build/claim"   "$PTAU12_FILE"

# =============================================================================
# 7. Export Solidity verifiers (for documentation / cross-chain reference)
# =============================================================================
section "7 / 7  Exporting Solidity verifiers (reference only)"

mkdir -p build/solidity_ref

export_solidity() {
    local name="$1"
    local zkey="$2"
    local out="$3"

    info "Exporting Solidity verifier for $name..."
    ${SNARKJS} zkey export solidityverifier \
        "$zkey" \
        "$out" \
        2>&1
    success "Solidity verifier: $out"
}

export_solidity "kpi"               "build/kpi/kpi_final.zkey"               "build/solidity_ref/KpiVerifier.sol"
export_solidity "payroll_aggregator" "build/payroll/payroll_aggregator_final.zkey" "build/solidity_ref/PayrollVerifier.sol"
export_solidity "auditor_disclosure" "build/auditor/auditor_disclosure_final.zkey" "build/solidity_ref/AuditorVerifier.sol"
export_solidity "claim"              "build/claim/claim_final.zkey"               "build/solidity_ref/ClaimVerifier.sol"

# =============================================================================
# 8. Sync circuit artefacts to Next.js public folder
# =============================================================================
section "8 / 8  Syncing circuits to web/public"

sync_circuit() {
    local dest_name="$1"
    local wasm_src="$2"
    local zkey_src="$3"
    local dest="$PROJECT_ROOT/web/public/circuits/$dest_name"
    mkdir -p "$dest"
    cp -f "$wasm_src" "$dest/"
    cp -f "$zkey_src" "$dest/"
    success "Synced $dest_name → web/public/circuits/$dest_name"
}

sync_circuit "kpi"     "build/kpi/kpi_js/kpi.wasm"                         "build/kpi/kpi_final.zkey"
sync_circuit "payroll" "build/payroll/payroll_aggregator_js/payroll_aggregator.wasm" "build/payroll/payroll_aggregator_final.zkey"
sync_circuit "auditor" "build/auditor/auditor_disclosure_js/auditor_disclosure.wasm" "build/auditor/auditor_disclosure_final.zkey"
sync_circuit "claim"   "build/claim/claim_js/claim.wasm"                   "build/claim/claim_final.zkey"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  MeritPay ZK Setup Complete${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Generated artefacts:${NC}"
echo ""
echo -e "  ${CYAN}KPI Circuit${NC}"
echo    "    build/kpi/kpi.r1cs"
echo    "    build/kpi/kpi_js/kpi.wasm"
echo    "    build/kpi/kpi_final.zkey"
echo    "    build/kpi/kpi_vkey.json"
echo ""
echo -e "  ${CYAN}Payroll Aggregator${NC}"
echo    "    build/payroll/payroll_aggregator.r1cs"
echo    "    build/payroll/payroll_aggregator_js/payroll_aggregator.wasm"
echo    "    build/payroll/payroll_aggregator_final.zkey"
echo    "    build/payroll/payroll_aggregator_vkey.json"
echo ""
echo -e "  ${CYAN}Auditor Disclosure${NC}"
echo    "    build/auditor/auditor_disclosure.r1cs"
echo    "    build/auditor/auditor_disclosure_js/auditor_disclosure.wasm"
echo    "    build/auditor/auditor_disclosure_final.zkey"
echo    "    build/auditor/auditor_disclosure_vkey.json"
echo ""
echo -e "  ${CYAN}Solidity Verifiers (reference)${NC}"
echo    "    build/solidity_ref/KpiVerifier.sol"
echo    "    build/solidity_ref/PayrollVerifier.sol"
echo    "    build/solidity_ref/AuditorVerifier.sol"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo    "    node scripts/gen_proof.js    # Generate and verify test proofs"
echo    "    ./scripts/deploy.sh          # Deploy Soroban contracts to testnet"
echo ""
