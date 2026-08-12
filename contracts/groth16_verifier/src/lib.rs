//! MeritPay Groth16 Verifier Contract
//!
//! Verifies Groth16 proofs over BN254 using Stellar Soroban's native
//! host functions. The verification key is stored once by the deployer;
//! callers pass a proof and public signals to `verify`.
//!
//! ## Groth16 Verification Equation
//!
//!   e(A, B) · e(-alpha, beta) · e(-vk_x, gamma) · e(-C, delta) == 1
//!
//! where:
//!   vk_x = ic[0] + MSM( ic[1..n_ic], public_signals )
//!
//! ## Wire Format (all field coordinates big-endian, 32 bytes each)
//!
//! **Proof bytes** (256 bytes total):
//!   - pi_a : G1 — 64 bytes  (x ‖ y)
//!   - pi_b : G2 — 128 bytes (x_im ‖ x_re ‖ y_im ‖ y_re, each 32 bytes)
//!   - pi_c : G1 — 64 bytes
//!
//! **VK bytes** layout (stored via `set_vk`):
//!   - alpha  : G1  — 64 bytes  [offset   0]
//!   - beta   : G2  — 128 bytes [offset  64]
//!   - gamma  : G2  — 128 bytes [offset 192]
//!   - delta  : G2  — 128 bytes [offset 320]
//!   - n_ic   : u32 — 4 bytes   [offset 448]  (= n_public + 1)
//!   - ic[0..n_ic] : G1, 64 bytes each [offset 452]

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Bytes, BytesN, Env, Vec,
};
use soroban_sdk::crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    VkNotSet          = 1,
    InvalidProofLength = 2,
    SignalCountMismatch = 3,
    InvalidVkLength    = 4,
}

// ---------------------------------------------------------------------------
// Storage wrapper
// ---------------------------------------------------------------------------

#[contracttype]
pub struct StoredVk {
    pub raw: Bytes,
}

// ---------------------------------------------------------------------------
// Byte-level helpers
// ---------------------------------------------------------------------------

fn read_g1(env: &Env, src: &Bytes, offset: u32) -> Bn254G1Affine {
    let slice: BytesN<64> = src
        .slice(offset..offset + 64)
        .try_into()
        .unwrap_or_else(|_| BytesN::from_array(env, &[0u8; 64]));
    Bn254G1Affine::from_bytes(slice)
}

fn read_g2(env: &Env, src: &Bytes, offset: u32) -> Bn254G2Affine {
    let slice: BytesN<128> = src
        .slice(offset..offset + 128)
        .try_into()
        .unwrap_or_else(|_| BytesN::from_array(env, &[0u8; 128]));
    Bn254G2Affine::from_bytes(slice)
}

fn read_fr(env: &Env, src: &Bytes, offset: u32) -> Bn254Fr {
    let slice: BytesN<32> = src
        .slice(offset..offset + 32)
        .try_into()
        .unwrap_or_else(|_| BytesN::from_array(env, &[0u8; 32]));
    Bn254Fr::from_bytes(slice)
}

fn read_u32_be(src: &Bytes, offset: u32) -> u32 {
    let b0 = src.get(offset).unwrap_or(0) as u32;
    let b1 = src.get(offset + 1).unwrap_or(0) as u32;
    let b2 = src.get(offset + 2).unwrap_or(0) as u32;
    let b3 = src.get(offset + 3).unwrap_or(0) as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct Groth16Verifier;

#[contractimpl]
impl Groth16Verifier {
    /// Store the verification key. Must be called once after deployment.
    /// `vk_bytes` must follow the wire format in the module doc.
    pub fn set_vk(env: Env, vk_bytes: Bytes) -> Result<(), VerifierError> {
        // Minimum: alpha(64)+beta(128)+gamma(128)+delta(128)+n_ic(4) = 452
        // plus at least one IC point (64 bytes) → 516 bytes minimum.
        if vk_bytes.len() < 516 {
            return Err(VerifierError::InvalidVkLength);
        }
        let n_ic = read_u32_be(&vk_bytes, 448);
        if n_ic == 0 {
            return Err(VerifierError::InvalidVkLength);
        }
        let expected_len = 452 + n_ic * 64;
        if vk_bytes.len() != expected_len {
            return Err(VerifierError::InvalidVkLength);
        }
        env.storage()
            .persistent()
            .set(&symbol_short!("VK"), &StoredVk { raw: vk_bytes });
        Ok(())
    }

    /// Returns `true` if a verification key has been stored.
    pub fn has_vk(env: Env) -> bool {
        env.storage().persistent().has(&symbol_short!("VK"))
    }

    /// Verify a Groth16 proof against the stored VK.
    ///
    /// `proof_bytes`    — 256-byte proof (pi_a ‖ pi_b ‖ pi_c)
    /// `public_signals` — one 32-byte big-endian scalar per public input
    pub fn verify(
        env: Env,
        proof_bytes: Bytes,
        public_signals: Vec<BytesN<32>>,
    ) -> Result<bool, VerifierError> {
        // 1. Load VK
        let stored: StoredVk = env
            .storage()
            .persistent()
            .get(&symbol_short!("VK"))
            .ok_or(VerifierError::VkNotSet)?;
        let vk = stored.raw;

        // 2. Validate proof length (pi_a=64, pi_b=128, pi_c=64 → 256 bytes)
        if proof_bytes.len() != 256 {
            return Err(VerifierError::InvalidProofLength);
        }

        // 3. Validate public signal count
        let n_ic = read_u32_be(&vk, 448);
        let n_public = n_ic - 1;
        if public_signals.len() as u32 != n_public {
            return Err(VerifierError::SignalCountMismatch);
        }

        // 4. Parse proof
        let pi_a = read_g1(&env, &proof_bytes, 0);
        let pi_b = read_g2(&env, &proof_bytes, 64);
        let pi_c = read_g1(&env, &proof_bytes, 192);

        // 5. Parse VK
        let vk_alpha = read_g1(&env, &vk, 0);
        let vk_beta  = read_g2(&env, &vk, 64);
        let vk_gamma = read_g2(&env, &vk, 192);
        let vk_delta = read_g2(&env, &vk, 320);
        let ic0      = read_g1(&env, &vk, 452);

        // 6. Compute vk_x = ic[0] + MSM( ic[1..], public_signals )
        let bn254 = env.crypto().bn254();

        let vk_x = if n_public == 0 {
            ic0
        } else {
            let mut msm_points: Vec<Bn254G1Affine> = Vec::new(&env);
            let mut msm_scalars: Vec<Bn254Fr> = Vec::new(&env);

            for i in 0..n_public {
                // IC points start at byte 452; ic[0] at 452, ic[i+1] at 452+64+i*64
                let ic_i = read_g1(&env, &vk, 516 + i * 64);
                msm_points.push_back(ic_i);

                // Convert BytesN<32> public signal → Bn254Fr
                let sig_bytes: BytesN<32> = public_signals.get(i).unwrap();
                let fr = Bn254Fr::from_bytes(sig_bytes);
                msm_scalars.push_back(fr);
            }

            let msm_result = bn254.g1_msm(msm_points, msm_scalars);
            bn254.g1_add(&ic0, &msm_result)
        };

        // 7. Negate G1 points using the Neg trait impl on Bn254G1Affine
        let neg_alpha = -vk_alpha;
        let neg_vk_x  = -vk_x;
        let neg_pi_c  = -pi_c;

        // 8. Multi-pairing check:
        //    e(A, B) · e(-alpha, beta) · e(-vk_x, gamma) · e(-C, delta) == 1
        let mut g1_points: Vec<Bn254G1Affine> = Vec::new(&env);
        g1_points.push_back(pi_a);
        g1_points.push_back(neg_alpha);
        g1_points.push_back(neg_vk_x);
        g1_points.push_back(neg_pi_c);

        let mut g2_points: Vec<Bn254G2Affine> = Vec::new(&env);
        g2_points.push_back(pi_b);
        g2_points.push_back(vk_beta);
        g2_points.push_back(vk_gamma);
        g2_points.push_back(vk_delta);

        let valid = bn254.pairing_check(g1_points, g2_points);
        Ok(valid)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn dummy_vk_bytes(env: &Env, n_public: u32) -> Bytes {
        let n_ic = n_public + 1;
        let mut b = Bytes::new(env);
        for _ in 0..448usize {
            b.push_back(0u8);
        }
        b.push_back(((n_ic >> 24) & 0xFF) as u8);
        b.push_back(((n_ic >> 16) & 0xFF) as u8);
        b.push_back(((n_ic >>  8) & 0xFF) as u8);
        b.push_back(( n_ic        & 0xFF) as u8);
        for _ in 0..(n_ic * 64) as usize {
            b.push_back(0u8);
        }
        b
    }

    #[test]
    fn test_set_vk_and_has_vk() {
        let env = Env::default();
        let contract_id = env.register(Groth16Verifier, ());
        let client = Groth16VerifierClient::new(&env, &contract_id);
        assert!(!client.has_vk());
        client.set_vk(&dummy_vk_bytes(&env, 3));
        assert!(client.has_vk());
    }

    #[test]
    fn test_set_vk_rejects_too_short() {
        let env = Env::default();
        let contract_id = env.register(Groth16Verifier, ());
        let client = Groth16VerifierClient::new(&env, &contract_id);
        let short = Bytes::from_slice(&env, &[0u8; 100]);
        assert!(client.try_set_vk(&short).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_proof_length() {
        let env = Env::default();
        let contract_id = env.register(Groth16Verifier, ());
        let client = Groth16VerifierClient::new(&env, &contract_id);
        client.set_vk(&dummy_vk_bytes(&env, 1));
        let short_proof = Bytes::from_slice(&env, &[0u8; 128]);
        let signals: Vec<BytesN<32>> = Vec::new(&env);
        assert!(client.try_verify(&short_proof, &signals).is_err());
    }

    #[test]
    fn test_verify_rejects_signal_count_mismatch() {
        let env = Env::default();
        let contract_id = env.register(Groth16Verifier, ());
        let client = Groth16VerifierClient::new(&env, &contract_id);
        client.set_vk(&dummy_vk_bytes(&env, 2));
        let proof = Bytes::from_slice(&env, &[0u8; 256]);
        let mut signals: Vec<BytesN<32>> = Vec::new(&env);
        signals.push_back(BytesN::from_array(&env, &[0u8; 32]));
        assert!(client.try_verify(&proof, &signals).is_err());
    }

    #[test]
    fn test_verify_no_vk_returns_error() {
        let env = Env::default();
        let contract_id = env.register(Groth16Verifier, ());
        let client = Groth16VerifierClient::new(&env, &contract_id);
        let proof = Bytes::from_slice(&env, &[0u8; 256]);
        let signals: Vec<BytesN<32>> = Vec::new(&env);
        assert!(client.try_verify(&proof, &signals).is_err());
    }
}
