//! MeritPay Claim Contract
//!
//! Holds payroll escrow released by the payroll contract after a verified batch.
//! Employees claim individual payouts by presenting a Groth16 claim proof tied
//! to their nullifier from the payroll batch.

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, token, Address, Bytes, BytesN, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ClaimError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NullifierNotAuthorized = 3,
    AlreadyClaimed = 4,
    InvalidProof = 5,
    InvalidAmount = 6,
    InsufficientEscrow = 7,
    PayrollEpochNotExecuted = 8,
    SignalMismatch = 9,
    /// Caller is not authorized as admin.
    Unauthorized = 10,
    /// The contract is currently paused by the admin.
    ContractPaused = 11,
    /// No pending admin transfer exists to accept.
    NoPendingAdmin = 12,
}

#[inline]
fn key_admin() -> soroban_sdk::Symbol {
    symbol_short!("admin")
}
#[inline]
fn key_pending_admin() -> soroban_sdk::Symbol {
    symbol_short!("p_admin")
}
#[inline]
fn key_payroll() -> soroban_sdk::Symbol {
    symbol_short!("payroll")
}
#[inline]
fn key_verifier() -> soroban_sdk::Symbol {
    symbol_short!("verifier")
}
#[inline]
fn key_token() -> soroban_sdk::Symbol {
    symbol_short!("token")
}
#[inline]
fn key_paused() -> soroban_sdk::Symbol {
    symbol_short!("paused")
}

mod verifier_contract {
    use soroban_sdk::{contractclient, Bytes, BytesN, Env, Vec};

    #[contractclient(name = "VerifierClient")]
    pub trait VerifierInterface {
        fn verify(env: Env, proof_bytes: Bytes, public_signals: Vec<BytesN<32>>) -> bool;
    }
}

mod payroll_contract {
    use soroban_sdk::{contractclient, BytesN, Env};

    #[contractclient(name = "PayrollClient")]
    pub trait PayrollInterface {
        fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool;
        fn get_epoch(env: Env) -> u64;
    }
}

use payroll_contract::PayrollClient;
use verifier_contract::VerifierClient;

#[contract]
pub struct ClaimContract;

#[contractimpl]
impl ClaimContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        payroll_contract: Address,
        verifier_contract: Address,
        token_address: Address,
    ) -> Result<(), ClaimError> {
        if env.storage().persistent().has(&key_admin()) {
            return Err(ClaimError::AlreadyInitialized);
        }

        admin.require_auth();

        env.storage().persistent().set(&key_admin(), &admin);
        env.storage()
            .persistent()
            .set(&key_payroll(), &payroll_contract);
        env.storage()
            .persistent()
            .set(&key_verifier(), &verifier_contract);
        env.storage().persistent().set(&key_token(), &token_address);

        env.events().publish(
            (symbol_short!("init"),),
            (admin, payroll_contract, verifier_contract, token_address),
        );

        Ok(())
    }

    /// Withdraw a verified payout to `recipient`.
    ///
    /// Public signals (claim circuit): [nullifier, payrollEpoch, amount]
    pub fn claim_payout(
        env: Env,
        recipient: Address,
        proof: Bytes,
        public_signals: Vec<BytesN<32>>,
        nullifier: BytesN<32>,
        amount: i128,
    ) -> Result<bool, ClaimError> {
        Self::assert_initialized(&env)?;

        if env
            .storage()
            .persistent()
            .get(&key_paused())
            .unwrap_or(false)
        {
            return Err(ClaimError::ContractPaused);
        }

        if amount <= 0 {
            return Err(ClaimError::InvalidAmount);
        }

        recipient.require_auth();

        if public_signals.len() != 3 {
            return Err(ClaimError::SignalMismatch);
        }

        let first_signal = public_signals.get(0).ok_or(ClaimError::SignalMismatch)?;
        if first_signal != nullifier {
            return Err(ClaimError::SignalMismatch);
        }

        let payroll_addr: Address = env
            .storage()
            .persistent()
            .get(&key_payroll())
            .ok_or(ClaimError::NotInitialized)?;
        let payroll = PayrollClient::new(&env, &payroll_addr);

        // Nullifier must have been spent in a payroll batch to be valid
        if !payroll.is_nullifier_spent(&nullifier) {
            return Err(ClaimError::NullifierNotAuthorized);
        }

        let claimed: bool = env
            .storage()
            .persistent()
            .get::<BytesN<32>, bool>(&nullifier)
            .unwrap_or(false);
        if claimed {
            return Err(ClaimError::AlreadyClaimed);
        }

        let on_chain_epoch = payroll.get_epoch();
        let proof_epoch_bytes = public_signals.get(1).ok_or(ClaimError::SignalMismatch)?;
        let proof_epoch = Self::bytes_to_u64(&proof_epoch_bytes)?;
        if on_chain_epoch < proof_epoch {
            return Err(ClaimError::PayrollEpochNotExecuted);
        }

        let proof_amount_bytes = public_signals.get(2).ok_or(ClaimError::SignalMismatch)?;
        let proof_amount = Self::bytes_to_i128(&proof_amount_bytes)?;
        if proof_amount != amount {
            return Err(ClaimError::SignalMismatch);
        }

        let verifier_addr: Address = env
            .storage()
            .persistent()
            .get(&key_verifier())
            .ok_or(ClaimError::NotInitialized)?;
        let verifier = VerifierClient::new(&env, &verifier_addr);
        if !verifier.verify(&proof, &public_signals) {
            return Err(ClaimError::InvalidProof);
        }

        env.storage().persistent().set(&nullifier, &true);

        let token_addr: Address = env
            .storage()
            .persistent()
            .get(&key_token())
            .ok_or(ClaimError::NotInitialized)?;
        let token = token::Client::new(&env, &token_addr);
        token.transfer(&env.current_contract_address(), &recipient, &amount);

        env.events()
            .publish((symbol_short!("claim"),), (recipient, nullifier, amount));

        Ok(true)
    }

    pub fn is_claimed(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get::<BytesN<32>, bool>(&nullifier)
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // set_verifier
    //
    // Admin-only. Rotates the Groth16 verifier contract address.
    // -----------------------------------------------------------------------
    pub fn set_verifier(
        env: Env,
        admin: Address,
        verifier_contract: Address,
    ) -> Result<(), ClaimError> {
        Self::assert_initialized(&env)?;

        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&key_admin())
            .ok_or(ClaimError::NotInitialized)?;
        if admin != stored_admin {
            return Err(ClaimError::Unauthorized);
        }

        let old_verifier: Address = env
            .storage()
            .persistent()
            .get(&key_verifier())
            .ok_or(ClaimError::NotInitialized)?;
        env.storage()
            .persistent()
            .set(&key_verifier(), &verifier_contract);

        env.events().publish(
            (symbol_short!("set_ver"),),
            (old_verifier, verifier_contract),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // set_payroll_contract
    //
    // Admin-only. Points the claim contract to an updated payroll contract.
    // -----------------------------------------------------------------------
    pub fn set_payroll_contract(
        env: Env,
        admin: Address,
        payroll_contract: Address,
    ) -> Result<(), ClaimError> {
        Self::assert_initialized(&env)?;

        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&key_admin())
            .ok_or(ClaimError::NotInitialized)?;
        if admin != stored_admin {
            return Err(ClaimError::Unauthorized);
        }

        let old_payroll: Address = env
            .storage()
            .persistent()
            .get(&key_payroll())
            .ok_or(ClaimError::NotInitialized)?;
        env.storage()
            .persistent()
            .set(&key_payroll(), &payroll_contract);

        env.events()
            .publish((symbol_short!("pay_set"),), (old_payroll, payroll_contract));

        Ok(())
    }

    // -----------------------------------------------------------------------
    // set_paused
    //
    // Admin-only. Pauses or unpauses claim payouts during incidents or migration.
    // -----------------------------------------------------------------------
    pub fn set_paused(env: Env, admin: Address, paused: bool) -> Result<(), ClaimError> {
        Self::assert_initialized(&env)?;

        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&key_admin())
            .ok_or(ClaimError::NotInitialized)?;
        if admin != stored_admin {
            return Err(ClaimError::Unauthorized);
        }

        env.storage().persistent().set(&key_paused(), &paused);

        env.events().publish((symbol_short!("pause"),), paused);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // transfer_admin
    //
    // Step 1 of two-step admin rotation. Admin sets `new_admin` as pending.
    // -----------------------------------------------------------------------
    pub fn transfer_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), ClaimError> {
        Self::assert_initialized(&env)?;

        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&key_admin())
            .ok_or(ClaimError::NotInitialized)?;
        if admin != stored_admin {
            return Err(ClaimError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&key_pending_admin(), &new_admin);

        env.events()
            .publish((symbol_short!("adm_xfer"),), (admin, new_admin));

        Ok(())
    }

    // -----------------------------------------------------------------------
    // accept_admin
    //
    // Step 2 of two-step admin rotation. `new_admin` claims the admin role.
    // -----------------------------------------------------------------------
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), ClaimError> {
        Self::assert_initialized(&env)?;

        new_admin.require_auth();
        let pending_admin: Address = env
            .storage()
            .persistent()
            .get(&key_pending_admin())
            .ok_or(ClaimError::NoPendingAdmin)?;
        if new_admin != pending_admin {
            return Err(ClaimError::Unauthorized);
        }

        let old_admin: Address = env
            .storage()
            .persistent()
            .get(&key_admin())
            .ok_or(ClaimError::NotInitialized)?;
        env.storage().persistent().set(&key_admin(), &new_admin);
        env.storage().persistent().remove(&key_pending_admin());

        env.events()
            .publish((symbol_short!("adm_acc"),), (old_admin, new_admin));

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Config getters
    // -----------------------------------------------------------------------

    pub fn get_admin(env: Env) -> Result<Address, ClaimError> {
        Self::assert_initialized(&env)?;
        env.storage()
            .persistent()
            .get(&key_admin())
            .ok_or(ClaimError::NotInitialized)
    }

    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&key_pending_admin())
    }

    pub fn get_payroll_contract(env: Env) -> Result<Address, ClaimError> {
        Self::assert_initialized(&env)?;
        env.storage()
            .persistent()
            .get(&key_payroll())
            .ok_or(ClaimError::NotInitialized)
    }

    pub fn get_verifier(env: Env) -> Result<Address, ClaimError> {
        Self::assert_initialized(&env)?;
        env.storage()
            .persistent()
            .get(&key_verifier())
            .ok_or(ClaimError::NotInitialized)
    }

    pub fn get_token(env: Env) -> Result<Address, ClaimError> {
        Self::assert_initialized(&env)?;
        env.storage()
            .persistent()
            .get(&key_token())
            .ok_or(ClaimError::NotInitialized)
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&key_paused())
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // Note on token immutability:
    // The SEP-41 token address (`token`) is intentionally immutable once set in
    // `initialize`. Escrow funds held by this contract are reserved for employee
    // claims. Permitting token address rotation would risk locked funds becoming
    // unwithdrawable or unauthorized asset substitution. If a different asset
    // is to be distributed, a new Claim contract instance must be deployed.
    // -----------------------------------------------------------------------

    fn assert_initialized(env: &Env) -> Result<(), ClaimError> {
        if !env.storage().persistent().has(&key_admin()) {
            return Err(ClaimError::NotInitialized);
        }
        Ok(())
    }

    /// Converts a 32-byte BN254 field-element public signal into a `u64`.
    ///
    /// The circuit does not constrain this signal to fit in 64 bits, so a
    /// malicious prover could choose a field element whose low 8 bytes equal
    /// any desired `u64` while the high 24 bytes are non-zero (i.e. the true
    /// field value is astronomically larger than the truncated result).
    /// Rejecting any non-zero high-order bytes ensures the on-chain integer
    /// is a faithful, non-wrapped representation of the signal.
    fn bytes_to_u64(bytes: &BytesN<32>) -> Result<u64, ClaimError> {
        let arr = bytes.to_array();
        if arr[0..24].iter().any(|&b| b != 0) {
            return Err(ClaimError::SignalMismatch);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&arr[24..32]);
        Ok(u64::from_be_bytes(buf))
    }

    /// Converts a 32-byte BN254 field-element public signal into an `i128`.
    /// See `bytes_to_u64` for why the high-order bytes must be checked.
    fn bytes_to_i128(bytes: &BytesN<32>) -> Result<i128, ClaimError> {
        let arr = bytes.to_array();
        if arr[0..16].iter().any(|&b| b != 0) {
            return Err(ClaimError::SignalMismatch);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&arr[16..32]);
        Ok(i128::from_be_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    mod mock_ok {
        use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};

        #[contract]
        pub struct MockOk;

        #[contractimpl]
        impl MockOk {
            pub fn verify(_env: Env, _proof: Bytes, _signals: Vec<BytesN<32>>) -> bool {
                true
            }
        }
    }

    mod mock_payroll {
        use soroban_sdk::{contract, contractimpl, BytesN, Env};

        #[contract]
        pub struct MockPayroll;

        #[contractimpl]
        impl MockPayroll {
            pub fn is_nullifier_spent(_env: Env, _nullifier: BytesN<32>) -> bool {
                true
            }

            pub fn get_epoch(_env: Env) -> u64 {
                2
            }
        }
    }

    fn setup(env: &Env) -> (Address, Address, Address, Address, Address, Address) {
        let admin = Address::generate(env);
        let recipient = Address::generate(env);
        let payroll_id = env.register(mock_payroll::MockPayroll, ());
        let verifier_id = env.register(mock_ok::MockOk, ());
        let xlm_id = env
            .register_stellar_asset_contract_v2(recipient.clone())
            .address();
        let claim_id = env.register(ClaimContract, ());

        env.mock_all_auths();

        let client = ClaimContractClient::new(env, &claim_id);
        client.initialize(&admin, &payroll_id, &verifier_id, &xlm_id);

        let xlm = token::StellarAssetClient::new(env, &xlm_id);
        xlm.mint(&recipient, &1_000_0000000i128);
        xlm.transfer(&recipient, &claim_id, &500_0000000i128);

        (admin, recipient, claim_id, xlm_id, payroll_id, verifier_id)
    }

    #[test]
    fn test_claim_payout_happy_path() {
        let env = Env::default();
        let (_admin, recipient, claim_id, _xlm_id, _payroll_id, _verifier_id) = setup(&env);
        let client = ClaimContractClient::new(&env, &claim_id);

        let nullifier = BytesN::from_array(&env, &[0xABu8; 32]);
        let mut signals: Vec<BytesN<32>> = Vec::new(&env);
        signals.push_back(nullifier.clone());
        signals.push_back(BytesN::from_array(&env, &{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        }));
        signals.push_back(BytesN::from_array(&env, &{
            let mut b = [0u8; 32];
            let amt: i128 = 10_0000000;
            b[16..32].copy_from_slice(&amt.to_be_bytes());
            b
        }));

        let proof = Bytes::from_slice(&env, &[0u8; 256]);
        let result = client.claim_payout(&recipient, &proof, &signals, &nullifier, &10_0000000i128);
        assert!(result);
        assert!(client.is_claimed(&nullifier));
    }

    #[test]
    fn test_claim_config_getters() {
        let env = Env::default();
        let (admin, _recipient, claim_id, xlm_id, payroll_id, verifier_id) = setup(&env);
        let client = ClaimContractClient::new(&env, &claim_id);

        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_payroll_contract(), payroll_id);
        assert_eq!(client.get_verifier(), verifier_id);
        assert_eq!(client.get_token(), xlm_id);
        assert_eq!(client.get_pending_admin(), None);
        assert_eq!(client.is_paused(), false);
    }

    #[test]
    fn test_claim_set_verifier_happy_and_unauthorized() {
        let env = Env::default();
        let (admin, _recipient, claim_id, _xlm_id, _payroll_id, _verifier_id) = setup(&env);
        let client = ClaimContractClient::new(&env, &claim_id);

        let new_verifier = env.register(mock_ok::MockOk, ());
        let attacker = Address::generate(&env);

        let fail = client.try_set_verifier(&attacker, &new_verifier);
        assert!(fail.is_err());

        client.set_verifier(&admin, &new_verifier);
        assert_eq!(client.get_verifier(), new_verifier);
    }

    #[test]
    fn test_claim_set_payroll_happy_and_unauthorized() {
        let env = Env::default();
        let (admin, _recipient, claim_id, _xlm_id, _payroll_id, _verifier_id) = setup(&env);
        let client = ClaimContractClient::new(&env, &claim_id);

        let new_payroll = env.register(mock_payroll::MockPayroll, ());
        let attacker = Address::generate(&env);

        let fail = client.try_set_payroll_contract(&attacker, &new_payroll);
        assert!(fail.is_err());

        client.set_payroll_contract(&admin, &new_payroll);
        assert_eq!(client.get_payroll_contract(), new_payroll);
    }

    #[test]
    fn test_claim_set_paused_halts_and_resumes() {
        let env = Env::default();
        let (admin, recipient, claim_id, _xlm_id, _payroll_id, _verifier_id) = setup(&env);
        let client = ClaimContractClient::new(&env, &claim_id);

        let attacker = Address::generate(&env);

        // Attacker cannot pause
        let unauth = client.try_set_paused(&attacker, &true);
        assert!(unauth.is_err());

        // Admin pauses
        client.set_paused(&admin, &true);
        assert!(client.is_paused());

        let nullifier = BytesN::from_array(&env, &[0xCDu8; 32]);
        let mut signals: Vec<BytesN<32>> = Vec::new(&env);
        signals.push_back(nullifier.clone());
        signals.push_back(BytesN::from_array(&env, &{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        }));
        signals.push_back(BytesN::from_array(&env, &{
            let mut b = [0u8; 32];
            let amt: i128 = 5_0000000;
            b[16..32].copy_from_slice(&amt.to_be_bytes());
            b
        }));
        let proof = Bytes::from_slice(&env, &[0u8; 256]);

        // Payout rejected when paused
        let paused_err =
            client.try_claim_payout(&recipient, &proof, &signals, &nullifier, &5_0000000i128);
        assert_eq!(paused_err, Err(Ok(ClaimError::ContractPaused)));

        // Unpause
        client.set_paused(&admin, &false);
        assert!(!client.is_paused());

        // Payout succeeds
        let res = client.claim_payout(&recipient, &proof, &signals, &nullifier, &5_0000000i128);
        assert!(res);
    }

    #[test]
    fn test_claim_two_step_admin_transfer_full_lifecycle() {
        let env = Env::default();
        let (admin, _recipient, claim_id, _xlm_id, _payroll_id, _verifier_id) = setup(&env);
        let client = ClaimContractClient::new(&env, &claim_id);

        let new_admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        // Attacker cannot initiate transfer
        let unauth_xfer = client.try_transfer_admin(&attacker, &new_admin);
        assert!(unauth_xfer.is_err());

        // Accept with no pending transfer fails
        let no_pend = client.try_accept_admin(&new_admin);
        assert_eq!(no_pend, Err(Ok(ClaimError::NoPendingAdmin)));

        // Admin initiates transfer
        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.get_pending_admin(), Some(new_admin.clone()));
        assert_eq!(client.get_admin(), admin);

        // Attacker cannot accept
        let attacker_accept = client.try_accept_admin(&attacker);
        assert!(attacker_accept.is_err());

        // New admin accepts
        client.accept_admin(&new_admin);
        assert_eq!(client.get_admin(), new_admin);
        assert_eq!(client.get_pending_admin(), None);

        // Old admin loses privileges
        let old_admin_action = client.try_set_paused(&admin, &true);
        assert!(old_admin_action.is_err());

        // New admin has privileges
        client.set_paused(&new_admin, &true);
        assert!(client.is_paused());
    }
}
