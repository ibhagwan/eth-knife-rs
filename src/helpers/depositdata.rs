use alloy::primitives::{B256, FixedBytes};

#[derive(Debug, tree_hash_derive::TreeHash, serde::Serialize)]
pub struct DepositData {
    /// Validator public key
    pub pubkey: FixedBytes<48>,
    /// Withdrawal credentials
    pub withdrawal_credentials: B256,
    /// Amount of ether deposited in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    /// Deposit signature
    pub signature: FixedBytes<96>,
}
