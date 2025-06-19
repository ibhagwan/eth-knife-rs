use colored::*;
use eyre::{Result, WrapErr, bail, eyre};
use log::*;
use once_cell::sync::Lazy;
use std::sync::Arc;

use alloy::{
    network::TransactionBuilder,
    primitives::{
        Address, Bytes, TxHash, U256, hex,
        utils::{Unit, parse_ether},
    },
    providers::Provider,
    rpc::types::TransactionRequest,
};

use crate::{
    account::Account, config::TxCommonArgs, global, helpers::depositdata::DepositData,
    parse_address, rpc,
};

// https://eips.ethereum.org/EIPS/eip-7251
static CONSOLIDATION_CONTRACR_ADDR: Lazy<Address> =
    Lazy::new(|| parse_address!("0x0000BBdDc7CE488642fb579F8B00f3a590007251"));

// https://eips.ethereum.org/EIPS/eip-7002
static WITHDRAWAL_CONTRACR_ADDR: Lazy<Address> =
    Lazy::new(|| parse_address!("0x00000961Ef480Eb55e80D19ad83579A64c007002"));

// Compund is a consolidation request where both source and target
// public keys are equal (in place validator upgrade, 0x1 -> 0x2)
pub async fn comppound(
    account: Arc<Account>,
    pubkey: &String,
    max_fee: u128,
    tx_args: &TxCommonArgs,
) -> Result<Option<TxHash>> {
    consolidate(account, pubkey, pubkey, max_fee, tx_args).await
}

pub async fn consolidate(
    account: Arc<Account>,
    source: &String,
    target: &String,
    max_fee: u128,
    tx_args: &TxCommonArgs,
) -> Result<Option<TxHash>> {
    let parse_pubkey = |pubkey: &str| -> Result<blst::min_pk::PublicKey> {
        blst::min_pk::PublicKey::from_bytes(hex::decode(pubkey)?.as_slice())
            .map_err(|e| eyre!("{:#?}", e))
    };
    let source =
        parse_pubkey(source.as_str()).wrap_err_with(|| "source public key parsing failed")?;
    let target =
        parse_pubkey(target.as_str()).wrap_err_with(|| "target public key parsing failed")?;
    debug!(
        "Source: {}",
        hex::encode(source.to_bytes()).to_string().green()
    );
    debug!(
        "Target: {}",
        hex::encode(target.to_bytes()).to_string().blue()
    );

    let fee: u128 = match tx_args.offline {
        true => max_fee,
        false => {
            // Query the consolidation contract for the fee
            // let provider = global!(client).provider().await?;
            let out = global!(client)
                .provider()
                .await?
                .call(
                    TransactionRequest::default()
                        .with_to(CONSOLIDATION_CONTRACR_ADDR.clone())
                        .with_input([]),
                )
                .await?;
            // Retrurned bytes are 32 in length (U256), we convert to u128 by using
            // the 16 rightmost bytes as the fee should never be as high to require
            // the full length U256, in fact, the returned fee is currently always 1
            let bytes: [u8; 16] = out[16..32].try_into()?;
            u128::from_be_bytes(bytes)
        }
    };

    if fee > max_fee {
        bail!(
            "Consolidation fee ({}) > Max consolidation fee ({})",
            fee,
            max_fee
        )
    }
    debug!(
        "Consolidation contract fee (wei): {}",
        fee.to_string().magenta()
    );

    let mut input: Vec<u8> = source.to_bytes().into();
    input.extend(target.to_bytes());
    let tx = rpc::gen_tx_request(
        account.address()?,
        CONSOLIDATION_CONTRACR_ADDR.clone(),
        tx_args,
    )
    .await?
    .with_value(U256::from(fee))
    .with_input(input);
    trace!("{:#?}", tx);

    let gas_limit = match tx_args.offline {
        true => tx_args.gas_limit.unwrap(),
        false => {
            global!(client)
                .provider()
                .await?
                .estimate_gas(tx.clone())
                .await?
        }
    };
    debug!("gas_limit: {gas_limit}");

    rpc::send_tx(&tx.with_gas_limit(gas_limit), Arc::clone(&account), tx_args).await
}

pub async fn withdrawal(
    account: Arc<Account>,
    pubkey: &String,
    amount: f64,
    max_fee: u128,
    tx_args: &TxCommonArgs,
) -> Result<Option<TxHash>> {
    let parse_pubkey = |pubkey: &str| -> Result<blst::min_pk::PublicKey> {
        blst::min_pk::PublicKey::from_bytes(hex::decode(pubkey)?.as_slice())
            .map_err(|e| eyre!("{:#?}", e))
    };
    let pubkey =
        parse_pubkey(pubkey.as_str()).wrap_err_with(|| "source public key parsing failed")?;
    debug!(
        "Pubkey: {}",
        hex::encode(pubkey.to_bytes()).to_string().blue()
    );

    let fee: u128 = match tx_args.offline {
        true => max_fee,
        false => {
            // Query the consolidation contract for the fee
            let out = global!(client)
                .provider()
                .await?
                .call(
                    TransactionRequest::default()
                        .with_to(WITHDRAWAL_CONTRACR_ADDR.clone())
                        .with_input([]),
                )
                .await?;
            // Retrurned bytes are 32 in length (U256), we convert to u128 by using
            // the 16 rightmost bytes as the fee should never be as high to require
            // the full length U256, in fact, the returned fee is currently always 1
            let bytes: [u8; 16] = out[16..32].try_into()?;
            u128::from_be_bytes(bytes)
        }
    };

    if fee > max_fee {
        bail!(
            "Withdrawal fee ({}) > Max withdrawal fee ({})",
            fee,
            max_fee
        )
    }
    debug!(
        "Withdrawal contract fee (wei): {}",
        fee.to_string().magenta()
    );

    // amount arg is fractional eth, withdrawal contract
    // requires gwei encoded as 8 byte big-endian slice
    let amount_gwei = parse_ether(&amount.to_string())? / Unit::GWEI.wei();
    let amount_bytes: [u8; 8] = amount_gwei.to_be_bytes::<32>()[24..32].try_into()?;
    assert_eq!(
        amount_gwei,
        U256::from(u64::from_be_bytes(amount_bytes)),
        "gwei byte conversion mismatch"
    );
    let mut input: Vec<u8> = pubkey.to_bytes().into();
    input.extend(amount_bytes);
    let tx = rpc::gen_tx_request(
        account.address()?,
        WITHDRAWAL_CONTRACR_ADDR.clone(),
        tx_args,
    )
    .await?
    .with_value(U256::from(fee))
    .with_input(input);
    trace!("{:#?}", tx);

    let gas_limit = match tx_args.offline {
        true => tx_args.gas_limit.unwrap(),
        false => {
            global!(client)
                .provider()
                .await?
                .estimate_gas(tx.clone())
                .await?
        }
    };
    debug!("gas_limit: {gas_limit}");

    rpc::send_tx(&tx.with_gas_limit(gas_limit), Arc::clone(&account), tx_args).await
}

pub async fn deposit(
    account: Arc<Account>,
    pubkey: &String,
    amount: f64,
    tx_args: &TxCommonArgs,
) -> Result<Option<TxHash>> {
    // https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol
    alloy::sol! {
        #[sol(rpc)]
        #[derive(Debug, PartialEq)]
        interface IDepositContract {
            /// @notice Submit a Phase 0 DepositData object.
            /// @param pubkey A BLS12-381 public key.
            /// @param withdrawal_credentials Commitment to a public key for withdrawals.
            /// @param signature A BLS12-381 signature.
            /// @param deposit_data_root The SHA-256 hash of the SSZ-encoded DepositData object.
            /// Used as a protection against malformed input.
            function deposit(
                bytes calldata pubkey,
                bytes calldata withdrawal_credentials,
                bytes calldata signature,
                bytes32 deposit_data_root
            ) external payable;
        }
    }

    let deposit_contract = match global!(chain).deposit_contract {
        Address::ZERO => bail!("Unknown chain"),
        addr => addr,
    };

    // NOT USED
    // Deposit function signature
    // use alloy::primitives::keccak256;
    // let deposit_selector: [u8; 4] =
    //     keccak256("deposit(bytes,bytes,bytes,bytes32)".as_bytes())[0..4].try_into()?;

    let parse_pubkey = |pubkey: &str| -> Result<blst::min_pk::PublicKey> {
        blst::min_pk::PublicKey::from_bytes(hex::decode(pubkey)?.as_slice())
            .map_err(|e| eyre!("{:#?}", e))
    };
    let pubkey: [u8; 48] = parse_pubkey(pubkey.as_str())
        .wrap_err_with(|| "source public key parsing failed")?
        .to_bytes()[..]
        .try_into()?;
    debug!("Pubkey: {}", hex::encode(pubkey).to_string().blue());

    // Create our contract instqnce
    let provider = global!(client).provider().await?;
    let contract = IDepositContract::new(deposit_contract, provider.clone());

    // amount arg is fractional eth, withdrawal contract
    // requires gwei encoded as 8 byte big-endian slice
    let amount_wei = parse_ether(&amount.to_string())?;
    let amount_gwei = amount_wei / Unit::GWEI.wei();
    let amount_bytes: [u8; 8] = amount_gwei.to_be_bytes::<32>()[24..32].try_into()?;
    assert_eq!(
        amount_gwei,
        U256::from(u64::from_be_bytes(amount_bytes)),
        "gwei byte conversion mismatch"
    );
    // Withdrawal credentials and signature are ignored for topup requests
    let zeroed_credentials: [u8; 32] = [0u8; 32];
    let zeroed_signature: [u8; 96] = [0u8; 96];
    let deposit_data = DepositData {
        pubkey: pubkey.into(),
        withdrawal_credentials: zeroed_credentials.into(),
        amount: u64::from_be_bytes(amount_bytes),
        signature: zeroed_signature.into(),
    };
    use tree_hash::TreeHash; // import tree_hash_root() trait
    let input: Bytes = contract
        .deposit(
            deposit_data.pubkey.into(),
            deposit_data.withdrawal_credentials.into(),
            deposit_data.signature.into(),
            deposit_data.tree_hash_root().into(),
        )
        .into_transaction_request()
        .input
        .input()
        .unwrap()
        .clone();
    let tx = rpc::gen_tx_request(account.address()?, deposit_contract, tx_args)
        .await?
        .with_value(amount_wei)
        .with_input(input);
    trace!("{:#?}", tx);

    let gas_limit = match tx_args.offline {
        true => tx_args.gas_limit.unwrap(),
        false => global!(client)
            .provider()
            .await?
            .estimate_gas(tx.clone())
            .await
            .wrap_err_with(|| "estimate_gas failed")?,
    };
    debug!("gas_limit: {gas_limit}");

    rpc::send_tx(&tx.with_gas_limit(gas_limit), Arc::clone(&account), tx_args).await
}
