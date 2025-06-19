use alloy::{
    consensus::{Signed, TxEnvelope, TypedTransaction},
    eips::{
        BlockNumberOrTag,
        eip1559::{BaseFeeParams, Eip1559Estimation},
        eip2718::Decodable2718,
    },
    network::{Ethereum, TransactionBuilder},
    primitives::{
        Address, BlockNumber, Bytes, TxHash, U256,
        utils::{format_ether, format_units, parse_units},
    },
    providers::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder},
    rpc::types::{Block, TransactionRequest},
};
use colored::*;
use eyre::{Result, WrapErr, bail, eyre};
use log::*;
use std::sync::{Arc, Mutex};

use crate::{
    account::Account,
    config::TxCommonArgs,
    format_eth, global, global_set, globals, helpers,
    tx_db::{self, TxEntry},
};

pub struct Client {
    pub rpc_url: String,
    pub chain_id: Mutex<u64>,
    pub provider: Mutex<Option<DynProvider>>,
}

// So we can set the initial value in globals to `Client::default()`
impl Default for Client {
    fn default() -> Self {
        Self {
            rpc_url: String::default(),
            chain_id: Mutex::new(0),
            provider: Mutex::new(None),
        }
    }
}

impl Client {
    pub fn new(url: &String) -> Result<Arc<Client>> {
        if url.trim().is_empty() {
            bail!("must specify a valid --http-url")
        };

        if global!(client).rpc_url == url.to_string() {
            return Ok(Arc::clone(&global!(client)));
        };

        // https://github.com/alloy-rs/examples/blob/main/examples/providers/examples/http_with_auth.rs
        // Create the HTTP transport.
        // let rpc_url = url
        //     .parse()
        //     // RUST_OPTION_RESULT_CONVERSIONS.md
        //     // https://gist.github.com/novafacing/6e087e5a62301a5b5c5a3fbd95263356
        //     .map_err(|e| eyre!(URL parse failed: {}", e))?;
        // let http = Http::new(rpc_url);
        // let rpc_client = RpcClient::new(http, false);

        let client = Arc::new(Client {
            rpc_url: url.to_string(),
            chain_id: Mutex::new(0),
            provider: Mutex::new(None),
        });

        // Store a global copy of our client
        global_set!(client) = Arc::clone(&client);

        Ok(client)
    }

    pub fn is_connected(&self) -> bool {
        self.provider.lock().unwrap().is_some() && *self.chain_id.lock().unwrap() != 0
    }

    pub async fn connect(&self) -> Result<&Self> {
        match self.is_connected() {
            true => Ok(self),
            false => self._connect().await,
        }
    }

    pub async fn provider(&self) -> Result<DynProvider> {
        if !self.is_connected() {
            self._connect().await?;
        }
        Ok(DynProvider::clone(
            self.provider.lock().unwrap().as_ref().unwrap(),
        ))
    }

    async fn _connect(&self) -> Result<&Self> {
        // Create a provider with the HTTP transport.
        let mut prov = self.provider.lock().unwrap();
        *prov = Some(DynProvider::new(
            ProviderBuilder::new()
                .connect(self.rpc_url.as_str())
                .await
                .wrap_err_with(|| format!("Connect failed to '{}'", self.rpc_url))?,
        ));

        let provider = DynProvider::clone(&prov.as_ref().unwrap());

        // Get chain ID and height
        let chain_id = provider.get_chain_id().await?;
        let height = provider.get_block_number().await?;

        // We use a mutex member to prevent having to set this function
        // as mut and forcing the borrowers to use `let mut`, this also
        // enables us to store the struct inside std::Arc as it doesn't
        // allow deref as mut
        let mut id = self.chain_id.lock().unwrap();
        *id = chain_id;

        // Init global chain data
        globals::set_chain(&chain_id);
        global_set!(height) = height;

        debug!(
            "Connected to {} {}:{} {}:{}",
            format!("{}", global!(chain).name).green().bold(),
            "chainId".white().bold(),
            format!("{:?}", chain_id).blue(),
            "height".white().bold(),
            format!("{:?}", height).blue(),
        );
        Ok(self)
    }

    pub fn chain_id(&self) -> u64 {
        *self.chain_id.lock().unwrap()
    }

    pub async fn get_chain_id(&self) -> Result<u64> {
        Ok(self.provider().await?.get_chain_id().await?)
    }

    pub async fn block_number(&self) -> Result<BlockNumber> {
        Ok(self.provider().await?.get_block_number().await?)
    }

    pub async fn block(&self) -> Result<Block> {
        Ok(self
            .provider()
            .await?
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .unwrap())
    }

    pub async fn estimate_fees(&self) -> Result<Eip1559Estimation> {
        Ok(self.provider().await?.estimate_eip1559_fees().await?)
    }

    pub async fn balance(&self, addr: &Address) -> Result<U256> {
        Ok(self.provider().await?.get_balance(*addr).await?)
    }

    pub async fn nonce(&self, addr: &Address) -> Result<u64> {
        Ok(self.provider().await?.get_transaction_count(*addr).await?)
    }

    pub async fn send_tx_envelope(
        &self,
        tx: TxEnvelope,
    ) -> Result<PendingTransactionBuilder<Ethereum>> {
        Ok(self.provider().await?.send_tx_envelope(tx).await?)
    }

    pub async fn send_tx_signed(
        &self,
        tx_signed: Signed<TypedTransaction>,
    ) -> Result<PendingTransactionBuilder<Ethereum>> {
        let mut buf: Vec<u8> = Vec::new();
        tx_signed.eip2718_encode(&mut buf);
        let tx = TxEnvelope::decode_2718(&mut buf.as_ref())?;
        Ok(self.provider().await?.send_tx_envelope(tx).await?)
    }
}

pub async fn gen_tx_request(
    from: Address,
    to: Address,
    tx_args: &TxCommonArgs,
) -> Result<TransactionRequest> {
    let chain_id = match tx_args.chain_id {
        Some(chain_id) => chain_id,
        None => global!(client).chain_id(),
    };
    let nonce = match tx_args.nonce {
        Some(nonce) => nonce,
        None => global!(client).nonce(&from).await?,
    };
    let estimation = match tx_args.max_priority.is_some() {
        true => Eip1559Estimation {
            max_fee_per_gas: parse_units(&tx_args.max_fee.unwrap().to_string(), "gwei")?
                .try_into()?,
            max_priority_fee_per_gas: parse_units(
                &tx_args.max_priority.unwrap().to_string(),
                "gwei",
            )?
            .try_into()?,
        },
        false => global!(client).estimate_fees().await?,
    };

    let tx = TransactionRequest::default()
        .with_from(from)
        .with_to(to)
        .with_nonce(nonce)
        .with_chain_id(chain_id)
        .with_max_priority_fee_per_gas(estimation.max_priority_fee_per_gas)
        .with_max_fee_per_gas(estimation.max_fee_per_gas);

    let tx = match tx_args.gas_limit {
        Some(gas_limit) => tx.with_gas_limit(gas_limit),
        None => tx,
    };

    Ok(tx)
}

pub async fn estimate_fees() -> Result<(Eip1559Estimation, u64)> {
    let latest_block = global!(client).block().await?;
    let base_fee = latest_block.header.base_fee_per_gas.unwrap();
    let next_block_base_fee = latest_block
        .header
        .next_block_base_fee(BaseFeeParams::ethereum())
        .unwrap();
    let estimation = global!(client).estimate_fees().await?;
    let next_base_plus_priority = estimation.max_priority_fee_per_gas + next_block_base_fee as u128;
    let align = 26;
    let mut pretty_fee = String::default();
    pretty_fee.push_str(
        format!(
            "    {:align$}{}\n",
            "block_number:".white().bold(),
            latest_block.header.number.to_string().red().bold(),
        )
        .as_str(),
    );
    pretty_fee.push_str(format_eth!(
        align,
        "max_priority_fee",
        white,
        estimation.max_priority_fee_per_gas,
        blue
    ));
    pretty_fee.push_str(format_eth!(
        align,
        "max_fee_per_gas",
        white,
        estimation.max_fee_per_gas,
        blue
    ));
    pretty_fee.push_str(format_eth!(align, "base_fee", white, base_fee, blue));
    pretty_fee.push_str(format_eth!(
        align,
        "next_base_fee",
        white,
        next_block_base_fee,
        blue
    ));
    pretty_fee.push_str(format_eth!(
        align,
        "next_base+priority",
        white,
        next_base_plus_priority,
        magenta
    ));
    print!("{pretty_fee}");
    Ok((estimation, next_block_base_fee))
}

// Loop querying network for fees and prompt the user for selection
pub async fn prompt_for_fees(account: Arc<Account>, tx: &TransactionRequest) -> Result<TxEnvelope> {
    loop {
        let gas_limit = tx.gas.unwrap();
        let (estimation, next_block_base_fee) = estimate_fees().await?;
        let diff = estimation.max_priority_fee_per_gas * 25 / 100;
        let estimation_low = Eip1559Estimation {
            max_fee_per_gas: estimation.max_fee_per_gas - diff,
            max_priority_fee_per_gas: estimation.max_priority_fee_per_gas - diff,
        };
        let estimation_high = Eip1559Estimation {
            max_fee_per_gas: estimation.max_fee_per_gas + diff,
            max_priority_fee_per_gas: estimation.max_priority_fee_per_gas + diff,
        };
        let mut prompt = String::default();
        let align = 26;
        prompt.push_str(
            format!(
                "    {:align$}{}\n",
                "gas_limit:".white().bold(),
                gas_limit.to_string().magenta(),
            )
            .as_str(),
        );
        prompt.push_str(
            format!("\t\t{:-^40}\n", "")
                .white()
                .bold()
                .to_string()
                .as_str(),
        );
        prompt.push_str(format_eth!(
            align,
            "LOW",
            green,
            gas_limit * (estimation_low.max_priority_fee_per_gas as u64 + next_block_base_fee),
            green
        ));
        prompt.push_str(format_eth!(
            align,
            "MID",
            yellow,
            gas_limit * (estimation.max_priority_fee_per_gas as u64 + next_block_base_fee),
            yellow
        ));
        prompt.push_str(format_eth!(
            align,
            "HIGH",
            red,
            gas_limit * (estimation_high.max_priority_fee_per_gas as u64 + next_block_base_fee),
            red
        ));
        prompt.push_str(
            format!(
                "{} {}{}{}{}{}{}{} {}\n",
                "Please type".green(),
                "[L]ow".green().bold(),
                ", ".white().bold(),
                "[M]ed".yellow().bold(),
                ", ".white().bold(),
                "[H]igh".red().bold(),
                " or ".white().bold(),
                "[C]ustom".red().bold(),
                "to confirm, ENTER for next block, CTRL-C to cacnel.".green(),
            )
            .as_str(),
        );
        let estimation = match helpers::reedline::read_line(&prompt)?.as_str() {
            "m" | "M" => estimation,
            "l" | "L" => estimation_low,
            "h" | "H" => estimation_high,
            "c" | "C" => {
                macro_rules! read_gwei {
                    ($x:expr) => {
                        match helpers::reedline::read::<f64>($x) {
                            Ok(gwei) => {
                                let wei: U256 = parse_units(&gwei.to_string(), "gwei")?.into();
                                wei.to::<u128>()
                            }
                            Err(e) => {
                                // error!("{}", e);
                                println!("{}", e.to_string().red());
                                continue;
                            }
                        }
                    };
                }
                let max_priority =
                    read_gwei!("Please enter max priority fee per gas (miner tip) in gwei.\n");
                let max_fee =
                    read_gwei!("Please enter max fee per gas (base + priority) in gwei.\n");
                match max_fee > max_priority {
                    true => Eip1559Estimation {
                        max_fee_per_gas: max_fee,
                        max_priority_fee_per_gas: max_priority,
                    },
                    _ => {
                        println!(
                            "{}",
                            format!(
                                "Max fee ({}) must be greater than priority fee ({})",
                                max_fee, max_priority
                            )
                            .red()
                        );
                        continue;
                    }
                }
            }
            _ => {
                continue;
            }
        };
        let new_tx = tx
            .clone()
            .max_fee_per_gas(estimation.max_fee_per_gas)
            .max_priority_fee_per_gas(estimation.max_priority_fee_per_gas);
        return account.sign_tx_and_decode(&new_tx).await;
    }
}

pub async fn send_tx(
    tx: &TransactionRequest,
    account: Arc<Account>,
    tx_args: &TxCommonArgs,
) -> Result<Option<TxHash>> {
    // Prompt for fees and sign the tx, do not send account
    // to `send_tx_signed` as we already prompted for fees
    let tx_envelope = match tx_args.max_priority.is_some() {
        true => account.sign_tx_and_decode(&tx).await?,
        false => prompt_for_fees(account, tx).await?,
    };
    send_tx_signed(tx_envelope, None, tx_args).await
}

pub async fn send_tx_signed(
    tx_envelope: TxEnvelope,
    account: Option<Arc<Account>>,
    tx_args: &TxCommonArgs,
) -> Result<Option<TxHash>> {
    // TxEnvelope doesn't contain the from address
    let from = tx_envelope.clone().into_signed().recover_signer()?;

    // (1) No account was supplied (imported tx with none/locked account)
    // we cannot change the gas fees as this will require resigning the tx
    // (2) Account supplied, prompt the user for current network fees
    // and resign the transaction, this generates a new envelope (new tx hash)
    let tx_envelope = match account.is_none() || tx_args.offline {
        true => Ok(tx_envelope),
        false => {
            // Extract the request details from the envelope
            let tx = TransactionRequest::from(tx_envelope.clone().into(), from);
            prompt_for_fees(account.unwrap(), &tx).await
        }
    }?;

    let simulate_tx = async |tx: &TransactionRequest| -> Result<Bytes> {
        global!(client)
            .provider()
            .await?
            .call(tx.clone())
            .await
            .map_err(|e| eyre!("tx simulation failed: {:#?}", e))
    };

    // Refresh tx data as may have changed after the fee selection
    let tx = TransactionRequest::from(tx_envelope.clone().into(), from);

    // Bail early if simulation fails
    if !tx_args.offline {
        simulate_tx(&tx).await?;
    }

    if tx_args.out.is_some() {
        // Write hex encoded signed tx data to file and return
        let filepath = tx_args.out.clone().unwrap();
        tx_db::write_eip2718(&tx_envelope, &filepath)?;
        tx_db::print_tx(&tx);
        println!(
            "\n{} {} {}{}{}",
            "Transaction".white(),
            tx_envelope.hash().to_string().red(),
            "succesfully written to \"".white(),
            filepath.green(),
            "\".".white(),
        );
        return Ok(None);
    }

    if !tx_args.yes {
        loop {
            if helpers::reedline::confirm(
                format!(
                    "\n{}\n{} {} {}\n",
                    tx_db::sprintf_tx(&tx, None),
                    "Please type".green(),
                    "YES".red().bold(),
                    "to confirm sending the transaction, CTRL-C to cacnel.".green()
                )
                .as_str(),
                "YES",
            )? {
                break;
            }
        }
    }

    // After confirmation store in the tx db
    let tx_entry = TxEntry::new(tx_envelope.hash(), &tx)?;
    tx_db::print_entry(&tx_entry, None)?;

    // Isolate global client mutex lock
    let send_tx = async |tx_envelope| -> Result<PendingTransactionBuilder<Ethereum>> {
        Ok(global!(client)
            .send_tx_envelope(tx_envelope)
            .await?
            // NOTE: This is the builder config for the later `register()`
            // it doesn't make the following await wait for the confirmation
            .with_required_confirmations(1)
            .with_timeout(Some(std::time::Duration::from_secs(60))))
    };

    match send_tx(tx_envelope.clone()).await?.register().await {
        Ok(pending_tx) => {
            println!(
                "Transaction {} succesfully sent.",
                tx_envelope.hash().to_string().red()
            );
            match tx_args.wait {
                true => {
                    println!("Waiting for transaction confirmation...");
                    let tx_hash = pending_tx.await?;
                    println!("Transaction {} confirmed.", tx_hash.to_string().red());
                    Ok(Some(tx_hash))
                }
                false => Ok(None),
            }
        }
        _ => Ok(None),
    }
}
