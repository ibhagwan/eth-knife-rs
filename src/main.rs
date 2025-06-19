#[macro_use]
extern crate log;

use clap::{CommandFactory, Parser};
use colored::*;
use eyre::{Result, WrapErr};
use std::sync::Arc;

use alloy::{
    eips::eip1559::BaseFeeParams,
    network::TransactionBuilder,
    primitives::{
        Address, hex,
        utils::{Unit, format_ether, format_units, parse_ether, parse_units},
    },
};

#[allow(unused_imports)]
use clap_repl::{
    ClapEditor, ReadCommandOutput,
    reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory, Reedline, Signal},
};

// not needed since we import lib::{global, ...}
//pub(crate) mod macros;

// Re-export lib crate's `globals` in the bin crate, this is needed
// in order to use the `global!` macros as they call `crate::globals`
pub(crate) use eth_knife::globals;

// lib.rs imports
use eth_knife::{
    account::{self, Account, AccountIdentifier},
    address_db::{self, AddressEntry},
    config::{self, *},
    // globals easy access macros
    global,
    global_set,
    helpers,
    logger::Logger,
    printf,
    rpc::{self, Client},
    tx_db::{self, TxEntry},
    validator,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Install a backtrace hook
    // stable_eyre::install()?;

    // Parse args with clap
    let args = Cli::parse();

    // Load config file & shellexpand datadir so we can use "~/...", etc
    let mut config = config::merge_args_from_file::<CliArgs>(args.config, args.config_path)?;
    config.datadir = Some(
        shellexpand::full(
            &config
                .datadir
                .unwrap()
                .into_os_string()
                .into_string()
                .unwrap(),
        )?
        .to_string()
        .into(),
    );

    // Setup our global logger
    let logger = Logger::new(config.log_level.unwrap_or(4u8));
    logger.set_global();

    // Store global ref to our logger and config
    global_set!(logger) = logger;
    global_set!(config) = config;

    // Load account list from keystore
    account::load_keystore(global!(config).datadir.clone().unwrap())?;

    // Load saved addresses
    let addrdb_file = global!(config).addr_db.clone().unwrap();
    address_db::load(global!(config).datadir.clone().unwrap().join(addrdb_file))?;

    // Load saved transactions
    let txdb_file = global!(config).tx_db.clone().unwrap();
    tx_db::load(global!(config).datadir.clone().unwrap().join(txdb_file))?;

    // Set the URL in the rpc client for network queeies
    // outside of REPL mode, e.g. `eth-knife ba <addr>`
    if let Some(rpc_url) = global!(config).rpc_url.clone() {
        global_set!(client) = Client::new(&rpc_url)?;
    }

    match args.command {
        CliCmd::Attach { rpc_url: _ } | CliCmd::Console { rpc_url: _ } => {
            // Console doesn't automatically connect
            // Attach attempts to connect to user requested node
            // Both start a REPL session
            if let CliCmd::Attach { rpc_url } = &args.command {
                if let Err(e) = cmd_dispatch(
                    &Cli::command(),
                    &CliCmd::Attach {
                        rpc_url: rpc_url.clone(),
                    },
                )
                .await
                {
                    error!("{:?}", e);
                }
            }

            // Now entering REPL mode
            global_set!(is_repl) = true;

            let mut rl = match global!(config).history {
                0 => ClapEditor::<ReplCmd>::builder(),
                _ => ClapEditor::<ReplCmd>::builder().with_editor_hook(|reed| {
                    reed.with_history(Box::new(
                        FileBackedHistory::with_file(
                            10000,
                            global!(config)
                                .datadir
                                .clone()
                                .unwrap()
                                .join("history")
                                .into(),
                        )
                        .unwrap(),
                    ))
                }),
            };

            if global!(config).vi_mode {
                rl = rl.with_edit_mode(helpers::reedline::edit_mode_vi());
            };

            let mut rl = rl.build();

            rl.repl_async_result(async move |command| -> Result<()> {
                if let Err(e) = repl_cmd_dispatch(&Cli::command(), &command).await {
                    println!("{}", format!("Error: {:?}", e).red());
                };
                Ok(())
            })
            .await;
            Ok(())
        }
        _ => cmd_dispatch(&Cli::command(), &args.command).await,
    }
}

async fn repl_cmd_dispatch(app: &clap::Command, cmd: &ReplCmd) -> Result<()> {
    macro_rules! log_set_level {
        ($x:expr) => {
            global!(config).log_level = Some($x);
            global!(logger).set_log_level($x);
            println!(
                "Logging level set to {}",
                global!(config).log_level.unwrap()
            );
        };
    }
    match cmd {
        ReplCmd::Detach {} => {
            // First reset with an emmpty client so we don't reuse due to url match
            global_set!(client) = Arc::new(Client::default());
            global_set!(client) = Client::new(&global!(config).rpc_url.clone().unwrap())?;
            globals::set_chain(&0_u64);
            Ok(())
        }
        ReplCmd::CliCmd(cmd) => cmd_dispatch(app, &cmd).await,
        ReplCmd::Config(subcmd) => {
            match subcmd {
                CmdConfig::Get {} => {
                    println!("{:#?}", global!(config));
                }
                CmdConfig::Set(cmd_set) => match cmd_set {
                    CmdConfigSet::Datadir { datadir } => {
                        global!(config).datadir = Some(datadir.clone());
                    }
                    CmdConfigSet::RpcUrl { rpc_url } => {
                        global!(config).rpc_url = Some(rpc_url.clone());
                    }
                    CmdConfigSet::LogLevel(log_set) => match log_set {
                        CmdLogSet::Critical {} => {
                            log_set_level!(0);
                        }
                        CmdLogSet::Error {} => {
                            log_set_level!(1);
                        }
                        CmdLogSet::Warning {} => {
                            log_set_level!(2);
                        }
                        CmdLogSet::Info {} => {
                            log_set_level!(3);
                        }
                        CmdLogSet::Debug {} => {
                            log_set_level!(4);
                        }
                        CmdLogSet::Trace {} => {
                            log_set_level!(5);
                        }
                    },
                },
            }
            Ok(())
        }
    }
}

async fn cmd_dispatch(app: &clap::Command, cmd: &CliCmd) -> Result<()> {
    match cmd {
        CliCmd::Version {} => {
            let mut ver = app.render_version();
            ver.pop(); // remove "\n"
            println!("version: {}", ver);
        }
        CliCmd::Network(subcmd) => match subcmd {
            CmdNetwork::Id {} => match global!(client).get_chain_id().await? {
                0 => printf!("Not connected"),
                id => printf!("Chain id: {}", id.to_string().blue()),
            },
            CmdNetwork::Balance { address } => {
                if let Some(addr) = unwrap_or_select_addr(address)? {
                    let balance = global!(client).balance(&addr).await?;
                    printf!(
                        "{} {}: {} {}",
                        "Balance of".white().bold(),
                        addr.to_string().normal().blue(),
                        format_ether(balance).yellow(),
                        "eth".white().bold(),
                    );
                }
            }
            CmdNetwork::Nonce { address } => {
                if let Some(addr) = unwrap_or_select_addr(address)? {
                    let nonce = global!(client).nonce(&addr).await?;
                    printf!(
                        "{} {}: {}",
                        "Nonce for".white().bold(),
                        addr.to_string().normal().blue(),
                        nonce.to_string().magenta().bold()
                    );
                }
            }
            CmdNetwork::NextBaseFee {} => {
                let latest_block = global!(client).block().await?;
                let next_block_base_fee = latest_block
                    .header
                    .next_block_base_fee(BaseFeeParams::ethereum())
                    .unwrap();
                debug!(
                    "Lastest block: {:#?} Next base fee: {}",
                    latest_block.header.number, next_block_base_fee,
                );
                let next_base_fee = helpers::block_next_base_fee(&latest_block);
                helpers::print_block_next_base_fee(&latest_block, &next_base_fee);
                // Compare our calc to alloy
                assert_eq!(
                    next_base_fee, next_block_base_fee,
                    "Next base fee calc mismatch!"
                );
            }
            CmdNetwork::EstimateFees {} => {
                rpc::estimate_fees().await?;
            }
        },
        CliCmd::Account(subcmd) => match subcmd {
            CmdAccount::List {} => {
                // Refresh account list from keystore
                // account::load_keystore(global!(config).datadir.clone().unwrap())?;
                account::print_accounts();
            }
            CmdAccount::Info { address } => {
                let account = Account::select(address)?;
                use chrono::{DateTime, Local, TimeZone, Utc};
                let dt = Utc.timestamp_opt(account.created as i64, 0).unwrap();
                let dt: DateTime<Local> = DateTime::from(dt.to_utc());
                println!("{}\n  created: {}", account.name(), dt.to_rfc2822());
            }
            CmdAccount::New { name, password } => {
                let name = unwrap_or_prompt_for_account_name(name)?;
                let password = helpers::reedline::unwrap_or_prompt_for_password(
                    password,
                    "Please provide an encryption password for your account's keystore file.\n\
                        DO NOT FORGET THIS PASSWORD as it will be the only way to unlock your \
                        account.\n",
                )?;
                let _ = Account::new_random(
                    name.as_str(),
                    password.as_str(),
                    global!(config).datadir.clone().unwrap().join("keystore"),
                )?;
            }
            CmdAccount::NewMnemonic { word_count } => {
                use alloy::signers::local::coins_bip39::{English, Mnemonic};
                // Workaround clap value_parser accepting only string values
                let word_count = word_count.parse::<u8>().unwrap();
                let mut rng = rand::thread_rng();
                let mnemonic =
                    Mnemonic::<English>::new_with_count(&mut rng, usize::from(word_count))?;
                printf!("{}", mnemonic.to_phrase().magenta());
            }
            CmdAccount::ImportPrivkey {
                keyfile,
                name,
                password,
            } => {
                let private_key = match keyfile {
                    None => Some(helpers::reedline::unwrap_or_prompt(
                        &None,
                        "Please enter your account's private key.\n",
                    )?),
                    _ => None,
                };
                let name = unwrap_or_prompt_for_account_name(name)?;
                let password = helpers::reedline::unwrap_or_prompt_for_password(
                    password,
                    "Please provide an encryption password for your account's keystore file.\n\
                        DO NOT FORGET THIS PASSWORD as it will be the only way to unlock your \
                        account.\n",
                )?;
                match keyfile {
                    Some(keyfile) => {
                        let _ = Account::from_keyfile(
                            keyfile,
                            name.as_str(),
                            password.as_str(),
                            global!(config).datadir.clone().unwrap().join("keystore"),
                        )?;
                    }
                    None => {
                        let _ = Account::from_private_key(
                            &private_key.unwrap(),
                            name.as_str(),
                            password.as_str(),
                            global!(config).datadir.clone().unwrap().join("keystore"),
                        )?;
                    }
                }
            }
            CmdAccount::ImportMnemonic {
                mnemonic_file,
                mnemonic_password,
                index,
                derivation_path,
                keystore_name,
                keystore_password,
                is_validator,
            } => {
                let mnemoic_phrase = match mnemonic_file {
                    None => Some(helpers::reedline::unwrap_or_prompt(
                        &None,
                        "Please enter your account's mnemonic.\n",
                    )?),
                    _ => None,
                };
                let keystore_name = unwrap_or_prompt_for_account_name(keystore_name)?;
                let keystore_password = helpers::reedline::unwrap_or_prompt_for_password(
                    keystore_password,
                    "Please provide an encryption password for your account's keystore file.\n\
                        DO NOT FORGET THIS PASSWORD as it will be the only way to unlock your \
                        account.\n",
                )?;
                let mnemonic_password = match mnemonic_password {
                    None => None,
                    Some(p) => Some(p.as_str()),
                };
                match mnemonic_file {
                    Some(mnemonic_file) => {
                        let _ = Account::from_mnemonic_file(
                            mnemonic_file,
                            mnemonic_password,
                            *index,
                            derivation_path,
                            *is_validator,
                            keystore_name.as_str(),
                            keystore_password.as_str(),
                            global!(config).datadir.clone().unwrap().join("keystore"),
                        )?;
                    }
                    None => {
                        let _ = Account::from_mnemonic(
                            &mnemoic_phrase.unwrap(),
                            mnemonic_password,
                            *index,
                            derivation_path,
                            *is_validator,
                            keystore_name.as_str(),
                            keystore_password.as_str(),
                            global!(config).datadir.clone().unwrap().join("keystore"),
                        )?;
                    }
                }
            }
            CmdAccount::SetName { address, name } => {
                Account::select(address)?
                    .set_name(unwrap_or_prompt_for_account_name(name)?.as_str())?;
            }
            CmdAccount::SetPassword {
                address,
                old_password,
                new_password,
            } => {
                let account = Account::select(address)?;
                account.try_unlock(old_password)?;
                let new_password = helpers::reedline::unwrap_or_prompt_for_password(
                    new_password,
                    format!(
                        "Please provide a new password for account {}. \
                           Do not forget this password.\n",
                        account.ident
                    )
                    .as_str(),
                )?;
                account.set_password(&new_password)?;
            }
            CmdAccount::PrivateKey { address, password } => {
                let account = Account::select(address)?;
                account.try_unlock(password)?;
                printf!(
                    "{} {}",
                    "privkey:".white().bold(),
                    hex::encode(&account.secret.lock().unwrap().clone())
                        .to_string()
                        .red()
                );
            }
            CmdAccount::PublicKey { address, password } => {
                let account = Account::select(address)?;
                account.try_unlock(password)?;
                match &account.ident {
                    AccountIdentifier::PublicKey { pubkey: _ } => {
                        printf!(
                            "{} {}",
                            "bls pubkey:".white().bold(),
                            hex::encode(account.bls_public_key()?.compress())
                                .to_string()
                                .blue()
                        );
                    }
                    _ => {
                        println!(
                            "{} {}",
                            "pubkey:".white().bold(),
                            hex::encode(account.public_key()?.to_sec1_bytes())
                                .to_string()
                                .blue()
                        );
                    }
                };
            }
            CmdAccount::Unlock { address, password } => {
                let _ = Account::select(address)?.try_unlock(password)?;
            }
            CmdAccount::Lock { address } => {
                let _ = Account::select(address)?.lock();
            }
            CmdAccount::Del { address } => {
                let account = Account::select(address)?;
                if helpers::reedline::confirm(
                    format!(
                        "{} {} {} {}{}\n",
                        "Please type".green(),
                        "YES".red().bold(),
                        "to confirm deleting account".green(),
                        account.ident.to_string().blue(),
                        ", CTRL-C to cacnel.".green()
                    )
                    .as_str(),
                    "YES",
                )? {
                    std::fs::remove_file(account.keypath.clone())?;
                    global!(accounts).remove_entry(&account.ident.to_string());
                }
            }
        },
        CliCmd::Address(subcmd) => match subcmd {
            CmdAddress::List {} => {
                // Refresh address list
                let dbfile = global!(config).addr_db.clone().unwrap();
                address_db::load(global!(config).datadir.clone().unwrap().join(dbfile))?;
                address_db::print(None)?;
            }
            CmdAddress::Add { address, name } => {
                AddressEntry::new(address, unwrap_or_prompt_for_addr_alias(name)?.as_str())?;
            }
            CmdAddress::SetName { address, name } => {
                let _ = AddressEntry::select(&address)?
                    .set_name(unwrap_or_prompt_for_addr_alias(name)?.as_str())?;
            }
            CmdAddress::Del { address } => {
                let entry = AddressEntry::select(address)?;
                address_db::del(entry.addr.to_string().as_str())?;
            }
        },
        CliCmd::Tx(subcmd) => match subcmd {
            CmdTx::List { chain_id } => {
                let chain_id = match chain_id {
                    Some(id) => match id {
                        0 => None,
                        _ => Some(id.clone()),
                    },
                    None => globals::chain_id(),
                };
                // Refresh tx list
                let dbfile = global!(config).tx_db.clone().unwrap();
                tx_db::load(global!(config).datadir.clone().unwrap().join(dbfile))?;
                tx_db::print(chain_id, None)?;
            }
            CmdTx::Del { tx_hash } => {
                let entry = TxEntry::select(tx_hash)?;
                tx_db::del(entry.tx_hash.to_string().as_str())?;
            }
            CmdTx::Replace { tx_hash: _ } => {
                // let _ = TxEntry::select(&tx_hash)?
                //     .set_name(unwrap_or_prompt_for_addr_alias(name)?.as_str())?;
            }
            CmdTx::Import { filepath, tx_args } => {
                let tx_envelope = tx_db::read_eip2718(filepath)?;
                let from = tx_envelope.clone().into_signed().recover_signer()?;
                let account = match global!(accounts).get(from.to_string().as_str()) {
                    Some(account) => match account.is_unlocked() {
                        true => Some(Arc::clone(&account)),
                        false => {
                            println!(
                                "{} {} {}",
                                "UNLOCK ACCOUNT".yellow().bold(),
                                account.ident.to_string().red().bold(),
                                "IF YOU WISH TO CHANGE THE FEES".yellow().bold()
                            );
                            None
                        }
                    },
                    _ => None,
                };
                let _tx_hash = rpc::send_tx_signed(tx_envelope, account, tx_args).await?;
            }
        },
        CliCmd::Convert(subcmd) => match subcmd {
            CmdConvert::EthToGwei { amount } => {
                let wei = parse_ether(&amount.to_string())?;
                printf!("{} eth is {} gwei", amount, wei / Unit::GWEI.wei());
                // printf!("{} eth is {} gwei", amount, format_units(wei, "gwei")?);
            }
            CmdConvert::EthToWei { amount } => {
                let wei = parse_ether(&amount.to_string())?;
                printf!("{} eth is {} wei", amount, wei);
            }
            CmdConvert::GweiToEth { amount } => {
                let gwei = parse_units(&amount.to_string(), "gwei")?;
                printf!("{} gwei is {} eth", amount, format_units(gwei, "ether")?);
            }
            CmdConvert::WeiToEth { amount } => {
                let wei = parse_units(&amount.to_string(), "wei")?;
                printf!("{} wei is {} eth", amount, format_units(wei, "ether")?);
            }
        },
        CliCmd::Transfer { command } => match command {
            CmdTransfer::Eth {
                amount,
                to,
                tx_args,
            } => {
                let account = Account::select(&tx_args.from)?;
                let from = account.address()?;
                account.try_unlock(&None)?;
                if let Some(to) = unwrap_or_select_addr(to)? {
                    let wei = parse_units(&amount.to_string(), "ether")?;
                    let tx = rpc::gen_tx_request(from, to, tx_args)
                        .await?
                        .with_value(wei.try_into()?);
                    let tx = match tx_args.gas_limit {
                        Some(_) => tx, // Already set by `rpc::gen_tx_request`
                        None => tx.with_gas_limit(21_000),
                    };
                    let _tx_hash = rpc::send_tx(&tx, Arc::clone(&account), tx_args).await?;
                }
            }
        },
        CliCmd::Validator { command } => match command {
            // CmdValidator::Help => {},
            CmdValidator::Compound {
                pubkey,
                max_consolidation_fee,
                tx_args,
            } => {
                let account = Account::select(&tx_args.from)?;
                account.try_unlock(&None)?;
                let _tx_hash = validator::comppound(
                    Arc::clone(&account),
                    pubkey,
                    *max_consolidation_fee,
                    tx_args,
                )
                .await?;
            }
            CmdValidator::Consolidate {
                source,
                target,
                max_consolidation_fee,
                tx_args,
            } => {
                let account = Account::select(&tx_args.from)?;
                account.try_unlock(&None)?;
                let _tx_hash = validator::consolidate(
                    Arc::clone(&account),
                    source,
                    target,
                    *max_consolidation_fee,
                    tx_args,
                )
                .await?;
            }
            CmdValidator::Withdrawal {
                pubkey,
                eth,
                max_withdrawal_fee,
                tx_args,
            } => {
                let account = Account::select(&tx_args.from)?;
                account.try_unlock(&None)?;
                let _tx_hash = validator::withdrawal(
                    Arc::clone(&account),
                    pubkey,
                    *eth,
                    *max_withdrawal_fee,
                    tx_args,
                )
                .await?;
            }
            CmdValidator::Deposit {
                pubkey,
                eth,
                tx_args,
            } => {
                let account = Account::select(&tx_args.from)?;
                account.try_unlock(&None)?;
                let _tx_hash =
                    validator::deposit(Arc::clone(&account), pubkey, *eth, tx_args).await?;
            }
        },
        CliCmd::Console { rpc_url: _ } => {
            println!("Already in console");
        }
        CliCmd::Attach { rpc_url } => {
            let rpc_url = match rpc_url {
                Some(rpc_url) => Some(rpc_url.clone()),
                None => global!(config).rpc_url.clone(),
            };

            if let Some(rpc_url) = rpc_url {
                global_set!(client) = Client::new(&rpc_url)?;
            }

            // Connect and verify chain ID is modified in our global object
            let chain_id: u64 = global!(client).get_chain_id().await?;
            assert_eq!(
                chain_id,
                *global!(client).chain_id.lock().unwrap(),
                "Chain ID mismatch"
            );

            println!(
                "Connected to {} {}:{} {}:{}",
                global!(chain).name.green().bold(),
                "chainId".white(),
                chain_id.to_string().blue(),
                "height".white(),
                global!(height).to_string().blue(),
            );
        }
    };
    Ok(())
}

fn build_prompt() -> DefaultPrompt {
    let client = global!(client);
    let chain_data = global!(chain);
    match *client.chain_id.lock().unwrap() {
        0 => DefaultPrompt {
            left_prompt: DefaultPromptSegment::Basic(
                "[DISCONNECTED]".white().bold().to_string().to_owned(),
            ),
            ..DefaultPrompt::default()
        },
        id => DefaultPrompt {
            left_prompt: DefaultPromptSegment::Basic(format!(
                "{} {}",
                format!(
                    "({})",
                    match chain_data.id {
                        0 => format!("chainId:{}", id),
                        _ => chain_data.name.to_owned(),
                    }
                )
                .white()
                .bold(),
                format!("{}", client.rpc_url.clone()).green(),
            )),
            ..DefaultPrompt::default()
        },
    }
}
#[allow(async_fn_in_trait)]
pub trait AsyncResult<C> {
    async fn repl_async_result(&mut self, handler: impl AsyncFnMut(C) -> Result<()>)
    where
        C: Parser + Send + Sync + 'static;
}

impl<C: Parser + Send + Sync + 'static> AsyncResult<C> for ClapEditor<C> {
    async fn repl_async_result(&mut self, mut handler: impl AsyncFnMut(C) -> Result<()>) {
        loop {
            self.set_prompt(Box::new(build_prompt()));
            match self.read_command() {
                ReadCommandOutput::Command(c) => {
                    if let Err(e) = handler(c).await {
                        println!("{:?}", e);
                    }
                }
                ReadCommandOutput::EmptyLine => (),
                ReadCommandOutput::ClapError(e) => {
                    e.print().unwrap();
                }
                ReadCommandOutput::ShlexError => {
                    println!(
                        "{} input was not valid and could not be processed",
                        ("Error:").red().bold()
                    );
                }
                ReadCommandOutput::ReedlineError(e) => {
                    panic!("{e}");
                }
                ReadCommandOutput::CtrlC => continue,
                ReadCommandOutput::CtrlD => break,
            }
        }
    }
}

fn unwrap_or_prompt_for_account_name(name: &Option<String>) -> Result<String> {
    helpers::reedline::unwrap_or_prompt(name, "Please provide an account name.\n")
}

fn unwrap_or_prompt_for_addr_alias(name: &Option<String>) -> Result<String> {
    helpers::reedline::unwrap_or_prompt(name, "Please provide an address alias.\n")
}

fn unwrap_or_select_addr(addr_or_index: &Option<String>) -> Result<Option<Address>> {
    let addr_or_index = match addr_or_index {
        Some(inner) => inner.clone(),
        None => {
            // Print addresses after accounts
            let idx_addr = global!(accounts).len();
            println!("[{}]", "ACCOUNTS".magenta().bold());
            account::print_accounts_short();
            println!("[{}]", "ADDRESSES".magenta().bold());
            address_db::print(Some(idx_addr))?;
            helpers::reedline::read_line("Select account or address.\n")?
        }
    };
    match addr_or_index.len() {
        0 => Ok(None),
        _ => match addr_or_index.parse::<usize>() {
            Ok(index) => {
                let idx_addr = global!(accounts).len();
                match index > idx_addr {
                    false => {
                        let account = Account::select(&Some(index.to_string()))?;
                        match account.ident {
                            AccountIdentifier::PublicKey { pubkey: _ } => {
                                println!("Unavailable for BLS pubkeys.");
                                Ok(None)
                            }
                            AccountIdentifier::Address { address } => Ok(Some(address.clone())),
                        }
                    }
                    true => {
                        let entry = AddressEntry::select(&Some((index - idx_addr).to_string()))?;
                        Ok(Some(entry.addr))
                    }
                }
            }
            Err(_) => Ok(Some(
                addr_or_index
                    .parse::<Address>()
                    .wrap_err_with(|| "address parsing failed")?,
            )),
        },
    }
}
