use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::{fs::File, io::BufReader};

use eyre::{Result, WrapErr, bail};
use serde_derive::Deserialize;

use clap_serde_derive::{
    ClapSerde,
    clap::{self, Parser, Subcommand},
};

#[allow(deprecated)]
fn datadir() -> PathBuf {
    std::env::home_dir().unwrap().join(".eth-knife")
}

#[allow(deprecated)]
fn config_file() -> PathBuf {
    PathBuf::from(OsString::from(std::env::var("XDG_CONFIG_HOME").unwrap()))
        .join("eth-knife")
        .join("config.toml")
}

#[derive(Parser)]
#[command(author, version, about)]
// TODO: alias for help
//#[clap(mut_subcommand("help", |cmd| cmd.visible_alias("?")))]
pub struct Cli {
    /// Config file
    #[arg(short, long = "config", default_value = config_file().into_os_string())]
    pub config_path: Option<PathBuf>,

    /// Global arguments
    #[command(flatten)]
    pub config: <CliArgs as ClapSerde>::Opt,

    // Subcommands
    #[command(subcommand)]
    pub command: CliCmd,
}

// Make sure all values are optional or parsing fails if a value
// is missing in the config fill
#[derive(Debug, Clone, ClapSerde, Deserialize)]
pub struct CliArgs {
    /// Logging level
    #[arg(short, long = "log-level", required = false, default_value = "3")]
    pub log_level: Option<u8>,

    /// Enable vi edit mode
    #[arg(long = "vi", required = false, action = clap::ArgAction::SetTrue)]
    pub vi_mode: bool,

    /// Command hisrory length, 0 to disable history
    #[arg(long, required = false, default_value = "10000")]
    pub history: usize,

    /// Data directory
    #[arg(long = "datadir", default_value = datadir().into_os_string())]
    pub datadir: Option<PathBuf>,

    /// Address alias DB
    #[arg(long = "addr-db", default_value = "addr_db.json")]
    pub addr_db: Option<PathBuf>,

    /// Transction DB
    #[arg(long = "tx-db", default_value = "tx_db.json")]
    pub tx_db: Option<PathBuf>,

    /// JsonRPC URL
    #[arg(long = "rpc-url", required = false)]
    pub rpc_url: Option<String>,
}

fn is_repl() -> bool {
    *crate::global!(is_repl)
}

// Command line cmds
#[derive(Subcommand)]
pub enum CliCmd {
    /// Print version information
    #[clap(visible_alias = "ver")]
    Version {},
    /// Start an interactive REPL
    #[clap(hide = is_repl())]
    Console {
        // Argument is hiden and ignored, only used
        // so we can match both attach and console
        #[arg(hide(true), required = false)]
        rpc_url: Option<String>,
    },
    /// Attach to a node and start an interactive REPL
    #[clap(visible_alias = "at")]
    Attach {
        #[arg(required = false)]
        rpc_url: Option<String>,
    },
    /// Query the ethereum network
    #[clap(visible_alias = "net")]
    #[command(subcommand)]
    Network(CmdNetwork),
    /// Convert eth <-> gwei <-> wei
    #[clap(visible_alias = "conv")]
    #[command(subcommand)]
    Convert(CmdConvert),
    /// Manage accounts
    #[command(subcommand)]
    #[clap(visible_alias = "ac")]
    Account(CmdAccount),
    /// Manage addresses
    #[command(subcommand)]
    #[clap(visible_alias = "ad")]
    Address(CmdAddress),
    /// Manage transactions
    #[command(subcommand)]
    Tx(CmdTx),
    /// Transfer Eth or ERC20 tokens
    #[clap(visible_aliases = &["tr"])]
    Transfer {
        #[command(subcommand)]
        command: CmdTransfer,
    },
    // #[clap(visible_aliases = &["v"], disable_help_flag(true))]
    #[clap(visible_aliases = &["v"])]
    Validator {
        #[command(subcommand)]
        command: CmdValidator,
        // Print help
        // #[clap(short, long, visible_aliases = &["h"], action = clap::ArgAction::HelpLong)]
        // help: Option<bool>,
    },
}

#[derive(Parser)]
pub enum ReplCmd {
    // Subcommands
    #[command(flatten)]
    CliCmd(CliCmd),
    /// Disconnect from REST endpoint
    #[clap(visible_aliases = &["dt"])]
    Detach {},
    /// Global config
    #[command(subcommand)]
    #[clap(visible_aliases = &["c", "cfg"])]
    Config(CmdConfig),
}

#[derive(Subcommand)]
pub enum CmdConfig {
    /// Get config
    #[clap(visible_alias = "g")]
    Get {},
    /// Set config
    #[command(subcommand)]
    #[clap(visible_alias = "s")]
    Set(CmdConfigSet),
}

#[derive(Subcommand)]
pub enum CmdConfigSet {
    /// App logging level
    #[command(subcommand)]
    #[clap(visible_alias = "l")]
    LogLevel(CmdLogSet),
    /// App data directory
    #[clap(visible_alias = "d")]
    Datadir {
        #[arg(required = true)]
        datadir: PathBuf,
    },
    /// JsonRPC URL
    #[clap(visible_alias = "u")]
    RpcUrl {
        #[arg(required = true)]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
// #[clap(flatten_help(true))]
pub enum CmdLogSet {
    #[clap(visible_alias = "c", disable_help_flag(true))]
    Critical {},
    #[clap(visible_alias = "e", disable_help_flag(true))]
    Error {},
    #[clap(visible_alias = "w", disable_help_flag(true))]
    Warning {},
    #[clap(visible_alias = "i", disable_help_flag(true))]
    Info {},
    #[clap(visible_alias = "d", disable_help_flag(true))]
    Debug {},
    #[clap(visible_alias = "t", disable_help_flag(true))]
    Trace {},
}
#[derive(Subcommand)]
pub enum CmdNetwork {
    /// Print connected network/Chain ID
    Id {},
    /// Print balance for address
    #[clap(visible_alias = "ba")]
    Balance {
        #[arg(required = false)]
        address: Option<String>,
    },
    /// Print nonce for address
    #[clap(visible_alias = "no")]
    Nonce {
        #[arg(required = false)]
        address: Option<String>,
    },
    /// Next block base fee
    #[clap(visible_alias = "nbf")]
    NextBaseFee {},
    /// Estimate EIP1559 fees
    #[clap(visible_alias = "ef")]
    EstimateFees {},
}

#[derive(Subcommand)]
pub enum CmdConvert {
    /// Eth to Gwei
    #[clap(visible_aliases = &["eg", "e2g"])]
    EthToGwei {
        #[arg(required = true)]
        amount: f64,
    },
    /// Eth to Wei
    #[clap(visible_aliases = &["ew", "e2w"])]
    EthToWei {
        #[arg(required = true)]
        amount: f64,
    },
    /// Gwei to Eth
    #[clap(visible_aliases = &["ge", "g2e"])]
    GweiToEth {
        #[arg(required = true)]
        amount: f64,
    },
    /// Wei to Eth
    #[clap(visible_aliases = &["we", "w2e"])]
    WeiToEth {
        #[arg(required = true)]
        amount: f64,
    },
}

#[derive(Subcommand)]
pub enum CmdAccount {
    /// List existing accounts
    #[clap(visible_alias = "l")]
    List {},
    /// Display account info
    #[clap(visible_alias = "i")]
    Info {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
    },
    /// Create a new account (private key)
    #[clap(visible_alias = "n")]
    New {
        /// Account name
        #[arg(short, long, required = false)]
        name: Option<String>,
        /// Keystore encryption password
        #[arg(short, long, required = false, visible_aliases = &["pass"])]
        password: Option<String>,
    },
    /// Import a private key into a new account
    #[clap(visible_alias = "ik")]
    ImportPrivkey {
        /// File containing the account private key
        #[arg(short, long, required = false, visible_alias = "key")]
        keyfile: Option<PathBuf>,
        /// Account name
        #[arg(long, short, required = false)]
        name: Option<String>,
        /// Keystore encryption password
        #[arg(short, long, required = false, visible_aliases = &["pass"])]
        password: Option<String>,
    },
    /// Generate a new random mnemonic
    #[clap(visible_aliases = &["nm"])]
    NewMnemonic {
        /// Mnemonic word count
        #[arg(
            short,
            long,
            required = false,
            default_value = "24",
            value_parser = vec!["12", "15", "18", "21", "24"]
        )]
        word_count: String,
    },
    /// Import a HD key from mnemonic into a new account
    #[clap(visible_alias = "im")]
    ImportMnemonic {
        /// File containing the mnemonic phrase
        #[arg(long, visible_alias = "mf", required = false)]
        mnemonic_file: Option<PathBuf>,
        /// Mnemonic password
        #[arg(long, visible_alias = "mp", required = false)]
        mnemonic_password: Option<String>,
        /// HD key derivation path index
        #[arg(long, visible_alias = "i", required = false, default_value_t = 0)]
        index: u32,
        /// HD derivation path
        #[arg(
            long,
            visible_alias = "dp",
            required = false,
            default_value = "m/44'/60'/0'/0/{}"
        )]
        derivation_path: String,
        /// Account name
        #[arg(long, visible_alias = "kn", required = false)]
        keystore_name: Option<String>,
        /// Keystore encryption password
        #[arg(long, visible_alias = "kp", required = false)]
        keystore_password: Option<String>,
        /// Generate a BLS12-391 validator keystore at path "m/12381/3600/{}/0/0"
        #[arg(long = "validator", visible_alias ="v", required = false, action = clap::ArgAction::SetTrue)]
        is_validator: bool,
    },
    /// Update name for an existing account
    #[clap(visible_alias = "name")]
    SetName {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
        /// Account name
        #[arg(short, long, required = false)]
        name: Option<String>,
    },
    #[clap(visible_alias = "pass")]
    /// Update password for an existing account
    SetPassword {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
        /// Old keystore encryption password
        #[arg(short, long, required = false, visible_alias = "old")]
        old_password: Option<String>,
        /// New keystore encryption password
        #[arg(short, long, required = false, visible_alias = "new")]
        new_password: Option<String>,
    },
    /// Display account private key
    #[clap(visible_aliases = &["key", "priv"])]
    PrivateKey {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
        /// Keystore encryption password
        #[arg(short, long, required = false, visible_alias = "pass")]
        password: Option<String>,
    },
    /// Display account public key
    #[clap(visible_alias = "pub")]
    PublicKey {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
        /// Keystore encryption password
        #[arg(short, long, required = false, visible_alias = "pass")]
        password: Option<String>,
    },
    #[clap(visible_alias = "u")]
    /// Unlock account
    Unlock {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
        /// Keystore encryption password
        #[arg(short, long, required = false, visible_alias = "pass")]
        password: Option<String>,
    },
    #[clap(visible_aliases = &["lo"])]
    /// Lock account
    Lock {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
    },
    /// Delete an account
    #[clap(visible_alias = "d")]
    Del {
        /// Account address
        #[arg(required = false)]
        address: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum CmdAddress {
    /// List addresses
    #[clap(visible_alias = "l")]
    List {},
    /// Add or update address alias
    #[clap(visible_alias = "a")]
    Add {
        /// Address
        #[arg(required = true)]
        address: String,
        /// Name
        #[arg(required = false)]
        name: Option<String>,
    },
    /// Delete an address alias
    #[clap(visible_alias = "d")]
    Del {
        /// Address
        #[arg(required = false)]
        address: Option<String>,
    },
    /// Update name for an existing address
    #[clap(visible_alias = "name")]
    SetName {
        /// Address
        #[arg(required = false)]
        address: Option<String>,
        /// Name
        #[arg(required = false)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum CmdTx {
    /// List transactions
    #[clap(visible_alias = "l")]
    List {
        /// Chain id (0: all)
        chain_id: Option<u64>,
    },
    /// Delete an address alias
    #[clap(visible_alias = "d")]
    Del {
        /// Trasnaction
        #[arg(required = false)]
        tx_hash: Option<String>,
    },
    /// Replace or speed up a transaction
    #[clap(visible_alias = "r")]
    Replace {
        /// Trasnaction hash
        #[arg(required = false)]
        tx_hash: Option<String>,
    },
    /// Import transaction from raw data
    #[clap(visible_alias = "i")]
    Import {
        /// Filepath
        #[arg(required = true)]
        filepath: String,
        /// tx common args
        #[command(flatten)]
        tx_args: TxCommonArgs,
    },
}

#[derive(Subcommand)]
pub enum CmdTransfer {
    /// Transfer Eth
    #[clap(visible_alias = "e")]
    Eth {
        /// Eth amount
        #[arg(short, long, visible_aliases = &["e", "eth"], required = true)]
        amount: f64,
        /// To address
        #[arg(short, long = "to", required = false)]
        to: Option<String>,
        /// tx common args
        #[command(flatten)]
        tx_args: TxCommonArgs,
    },
}

#[derive(Subcommand)]
// #[clap(disable_help_subcommand(true))]
pub enum CmdValidator {
    /// Print this message or the help of the given subcommand(s)
    // #[clap(visible_aliases = &["h"])]
    // Help,
    /// Generate EIP-7251 validator compounding request
    #[clap(visible_aliases = &["comp", "cmp"])]
    Compound {
        /// Validator public key
        #[arg(short, long = "pubkey", required = true)]
        pubkey: String,
        /// Max consolidation fee
        #[arg(long, required = false, default_value_t = 10)]
        max_consolidation_fee: u128,
        /// tx common args
        #[command(flatten)]
        tx_args: TxCommonArgs,
    },
    /// Generate EIP-7251 validator consolidation request
    #[clap(visible_aliases = &["cons", "cns"])]
    Consolidate {
        /// Source validator public key
        #[arg(short, long = "source", required = true)]
        source: String,
        /// Source validator public key
        #[arg(short, long = "target", required = true)]
        target: String,
        /// Max consolidation fee
        #[arg(long, required = false, default_value_t = 10)]
        max_consolidation_fee: u128,
        /// tx common args
        #[command(flatten)]
        tx_args: TxCommonArgs,
    },
    /// Generate EIP-7002 validator withdrawal request
    #[clap(visible_aliases = &["w"])]
    Withdrawal {
        /// Validator public key
        #[arg(short, long = "pubkey", required = true)]
        pubkey: String,
        /// Eth amount to withdraw
        #[arg(short, long = "eth", visible_aliases = &["a", "amount"], required = true)]
        eth: f64,
        /// Max withdrawal fee
        #[arg(long, required = false, default_value_t = 10)]
        max_withdrawal_fee: u128,
        /// tx common args
        #[command(flatten)]
        tx_args: TxCommonArgs,
    },
    /// Generate validator deposit contract topup request
    #[clap(visible_aliases = &["d", "topup"])]
    Deposit {
        /// Validator public key
        #[arg(short, long = "pubkey", required = true)]
        pubkey: String,
        /// Eth amount to deposit
        #[arg(short, long = "eth", visible_aliases = &["a", "amount"], required = true)]
        eth: f64,
        /// tx common args
        #[command(flatten)]
        tx_args: TxCommonArgs,
    },
}

#[derive(Parser)]
#[clap(
    // Fees are "all-or-none", if one is present the other must be as well
    group(clap::ArgGroup::new("fee_args")
        .required(false)
        .multiple(true)
        .requires_all(&["max_fee", "max_priority"])
        .args(&["max_fee", "max_priority"])
    ),
    // --offline requires all network tx params and and output filename
    group(clap::ArgGroup::new("offline_args")
        .required(false)
        .multiple(true)
        .requires_all(&["offline", "out", "chain_id", "nonce", "max_fee", "max_priority", "gas_limit"])
        .args(&["offline"])
    )
)]
pub struct TxCommonArgs {
    /// From account
    #[arg(short, long, required = false)]
    pub from: Option<String>,
    /// Skip user confirmation ("yes" prompt)
    #[arg(short, long, required = false, action = clap::ArgAction::SetTrue)]
    pub yes: bool,
    /// Wait for network confirmation
    #[arg(short, long, required = false, action = clap::ArgAction::SetTrue)]
    pub wait: bool,
    /// Generate offline tx data
    #[arg(long, required = false, action = clap::ArgAction::SetTrue)]
    pub offline: bool,
    /// Output tx data to file
    #[arg(short, long, value_name = "FILEPATH", required = false)]
    pub out: Option<String>,
    /// Chain Id
    #[arg(long, required = false)]
    pub chain_id: Option<u64>,
    /// Nonce
    #[arg(long, required = false)]
    pub nonce: Option<u64>,
    /// Max priority fee per gas in gwei
    #[arg(long, required = false)]
    pub max_priority: Option<f64>,
    /// Max fee per gas in gwei
    #[arg(long, required = false)]
    pub max_fee: Option<f64>,
    /// TX gas limit
    #[arg(long, required = false)]
    pub gas_limit: Option<u64>,
}

pub fn merge_args_from_file<T>(
    args: <T as ClapSerde>::Opt,
    maybe_path: Option<PathBuf>,
) -> Result<T>
where
    T: ClapSerde + serde::de::DeserializeOwned,
{
    match maybe_path {
        Some(path) => {
            let config_path = std::path::Path::new(&path);
            match config_path.exists() {
                true => {
                    let config = match config_path.extension().and_then(OsStr::to_str) {
                        Some("toml") => read_toml_config::<T, _>(config_path),
                        Some("json") => read_json_config::<T, _>(config_path),
                        Some("jsonc") => read_jsonc_config::<T, _>(config_path),
                        _ => {
                            bail!("Unsupported config file type: {:?}", path);
                        }
                    }?;
                    // Fields which are not None in `other` will be cleared and used to update `self`.
                    // Fields which are None in `other` will not be modified in `self`.
                    // Uncomment if we want clap to overwrite the config file
                    //T::from(config).merge(args)
                    Ok(T::from(args).merge(config))
                }
                false => Ok(T::from(args)),
            }
        }
        None => Ok(T::from(args)),
    }
}

fn read_toml_config<T, P: AsRef<std::path::Path>>(path: P) -> Result<<T as ClapSerde>::Opt>
where
    P: AsRef<std::path::Path> + std::fmt::Debug + Copy,
    T: ClapSerde + serde::de::DeserializeOwned,
{
    let content = std::fs::read_to_string(path).wrap_err_with(|| format!("{:?}", path))?;
    Ok(toml::from_str(&content)?)
}

fn read_json_config<T: ClapSerde, P: AsRef<std::path::Path>>(
    path: P,
) -> Result<<T as ClapSerde>::Opt>
where
    P: AsRef<std::path::Path> + std::fmt::Debug + Copy,
{
    let f = File::open(path).wrap_err_with(|| format!("{:?}", path))?;
    let json_cfg = serde_json::from_reader::<_, <T as ClapSerde>::Opt>(BufReader::new(f))?;
    Ok(json_cfg)
    //Ok(T::from(json_cfg))
}

fn read_jsonc_config<T: ClapSerde, P: AsRef<std::path::Path>>(
    path: P,
) -> Result<<T as ClapSerde>::Opt>
where
    P: AsRef<std::path::Path> + std::fmt::Debug + Copy,
{
    let f = File::open(path).wrap_err_with(|| format!("{:?}", path))?;
    let jsonc_cfg = serde_jsonc::from_reader::<_, <T as ClapSerde>::Opt>(BufReader::new(f))?;
    Ok(jsonc_cfg)
    //Ok(T::from(jsonc_cfg))
}
