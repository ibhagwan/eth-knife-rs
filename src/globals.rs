use alloy::primitives::Address;
use log::*;
use once_cell::sync::Lazy;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use crate::{
    account::Account,
    config::CliArgs,
    logger::Logger,
    macros::{global, global_set, parse_address},
    rpc::Client,
};

pub struct GlobalData {
    pub is_repl: Mutex<bool>,
    pub logger: Mutex<Logger>,
    pub config: Mutex<CliArgs>,
    pub client: Mutex<Arc<Client>>,
    pub chain: Mutex<&'static ChainData>,
    pub height: Mutex<u64>,
    pub base_fee: Mutex<u64>,
    pub next_base_fee: Mutex<u64>,
    pub tx_db: Mutex<jfs::Store>,
    pub addr_db: Mutex<jfs::Store>,
    pub accounts: Mutex<BTreeMap<String, Arc<Account>>>,
}

#[derive(Debug, Clone)]
pub struct ChainData {
    pub id: u64,
    pub name: &'static str,
    pub deposit_contract: Address,
    pub weth_address: Address,
}

pub static G: Lazy<GlobalData> = Lazy::new(|| GlobalData {
    is_repl: Mutex::new(false),
    logger: Mutex::new(Logger::default()),
    config: Mutex::new(CliArgs::default()),
    client: Mutex::new(Arc::new(Client::default())),
    chain: Mutex::new(&CHAIN_UNKNOWN),
    height: Mutex::new(0),
    base_fee: Mutex::new(0),
    next_base_fee: Mutex::new(0),
    tx_db: Mutex::new(jfs::Store::new("").unwrap()),
    addr_db: Mutex::new(jfs::Store::new("").unwrap()),
    accounts: Mutex::new(BTreeMap::new()),
});

pub fn set_chain(chain_id: &u64) {
    global_set!(chain) = match CHAINDATA.get(&chain_id) {
        Some(cd) => cd,
        None => &CHAIN_UNKNOWN,
    };
    trace!("{:#?}", global!(chain));
}

pub fn chain_id() -> Option<u64> {
    match *global!(client).chain_id.lock().unwrap() {
        0 => None,
        id => Some(id),
    }
}

pub static CHAINDATA: Lazy<HashMap<u64, ChainData>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(1, CHAIN_ETH_MAINNET.clone());
    m.insert(17000, CHAIN_ETH_HOLESKY.clone());
    m.insert(560048, CHAIN_ETH_HOODI.clone());
    m
});

static CHAIN_UNKNOWN: Lazy<ChainData> = Lazy::new(|| {
    let c = ChainData {
        id: 0,
        name: "unknown",
        deposit_contract: Address::ZERO,
        weth_address: Address::ZERO,
    };
    c
});

static CHAIN_ETH_MAINNET: Lazy<ChainData> = Lazy::new(|| {
    let c = ChainData {
        id: 1,
        name: "mainnet",
        deposit_contract: parse_address!("0x00000000219ab540356cBB839Cbe05303d7705Fa"),
        weth_address: parse_address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
    };
    c
});
static CHAIN_ETH_HOLESKY: Lazy<ChainData> = Lazy::new(|| {
    let c = ChainData {
        id: 17000,
        name: "holesky",
        deposit_contract: parse_address!("0x4242424242424242424242424242424242424242"),
        weth_address: parse_address!("0x94373a4919B3240D86eA41593D5eBa789FEF3848"),
    };
    c
});

static CHAIN_ETH_HOODI: Lazy<ChainData> = Lazy::new(|| {
    let c = ChainData {
        id: 560048,
        name: "hoodi",
        deposit_contract: parse_address!("0x00000000219ab540356cBB839Cbe05303d7705Fa"),
        weth_address: parse_address!("0x94373a4919B3240D86eA41593D5eBa789FEF3848"),
    };
    c
});
