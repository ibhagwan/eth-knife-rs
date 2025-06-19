use colored::*;
use eyre::{Result, eyre};
use serde_derive::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

use crate::helpers::datetime::Timezone;

#[allow(unused_imports)]
use alloy::{
    consensus::TxEnvelope,
    eips::eip2718::Decodable2718,
    network::TransactionBuilder,
    primitives::{
        TxHash, TxKind, hex,
        utils::{format_ether, format_units},
    },
    rpc::types::TransactionRequest,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct TxEntry {
    pub timestamp: u64,
    pub chain_id: u64,
    pub tx: TransactionRequest,
    pub tx_hash: TxHash,
}

impl Clone for TxEntry {
    fn clone(&self) -> Self {
        TxEntry {
            timestamp: self.timestamp,
            chain_id: self.chain_id,
            tx: self.tx.clone(),
            tx_hash: self.tx_hash.clone(),
        }
    }
}

use crate::{globals, helpers, macros::global};

pub fn load(dbfile: PathBuf) -> Result<()> {
    let dir = dbfile.parent().unwrap();
    if !dir.exists() {
        return Ok(());
    }

    let mut cfg = jfs::Config::default();
    cfg.single = true;
    cfg.pretty = true;
    *global!(tx_db) = jfs::Store::new_with_cfg(&dbfile, cfg)?;
    Ok(())
}

pub fn sprintf_tx(tx: &TransactionRequest, align: Option<usize>) -> String {
    let mut pretty_tx = String::default();
    let align = match align {
        Some(n) => n,
        _ => 16,
    };
    let to = match tx.to.unwrap() {
        TxKind::Create => "CREATE".to_string(),
        TxKind::Call(address) => address.to_string(),
    };
    macro_rules! push_field {
        ($s:expr, $v: expr, $c: ident) => {
            pretty_tx.push_str(
                format!(
                    "\n    {:align$}{}",
                    format!("{}:", $s).white().bold(),
                    format!("{}", $v).$c(),
                )
                .as_str(),
            );
        };
    }
    push_field!("chain_id", tx.chain_id.unwrap(), green);
    push_field!("nonce", tx.nonce.unwrap(), magenta);
    push_field!("from", tx.from.unwrap(), blue);
    push_field!("to", to, blue);
    push_field!(
        "value",
        format!("{} eth", format_units(tx.value.unwrap(), "ether").unwrap()),
        yellow
    );
    if tx.input.input.is_some() && !tx.input.input.as_ref().unwrap().is_empty() {
        push_field!(
            "data",
            format!("{}", hex::encode(tx.input.input.as_ref().unwrap())),
            white
        );
    }
    if tx.gas.is_some() {
        push_field!("gas_limit", tx.gas.unwrap(), green);
    }
    push_field!(
        "fees",
        format!(
            "{} {} {} {} {}",
            "Priority".magenta(),
            format!(
                "{} gwei",
                format_units(tx.max_priority_fee_per_gas.unwrap(), "gwei").unwrap(),
            )
            .blue(),
            "|".white().bold(),
            "Max".magenta(),
            format!(
                "{} gwei",
                format_units(tx.max_fee_per_gas.unwrap(), "gwei").unwrap(),
            )
            .blue()
        ),
        normal
    );
    pretty_tx
}

pub fn print_tx(tx: &TransactionRequest) {
    let align = 16;
    println!("{}", sprintf_tx(tx, Some(align)));
}

pub fn print_entry(entry: &TxEntry, idx: Option<usize>) -> Result<()> {
    let align = 16;
    let mut pretty_tx = match idx {
        Some(idx) => String::from(format!(
            "{:<3} {}",
            format!("{}.", idx).green().bold(),
            format!("{}", &entry.tx_hash.to_string()).red(),
        )),
        _ => String::from(format!(
            "    {:align$}{}",
            "tx_hash:".white().bold(),
            format!("{}", &entry.tx_hash.to_string()).red(),
        )),
    };
    pretty_tx.push_str(
        format!(
            "\n    {:align$}{}",
            "timestamp:".white().bold(),
            OffsetDateTime::from_unix_timestamp(i64::try_from(entry.timestamp)?)
                .unwrap()
                .to_localtime()
                .to_formatted_string()
                .white()
        )
        .as_str(),
    );
    pretty_tx.push_str(sprintf_tx(&entry.tx, Some(align)).as_str());
    // pretty_tx.push_str(format!("\n{:#?}", entry.tx).as_str());
    println!("{pretty_tx}");
    Ok(())
}

pub fn print(chain_id: Option<u64>, start_idx: Option<usize>) -> Result<()> {
    let mut i = start_idx.unwrap_or(0);
    let all = &global!(tx_db).all::<TxEntry>()?;
    let mut sorted: Vec<&TxEntry> = all.into_iter().map(|(_hash, entry)| entry).collect();
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    sorted.iter().for_each(|entry| {
        if chain_id.is_some() && chain_id.unwrap() != entry.chain_id {
            return;
        }
        i = i + 1;
        let _ = print_entry(&entry, Some(i));
    });
    Ok(())
}

pub fn del(tx_hash: &str) -> Result<()> {
    let entry = global!(tx_db).get::<TxEntry>(tx_hash.to_string().as_str());
    match entry {
        Ok(_) => {
            global!(tx_db).delete(tx_hash.to_string().as_str())?;
            println!(
                "transaction {} tx_hash delted successfully.",
                tx_hash.to_string()
            );
            Ok(())
        }
        _ => Err(eyre!("transaction {} does not exist in the DB.", tx_hash)),
    }
}

pub fn write_eip2718(tx: &TxEnvelope, filepath: &String) -> Result<()> {
    let filepath = shellexpand::full(filepath)?.to_string();
    let mut data: Vec<u8> = Vec::new();
    tx.clone().into_signed().eip2718_encode(&mut data);
    let mut file = std::fs::OpenOptions::new()
        // .create_new(true)
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open(filepath)?;
    file.write_all(hex::encode(&data).as_str().as_bytes())?;
    Ok(())
}

pub fn read_eip2718(filepath: &String) -> Result<TxEnvelope> {
    let filepath = shellexpand::full(filepath)?.to_string();
    let mut file = std::fs::OpenOptions::new().read(true).open(filepath)?;
    let mut hexdata = String::new();
    file.read_to_string(&mut hexdata)?;
    let buf = hex::decode(hexdata)?;
    let tx = TxEnvelope::decode_2718(&mut buf.as_ref())?;
    Ok(tx)
}

impl TxEntry {
    pub fn new(tx_hash: &TxHash, tx: &TransactionRequest) -> Result<Arc<TxEntry>> {
        let entry = Arc::new(TxEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            chain_id: tx.chain_id().expect("tx without chain_id"),
            tx: tx.clone(),
            tx_hash: tx_hash.clone(),
        });

        if global!(tx_db)
            .get::<TxEntry>(tx_hash.to_string().as_str())
            .is_ok()
        {
            println!(
                "transaction {} already exists in the DB, updated tx data.",
                tx_hash.to_string()
            );
        }

        // Store in the db and get UUID
        global!(tx_db).save_with_id(&*entry, entry.tx_hash.to_string().as_str())?;

        Ok(Arc::clone(&entry))
    }

    pub fn select(tx_or_index: &Option<String>) -> Result<Arc<TxEntry>> {
        let tx_or_index = match tx_or_index {
            Some(inner) => inner.clone(),
            None => {
                print(globals::chain_id(), None)?;
                helpers::reedline::read_line("Select transaction.\n")?
            }
        };
        match tx_or_index.parse::<usize>() {
            Ok(idx) => {
                let chain_id = *global!(client).chain_id.lock().unwrap();
                let all = global!(tx_db).all::<TxEntry>().unwrap();
                let mut sorted: Vec<&TxEntry> = (&all)
                    .into_iter()
                    .map(|(_hash, entry)| entry)
                    .filter(|entry| match chain_id {
                        0 => true,
                        id => entry.chain_id == id,
                    })
                    .collect();
                sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
                match idx > 0 && sorted.len() >= idx {
                    true => Ok(Arc::new(sorted[idx - 1].clone())),
                    _ => Err(eyre!("Invalid index.")),
                }
            }
            _ => match global!(tx_db).get::<TxEntry>(tx_or_index.as_str()) {
                Ok(entry) => Ok(Arc::new(entry)),
                _ => Err(eyre!("Invalid tx hash or index.")),
            },
        }
    }
}
