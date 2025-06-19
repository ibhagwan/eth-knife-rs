use alloy::primitives::Address;
use colored::*;
use eyre::{Result, eyre};
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct AddressEntry {
    pub created: u64,
    pub addr: Address,
    pub name: Mutex<String>,
}

impl Clone for AddressEntry {
    fn clone(&self) -> Self {
        AddressEntry {
            created: self.created,
            addr: self.addr.clone(),
            name: Mutex::new(self.name.lock().unwrap().to_string()),
        }
    }
}

use crate::{helpers, macros::global};

pub fn load(dbfile: PathBuf) -> Result<()> {
    let dir = dbfile.parent().unwrap();
    if !dir.exists() {
        return Ok(());
    }

    //let dbfile = datadir.join("addr_db.json");
    let mut cfg = jfs::Config::default();
    cfg.single = true;
    cfg.pretty = true;
    *global!(addr_db) = jfs::Store::new_with_cfg(&dbfile, cfg)?;
    Ok(())
}

pub fn print(start_idx: Option<usize>) -> Result<()> {
    let mut i = start_idx.unwrap_or(0);
    let all = &global!(addr_db).all::<AddressEntry>()?;
    let mut sorted: Vec<&AddressEntry> = all.into_iter().map(|(_addr, entry)| entry).collect();
    sorted.sort_by(|a, b| a.created.cmp(&b.created));
    sorted.iter().for_each(|entry| {
        let name = entry.name.lock().unwrap();
        i = i + 1;
        println!(
            "{:<3} {:<14} {}",
            format!("{}.", i).green().bold(),
            format!(
                "{}",
                match name.len() {
                    0 => "<unnamed>",
                    _ => name.as_str(),
                }
            )
            .white()
            .bold(),
            format!("{}", &entry.addr.to_string()).blue(),
        );
    });
    Ok(())
}

pub fn del(addr: &str) -> Result<()> {
    let entry = global!(addr_db).get::<AddressEntry>(addr);
    match entry {
        Ok(_) => {
            global!(addr_db).delete(addr)?;
            Ok(())
        }
        _ => Err(eyre!("address {} does not exist in the DB.", addr)),
    }
}

impl AddressEntry {
    pub fn new(addr: &str, name: &str) -> Result<Arc<AddressEntry>> {
        let entry = Arc::new(AddressEntry {
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            addr: addr.parse::<Address>()?,
            name: Mutex::new(name.to_string()),
        });

        if global!(addr_db).get::<AddressEntry>(addr).is_ok() {
            println!("address {} already exists in the DB, updated name.", addr);
        }

        // Store in the db and get UUID
        global!(addr_db).save_with_id(&*entry, entry.addr.to_string().as_str())?;

        Ok(Arc::clone(&entry))
    }

    pub fn select(addr_or_index: &Option<String>) -> Result<Arc<AddressEntry>> {
        let addr_or_index = match addr_or_index {
            Some(inner) => inner.clone(),
            None => {
                print(None)?;
                helpers::reedline::read_line("Select address.\n")?
            }
        };
        match addr_or_index.parse::<usize>() {
            Ok(idx) => {
                let all = global!(addr_db).all::<AddressEntry>().unwrap();
                let mut sorted: Vec<&AddressEntry> =
                    (&all).into_iter().map(|(_addr, entry)| entry).collect();
                sorted.sort_by(|a, b| a.created.cmp(&b.created));
                match idx > 0 && sorted.len() >= idx {
                    true => Ok(Arc::new(sorted[idx - 1].clone())),
                    _ => Err(eyre!("Invalid index.")),
                }
            }
            _ => match global!(addr_db).get::<AddressEntry>(addr_or_index.as_str()) {
                Ok(entry) => Ok(Arc::new(entry)),
                _ => Err(eyre!("Invalid address or index.")),
            },
        }
    }

    // Workaround to deadlock in `:set_name` due to `save_with_id`
    // this way the mutex lock is confined within the function
    fn _set_name(&self, new_name: &str) {
        let mut name = self.name.lock().unwrap();
        *name = new_name.to_string();
    }

    pub fn set_name(&self, new_name: &str) -> Result<()> {
        self._set_name(new_name);
        global!(addr_db).save_with_id(self, self.addr.to_string().as_str())?;
        Ok(())
    }
}
