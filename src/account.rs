use colored::*;
use eyre::{Result, bail, eyre};
use log::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    consensus::{SignableTransaction, Signed, TxEnvelope, TypedTransaction},
    eips::eip2718::Decodable2718,
    network::TransactionBuilder,
    network::TxSigner,
    primitives::{Address, hex},
    rpc::types::TransactionRequest,
    signers::{
        k256::ecdsa::{SigningKey, VerifyingKey},
        local::{
            LocalSigner, MnemonicBuilder, PrivateKeySigner,
            coins_bip39::{English, Mnemonic},
        },
    },
};

use crate::{helpers, macros::global, macros::printf};

#[derive(Debug, Clone)]
pub enum AccountIdentifier {
    Address { address: Address }, // ECDSA/secp256k1 signing key address
    PublicKey { pubkey: String }, // Validator, BLS12-138 public key
}

impl std::fmt::Display for AccountIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AccountIdentifier::Address { address } => write!(f, "{}", address.to_string()),
            AccountIdentifier::PublicKey { pubkey } => write!(f, "{}", pubkey),
        }
    }
}

#[derive(Debug)]
pub struct Account {
    pub created: u64,
    pub uuid: String,
    pub name: Mutex<String>,
    pub ident: AccountIdentifier,
    pub secret: Mutex<Vec<u8>>,
    pub keypath: PathBuf,
}

impl Account {
    pub fn new(
        created: Option<u64>,
        uuid: &str,
        name: &str,
        ident: &AccountIdentifier,
        secret: &[u8],
        keypath: PathBuf,
    ) -> Arc<Account> {
        let account = Arc::new(Account {
            created: created.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }),
            uuid: uuid.to_string(),
            name: Mutex::new(name.to_string()),
            ident: ident.clone(),
            secret: Mutex::new(Vec::from(secret)),
            keypath: keypath.clone(),
        });

        // Check for existing accounts for same address
        let existing = Account::get(ident);
        if existing.is_some() && existing.clone().unwrap().keypath != account.keypath {
            warn!(
                "Duplicate Keystore for {}, ignoring.\nOld: {}\nNew: {}",
                ident.to_string(),
                existing.unwrap().keypath.display(),
                account.keypath.display()
            );
        } else {
            // New account or updated account from :set_password
            global!(accounts).insert(ident.to_string(), Arc::clone(&account));
        }
        account
    }

    pub fn get(ident: &AccountIdentifier) -> Option<Arc<Account>> {
        match global!(accounts).get(ident.to_string().as_str()) {
            Some(account) => Some(Arc::clone(&account)),
            None => None,
        }
    }

    pub fn from_secret(
        secret: &[u8],
        name: &str,
        ident: &AccountIdentifier,
        password: &str,
        dir: PathBuf,
        filename: Option<&str>,
    ) -> Result<Arc<Self>> {
        // Ensure keystore directory is accessible
        std::fs::create_dir_all(&dir)?;

        // We use our own fork of eth-keystore for "geth-compat" which adds an address field
        // to the json as well as v4 / BLS12-138 keystore support
        let mut rng = rand::thread_rng();
        let uuid = match ident {
            AccountIdentifier::PublicKey { pubkey: _ } => {
                eth_keystore::v4::encrypt_key(dir.clone(), &mut rng, &secret, password, filename)?
            }
            _ => eth_keystore::v3::encrypt_key(dir.clone(), &mut rng, &secret, password, filename)?,
        };

        let keypath = match filename {
            Some(filename) => dir.join(filename),
            _ => dir.join(uuid.clone()),
        };

        // Do we have an existing account for this address already?
        let existing = Account::get(ident);
        let updating = match existing.clone() {
            None => false,
            Some(existing) => existing.keypath == keypath,
        };

        let account = Account::new(None, uuid.as_str(), name, ident, secret, keypath.clone());

        // Add [created, name] to keystore json
        helpers::json::update(
            &keypath,
            vec![(
                "created",
                match updating {
                    true => existing.clone().unwrap().created,
                    false => account.created,
                },
            )],
        )?;

        match ident {
            AccountIdentifier::PublicKey { pubkey: _ } => {
                helpers::json::update(&keypath, vec![("name", name)])?;
            }
            AccountIdentifier::Address { address } => {
                // NOTE: eth-store "geth-compat" which stores the address lowercase
                // to actually be compat we need to save the checksum address (mix case)
                helpers::json::update(
                    &keypath,
                    vec![("name", name), ("address", address.to_string().as_str())],
                )?;
            }
        };

        printf!(
            "{} {}: {}",
            "Account".white().bold(),
            match updating {
                true => "updated",
                false => "created",
            }
            .white()
            .bold(),
            ident.to_string().blue(),
        );
        printf!(
            "{}: {}\n",
            "Keystore".white().bold(),
            keypath.display().to_string().green(),
        );

        Ok(account)
    }

    pub fn new_random(name: &str, password: &str, dir: PathBuf) -> Result<Arc<Account>> {
        // Build from random signer
        Account::from_signer(
            MnemonicBuilder::<English>::default().build_random()?,
            name,
            password,
            dir,
        )
    }

    pub fn new_mnemonic(
        word_count: &u8,
        name: &str,
        password: &str,
        dir: PathBuf,
    ) -> Result<Arc<Account>> {
        let mut rng = rand::thread_rng();

        // Child key at derivation path: m/44'/60'/0'/0/{index}.
        let phrase = Mnemonic::<English>::new_with_count(&mut rng, usize::from(*word_count))?;
        let mnemonic = MnemonicBuilder::<English>::default().phrase(phrase.to_phrase());
        let signer: PrivateKeySigner = mnemonic.index(0u32).unwrap().build().unwrap();

        println!("Mnemonic: {}", phrase.to_phrase());

        Account::from_signer(signer, name, password, dir)
    }

    pub fn select(addr_or_index: &Option<String>) -> Result<Arc<Account>> {
        let addr_or_index = match addr_or_index {
            Some(inner) => inner.clone(),
            None => {
                print_accounts();
                helpers::reedline::read_line("Select account.\n")?
            }
        };
        match addr_or_index.parse::<usize>() {
            Ok(idx) => {
                let mut sorted: Vec<Arc<Account>> = global!(accounts)
                    .iter()
                    .map(|(_addr, account)| Arc::clone(&account))
                    .collect();
                sorted.sort_by(|a, b| a.created.cmp(&b.created));
                match idx > 0 && sorted.len() >= idx {
                    true => Ok(Arc::clone(&sorted[idx - 1])),
                    _ => Err(eyre!("Invalid index.")),
                }
            }
            _ => match global!(accounts).get(addr_or_index.as_str()) {
                Some(account) => Ok(Arc::clone(&account)),
                _ => Err(eyre!("Invalid account address or index.")),
            },
        }
    }

    pub fn try_unlock(&self, password: &Option<String>) -> Result<&Self> {
        if self.is_unlocked() {
            return Ok(self);
        }
        let mut password = password.clone();
        for i in 0..3 {
            password = match password {
                Some(password) => Some(password),
                None => Some(helpers::reedline::read_password(
                    format!(
                        "Please provide the CURRENT password for account {} | \
                                Attempt {}/3.\n",
                        self.ident,
                        i + 1
                    )
                    .as_str(),
                )?),
            };
            match password {
                Some(pw) => match self.unlock(&pw) {
                    Ok(_) => {
                        return Ok(self);
                    }
                    Err(_) => {
                        println!("{}", "Invalid password".red());
                        password = None;
                    }
                },
                None => bail!("Cancelled"),
            }
        }
        Err(eyre!("Max tries exceeded"))
    }

    pub fn address(&self) -> Result<Address> {
        match &self.ident {
            AccountIdentifier::PublicKey { pubkey: _ } => Err(eyre!("Wrong keystore type!")),
            AccountIdentifier::Address { address } => Ok(address.clone()),
        }
    }

    pub fn signer(&self) -> Result<LocalSigner<SigningKey>> {
        match &self.ident {
            AccountIdentifier::PublicKey { pubkey: _ } => Err(eyre!("Wrong keystore type!")),
            AccountIdentifier::Address { address: _ } => {
                let is_unlocked = self.is_unlocked();
                match is_unlocked {
                    false => Err(eyre!("account {} is locked", self.name.lock().unwrap())),
                    true => Ok(LocalSigner::<SigningKey>::from_slice(
                        &self.secret.lock().unwrap(),
                    )?),
                }
            }
        }
    }

    pub async fn sign_transaction(
        &self,
        tx: &TransactionRequest,
    ) -> Result<Signed<TypedTransaction>> {
        let signer = self.signer()?;
        let mut tx_signable = tx.clone().build_unsigned()?;
        let signature = signer.sign_transaction(&mut tx_signable).await?;
        let tx_signed = tx_signable.into_signed(signature);
        Ok(tx_signed)
    }

    pub async fn sign_tx_and_decode(&self, tx: &TransactionRequest) -> Result<TxEnvelope> {
        let tx_signed = self.sign_transaction(tx).await?;
        let mut buf: Vec<u8> = Vec::new();
        tx_signed.eip2718_encode(&mut buf);
        let tx = TxEnvelope::decode_2718(&mut buf.as_ref())?;
        Ok(tx)
    }

    pub fn public_key(&self) -> Result<alloy::signers::k256::PublicKey> {
        let signing_key = SigningKey::from(self.signer()?.into_credential());
        let verifying_key = VerifyingKey::from(&signing_key);
        Ok(alloy::signers::k256::PublicKey::from_sec1_bytes(
            &verifying_key.to_sec1_bytes(),
        )?)
    }

    pub fn bls_public_key(&self) -> Result<blst::min_pk::PublicKey> {
        match &self.ident {
            AccountIdentifier::Address { address: _ } => Err(eyre!("Wrong keystore type!")),
            AccountIdentifier::PublicKey { pubkey: _ } => {
                let bls_sk =
                    blst::min_pk::SecretKey::from_bytes(&self.secret.lock().unwrap()).unwrap();
                Ok(bls_sk.sk_to_pk())
            }
        }
    }

    pub fn unlock(&self, password: &str) -> Result<&Self> {
        let key = eth_keystore::decrypt_key(&self.keypath, &password.to_string())?;
        // debug!("secret: {}", hex::encode(&key));
        let mut secret = self.secret.lock().unwrap();
        *secret = key;
        match &self.ident {
            AccountIdentifier::PublicKey { pubkey } => {
                let bls_sk = blst::min_pk::SecretKey::from_bytes(&secret).unwrap();
                let bls_pk = bls_sk.sk_to_pk().compress();
                debug!("unlocked pubkey: {}", hex::encode(bls_pk));
                assert_eq!(pubkey, hex::encode(bls_pk).as_str(), "Pubkey mismatch!");
            }
            AccountIdentifier::Address { address } => {
                let signer = LocalSigner::<SigningKey>::from_slice(&secret)?;
                debug!("unlocked address: {}", signer.address().to_string());
                assert_eq!(
                    address.to_string(),
                    signer.address().to_string(),
                    "Addeess mismatch!"
                );
            }
        };
        Ok(self)
    }

    pub fn lock(&self) {
        let mut secret = self.secret.lock().unwrap();
        *secret = Vec::<u8>::new()
    }

    pub fn is_unlocked(&self) -> bool {
        self.secret.lock().unwrap().len() > 0
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        let name = self.name.lock().unwrap();
        let secret = self.secret.lock().unwrap();
        let _ = Account::from_secret(
            &secret,
            name.as_str(),
            &self.ident,
            password,
            self.keypath.parent().unwrap().to_path_buf(),
            self.keypath.file_name().unwrap().to_str(),
        )?;
        print!("Password updated for account {} ({}).\n", name, self.ident);
        Ok(())
    }

    pub fn name(&self) -> String {
        self.name.lock().unwrap().to_string()
    }

    pub fn set_name(&self, new_name: &str) -> Result<()> {
        let mut name = self.name.lock().unwrap();
        *name = new_name.to_string();
        helpers::json::update(&self.keypath, vec![("name", new_name)])
    }

    pub fn from_signer(
        signer: PrivateKeySigner,
        name: &str,
        password: &str,
        dir: PathBuf,
    ) -> Result<Arc<Self>> {
        Account::from_secret(
            signer.to_bytes().as_ref(),
            name,
            &AccountIdentifier::Address {
                address: signer.address(),
            },
            password,
            dir,
            None,
        )
    }

    pub fn from_private_key(
        private_key: &String,
        name: &str,
        password: &str,
        dir: PathBuf,
    ) -> Result<Arc<Self>> {
        let signer: PrivateKeySigner = private_key.trim().parse()?;
        Account::from_signer(signer, name, password, dir)
    }

    pub fn from_keyfile(
        keyfile: &PathBuf,
        name: &str,
        password: &str,
        dir: PathBuf,
    ) -> Result<Arc<Self>> {
        let privkey = std::fs::read_to_string(keyfile)?;
        let signer: PrivateKeySigner = privkey.trim().parse()?;
        Account::from_signer(signer, name, password, dir)
    }

    pub fn from_mnemonic_file(
        mnemonic_file: &PathBuf,
        mnemonic_password: Option<&str>,
        index: u32,
        derivation_path: &str,
        is_validator: bool,
        keystore_name: &str,
        keystore_password: &str,
        dir: PathBuf,
    ) -> Result<Arc<Self>> {
        let filepath = shellexpand::full(
            mnemonic_file
                .clone()
                .into_os_string()
                .into_string()
                .unwrap()
                .as_str(),
        )?
        .to_string();
        let mnemonic_phrase = std::fs::read_to_string(filepath)?;
        Account::from_mnemonic(
            &mnemonic_phrase,
            mnemonic_password,
            index,
            derivation_path,
            is_validator,
            keystore_name,
            keystore_password,
            dir,
        )
    }

    pub fn from_mnemonic(
        mnemonic_phrase: &String,
        mnemonic_password: Option<&str>,
        index: u32,
        derivation_path: &str,
        is_validator: bool,
        keystore_name: &str,
        keystore_password: &str,
        dir: PathBuf,
    ) -> Result<Arc<Self>> {
        match is_validator {
            true => {
                debug!("Using derivation path m/12381/3600/{}/0/0", index);
                let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_phrase.trim())?;
                let seed = mnemonic.to_seed(mnemonic_password)?;
                let bls_master_sk = blst::min_pk::SecretKey::derive_master_eip2333(&seed).unwrap();
                let bls_sk = bls_master_sk
                    .derive_child_eip2333(12381)
                    .derive_child_eip2333(3600)
                    .derive_child_eip2333(index)
                    .derive_child_eip2333(0)
                    .derive_child_eip2333(0);
                let bls_pk = bls_sk.sk_to_pk().compress();
                let pubkey = hex::encode(bls_pk);
                debug!("pubkey: {}", pubkey);

                Account::from_secret(
                    bls_sk.to_bytes().as_ref(),
                    keystore_name,
                    &AccountIdentifier::PublicKey { pubkey },
                    keystore_password,
                    dir,
                    None,
                )
            }
            false => {
                // Construct the derivation path, replace {} with the index
                // If no {} was specified, treat derivation_path as prefix
                let derivation_path = match derivation_path.contains("{}") {
                    true => derivation_path.replace("{}", index.to_string().as_str()),
                    false => format!("{derivation_path}/{index}"),
                };
                debug!("Using derivation path {}", derivation_path);
                let mut mnemonic =
                    MnemonicBuilder::<English>::default().phrase(mnemonic_phrase.trim());
                if let Some(mnemonic_password) = mnemonic_password {
                    mnemonic = mnemonic.password(mnemonic_password);
                }
                let mnemonic = match derivation_path.len() {
                    0 => mnemonic.index(index).unwrap(),
                    _ => mnemonic.derivation_path(derivation_path)?,
                };
                let signer: PrivateKeySigner = mnemonic.build()?;
                Account::from_signer(signer, keystore_name, keystore_password, dir)
            }
        }
    }
}

pub fn load_keystore(datadir: PathBuf) -> Result<()> {
    let dir = datadir.join("keystore");
    if !dir.exists() {
        return Ok(());
    }
    let keystore_files = std::fs::read_dir(dir)?;
    for keypath in keystore_files {
        trace!(
            "Reading keystore {}",
            &keypath.as_ref().unwrap().path().display()
        );
        let file = std::fs::File::open(&keypath.as_ref().unwrap().path())?;
        let json = serde_json::from_reader::<_, serde_json::Value>(&file)?;
        let created: Option<u64> = json.get("created").and_then(|value| value.as_u64());
        // id (geth, store v3) or uuid (deposit cli, v4) must exist
        let uuid: &str = json
            .get("id")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| json.get("uuid").and_then(|value| value.as_str()).unwrap());
        // name is optional, the user can update it later
        let name: &str = json
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        // address (geth, store v3) or pubkey (deposit cli, v4) must exist
        let address = json.get("address").and_then(|value| value.as_str());
        let pubkey = json.get("pubkey").and_then(|value| value.as_str());
        let ident = match address {
            Some(address) => AccountIdentifier::Address {
                address: address.parse::<Address>()?,
            },
            None => AccountIdentifier::PublicKey {
                pubkey: pubkey.unwrap().to_string(),
            },
        };
        trace!(
            "Loading account {}\n  uuid: {}\n  ident:{}",
            name, uuid, ident
        );
        let _ = Account::new(
            created,
            uuid,
            name,
            &ident,
            &[],
            keypath.as_ref().unwrap().path(),
        );
    }
    Ok(())
}

pub fn print_accounts() {
    _print_accounts(true)
}

pub fn print_accounts_short() {
    _print_accounts(false)
}

fn _print_accounts(with_details: bool) {
    let mut i = 0;
    let mut sorted: Vec<Arc<Account>> = global!(accounts)
        .iter()
        .map(|(_addr, account)| Arc::clone(&account))
        .collect();
    sorted.sort_by(|a, b| a.created.cmp(&b.created));
    sorted.iter().for_each(|account| {
        let name = account.name.lock().unwrap();
        i = i + 1;
        println!(
            "{:<3} {:<14} {} [{},{}]{}",
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
            format!("{}", account.ident).blue(),
            format!(
                "{}",
                match &account.ident {
                    AccountIdentifier::PublicKey { pubkey: _ } => "bls",
                    AccountIdentifier::Address { address: _ } => "key",
                }
            )
            .yellow(),
            match account.is_unlocked() {
                true => format!("UNLOCKED").green().bold(),
                false => format!("LOCKED").red(),
            },
            match with_details {
                true => format!(
                    "\n    {:<14} {}",
                    "Keystore:".bold(),
                    &account.keypath.display().to_string().white()
                ),
                false => "".to_string(),
            }
        );
    });
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::hex,
        signers::local::{
            MnemonicBuilder,
            coins_bip39::{English, Mnemonic},
        },
    };
    use bip39::{Language, Seed};
    use ethsign::SecretKey;
    use nam_tiny_hderive::{bip32::ExtendedPrivKey, bip44::ChildNumber};
    use std::str::FromStr;

    #[test]
    fn bip39_to_address() {
        let phrase = "budget squeeze faculty width cousin cake vanish start grocery card elegant reopen pencil traffic minute";
        let mnemonic = bip39::Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");

        assert_eq!(
            "5d6c43a28c7177a25c2b6812dec03d9ca5b1f5988b276f9504fd69f8e32f0797cacda47c9746f8c97a273a525de465e67b65b17d75bacdbc0d01e788b9646288",
            hex::encode(seed.as_bytes()),
            "Seed is invalid"
        );

        let base_ext = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0").unwrap();
        let account0 = base_ext.child(ChildNumber::from_str("0").unwrap()).unwrap();
        let priv_key0 = SecretKey::from_raw(&account0.secret()).unwrap();

        assert_eq!(
            "28eb85aa9c01011fe9f62aee4c4446db069bc753",
            hex::encode(priv_key0.public().address()),
            "Address0 is invalid"
        );

        let account1 = base_ext
            .child(ChildNumber::non_hardened_from_u32(1u32))
            .unwrap();
        let priv_key1 = SecretKey::from_raw(&account1.secret()).unwrap();

        assert_eq!(
            "bf9f307eb4fb144a3225c077a39aa91c373a470e",
            hex::encode(priv_key1.public().address()),
            "Address1 is invalid"
        );

        let mnemonic = MnemonicBuilder::<English>::default().phrase(phrase);
        let signer0 = mnemonic.clone().index(0u32).unwrap().build().unwrap();
        let signer1 = mnemonic.clone().index(1u32).unwrap().build().unwrap();

        //assert_eq!(
        //    signer0.address().to_string(),
        //    hex::encode(priv_key0.public().address()),
        //    "Address0 mismatch"
        //);

        assert_eq!(
            hex::encode(
                Mnemonic::<English>::new_from_phrase(phrase)
                    .unwrap()
                    .to_seed(Some(""))
                    .unwrap()
            ),
            hex::encode(seed.as_bytes()),
            "Seed mismatch"
        );

        assert_eq!(signer0.to_bytes(), account0.secret(), "Account0 mismatch");

        assert_eq!(signer1.to_bytes(), account1.secret(), "Account1 mismatch");
    }
}
