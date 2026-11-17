use std::{
    fs,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use alloy::{
    primitives::{Address, hex},
    signers::local::{
        MnemonicBuilder, PrivateKeySigner,
        coins_bip39::{English, Mnemonic, WordCount},
    },
};
use bip39::{Language, Mnemonic as Bip39Mnemonic, Seed};
use eth_knife::account::{Account, AccountIdentifier, random_mnemonic};
use tempfile::tempdir;

const PHRASE: &str = "budget squeeze faculty width cousin cake vanish start grocery card elegant reopen pencil traffic minute";
const KEYSTORE_PASSWORD: &str = "correct horse battery staple";
const V4_FIXTURE_PASSWORD: &str = "testpassword🔑";

// The keystore formats use deliberately expensive KDFs. Running these tests
// in parallel can spike memory use, so serialize the keystore-heavy tests.
static KEYSTORE_LOCK: Mutex<()> = Mutex::new(());

fn keystore_guard() -> MutexGuard<'static, ()> {
    KEYSTORE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn tiny_bip39_seed(phrase: &str, password: &str) -> Seed {
    let mnemonic = Bip39Mnemonic::from_phrase(phrase, Language::English).unwrap();
    Seed::new(&mnemonic, password)
}

fn alloy_signer(phrase: &str, mnemonic_password: Option<&str>, index: u32) -> PrivateKeySigner {
    let builder = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .index(index)
        .unwrap();

    let builder = match mnemonic_password {
        Some(password) => builder.password(password),
        None => builder,
    };

    builder.build().unwrap()
}

fn eip2333_secret(index: u32) -> blst::min_pk::SecretKey {
    let seed = tiny_bip39_seed(PHRASE, "");
    blst::min_pk::SecretKey::derive_master_eip2333(seed.as_bytes())
        .unwrap()
        .derive_child_eip2333(12381)
        .derive_child_eip2333(3600)
        .derive_child_eip2333(index)
        .derive_child_eip2333(0)
        .derive_child_eip2333(0)
}

fn read_keystore(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn mnemonic_seed_matches_tiny_bip39_with_and_without_password() {
    for password in ["", "TREZOR"] {
        let expected = tiny_bip39_seed(PHRASE, password);
        let actual = Mnemonic::<English>::new_from_phrase(PHRASE)
            .unwrap()
            .to_seed(Some(password))
            .unwrap();

        assert_eq!(
            actual.as_slice(),
            expected.as_bytes(),
            "seed mismatch for password {password:?}"
        );
    }
}

#[test]
fn random_mnemonic_supports_all_word_counts() {
    for count in [12u8, 15, 18, 21, 24] {
        let mnemonic = random_mnemonic(count).unwrap();
        let expected_count = WordCount::try_from(usize::from(count)).unwrap();

        assert_eq!(mnemonic.word_count(), expected_count);
        assert_eq!(mnemonic.to_phrase().split(' ').count(), usize::from(count));
        assert!(Mnemonic::<English>::new_from_phrase(mnemonic.to_phrase().as_str()).is_ok());
    }
}

#[test]
fn random_mnemonic_rejects_invalid_word_counts() {
    for count in [0u8, 1, 11, 13, 17, 25] {
        assert!(
            random_mnemonic(count).is_err(),
            "word count {count} should be rejected"
        );
    }
}

#[test]
fn from_mnemonic_matches_alloy_with_password_and_explicit_index() {
    let dir = tempdir().unwrap();
    let mnemonic_password = "mnemonic-password";
    let index = 7;
    let account = Account::from_mnemonic(
        PHRASE,
        Some(mnemonic_password),
        index,
        "m/44'/60'/0'/0/{}",
        false,
        "alice",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();

    let expected = alloy_signer(PHRASE, Some(mnemonic_password), index);

    assert_eq!(account.address().unwrap(), expected.address());
    assert_eq!(account.name(), "alice");
    assert!(account.keypath.exists());
    assert!(account.unlock(KEYSTORE_PASSWORD).is_ok());
    assert_eq!(
        account.signer().unwrap().to_bytes().as_slice(),
        expected.to_bytes().as_slice()
    );
    assert_eq!(
        eth_keystore::decrypt_key(&account.keypath, KEYSTORE_PASSWORD).unwrap(),
        expected.to_bytes().to_vec()
    );
}

#[test]
fn from_mnemonic_prefix_path_appends_index() {
    let dir = tempdir().unwrap();
    let account = Account::from_mnemonic(
        PHRASE,
        None,
        3,
        "m/44'/60'/0'/0",
        false,
        "prefix-path",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();

    let expected = alloy_signer(PHRASE, None, 3);
    assert_eq!(account.address().unwrap(), expected.address());
}

#[test]
#[ignore = "slow: v4 scrypt KDF takes ~2 minutes in debug builds; run with --ignored"]
fn from_mnemonic_validator_matches_tiny_bip39_and_eip2333() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let index = 2;
    let expected_secret = eip2333_secret(index);
    let expected_pubkey = hex::encode(expected_secret.sk_to_pk().compress());

    let account = Account::from_mnemonic(
        PHRASE,
        None,
        index,
        "",
        true,
        "validator",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();

    match &account.ident {
        AccountIdentifier::PublicKey { pubkey } => assert_eq!(pubkey, &expected_pubkey),
        other => panic!("expected public-key account, got {other:?}"),
    }

    let keystore = read_keystore(&account.keypath);
    assert_eq!(keystore["version"], 4);
    assert_eq!(keystore["pubkey"], expected_pubkey);

    assert!(account.unlock(KEYSTORE_PASSWORD).is_ok());
    assert_eq!(
        account.secret.lock().unwrap().as_slice(),
        expected_secret.to_bytes().as_slice()
    );
    assert_eq!(
        hex::encode(account.bls_public_key().unwrap().compress()),
        expected_pubkey
    );
}

#[test]
fn keystore_v3_roundtrip_and_geth_compat_metadata() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let signer = alloy_signer(PHRASE, None, 0);
    let account = Account::from_signer(
        signer.clone(),
        "geth-account",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();

    assert_eq!(
        eth_keystore::decrypt_key(&account.keypath, KEYSTORE_PASSWORD).unwrap(),
        signer.to_bytes().to_vec()
    );

    let keystore = read_keystore(&account.keypath);
    assert_eq!(keystore["version"], 3);
    assert_eq!(
        keystore["address"].as_str().unwrap(),
        signer.address().to_string()
    );
    assert_eq!(keystore["name"], "geth-account");
    assert!(keystore["created"].as_u64().unwrap() > 0);
}

#[test]
fn keystore_wrong_password_and_lock() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let signer = alloy_signer(PHRASE, None, 1);
    let account = Account::from_signer(
        signer.clone(),
        "locked-account",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();

    assert!(account.is_unlocked());
    account.lock();
    assert!(!account.is_unlocked());
    assert!(account.signer().is_err());
    assert!(account.unlock("wrong password").is_err());
    assert!(account.unlock(KEYSTORE_PASSWORD).is_ok());
    assert_eq!(
        account.signer().unwrap().to_bytes().as_slice(),
        signer.to_bytes().as_slice()
    );
}

#[test]
fn keystore_custom_filename_and_password_change() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let signer = alloy_signer(PHRASE, None, 2);
    let ident = AccountIdentifier::Address {
        address: signer.address(),
    };
    let account = Account::from_secret(
        signer.to_bytes().as_slice(),
        "bob",
        &ident,
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
        Some("custom.json"),
    )
    .unwrap();

    assert_eq!(account.keypath, dir.path().join("custom.json"));
    assert!(account.unlock(KEYSTORE_PASSWORD).is_ok());

    account.set_name("robert").unwrap();
    account.set_password("new-password").unwrap();

    assert!(eth_keystore::decrypt_key(&account.keypath, "new-password").is_ok());
    assert!(eth_keystore::decrypt_key(&account.keypath, KEYSTORE_PASSWORD).is_err());
    assert_eq!(read_keystore(&account.keypath)["name"], "robert");
}

#[test]
fn keystore_v4_decrypts_eip2335_fixture() {
    let _guard = keystore_guard();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v4-pbkdf2.json");
    let expected_secret =
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();
    let pubkey = read_keystore(&fixture)["pubkey"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        eth_keystore::decrypt_key(&fixture, V4_FIXTURE_PASSWORD).unwrap(),
        expected_secret
    );

    let account = Account::new(
        None,
        "v4-fixture",
        "v4-fixture",
        &AccountIdentifier::PublicKey {
            pubkey: pubkey.clone(),
        },
        &[],
        fixture,
    );

    assert!(account.unlock("wrong password").is_err());
    assert!(account.unlock(V4_FIXTURE_PASSWORD).is_ok());
    assert_eq!(
        account.secret.lock().unwrap().as_slice(),
        expected_secret.as_slice()
    );
    assert_eq!(
        hex::encode(account.bls_public_key().unwrap().compress()),
        pubkey
    );
}

#[test]
fn keystore_v3_interops_with_alloy() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let signer = alloy_signer(PHRASE, None, 4);

    // eth-knife writes, alloy reads.
    let account = Account::from_signer(
        signer.clone(),
        "interop",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();
    let alloy_read =
        PrivateKeySigner::decrypt_keystore(&account.keypath, KEYSTORE_PASSWORD).unwrap();
    assert_eq!(alloy_read.address(), signer.address());

    // alloy writes, eth-knife reads.
    let alloy_dir = dir.path().join("alloy");
    fs::create_dir_all(&alloy_dir).unwrap();
    let mut rng = rand08::thread_rng();
    let (_alloy_write, _uuid) = PrivateKeySigner::encrypt_keystore(
        &alloy_dir,
        &mut rng,
        signer.to_bytes(),
        KEYSTORE_PASSWORD,
        Some("alloy.json"),
    )
    .unwrap();
    let alloy_path = alloy_dir.join("alloy.json");
    // The fork's `geth-compat` v3 reader requires an `address` field, which
    // upstream eth-keystore/alloy does not write. Add it so this exercises the
    // fork reading an otherwise alloy-produced keystore.
    let mut alloy_json = read_keystore(&alloy_path);
    alloy_json["address"] = serde_json::Value::String(signer.address().to_string());
    fs::write(&alloy_path, serde_json::to_vec(&alloy_json).unwrap()).unwrap();

    let alloy_account = Account::new(
        None,
        "alloy",
        "alloy",
        &AccountIdentifier::Address {
            address: signer.address(),
        },
        &[],
        alloy_path.clone(),
    );

    assert_eq!(
        eth_keystore::decrypt_key(&alloy_path, KEYSTORE_PASSWORD).unwrap(),
        signer.to_bytes().to_vec()
    );
    assert!(alloy_account.unlock(KEYSTORE_PASSWORD).is_ok());
    assert_eq!(alloy_account.address().unwrap(), signer.address());
}

#[test]
fn from_mnemonic_file_matches_direct_import() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    fs::write(&mnemonic_path, PHRASE).unwrap();

    let account = Account::from_mnemonic_file(
        &mnemonic_path,
        None,
        5,
        "m/44'/60'/0'/0/{}",
        false,
        "file-mnemonic",
        KEYSTORE_PASSWORD,
        dir.path().join("keystore"),
    )
    .unwrap();

    let expected = alloy_signer(PHRASE, None, 5);
    assert_eq!(account.address().unwrap(), expected.address());
    assert_eq!(
        eth_keystore::decrypt_key(&account.keypath, KEYSTORE_PASSWORD).unwrap(),
        expected.to_bytes().to_vec()
    );
}

#[test]
fn from_keyfile_matches_direct_import() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let signer = alloy_signer(PHRASE, None, 6);
    let key_path = dir.path().join("private-key.txt");
    fs::write(&key_path, format!("0x{}", hex::encode(signer.to_bytes()))).unwrap();

    let account = Account::from_keyfile(
        &key_path,
        "file-key",
        KEYSTORE_PASSWORD,
        dir.path().join("keystore"),
    )
    .unwrap();

    assert_eq!(account.address().unwrap(), signer.address());
    assert_eq!(
        eth_keystore::decrypt_key(&account.keypath, KEYSTORE_PASSWORD).unwrap(),
        signer.to_bytes().to_vec()
    );
}

#[test]
fn new_random_creates_unlockable_keystore() {
    let _guard = keystore_guard();
    let dir = tempdir().unwrap();
    let account = Account::new_random(
        "random-account",
        KEYSTORE_PASSWORD,
        dir.path().to_path_buf(),
    )
    .unwrap();

    assert!(account.keypath.exists());
    assert!(account.is_unlocked());
    account.lock();
    assert!(account.unlock(KEYSTORE_PASSWORD).is_ok());
    assert_eq!(account.name(), "random-account");
    assert_ne!(account.address().unwrap(), Address::ZERO);
}
