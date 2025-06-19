# :construction: THIS PROJECT IS IN BETA :construction:

> [!WARNING]
> **DISCLAIMER**:
> This software is provided to you "as is", use at your own risk and without warranties of any kind.
> It is your responsibility to read and understand the code and the implications of running this
> software. The usage of eth-knife involves various risks, including, but not limited to loss of
> funds associated with the ethereum account(s) used.
> No developers or entity involved will be liable for any claims and damages associated with your
> use, inability to use, or your interaction with other nodes or the software.

# eth-knife-rs :hocho:

![transfer](https://github.com/ibhagwan/eth-knife-rs/blob/master/screenshots/transfer-eth.png)

A "swiss-knife" cli tool (and wallet) for ethereum.

### rationale

While experimenting with ethereum I was surprised to see the lack of standalone wallet software as
well and the "soft" requirement to do everything on a browser extension (yikes), this project aims
to bridge that gap.

I'm also quite the cli nerd, want everything in the terminal and wanted to have some fun with rust
along the way.


## Table of contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  + [Basics](#basics)
  + [Accounts](#accounts)
  + [Transactions](#Transactions)
  + [Validators](#validators)
    - [Compound](#compound)
    - [Consolidate](#consolidate)
    - [Withdrawal](#withdrawal)
    - [Deposit](#deposit)
- [TODO](#todo)
- [Inspiration](#inspiration)


## Features

Current feature list, see [TODO](#todo) for future features:

- Console / REPL using nushell's [reedline](https://github.com/nushell/reedline)
- Wallet / Keystore management for normal accounts and validators (BLS12-138)
  + Import keystore from geth / lighthouse / etc
  + Import from mnemonic / private key
  + Update keystore password
- Conversion utilities (eth to gwei, etc)
- Network query utilities (next base fee, estimate fees, etc)
- Transfer eth between accounts
- Pectra validator operations
  + Compound
  + Consolidate
  + Withdrawal
  + Deposit (top-up)


## Installation

### Build from source

```sh
git clone https://github.com/ibhagwan/eth-knife-rs.git
cd eth-knife-rs
cargo build
```

## Usage

By default eth-knife reads configuration parameters from `$XDG_CONFIG_HOME/eth-knife/config.toml`
(most likely `~/.config/eth-knife/config.toml`) and searches for keystore files in the default
datadir subdirectory `~/.eth-knife/keystore/`.

Sample configuration file:
```toml
log_level = 3
vi_mode = false
history = 10000
datadir = "~/.eth-knife"
# At the minimum you'll need to configure the
# RPC URL of the ethereum node to connect to
rpc_url = "https://ethereum-rpc.publicnode.com"
```

See `--help` for the full list of configuration parameters available:
```
Options:
  -c, --config <CONFIG_PATH>     Config file [default: ~/.config/eth-knife/config.toml]
  -l, --log-level [<LOG_LEVEL>]  Logging level [default: 3]
      --vi                       Enable vi edit mode
      --history <HISTORY>        Command hisrory length, 0 to disable history [default: 10000]
      --datadir [<DATADIR>]      Data directory [default: /home/bhagwan/.eth-knife]
      --addr-db [<ADDR_DB>]      Address alias DB [default: addr_db.json]
      --tx-db [<TX_DB>]          Transction DB [default: tx_db.json]
      --rpc-url [<RPC_URL>]      JsonRPC URL
  -h, --help                     Print help
  -V, --version                  Print version
```

### Basics

After you've configured the RPC URL you can start interacting with the ethereum network, for
example querying the chain ID:
> [!TIP]
> Set `log_level=4` to see `DEBG` level messages
```
> eth-knife net id
version: 0.1.0
 2025-06-10 12:00:20.684 DEBG starting new connection: http://localhost:8545/
 2025-06-10 12:00:20.771 DEBG Connected to hoodi chainId:560048 height:576427
 2025-06-10 12:00:20.777 INFO Chain id: 560048
```

Alternatively you can use REPL mode using `console` or `attach <rpc_url>`:
```
> eth-knife console
[DISCONNECTED]: atttach https://localhost:8545/
Connected to hoodi chainId:560048 height:576471
(hoodi) https://localhost:8545/: net next-base-fee
        block_number:  576472
        base_fee:      0.933640626 gwei (0.000000000933640626 eth)
        gas_limit:     60000000
        gas_used:      57502415 (95.837%)
        next_base:     1.040629675 gwei (0.000000001040629675 eth)
```

### Accounts

eth-knife is compatible with standard ethereum keystores v3 (used by geth) and v4 (used for
validator keys, lighthouse, nimbus, etc).

> [!TIP]
> Use can use existing keystores (geth, lighthouse, nimbus, etc) by copying the keystore file
> into eth-knife's `<datadir>/keystore` folder (e.g. `~/.eth-knife/keystore/`).

Account creation commands:

- `account new` - generate a random ethereum account
- `account new-mnemonic` - generate a random mnemonic (does not create an account/keystore)
- `account import-privkey` - imports an account from an existing private key / secret
- `account import-mnemonic` - imports an account from an existing mnemonic and HD path
- `account import-mnemonic --validator` - imports a validator keystore from an existing mnemonic

> See `account help` for a complete list of account operations (set-name, set-password, etc)


### Transactions

Any transaction in eth-knife-rs can be sent immediately or stored offline as hex data to be sent
at a later stage without exposing your keystore / private key, to send a transaction offline
you'll need to specify transaction parameters in advance as without these we cannot generate a tx
signature, when using `--offline`, you will be notified which flags must be present:
```
(hoodi) https://localhost:8545/: transfer eth --amount 0.5 --to 2 --offline --out tx.hex
error: the following required arguments were not provided:
  --chain-id <CHAIN_ID>
  --nonce <NONCE>
  --max-fee <MAX_FEE>
  --max-priority <MAX_PRIORITY>
  --gas-limit <GAS_LIMIT>
```

You can gather the required parameters using the `net` command:
> [!TIP]
> Max priority fee and max fee per gas are determined depending on network congestion at the time
> the command is run, to send an offline successful transaction without overpaying read about
> EIP-1559 fees [here](https://www.blocknative.com/blog/eip-1559-fees).
```
(hoodi) http://localhost:8545: net id
Chain id: 560048
(hoodi) http://localhost:8545: net balance 0xA55AeF2Cd8b6Aa82C6687995b6953f8b3e355158
Balance of 0xA55AeF2Cd8b6Aa82C6687995b6953f8b3e355158: 70.991749169512371215 eth
(hoodi) http://localhost:8545: net nonce 0xA55AeF2Cd8b6Aa82C6687995b6953f8b3e355158
Nonce for 0xA55AeF2Cd8b6Aa82C6687995b6953f8b3e355158: 8
(hoodi) http://localhost:8545: net estimate-fees
    block_number:             617906
    max_priority_fee:         0.099566599 gwei (0.000000000099566599 eth)
    max_fee_per_gas:          2.065834491 gwei (0.000000002065834491 eth)
    base_fee:                 0.983133946 gwei (0.000000000983133946 eth)
    next_base_fee:            1.065356702 gwei (0.000000001065356702 eth)
    next_base+priority:       1.164923301 gwei (0.000000001164923301 eth)
```

The above will save a transaction into a file named `tx.hex` which you can then send with:
> [!NOTE]
> If you unlock the originating account using `account unlock` you can change the fees but at
> this point you're no longer sending an "offline" transaction as your key is unlocked in memory
> and used to resign the transaction.
```
(hoodi) http://localhost:8545: tx import tx.hex
UNLOCK ACCOUNT 0xA55AeF2Cd8b6Aa82C6687995b6953f8b3e355158 IF YOU WISH TO CHANGE THE FEES
    chain_id:       560048
    nonce:          9
    from:           0xA55AeF2Cd8b6Aa82C6687995b6953f8b3e355158
    to:             0xd09602361a7F9385E22954D570b959EfF091C41E
    value:          0.500000000000000000 eth
    gas_limit:      21000
    fees:           Priority 1.000000000 gwei | Max 2.000000000 gwei
```

### Validators

eth-knife-rs supports ethereum pectra upgrade validator operations:
- Compound (convert 0x1 validator to a 0x2 validator, EIP-7251)
- Consolidate (migrate a 0x1 validator into a 0x2 validator, EIP-7251)
- Partial withdrawal from a validator (EIP-7002)
- Deposit (top-up) a validator


> [!WARNING]
> eth-knife currently **does not perform any safety checks** (withdrawal addr check, etc)
> to avoid losing eth on failed transactions kindly **double-check your addresses before
> submitting the request**

#### Compound

[EIP-7251](https://eips.ethereum.org/EIPS/eip-7251) compounding request upgrades a non-compounding
validator (max balance 32 eth, 0x1 prefix) into a compounding validator (max balance 2048 eth, 0x2
prefix).

> [!NOTE]
> - Validator must already have a type 1 withdrawal credential (0x1 prefix)
> - If you need to upgrade an old type 0 validator, use
>   [ethdo](https://github.com/wealdtech/ethdo/blob/master/docs/changingwithdrawalcredentials.md)
> - Request must originate from the validator withdrawal address account

```
validator compound --pubkey <validator BLS pubkey> --from <withdrawal addr>
```

#### Consolidate

[EIP-7251](https://eips.ethereum.org/EIPS/eip-7251) consolidate request transfers the balance of a
non-compounding validator (max balance 32 eth, 0x1 prefix) into an existing compounding validator
(max balance 2048 eth, 0x2 prefix).

> [!NOTE]
> - Source validator must already have a type 1 withdrawal credential (0x1 prefix)
> - Target validator must already be upgraded to type 2 compounding validator (0x2 prefix)
> - Request must originate from the source validator withdrawal address account

```
validator consolidate --source <source BLS pubkey> --target <target BLS pubkey> --from <withdrawal addr>
```

#### Withdrawal

[EIP-7002](https://eips.ethereum.org/EIPS/eip-7002) partial withdrawal request.

> [!NOTE]
> - Validator must already be upgraded to type 2 compounding validator (0x2 prefix)
> - **This isn't an "exit" operation**, validator balance must remain >= 32 eth
> - Request must originate from the validator withdrawal address account

```
validator withdrawal --pubkey <validator BLS pubkey> --eth <amount> --from <withdrawal addr>
```

#### Deposit

Validator topup, add funds to an existing compounding validator.

> [!WARNING]
> Request can originate from any account, **DOUBLE CHECK THE TARGET VALIDATOR PUBKEY**

```
validator deposit --pubkey <validator BLS pubkey> --eth <amount>
```

## TODO

- - [ ] Add `h` alias for subcommand help (waiting for
        [clap#5815](https://github.com/clap-rs/clap/issues/5815))
- - [ ] Transaction cancel/replace
- - [ ] Contract deploy
- - [ ] CREATE2 vanity address generator
- - [ ] CREATE2 re-deployable contract
- - [ ] More `trace|debug` logging
- - [ ] CI / Testing


## Inspiration

Similar tools which inspired me to write this:

- [wealdtech/ethdo](https://github.com/wealdtech/ethdo)
- [wealdtech/ethereal](https://github.com/wealdtech/ethereal)
- [protofire/eth-cli](https://github.com/protofire/eth-cli)
