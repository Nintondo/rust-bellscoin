// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use hashes::{sha256d, Hash};
use hex_lit::hex;
use internals::impl_array_newtype;

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::blockdata::witness::Witness;
use crate::internal_macros::impl_bytes_newtype;
use crate::network::Network;
use crate::pow::CompactTarget;
use crate::Amount;

/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 60;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 4 * 3600;

#[deprecated(since = "0.31.0", note = "Use Weight::MAX_BLOCK instead")]
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;

#[deprecated(since = "0.31.0", note = "Use Weight::MIN_TRANSACTION instead")]
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bellscoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 25; // 0x00
/// Mainnet (bellscoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 30; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 33; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 22; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 30;

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bellscoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new()
        .push_int(486604799)
        .push_int_non_minimal(4)
        .push_slice(b"Nintondo")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9");
    let out_script =
        script::Builder::new().push_slice(script_bytes).push_opcode(OP_CHECKSIG).into_script();
    ret.output.push(TxOut { value: Amount::from_sat(88 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bellscoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Mainnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1383509530,
                bits: CompactTarget::from_consensus(0x1e00ffff),
                nonce: 44481,
                auxpow: None,
            },
            txdata,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 414098458,
                auxpow: None,
            },
            txdata,
        },
        Network::Signet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1598918400,
                bits: CompactTarget::from_consensus(0x1e0377ae),
                nonce: 52613770,
                auxpow: None,
            },
            txdata,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 2,
                auxpow: None,
            },
            txdata,
        },
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet bellscoin.
    pub const MAINNET: Self = Self([
        152, 6, 254, 154, 146, 251, 30, 237, 27, 80, 72, 235, 248, 248, 72, 105, 41, 97, 169, 189,
        6, 47, 92, 209, 130, 58, 196, 87, 223, 36, 190, 229,
    ]);
    /// `ChainHash` for testnet bellscoin.
    pub const TESTNET: Self = Self([
        152, 6, 254, 154, 146, 251, 30, 237, 27, 80, 72, 235, 248, 248, 72, 105, 41, 97, 169, 189,
        6, 47, 92, 209, 130, 58, 196, 87, 223, 36, 190, 229,
    ]);
    /// `ChainHash` for signet bellscoin.
    pub const SIGNET: Self = Self([
        246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159, 249,
        240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0,
    ]);
    /// `ChainHash` for regtest bellscoin.
    pub const REGTEST: Self = Self([
        6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94,
        51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15,
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::MAINNET, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}
