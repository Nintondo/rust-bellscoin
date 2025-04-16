// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for ordinary base58 Bitcoin addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! # #[cfg(feature = "rand-std")] {
//! use bitcoin::{Address, PublicKey, Network};
//! use bitcoin::secp256k1::{rand, Secp256k1};
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut rand::thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! # }
//! ```
//!
//! # Note: creating a new address requires the rand-std feature flag
//!
//! ```toml
//! bitcoin = { version = "...", features = ["rand-std"] }
//! ```

use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::hrp::{self, Hrp};
use hashes::{sha256, Hash, HashEngine};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use crate::base58;
use crate::blockdata::constants::{
    MAX_SCRIPT_ELEMENT_SIZE, PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_TEST,
};
use crate::blockdata::script::witness_program::WitnessProgram;
use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{self, Script, ScriptBuf, ScriptHash};
use crate::crypto::key::{PubkeyHash, PublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::network::Network;
use crate::prelude::*;
use crate::script::PushBytesBuf;
use crate::taproot::TapNodeHash;

/// Error code for the address module.
pub mod error;
pub use self::error::{Error, ParseError, UnknownAddressTypeError};

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to taproot.
    P2tr,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
            AddressType::P2tr => "p2tr",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            "p2tr" => Ok(AddressType::P2tr),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

/// The method used to produce an address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Payload {
    /// P2PKH address.
    PubkeyHash(PubkeyHash),
    /// P2SH address.
    ScriptHash(ScriptHash),
    /// Segwit address.
    WitnessProgram(WitnessProgram),
}

impl Payload {
    /// Constructs a [Payload] from an output script (`scriptPubkey`).
    pub fn from_script(script: &Script) -> Result<Payload, Error> {
        Ok(if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            Payload::PubkeyHash(PubkeyHash::from_byte_array(bytes))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            Payload::ScriptHash(ScriptHash::from_byte_array(bytes))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("witness_version guarantees len() > 4");

            let witness_program = script.as_bytes()[2..].to_vec();

            let witness_program =
                WitnessProgram::new(WitnessVersion::try_from(opcode)?, witness_program)?;
            Payload::WitnessProgram(witness_program)
        } else {
            return Err(Error::UnrecognizedScript);
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> ScriptBuf {
        match *self {
            Payload::PubkeyHash(ref hash) => ScriptBuf::new_p2pkh(hash),
            Payload::ScriptHash(ref hash) => ScriptBuf::new_p2sh(hash),
            Payload::WitnessProgram(ref prog) => ScriptBuf::new_witness_program(prog),
        }
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        match *self {
            Payload::PubkeyHash(ref hash) if script.is_p2pkh() => {
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            Payload::ScriptHash(ref hash) if script.is_p2sh() => {
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            Payload::WitnessProgram(ref prog) if script.is_witness_program() => {
                &script.as_bytes()[2..] == prog.program().as_bytes()
            }
            Payload::PubkeyHash(_) | Payload::ScriptHash(_) | Payload::WitnessProgram(_) => false,
        }
    }

    /// Creates a pay to (compressed) public key hash payload from a public key
    #[inline]
    pub fn p2pkh(pk: &PublicKey) -> Payload {
        Payload::PubkeyHash(pk.pubkey_hash())
    }

    /// Creates a pay to script hash P2SH payload from a script
    #[inline]
    pub fn p2sh(script: &Script) -> Result<Payload, Error> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(Error::ExcessiveScriptSize);
        }
        Ok(Payload::ScriptHash(script.script_hash()))
    }

    /// Create a witness pay to public key payload from a public key
    pub fn p2wpkh(pk: &PublicKey) -> Result<Payload, Error> {
        let prog = WitnessProgram::new(
            WitnessVersion::V0,
            pk.wpubkey_hash().ok_or(Error::UncompressedPubkey)?,
        )?;
        Ok(Payload::WitnessProgram(prog))
    }

    /// Create a pay to script payload that embeds a witness pay to public key
    pub fn p2shwpkh(pk: &PublicKey) -> Result<Payload, Error> {
        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(pk.wpubkey_hash().ok_or(Error::UncompressedPubkey)?);

        Ok(Payload::ScriptHash(builder.into_script().script_hash()))
    }

    /// Create a witness pay to script hash payload.
    pub fn p2wsh(script: &Script) -> Payload {
        let prog = WitnessProgram::new(WitnessVersion::V0, script.wscript_hash())
            .expect("wscript_hash has len 32 compatible with segwitv0");
        Payload::WitnessProgram(prog)
    }

    /// Create a pay to script payload that embeds a witness pay to script hash address
    pub fn p2shwsh(script: &Script) -> Payload {
        let ws = script::Builder::new().push_int(0).push_slice(script.wscript_hash()).into_script();

        Payload::ScriptHash(ws.script_hash())
    }

    /// Create a pay to taproot payload from untweaked key
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Payload {
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let prog = WitnessProgram::new(WitnessVersion::V1, output_key.to_inner().serialize())
            .expect("taproot output key has len 32 <= 40");
        Payload::WitnessProgram(prog)
    }

    /// Create a pay to taproot payload from a pre-tweaked output key.
    ///
    /// This method is not recommended for use and [Payload::p2tr()] should be used where possible.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> Payload {
        let prog = WitnessProgram::new(WitnessVersion::V1, output_key.to_inner().serialize())
            .expect("taproot output key has len 32 <= 40");
        Payload::WitnessProgram(prog)
    }

    /// Returns a byte slice of the inner program of the payload. If the payload
    /// is a script hash or pubkey hash, a reference to the hash is returned.
    fn inner_prog_as_bytes(&self) -> &[u8] {
        match self {
            Payload::ScriptHash(hash) => hash.as_ref(),
            Payload::PubkeyHash(hash) => hash.as_ref(),
            Payload::WitnessProgram(prog) => prog.program().as_bytes(),
        }
    }
}

/// A utility struct to encode an address payload with the given parameters.
/// This is a low-level utility struct. Consider using `Address` instead.
pub struct AddressEncoding<'a> {
    /// The address payload to encode.
    pub payload: &'a Payload,
    /// base58 version byte for p2pkh payloads (e.g. 0x00 for "1..." addresses).
    pub p2pkh_prefix: u8,
    /// base58 version byte for p2sh payloads (e.g. 0x05 for "3..." addresses).
    pub p2sh_prefix: u8,
    /// The bech32 human-readable part.
    pub hrp: Hrp,
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressEncoding<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Payload::WitnessProgram(witness_program) => {
                let hrp = &self.hrp;
                let version = witness_program.version().to_fe();
                let program = witness_program.program().as_bytes();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
                }
            }
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation: sealed::NetworkValidation + Sync + Send + Sized + Unpin {
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

/// The inner representation of an address, without the network validation tag.
///
/// An `Address` is composed of a payload and a network. This struct represents the inner
/// representation of an address without the network validation tag, which is used to ensure that
/// addresses are used only on the appropriate network.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AddressInner {
    payload: Payload,
    network: Network,
}

/// A Bitcoin address.
///
/// ### Parsing addresses
///
/// When parsing string as an address, one has to pay attention to the network, on which the parsed
/// address is supposed to be valid. For the purpose of this validation, `Address` has
/// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
/// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
/// address has been checked. This marker type will prevent from calling certain functions unless the network
/// verification has been successfully completed.
///
/// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
/// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
/// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
/// `Address<NetworkChecked>` is returned.
///
/// The types `Address` and `Address<NetworkChecked>` are synonymous, i. e. they can be used interchangeably.
///
/// ```rust
/// use std::str::FromStr;
/// use bitcoin::{Address, Network};
/// use bitcoin::address::{NetworkUnchecked, NetworkChecked};
///
/// // variant 1
/// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
/// let address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();
///
/// // variant 2
/// let address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap()
///                .require_network(Network::Bitcoin).unwrap();
///
/// // variant 3
/// let address: Address<NetworkChecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse::<Address<_>>()
///                .unwrap().require_network(Network::Bitcoin).unwrap();
/// ```
///
/// ### Formatting addresses
///
/// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
/// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
///
/// 1. `Display` is implemented only for `Address<NetworkChecked>`:
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap().assume_checked();
/// assert_eq!(address.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
/// ```
///
/// ```ignore
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap();
/// let s = address.to_string(); // does not compile
/// ```
///
/// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
/// an indicator that its network has not been checked. This is to encourage programmer to properly
/// check the network and use `Display` in user-facing context.
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkUnchecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap();
/// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM)");
/// ```
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap().assume_checked();
/// assert_eq!(format!("{:?}", address), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
/// ```
///
/// ### Relevant BIPs
///
/// * [BIP13 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
/// * [BIP16 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
/// * [BIP141 - Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
/// * [BIP142 - Address Format for Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki)
/// * [BIP341 - Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
/// * [BIP350 - Bech32m format for v1+ witness addresses](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
///
/// The `#[repr(transparent)]` attribute is used to guarantee that the layout of the
/// `Address` struct is the same as the layout of the `AddressInner` struct. This attribute is
/// an implementation detail and users should not rely on it in their code.
///
#[repr(transparent)]
pub struct Address<V = NetworkChecked>(AddressInner, PhantomData<V>)
where
    V: NetworkValidation;

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_internal(fmt)
    }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(Address<NetworkUnchecked>, "a Bitcoin address");

#[cfg(feature = "serde")]
impl<N: NetworkValidation> serde::Serialize for Address<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    /// Returns a reference to the payload of this address.
    pub fn payload(&self) -> &Payload {
        &self.0.payload
    }

    /// Returns a reference to the network of this address.
    pub fn network(&self) -> &Network {
        &self.0.network
    }

    /// Returns a reference to the unchecked address, which is dangerous to use if the address
    /// is invalid in the context of `NetworkUnchecked`.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }

    /// Extracts and returns the network and payload components of the `Address`.
    pub fn into_parts(self) -> (Network, Payload) {
        let AddressInner { payload, network } = self.0;
        (network, payload)
    }

    /// Gets the address type of the address.
    ///
    /// This method is publicly available as [`address_type`](Address<NetworkChecked>::address_type)
    /// on `Address<NetworkChecked>` but internally can be called on `Address<NetworkUnchecked>` as
    /// `address_type_internal`.
    ///
    /// # Returns
    /// None if unknown, non-standard or related to the future witness version.
    fn address_type_internal(&self) -> Option<AddressType> {
        match self.payload() {
            Payload::PubkeyHash(_) => Some(AddressType::P2pkh),
            Payload::ScriptHash(_) => Some(AddressType::P2sh),
            Payload::WitnessProgram(ref prog) => {
                // BIP-141 p2wpkh or p2wsh addresses.
                match prog.version() {
                    WitnessVersion::V0 => match prog.program().len() {
                        20 => Some(AddressType::P2wpkh),
                        32 => Some(AddressType::P2wsh),
                        _ => unreachable!(
                            "Address creation invariant violation: invalid program length"
                        ),
                    },
                    WitnessVersion::V1 if prog.program().len() == 32 => Some(AddressType::P2tr),
                    _ => None,
                }
            }
        }
    }

    /// Format the address for the usage by `Debug` and `Display` implementations.
    fn fmt_internal(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let p2pkh_prefix = match self.network() {
            Network::Mainnet => PUBKEY_ADDRESS_PREFIX_MAIN,
            Network::Testnet | Network::Signet | Network::Regtest => PUBKEY_ADDRESS_PREFIX_TEST,
        };
        let p2sh_prefix = match self.network() {
            Network::Mainnet => SCRIPT_ADDRESS_PREFIX_MAIN,
            Network::Testnet | Network::Signet | Network::Regtest => SCRIPT_ADDRESS_PREFIX_TEST,
        };
        let hrp = match self.network() {
            Network::Mainnet => hrp::BC,
            Network::Testnet | Network::Signet => hrp::TB,
            Network::Regtest => hrp::BCRT,
        };
        let encoding = AddressEncoding { payload: self.payload(), p2pkh_prefix, p2sh_prefix, hrp };

        use fmt::Display;

        encoding.fmt(fmt)
    }

    /// Create new address from given components, infering the network validation
    /// marker type of the address.
    #[inline]
    pub fn new(network: Network, payload: Payload) -> Self {
        Self(AddressInner { network, payload }, PhantomData)
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: &PublicKey, network: Network) -> Address {
        Address::new(network, Payload::p2pkh(pk))
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2sh(script)?))
    }

    /// Creates a witness pay to public key address from a public key.
    ///
    /// This is the native segwit address type for an output redeemable with a single signature.
    ///
    /// # Errors
    /// Will only return an error if an uncompressed public key is provided.
    pub fn p2wpkh(pk: &PublicKey, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2wpkh(pk)?))
    }

    /// Creates a pay to script address that embeds a witness pay to public key.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    ///
    /// # Errors
    /// Will only return an Error if an uncompressed public key is provided.
    pub fn p2shwpkh(pk: &PublicKey, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2shwpkh(pk)?))
    }

    /// Creates a witness pay to script hash address.
    pub fn p2wsh(script: &Script, network: Network) -> Address {
        Address::new(network, Payload::p2wsh(script))
    }

    /// Creates a pay to script address that embeds a witness pay to script hash address.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(script: &Script, network: Network) -> Address {
        Address::new(network, Payload::p2shwsh(script))
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        network: Network,
    ) -> Address {
        Address::new(network, Payload::p2tr(secp, internal_key, merkle_root))
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    ///
    /// This method is not recommended for use, [`Address::p2tr()`] should be used where possible.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, network: Network) -> Address {
        Address::new(network, Payload::p2tr_tweaked(output_key))
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        self.address_type_internal()
    }

    /// Checks whether or not the address is following Bitcoin standardness rules when
    /// *spending* from this address. *NOT* to be called by senders.
    ///
    /// <details>
    /// <summary>Spending Standardness</summary>
    ///
    /// For forward compatibility, the senders must send to any [`Address`]. Receivers
    /// can use this method to check whether or not they can spend from this address.
    ///
    /// SegWit addresses with unassigned witness versions or non-standard program sizes are
    /// considered non-standard.
    /// </details>
    ///
    pub fn is_spend_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(script: &Script, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::from_script(script)?))
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.payload().script_pubkey()
    }

    /// Creates a URI string *bitcoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, the address becomes uppercase.
    /// If the address is base58, the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// Note however that despite BIP21 explicitly stating that the `bitcoin:` prefix should be
    /// parsed as case-insensitive many wallets got this wrong and don't parse correctly.
    /// [See compatibility table.](https://github.com/btcpayserver/btcpayserver/issues/2110)
    ///
    /// If you want to avoid allocation you can use alternate display instead:
    /// ```
    /// # use core::fmt::Write;
    /// # const ADDRESS: &str = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
    /// # let address = ADDRESS.parse::<bitcoin::Address<_>>().unwrap().assume_checked();
    /// # let mut writer = String::new();
    /// # // magic trick to make error handling look better
    /// # (|| -> Result<(), core::fmt::Error> {
    ///
    /// write!(writer, "{:#}", address)?;
    ///
    /// # Ok(())
    /// # })().unwrap();
    /// # assert_eq!(writer, ADDRESS);
    /// ```
    pub fn to_qr_uri(&self) -> String {
        format!("bellscoin:{:#}", self)
    }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the segwit redeem hash generated from the
    /// given key. For taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload().inner_prog_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(&pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: &XOnlyPublicKey) -> bool {
        let payload = self.payload().inner_prog_as_bytes();
        payload == xonly_pubkey.serialize()
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script_pubkey: &Script) -> bool {
        self.payload().matches_script_pubkey(script_pubkey)
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        unsafe { &*(self as *const Address<NetworkUnchecked> as *const Address) }
    }
    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and signet addresse use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 signet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use bitcoin::{Address, Network};
    /// use bitcoin::address::NetworkUnchecked;
    ///
    /// let address: Address<NetworkUnchecked> = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Signet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Bitcoin), false);
    ///
    /// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Bitcoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    /// ```
    pub fn is_valid_for_network(&self, network: Network) -> bool {
        let is_legacy = matches!(
            self.address_type_internal(),
            Some(AddressType::P2pkh) | Some(AddressType::P2sh)
        );

        match (self.network(), network) {
            (a, b) if *a == b => true,
            (Network::Mainnet, _) | (_, Network::Mainnet) => false,
            (Network::Regtest, _) | (_, Network::Regtest) if !is_legacy => false,
            (Network::Testnet, _) | (Network::Regtest, _) | (Network::Signet, _) => true,
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, Error> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(Error::NetworkValidation { found: *self.network(), required, address: self })
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address {
        let (network, payload) = self.into_parts();
        Address::new(network, payload)
    }
}

// For NetworkUnchecked , it compare Addresses and if network and payload matches then return true.
impl PartialEq<Address<NetworkUnchecked>> for Address {
    fn eq(&self, other: &Address<NetworkUnchecked>) -> bool {
        self.network() == other.network() && self.payload() == other.payload()
    }
}

impl PartialEq<Address> for Address<NetworkUnchecked> {
    fn eq(&self, other: &Address) -> bool {
        other == self
    }
}

impl From<Address> for script::ScriptBuf {
    fn from(a: Address) -> Self {
        a.script_pubkey()
    }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(fmt)
    }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            self.fmt_internal(f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            self.fmt_internal(f)?;
            write!(f, ")")
        }
    }
}

/// Extracts the bech32 prefix.
///
/// # Returns
/// The input slice if no prefix is found.
fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // try bech32
        let bech32_network = match find_bech32_prefix(s) {
            // note that upper or lowercase is allowed but NOT mixed case
            "bel" => Some(Network::Mainnet),
            "tbel" => Some(Network::Testnet), // this may also be signet
            "bcrt" => Some(Network::Regtest),
            _ => None,
        };
        if let Some(network) = bech32_network {
            let (_hrp, version, data) = bech32::segwit::decode(s)?;
            let version = WitnessVersion::try_from(version).expect("we know this is in range 0-16");
            let program = PushBytesBuf::try_from(data).expect("decode() guarantees valid length");
            let witness_program = WitnessProgram::new(version, program)?;

            return Ok(Address::new(network, Payload::WitnessProgram(witness_program)));
        }

        // Base58
        if s.len() > 50 {
            return Err(ParseError::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(ParseError::Base58(base58::Error::InvalidLength(data.len())));
        }

        let (network, payload) = match data[0] {
            PUBKEY_ADDRESS_PREFIX_MAIN => {
                (Network::Mainnet, Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()))
            }
            SCRIPT_ADDRESS_PREFIX_MAIN => {
                (Network::Mainnet, Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()))
            }
            PUBKEY_ADDRESS_PREFIX_TEST => {
                (Network::Testnet, Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()))
            }
            SCRIPT_ADDRESS_PREFIX_TEST => {
                (Network::Testnet, Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()))
            }
            x => return Err(ParseError::Base58(base58::Error::InvalidAddressVersion(x))),
        };

        Ok(Address::new(network, payload))
    }
}

/// Convert a byte array of a pubkey hash into a segwit redeem hash
fn segwit_redeem_hash(pubkey_hash: &PubkeyHash) -> crate::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash.as_ref());
    crate::hashes::hash160::Hash::from_engine(sha_engine)
}
