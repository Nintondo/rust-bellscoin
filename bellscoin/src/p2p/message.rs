// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network messages.
//!
//! This module defines the `NetworkMessage` and `RawNetworkMessage` types that
//! are used for (de)serializing Bitcoin objects for transmission on the network.
//!

use core::convert::TryFrom;
use core::{fmt, iter};

use hashes::{sha256d, Hash};
use io::Read as _;

use crate::blockdata::{block, transaction};
use crate::consensus::encode::{self, CheckedData, Decodable, Encodable, VarInt};
use crate::io;
use crate::merkle_tree::MerkleBlock;
use crate::p2p::address::{AddrV2Message, Address};
use crate::p2p::{
    message_blockdata, message_bloom, message_compact_blocks, message_filter, message_network,
    Magic,
};
use crate::prelude::*;

/// The maximum number of [super::message_blockdata::Inventory] items in an `inv` message.
///
/// This limit is not currently enforced by this implementation.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum size, in bytes, of an encoded message
/// This by neccessity should be larger tham `MAX_VEC_SIZE`
pub const MAX_MSG_SIZE: usize = 5_000_000;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(Cow<'static, str>);

impl CommandString {
    /// Converts `&'static str` to `CommandString`
    ///
    /// This is more efficient for string literals than non-static conversions because it avoids
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if, and only if, the string is
    /// larger than 12 characters in length.
    pub fn try_from_static(s: &'static str) -> Result<CommandString, CommandStringError> {
        Self::try_from_static_cow(s.into())
    }

    fn try_from_static_cow(cow: Cow<'static, str>) -> Result<CommandString, CommandStringError> {
        if cow.len() > 12 {
            Err(CommandStringError { cow })
        } else {
            Ok(CommandString(cow))
        }
    }
}

impl TryFrom<String> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.into())
    }
}

impl TryFrom<Box<str>> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: Box<str>) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(String::from(value).into())
    }
}

impl<'a> TryFrom<&'a str> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.to_owned().into())
    }
}

impl core::str::FromStr for CommandString {
    type Err = CommandStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_static_cow(s.to_owned().into())
    }
}

impl fmt::Display for CommandString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl AsRef<str> for CommandString {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Encodable for CommandString {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        debug_assert!(strbytes.len() <= 12);
        rawbytes[..strbytes.len()].copy_from_slice(strbytes);
        rawbytes.consensus_encode(w)
    }
}

impl Decodable for CommandString {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let rawbytes: [u8; 12] = Decodable::consensus_decode(r)?;
        let rv = iter::FromIterator::from_iter(rawbytes.iter().filter_map(|&u| {
            if u > 0 {
                Some(u as char)
            } else {
                None
            }
        }));
        Ok(CommandString(rv))
    }
}

/// Error returned when a command string is invalid.
///
/// This is currently returned for command strings longer than 12.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommandStringError {
    cow: Cow<'static, str>,
}

impl fmt::Display for CommandStringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "the command string '{}' has length {} which is larger than 12",
            self.cow,
            self.cow.len()
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CommandStringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// A Network message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawNetworkMessage {
    magic: Magic,
    payload: NetworkMessage,
    payload_len: u32,
    checksum: [u8; 4],
}

/// A Network message payload. Proper documentation is available on at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(Vec<(u32, Address)>),
    /// `inv`
    Inv(Vec<message_blockdata::Inventory>),
    /// `getdata`
    GetData(Vec<message_blockdata::Inventory>),
    /// `notfound`
    NotFound(Vec<message_blockdata::Inventory>),
    /// `getblocks`
    GetBlocks(message_blockdata::GetBlocksMessage),
    /// `getheaders`
    GetHeaders(message_blockdata::GetHeadersMessage),
    /// `mempool`
    MemPool,
    /// tx
    Tx(transaction::Transaction),
    /// `block`
    Block(block::Block),
    /// `headers`
    Headers(Vec<block::Header>),
    /// `sendheaders`
    SendHeaders,
    /// `getaddr`
    GetAddr,
    // TODO: checkorder,
    // TODO: submitorder,
    // TODO: reply,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64),
    /// `merkleblock`
    MerkleBlock(MerkleBlock),
    /// BIP 37 `filterload`
    FilterLoad(message_bloom::FilterLoad),
    /// BIP 37 `filteradd`
    FilterAdd(message_bloom::FilterAdd),
    /// BIP 37 `filterclear`
    FilterClear,
    /// BIP157 getcfilters
    GetCFilters(message_filter::GetCFilters),
    /// BIP157 cfilter
    CFilter(message_filter::CFilter),
    /// BIP157 getcfheaders
    GetCFHeaders(message_filter::GetCFHeaders),
    /// BIP157 cfheaders
    CFHeaders(message_filter::CFHeaders),
    /// BIP157 getcfcheckpt
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// BIP157 cfcheckpt
    CFCheckpt(message_filter::CFCheckpt),
    /// BIP152 sendcmpct
    SendCmpct(message_compact_blocks::SendCmpct),
    /// BIP152 cmpctblock
    CmpctBlock(message_compact_blocks::CmpctBlock),
    /// BIP152 getblocktxn
    GetBlockTxn(message_compact_blocks::GetBlockTxn),
    /// BIP152 blocktxn
    BlockTxn(message_compact_blocks::BlockTxn),
    /// `alert`
    Alert(Vec<u8>),
    /// `reject`
    Reject(message_network::Reject),
    /// `feefilter`
    FeeFilter(i64),
    /// `wtxidrelay`
    WtxidRelay,
    /// `addrv2`
    AddrV2(Vec<AddrV2Message>),
    /// `sendaddrv2`
    SendAddrV2,

    /// Any other message.
    Unknown {
        /// The command of this message.
        command: CommandString,
        /// The payload of this message.
        payload: Vec<u8>,
    },
}

impl NetworkMessage {
    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        match *self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::MerkleBlock(_) => "merkleblock",
            NetworkMessage::FilterLoad(_) => "filterload",
            NetworkMessage::FilterAdd(_) => "filteradd",
            NetworkMessage::FilterClear => "filterclear",
            NetworkMessage::GetCFilters(_) => "getcfilters",
            NetworkMessage::CFilter(_) => "cfilter",
            NetworkMessage::GetCFHeaders(_) => "getcfheaders",
            NetworkMessage::CFHeaders(_) => "cfheaders",
            NetworkMessage::GetCFCheckpt(_) => "getcfcheckpt",
            NetworkMessage::CFCheckpt(_) => "cfcheckpt",
            NetworkMessage::SendCmpct(_) => "sendcmpct",
            NetworkMessage::CmpctBlock(_) => "cmpctblock",
            NetworkMessage::GetBlockTxn(_) => "getblocktxn",
            NetworkMessage::BlockTxn(_) => "blocktxn",
            NetworkMessage::Alert(_) => "alert",
            NetworkMessage::Reject(_) => "reject",
            NetworkMessage::FeeFilter(_) => "feefilter",
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::AddrV2(_) => "addrv2",
            NetworkMessage::SendAddrV2 => "sendaddrv2",
            NetworkMessage::Unknown { .. } => "unknown",
        }
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        match *self {
            NetworkMessage::Unknown { command: ref c, .. } => c.clone(),
            _ => CommandString::try_from_static(self.cmd()).expect("cmd returns valid commands"),
        }
    }
}

impl RawNetworkMessage {
    /// Creates a [RawNetworkMessage]
    pub fn new(magic: Magic, payload: NetworkMessage) -> Self {
        let mut engine = sha256d::Hash::engine();
        let payload_len = payload.consensus_encode(&mut engine).expect("engine doesn't error");
        let payload_len = u32::try_from(payload_len).expect("network message use u32 as length");
        let checksum = sha256d::Hash::from_engine(engine);
        let checksum = [checksum[0], checksum[1], checksum[2], checksum[3]];
        Self { magic, payload, payload_len, checksum }
    }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage {
        &self.payload
    }

    /// Magic bytes to identify the network these messages are meant for
    pub fn magic(&self) -> &Magic {
        &self.magic
    }

    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        self.payload.cmd()
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        self.payload.command()
    }
}

struct HeaderSerializationWrapper<'a>(&'a Vec<block::Header>);

impl<'a> Encodable for HeaderSerializationWrapper<'a> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt::from(self.0.len()).consensus_encode(w)?;
        for header in self.0.iter() {
            len += header.consensus_encode(w)?;
            len += 0u8.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Encodable for NetworkMessage {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            NetworkMessage::Version(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Addr(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Inv(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetData(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::NotFound(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetBlocks(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetHeaders(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Tx(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Block(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Headers(ref dat) => {
                HeaderSerializationWrapper(dat).consensus_encode(writer)
            }
            NetworkMessage::Ping(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Pong(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::MerkleBlock(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::FilterLoad(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::FilterAdd(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetCFilters(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CFilter(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetCFHeaders(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CFHeaders(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetCFCheckpt(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CFCheckpt(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::SendCmpct(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CmpctBlock(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetBlockTxn(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::BlockTxn(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Alert(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Reject(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::FeeFilter(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::AddrV2(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => Ok(0),
            NetworkMessage::Unknown { payload: ref data, .. } => data.consensus_encode(writer),
        }
    }
}

impl Encodable for RawNetworkMessage {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(w)?;
        len += self.command().consensus_encode(w)?;
        len += self.payload_len.consensus_encode(w)?;
        len += self.checksum.consensus_encode(w)?;
        len += self.payload().consensus_encode(w)?;
        Ok(len)
    }
}

struct HeaderDeserializationWrapper(Vec<block::Header>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
            if u8::consensus_decode(r)? != 0u8 {
                return Err(encode::Error::ParseFailed(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}

impl Decodable for RawNetworkMessage {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode_from_finite_reader(r)?;
        let cmd = CommandString::consensus_decode_from_finite_reader(r)?;
        let checked_data = CheckedData::consensus_decode_from_finite_reader(r)?;
        let checksum = checked_data.checksum();
        let raw_payload = checked_data.into_data();
        let payload_len = raw_payload.len() as u32;

        let mut mem_d = io::Cursor::new(raw_payload);
        let payload = match &cmd.0[..] {
            "version" => {
                NetworkMessage::Version(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "verack" => NetworkMessage::Verack,
            "addr" => {
                NetworkMessage::Addr(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "inv" => {
                NetworkMessage::Inv(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "getdata" => {
                NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "getblocks" => NetworkMessage::GetBlocks(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getheaders" => NetworkMessage::GetHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "mempool" => NetworkMessage::MemPool,
            "block" => {
                NetworkMessage::Block(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "headers" => NetworkMessage::Headers(
                HeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut mem_d)?.0,
            ),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "ping" => {
                NetworkMessage::Ping(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "pong" => {
                NetworkMessage::Pong(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "merkleblock" => NetworkMessage::MerkleBlock(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filterload" => NetworkMessage::FilterLoad(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filteradd" => NetworkMessage::FilterAdd(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filterclear" => NetworkMessage::FilterClear,
            "tx" => NetworkMessage::Tx(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getcfilters" => NetworkMessage::GetCFilters(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfilter" => {
                NetworkMessage::CFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "getcfheaders" => NetworkMessage::GetCFHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfheaders" => NetworkMessage::CFHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfcheckpt" => NetworkMessage::CFCheckpt(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "reject" => {
                NetworkMessage::Reject(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "alert" => {
                NetworkMessage::Alert(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "feefilter" => NetworkMessage::FeeFilter(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "sendcmpct" => NetworkMessage::SendCmpct(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cmpctblock" => NetworkMessage::CmpctBlock(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getblocktxn" => NetworkMessage::GetBlockTxn(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "blocktxn" => NetworkMessage::BlockTxn(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "addrv2" => {
                NetworkMessage::AddrV2(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            _ => NetworkMessage::Unknown { command: cmd, payload: mem_d.into_inner() },
        };
        Ok(RawNetworkMessage { magic, payload, payload_len, checksum })
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}
