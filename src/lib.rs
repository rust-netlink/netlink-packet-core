// SPDX-License-Identifier: MIT

//! `netlink-packet-core` provides a generic netlink message
//! `NetlinkMessage<T>` that is independant of the sub-protocol. Such
//! messages are not very useful by themselves, since they are just
//! used to carry protocol-dependant messages. That is what the `T`
//! represent: `T` is the `NetlinkMessage`'s protocol-dependant
//! message. This can be any type that implements
//! `NetlinkMessagePayload` and `NetlinkDeserializable`.
//!
//! For instance, the `netlink-packet-route` crate provides rtnetlink
//! messages via `netlink_packet_route::RouteNetlinkMessage`, and
//! `netlink-packet-audit` provides audit messages via
//! `netlink_packet_audit::AuditMessage`.
//!
//! By itself, the `netlink-packet-core` crate is not very
//! useful. However, it is used in `netlink-proto` to provide an
//! asynchronous implementation of the netlink protocol for any
//! sub-protocol. Thus, a crate that defines messages for a given
//! netlink sub-protocol could integrate with `netlink-packet-core`
//! and would get an asynchronous implementation for free. See the
//! second example below for such an integration, via the
//! `NetlinkMessagePayload` and `NetlinkDeserializable` traits.
//!
//! # Example: usage with `netlink-packet-route`
//!
//! This example shows how to serialize and deserialize netlink packet
//! for the rtnetlink sub-protocol. It requires
//! `netlink-packet-route`.
//!
//! ```rust,ignore
//! use netlink_packet_core::{
//!     Emitable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP,
//!     NLM_F_REQUEST,
//! };
//! use netlink_packet_route::{link::LinkMessage, RouteNetlinkMessage};
//!
//! // Create the netlink message, that contains the rtnetlink
//! // message
//! let mut header = NetlinkHeader::default();
//! header.sequence_number = 1;
//! header.flags = NLM_F_DUMP | NLM_F_REQUEST;
//! let packet = NetlinkMessage::new(
//!     header,
//!     NetlinkPayload::from(RouteNetlinkMessage::GetLink(
//!         LinkMessage::default(),
//!     )),
//! );
//!
//! // Serialize the packet. The header length and message type are
//! // computed during emission.
//! let mut buf = Vec::new();
//! packet.emit(&mut buf).unwrap();
//!
//! // Deserialize the packet
//! let deserialized_packet = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf)
//!     .expect("Failed to deserialize message");
//!
//! // The serialized header is reconstructed when parsing; the original
//! // in-memory packet header is not modified by emit().
//! assert_eq!(deserialized_packet.payload, packet.payload);
//!
//! println!("{:?}", deserialized_packet);
//! ```
//!
//! # Example: adding messages for new netlink sub-protocol
//!
//! Let's assume we have a netlink protocol called "ping pong" that
//! defines two types of messages: "ping" messages, which payload can
//! be any sequence of bytes, and "pong" message, which payload is
//! also a sequence of bytes.  The protocol works as follow: when an
//! enpoint receives a "ping" message, it answers with a "pong", with
//! the payload of the "ping" it's answering to.
//!
//! "ping" messages have type 18 and "pong" have type "20". Here is
//! what a "ping" message that would look like if its payload is `[0,
//! 1, 2, 3]`:
//!
//! ```no_rust
//! 0                8                16              24               32
//! +----------------+----------------+----------------+----------------+
//! |                 packet length (including header) = 16 + 4 = 20    |
//! +----------------+----------------+----------------+----------------+
//! |     message type = 18 (ping)    |              flags              |
//! +----------------+----------------+----------------+----------------+
//! |                           sequence number                         |
//! +----------------+----------------+----------------+----------------+
//! |                            port number                            |
//! +----------------+----------------+----------------+----------------+
//! |       0        |         1      |         2      |        3       |
//! +----------------+----------------+----------------+----------------+
//! ```
//!
//! And the "pong" response would be:
//!
//! ```no_rust
//! 0                8                16              24               32
//! +----------------+----------------+----------------+----------------+
//! |                 packet length (including header) = 16 + 4 = 20    |
//! +----------------+----------------+----------------+----------------+
//! |     message type = 20 (pong)    |              flags              |
//! +----------------+----------------+----------------+----------------+
//! |                           sequence number                         |
//! +----------------+----------------+----------------+----------------+
//! |                            port number                            |
//! +----------------+----------------+----------------+----------------+
//! |       0        |         1      |         2      |        3       |
//! +----------------+----------------+----------------+----------------+
//! ```
//!
//! Here is how we could implement the messages for such a protocol
//! and integrate this implementation with `netlink-packet-core`:
//!
//! ```rust
//! use netlink_packet_core::{
//!     DecodeError, DecodeErrorKind, Emitable, NetlinkDeserializable,
//!     NetlinkHeader, NetlinkMessage, NetlinkMessagePayload, NetlinkPayload,
//! };
//!
//! // PingPongMessage represent the messages for the "ping-pong" netlink
//! // protocol. There are only two types of messages.
//! #[derive(Debug, Clone, Eq, PartialEq)]
//! pub enum PingPongMessage {
//!     Ping(Vec<u8>),
//!     Pong(Vec<u8>),
//! }
//!
//! // The netlink header contains a "message type" field that identifies
//! // the message it carries. Some values are reserved, and we
//! // arbitrarily decided that "ping" type is 18 and "pong" type is 20.
//! pub const PING_MESSAGE: u16 = 18;
//! pub const PONG_MESSAGE: u16 = 20;
//!
//! // NetlinkDeserializable implementation
//! impl NetlinkDeserializable for PingPongMessage {
//!     fn deserialize(
//!         header: &NetlinkHeader,
//!         payload: &[u8],
//!     ) -> Result<Self, DecodeError> {
//!         match header.message_type {
//!             PING_MESSAGE => Ok(PingPongMessage::Ping(payload.to_vec())),
//!             PONG_MESSAGE => Ok(PingPongMessage::Pong(payload.to_vec())),
//!             _ => Err(DecodeError::new(
//!                 DecodeErrorKind::InvalidValue,
//!                 "invalid ping-pong message: invalid message type",
//!             )),
//!         }
//!     }
//! }
//!
//! // Emitable provides the wire bytes; NetlinkMessagePayload provides the
//! // message type used in the netlink header.
//! impl Emitable for PingPongMessage {
//!     fn emit_value(
//!         &self,
//!         buffer: &mut Vec<u8>,
//!     ) -> Result<(), netlink_packet_core::EncodeError> {
//!         match self {
//!             PingPongMessage::Ping(vec) | PingPongMessage::Pong(vec) => {
//!                 buffer.extend_from_slice(vec);
//!             }
//!         }
//!         Ok(())
//!     }
//! }
//!
//! impl NetlinkMessagePayload for PingPongMessage {
//!     fn message_type(&self) -> u16 {
//!         match self {
//!             PingPongMessage::Ping(_) => PING_MESSAGE,
//!             PingPongMessage::Pong(_) => PONG_MESSAGE,
//!         }
//!     }
//! }
//!
//! // It can be convenient to be able to create a NetlinkMessage directly
//! // from a PingPongMessage. Since NetlinkMessage<T> already implements
//! // From<NetlinkPayload<T>>, we just need to implement
//! // From<NetlinkPayload<PingPongMessage>> for this to work.
//! impl From<PingPongMessage> for NetlinkPayload<PingPongMessage> {
//!     fn from(message: PingPongMessage) -> Self {
//!         NetlinkPayload::InnerMessage(message)
//!     }
//! }
//!
//! fn main() {
//!     let ping_pong_message = PingPongMessage::Ping(vec![0, 1, 2, 3]);
//!     let packet = NetlinkMessage::from(ping_pong_message);
//!
//!     // Serialize the packet. The header length and message type are
//!     // computed during emission.
//!     let mut buf = Vec::new();
//!     packet.emit(&mut buf).unwrap();
//!
//!     // Deserialize the packet
//!     let deserialized_packet = NetlinkMessage::<PingPongMessage>::deserialize(&buf)
//!         .expect("Failed to deserialize message");
//!
//!     // The serialized header is reconstructed when parsing; the original
//!     // in-memory packet header is not modified by emit().
//!     assert_eq!(deserialized_packet.payload, packet.payload);
//!
//!     // This should print:
//!     // NetlinkMessage { header: NetlinkHeader { length: 20, message_type: 18, flags: 0, sequence_number: 0, port_number: 0 }, payload: InnerMessage(Ping([0, 1, 2, 3])) }
//!     println!("{:?}", deserialized_packet);
//! }
//! ```

use core::ops::{Range, RangeFrom};
/// Represent a multi-bytes field with a fixed size in a packet
pub(crate) type Field = Range<usize>;
/// Represent a field that starts at a given index in a packet
pub(crate) type Rest = RangeFrom<usize>;

mod buffer;
mod constants;
mod done;
mod error;
mod header;
mod mac;
mod message;
mod nla;
mod parsers;
mod payload;
mod traits;

pub use self::buffer::NetlinkBuffer;
pub use self::constants::{
    NLM_F_ACK, NLM_F_ACK_TLVS, NLM_F_APPEND, NLM_F_ATOMIC, NLM_F_BULK,
    NLM_F_CAPPED, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_FILTERED,
    NLM_F_DUMP_INTR, NLM_F_ECHO, NLM_F_EXCL, NLM_F_MATCH, NLM_F_MULTIPART,
    NLM_F_NONREC, NLM_F_REPLACE, NLM_F_REQUEST, NLM_F_ROOT,
};
pub use self::done::{DoneBuffer, DoneMessage};
pub use self::error::{
    DecodeError, DecodeErrorKind, EncodeError, EncodeErrorKind, ErrorBuffer,
    ErrorContext, ErrorMessage,
};
pub use self::header::NetlinkHeader;
pub use self::mac::EthernetProtocol;
pub use self::message::NetlinkMessage;
pub use self::nla::{
    nla_total_size, DefaultNla, NlaBuffer, NlasIterator, NLA_F_NESTED,
    NLA_F_NET_BYTEORDER, NLA_HEADER_SIZE, NLA_MAX_VALUE_LEN, NLA_TYPE_MASK,
};
pub use self::parsers::{
    append_bytes, append_i32, append_i64, append_u16, append_u16_be,
    append_u32, append_u32_be, append_u64, append_u64_be, append_u8, parse_i32,
    parse_i64, parse_i8, parse_ip, parse_ipv6, parse_mac, parse_string,
    parse_u16, parse_u16_be, parse_u16_le, parse_u32, parse_u32_be, parse_u64,
    parse_u64_be, parse_u8,
};
pub use self::payload::NetlinkPayload;
pub use self::traits::{
    Emitable, NetlinkDeserializable, NetlinkMessagePayload, Nla, Parseable,
    ParseableParametrized,
};
