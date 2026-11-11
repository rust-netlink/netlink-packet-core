// SPDX-License-Identifier: MIT

use std::{error::Error, fmt};

use netlink_packet_core::{
    Emitable, EncodeError, NetlinkDeserializable, NetlinkHeader,
    NetlinkMessage, NetlinkMessagePayload, NetlinkPayload,
};

// PingPongMessage represent the messages for the "ping-pong" netlink
// protocol. There are only two types of messages.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PingPongMessage {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

// The netlink header contains a "message type" field that identifies
// the message it carries. Some values are reserved, and we
// arbitrarily decided that "ping" type is 18 and "pong" type is 20.
pub const PING_MESSAGE: u16 = 18;
pub const PONG_MESSAGE: u16 = 20;

// A custom error type for when deserialization fails. This is
// required because `NetlinkDeserializable::Error` must implement
// `std::error::Error`, so a simple `String` won't cut it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeserializeError(&'static str);

impl Error for DeserializeError {
    fn description(&self) -> &str {
        self.0
    }
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// NetlinkDeserializable implementation
impl NetlinkDeserializable for PingPongMessage {
    type Error = DeserializeError;

    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error> {
        match header.message_type {
            PING_MESSAGE => Ok(PingPongMessage::Ping(payload.to_vec())),
            PONG_MESSAGE => Ok(PingPongMessage::Pong(payload.to_vec())),
            _ => Err(DeserializeError(
                "invalid ping-pong message: invalid message type",
            )),
        }
    }
}

// Emitable provides the wire bytes; NetlinkMessagePayload provides the message
// type used in the netlink header.
impl Emitable for PingPongMessage {
    fn emit_value(&self, buffer: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            PingPongMessage::Ping(vec) | PingPongMessage::Pong(vec) => {
                buffer.extend_from_slice(vec);
            }
        }
        Ok(())
    }
}

impl NetlinkMessagePayload for PingPongMessage {
    fn message_type(&self) -> u16 {
        match self {
            PingPongMessage::Ping(_) => PING_MESSAGE,
            PingPongMessage::Pong(_) => PONG_MESSAGE,
        }
    }
}

// It can be convenient to be able to create a NetlinkMessage directly
// from a PingPongMessage. Since NetlinkMessage<T> already implements
// From<NetlinkPayload<T>>, we just need to implement
// From<NetlinkPayload<PingPongMessage>> for this to work.
impl From<PingPongMessage> for NetlinkPayload<PingPongMessage> {
    fn from(message: PingPongMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

fn main() {
    let ping_pong_message = PingPongMessage::Ping(vec![0, 1, 2, 3]);
    let packet = NetlinkMessage::from(ping_pong_message);

    // Serialize the packet. The header length and message type are computed
    // during emission.
    let mut buf = Vec::new();
    packet.emit(&mut buf).unwrap();

    // Deserialize the packet
    let deserialized_packet =
        NetlinkMessage::<PingPongMessage>::deserialize(&buf)
            .expect("Failed to deserialize message");

    // The serialized header is reconstructed when parsing; the original
    // in-memory packet header is not modified by emit().
    assert_eq!(deserialized_packet.payload, packet.payload);

    // This should print:
    // NetlinkMessage { header: NetlinkHeader { length: 20, message_type: 18,
    // flags: 0, sequence_number: 0, port_number: 0 }, payload:
    // InnerMessage(Ping([0, 1, 2, 3])) }
    println!("{deserialized_packet:?}");
}
