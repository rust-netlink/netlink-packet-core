// SPDX-License-Identifier: MIT

use crate::{
    append_bytes, DecodeError, Emitable, EncodeError, NetlinkDeserializable,
    NetlinkHeader, NetlinkMessagePayload,
};

/// An opaque netlink message whose type is unknown to the caller.
///
/// [`DefaultNla`](crate::DefaultNla) represents an unknown *attribute* nested
/// inside a message payload, while `DefaultMessage` represents a whole
/// message: it preserves the raw message type and payload so the message can
/// be inspected or re-emitted unchanged.
///
/// Unlike protocol-specific string payloads, the payload is kept as raw bytes,
/// so NUL bytes, invalid UTF-8, and trailing padding survive a parse/emit
/// round-trip.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DefaultMessage {
    message_type: u16,
    payload: Vec<u8>,
}

impl DefaultMessage {
    /// Create an opaque message from its raw message type and payload.
    pub fn new(message_type: u16, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            payload,
        }
    }

    /// Return the raw netlink message type.
    pub fn message_type(&self) -> u16 {
        self.message_type
    }

    /// Return the raw message payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Emitable for DefaultMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, &self.payload);
        Ok(())
    }
}

impl NetlinkMessagePayload for DefaultMessage {
    fn message_type(&self) -> u16 {
        self.message_type
    }
}

impl NetlinkDeserializable for DefaultMessage {
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(Self::new(header.message_type, payload.to_vec()))
    }
}

impl From<DefaultMessage> for crate::NetlinkPayload<DefaultMessage> {
    fn from(message: DefaultMessage) -> Self {
        crate::NetlinkPayload::InnerMessage(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetlinkMessage;

    #[test]
    fn accessors() {
        let message = DefaultMessage::new(0x1234, vec![0, 1, 2, 0, 0xff]);
        assert_eq!(message.message_type(), 0x1234);
        assert_eq!(message.payload(), &[0, 1, 2, 0, 0xff]);
    }

    #[test]
    fn parse_preserves_raw_payload() {
        let header = NetlinkHeader {
            message_type: 0x1234,
            ..Default::default()
        };
        let payload = [b'a', 0, b'b', 0xff];

        let message = DefaultMessage::deserialize(&header, &payload).unwrap();
        assert_eq!(message.message_type(), 0x1234);
        assert_eq!(message.payload(), &payload);
    }

    #[test]
    fn round_trip_netlink_message() {
        let message = DefaultMessage::new(0x1234, vec![b'a', 0, b'b', 0xff]);
        let packet = NetlinkMessage::from(message.clone());

        let mut buffer = Vec::new();
        packet.emit(&mut buffer).unwrap();

        let parsed =
            NetlinkMessage::<DefaultMessage>::deserialize(&buffer).unwrap();
        assert_eq!(parsed.header.message_type, 0x1234);
        assert_eq!(
            parsed.payload,
            crate::NetlinkPayload::InnerMessage(message)
        );
    }
}
