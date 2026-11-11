// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use crate::{
    append_bytes,
    buffer::NETLINK_HEADER_LEN,
    done::DONE_HEADER_LEN,
    payload::{NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN},
    DecodeError, DoneBuffer, DoneMessage, Emitable, EncodeError,
    EncodeErrorKind, ErrorBuffer, ErrorContext, ErrorMessage, NetlinkBuffer,
    NetlinkDeserializable, NetlinkHeader, NetlinkMessagePayload,
    NetlinkPayload, Parseable,
};

/// Represent a netlink message.
///
/// When this message is emitted (with [`Emitable::emit`]), the netlink
/// header written to the output gets its `length` from the number of bytes
/// emitted and its `message_type` from `self.payload.message_type()`. They are
/// not taken from `self.header`, which is left unchanged by emission. Emit a
/// [`NetlinkHeader`] directly instead to write its fields verbatim.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NetlinkMessage<I> {
    /// Message header (this is common to all the netlink protocols)
    pub header: NetlinkHeader,
    /// Inner message, which depends on the netlink protocol being used.
    pub payload: NetlinkPayload<I>,
}

impl<I> NetlinkMessage<I> {
    /// Create a new netlink message from the given header and payload
    pub fn new(header: NetlinkHeader, payload: NetlinkPayload<I>) -> Self {
        NetlinkMessage { header, payload }
    }

    /// Consume this message and return its header and payload
    pub fn into_parts(self) -> (NetlinkHeader, NetlinkPayload<I>) {
        (self.header, self.payload)
    }
}

impl<I> NetlinkMessage<I>
where
    I: NetlinkDeserializable,
{
    /// Parse an already validated netlink buffer.
    ///
    /// Use this when the caller already validated the buffer, for example to
    /// determine the datagram length, and wants to avoid validating it a
    /// second time. [`deserialize`](Self::deserialize) is the byte-slice
    /// convenience wrapper.
    pub fn parse_buffer<B>(
        buffer: &NetlinkBuffer<&B>,
    ) -> Result<Self, DecodeError>
    where
        B: AsRef<[u8]> + ?Sized,
    {
        use self::NetlinkPayload::*;

        let header =
            <NetlinkHeader as Parseable<NetlinkBuffer<&B>>>::parse(buffer)
                .context("failed parsing NetlinkHeader")?;

        let bytes = buffer.payload();
        let payload = match header.message_type {
            NLMSG_ERROR => {
                let msg = ErrorBuffer::new(&bytes)
                    .and_then(|buf| ErrorMessage::parse(&buf))
                    .context("failed parsing NLMSG_ERROR")?;
                Error(msg)
            }
            NLMSG_NOOP => Noop,
            NLMSG_DONE => {
                // Linux kernel allows zero sized of NLMSG_DONE
                let msg = if bytes.is_empty() {
                    DoneBuffer::new(&[0u8; DONE_HEADER_LEN])
                        .and_then(|buf| DoneMessage::parse(&buf))
                        .context("failed to parse NLMSG_DONE")?
                } else {
                    DoneBuffer::new(&bytes)
                        .and_then(|buf| DoneMessage::parse(&buf))
                        .context("failed to parse NLMSG_DONE")?
                };
                Done(msg)
            }
            NLMSG_OVERRUN => Overrun(bytes.to_vec()),
            message_type => InnerMessage(
                I::deserialize(&header, bytes).with_context(|| {
                    format!("failed to parse message with type {message_type}")
                })?,
            ),
        };
        Ok(NetlinkMessage { header, payload })
    }

    /// Parse the given buffer as a netlink message.
    ///
    /// This validates `buffer` and then calls
    /// [`parse_buffer`](Self::parse_buffer). Any `AsRef<[u8]>` is accepted,
    /// such as `&[u8]`, `Vec<u8>`, or a fixed-size array. If you already have
    /// a validated [`NetlinkBuffer`], call `parse_buffer` directly to avoid
    /// validating twice.
    pub fn deserialize(buffer: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        let bytes = buffer.as_ref();
        let netlink_buffer = NetlinkBuffer::new(bytes)
            .context("failed deserializing NetlinkMessage")?;
        Self::parse_buffer(&netlink_buffer)
    }
}

impl<B, I> Parseable<NetlinkBuffer<&B>> for NetlinkMessage<I>
where
    B: AsRef<[u8]> + ?Sized,
    I: NetlinkDeserializable,
{
    fn parse(buf: &NetlinkBuffer<&B>) -> Result<Self, DecodeError> {
        Self::parse_buffer(buf)
    }
}

impl<I> Emitable for NetlinkMessage<I>
where
    I: NetlinkMessagePayload,
{
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use self::NetlinkPayload::*;

        let start = out.len();
        let message_type = self.payload.message_type();
        let header_end = start
            .checked_add(NETLINK_HEADER_LEN)
            .ok_or_else(|| EncodeError::length_overflow("netlink message"))?;
        out.resize(header_end, 0);

        match &self.payload {
            Noop => {}
            Done(msg) => msg.emit(out)?,
            Overrun(bytes) => append_bytes(out, bytes),
            Error(msg) => msg.emit(out)?,
            InnerMessage(msg) => msg.emit(out)?,
        }

        if out.len() < header_end {
            return Err(EncodeError::new(
                EncodeErrorKind::Bug,
                "netlink message payload emitter truncated the buffer below \
                 the netlink header",
            ));
        }

        let total = out.len() - start;
        if total > u32::MAX as usize {
            return Err(EncodeError::message_too_long(
                total,
                u32::MAX as usize,
            ));
        }

        out[start..start + 4].copy_from_slice(&(total as u32).to_ne_bytes());
        out[start + 4..start + 6].copy_from_slice(&message_type.to_ne_bytes());
        out[start + 6..start + 8]
            .copy_from_slice(&self.header.flags.to_ne_bytes());
        out[start + 8..start + 12]
            .copy_from_slice(&self.header.sequence_number.to_ne_bytes());
        out[start + 12..header_end]
            .copy_from_slice(&self.header.port_number.to_ne_bytes());
        Ok(())
    }
}

impl<T> From<T> for NetlinkMessage<T>
where
    T: Into<NetlinkPayload<T>>,
{
    fn from(inner_message: T) -> Self {
        NetlinkMessage {
            header: NetlinkHeader::default(),
            payload: inner_message.into(),
        }
    }
}

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod tests {
    use super::*;

    use std::{mem::size_of, num::NonZeroI32};

    fn emit<T: Emitable>(value: &T) -> Vec<u8> {
        let mut out = Vec::new();
        value.emit(&mut out).unwrap();
        out
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct FakeNetlinkInnerMessage;

    impl Emitable for FakeNetlinkInnerMessage {
        fn emit_value(&self, _out: &mut Vec<u8>) -> Result<(), EncodeError> {
            unimplemented!("unused by tests")
        }
    }

    impl NetlinkDeserializable for FakeNetlinkInnerMessage {
        fn deserialize(
            _header: &NetlinkHeader,
            _payload: &[u8],
        ) -> Result<Self, DecodeError> {
            unimplemented!("unused by tests")
        }
    }

    impl NetlinkMessagePayload for FakeNetlinkInnerMessage {
        fn message_type(&self) -> u16 {
            unimplemented!("unused by tests")
        }
    }

    // Arbitrary non-reserved message type. These tests fail before the header
    // is written, so the actual value is never observed.
    const TEST_MESSAGE_TYPE: u16 = 0x1234;

    #[derive(Clone, Debug, Default, PartialEq)]
    struct FailingDeserializeMessage;

    impl Emitable for FailingDeserializeMessage {
        fn emit_value(&self, _out: &mut Vec<u8>) -> Result<(), EncodeError> {
            Ok(())
        }
    }

    impl NetlinkMessagePayload for FailingDeserializeMessage {
        fn message_type(&self) -> u16 {
            TEST_MESSAGE_TYPE
        }
    }

    impl NetlinkDeserializable for FailingDeserializeMessage {
        fn deserialize(
            _header: &NetlinkHeader,
            _payload: &[u8],
        ) -> Result<Self, DecodeError> {
            Err(DecodeError::new(
                crate::DecodeErrorKind::InvalidValue,
                "boom",
            ))
        }
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct FailingInnerMessage;

    impl Emitable for FailingInnerMessage {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            out.extend_from_slice(&[1, 2, 3]);
            Err(EncodeError::new(
                EncodeErrorKind::Bug,
                "inner message emission failed",
            ))
        }
    }

    impl NetlinkMessagePayload for FailingInnerMessage {
        fn message_type(&self) -> u16 {
            TEST_MESSAGE_TYPE
        }
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct TruncatingInnerMessage;

    impl Emitable for TruncatingInnerMessage {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            let len = out.len();
            out.truncate(len.saturating_sub(4));
            Ok(())
        }
    }

    impl NetlinkMessagePayload for TruncatingInnerMessage {
        fn message_type(&self) -> u16 {
            TEST_MESSAGE_TYPE
        }
    }

    #[test]
    fn test_done() {
        let header = NetlinkHeader::default();
        let done_msg = DoneMessage {
            code: 0,
            extended_ack: vec![6, 7, 8, 9],
        };
        let mut want = NetlinkMessage::new(
            header,
            NetlinkPayload::<FakeNetlinkInnerMessage>::Done(done_msg.clone()),
        );

        let buf = emit(&want);
        assert_eq!(
            buf.len(),
            NETLINK_HEADER_LEN + size_of::<i32>() + done_msg.extended_ack.len()
        );

        let done_buf = DoneBuffer::new(&buf[NETLINK_HEADER_LEN..]).unwrap();
        assert_eq!(done_buf.code(), done_msg.code);
        assert_eq!(done_buf.extended_ack(), &done_msg.extended_ack);

        let got =
            NetlinkMessage::parse(&NetlinkBuffer::new(&buf).unwrap()).unwrap();
        want.header.length = buf.len() as u32;
        want.header.message_type = NLMSG_DONE;
        assert_eq!(got, want);
    }

    #[test]
    fn emit_computes_header() {
        let header = NetlinkHeader {
            length: 1234,
            message_type: 5678,
            flags: 0x0001,
            sequence_number: 42,
            port_number: 7,
        };
        let msg = NetlinkMessage::<FakeNetlinkInnerMessage>::new(
            header,
            NetlinkPayload::Noop,
        );

        let buf = emit(&msg);
        let parsed =
            NetlinkHeader::parse(&NetlinkBuffer::new(&buf).unwrap()).unwrap();
        assert_eq!(parsed.length, NETLINK_HEADER_LEN as u32);
        assert_eq!(parsed.message_type, NLMSG_NOOP);
        assert_eq!(parsed.flags, 0x0001);
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.port_number, 7);
    }

    #[test]
    fn inner_deserialize_error_keeps_kind_and_context() {
        let msg = NetlinkMessage::<FailingDeserializeMessage>::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(FailingDeserializeMessage),
        );
        let buf = emit(&msg);

        let err = NetlinkMessage::<FailingDeserializeMessage>::deserialize(buf)
            .unwrap_err();
        assert_eq!(err.kind(), crate::DecodeErrorKind::InvalidValue);
        let text = err.to_string();
        assert!(text.contains("failed to parse message with type"));
        assert!(text.contains("boom"));
    }

    #[test]
    fn inner_message_error_rolls_back() {
        let msg = NetlinkMessage::<FailingInnerMessage>::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(FailingInnerMessage),
        );

        let mut out = vec![0xaa, 0xbb];
        let error = msg.emit(&mut out).unwrap_err();
        assert_eq!(error.kind(), crate::EncodeErrorKind::Bug);
        assert_eq!(out, vec![0xaa, 0xbb]);
    }

    #[test]
    fn inner_message_truncation_is_an_error() {
        let msg = NetlinkMessage::<TruncatingInnerMessage>::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(TruncatingInnerMessage),
        );

        let mut out = vec![0xaa, 0xbb];
        let error = msg.emit(&mut out).unwrap_err();
        assert_eq!(error.kind(), crate::EncodeErrorKind::Bug);
        assert_eq!(out, vec![0xaa, 0xbb]);
    }

    #[test]
    fn emit_appends_to_existing_buffer() {
        let header = NetlinkHeader {
            length: NETLINK_HEADER_LEN as u32,
            message_type: 1234,
            ..Default::default()
        };
        let msg = NetlinkMessage::<FakeNetlinkInnerMessage>::new(
            header,
            NetlinkPayload::Noop,
        );

        let mut out = vec![0xaa];
        msg.emit(&mut out).unwrap();
        assert_eq!(out[0], 0xaa);
        assert_eq!(&out[1..], emit(&msg));
    }

    #[test]
    fn test_error() {
        let error_code = NonZeroI32::new(-8765).unwrap();

        let header = NetlinkHeader::default();
        let error_msg = ErrorMessage {
            code: Some(error_code),
            header: vec![],
        };
        let mut want = NetlinkMessage::new(
            header,
            NetlinkPayload::<FakeNetlinkInnerMessage>::Error(error_msg.clone()),
        );

        let buf = emit(&want);
        assert_eq!(buf.len(), NETLINK_HEADER_LEN + emit(&error_msg).len());

        let error_buf = ErrorBuffer::new(&buf[NETLINK_HEADER_LEN..]).unwrap();
        assert_eq!(error_buf.code(), error_msg.code);

        let got =
            NetlinkMessage::parse(&NetlinkBuffer::new(&buf).unwrap()).unwrap();
        want.header.length = buf.len() as u32;
        want.header.message_type = NLMSG_ERROR;
        assert_eq!(got, want);
    }
}
