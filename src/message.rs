// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use crate::{
    append_bytes,
    buffer::NETLINK_HEADER_LEN,
    done::DONE_HEADER_LEN,
    emit_u16, emit_u32,
    payload::{NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN},
    DecodeError, DoneBuffer, DoneMessage, Emitable, EncodeError, ErrorBuffer,
    ErrorContext, ErrorMessage, NetlinkBuffer, NetlinkDeserializable,
    NetlinkHeader, NetlinkPayload, NetlinkSerializable, Parseable,
};

/// Represent a netlink message.
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
    /// Parse the given buffer as a netlink message
    pub fn deserialize(buffer: &[u8]) -> Result<Self, DecodeError> {
        let netlink_buffer = NetlinkBuffer::new_checked(&buffer)
            .context("failed deserializing NetlinkMessage")?;
        <Self as Parseable<NetlinkBuffer<&&[u8]>>>::parse(&netlink_buffer)
    }
}

impl<I> NetlinkMessage<I>
where
    I: NetlinkSerializable,
{
    /// Append this message to an existing buffer.
    ///
    /// This is the allocation-free entry point for transports such as
    /// `netlink-proto`, which append messages directly to their send buffer.
    /// The header length and message type are computed from the payload.
    pub fn serialize_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.emit_into(out)
    }
}

impl<B, I> Parseable<NetlinkBuffer<&B>> for NetlinkMessage<I>
where
    B: AsRef<[u8]>,
    I: NetlinkDeserializable,
{
    fn parse(buf: &NetlinkBuffer<&B>) -> Result<Self, DecodeError> {
        use self::NetlinkPayload::*;

        let header =
            <NetlinkHeader as Parseable<NetlinkBuffer<&B>>>::parse(buf)
                .context("failed parsing NetlinkHeader")?;

        let bytes = buf.payload();
        let payload = match header.message_type {
            NLMSG_ERROR => {
                let msg = ErrorBuffer::new_checked(&bytes)
                    .and_then(|buf| ErrorMessage::parse(&buf))
                    .context("failed parsing NLMSG_ERROR")?;
                Error(msg)
            }
            NLMSG_NOOP => Noop,
            NLMSG_DONE => {
                // Linux kernel allows zero sized of NLMSG_DONE
                let msg = if bytes.is_empty() {
                    DoneBuffer::new_checked(&[0u8; DONE_HEADER_LEN])
                        .and_then(|buf| DoneMessage::parse(&buf))
                        .context("failed to parse NLMSG_DONE")?
                } else {
                    DoneBuffer::new_checked(&bytes)
                        .and_then(|buf| DoneMessage::parse(&buf))
                        .context("failed to parse NLMSG_DONE")?
                };
                Done(msg)
            }
            NLMSG_OVERRUN => Overrun(bytes.to_vec()),
            message_type => match I::deserialize(&header, bytes) {
                Err(e) => {
                    return Err(format!(
                        "Failed to parse message with type {message_type}: {e}"
                    )
                    .into())
                }
                Ok(inner_msg) => InnerMessage(inner_msg),
            },
        };
        Ok(NetlinkMessage { header, payload })
    }
}

impl<I> Emitable for NetlinkMessage<I>
where
    I: NetlinkSerializable,
{
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use self::NetlinkPayload::*;

        let start = out.len();
        let message_type = self.payload.message_type();
        let header_end = start
            .checked_add(NETLINK_HEADER_LEN)
            .ok_or_else(|| EncodeError::length_overflow("netlink message"))?;
        out.resize(header_end, 0);

        let result = (|| -> Result<(), EncodeError> {
            match &self.payload {
                Noop => {}
                Done(msg) => msg.emit_into(out)?,
                Overrun(bytes) => append_bytes(out, bytes),
                Error(msg) => msg.emit_into(out)?,
                InnerMessage(msg) => msg.emit_into(out)?,
            }

            let total = out.len() - start;
            if total > u32::MAX as usize {
                return Err(EncodeError::message_too_long(
                    total,
                    u32::MAX as usize,
                ));
            }

            emit_u32(&mut out[start..start + 4], total as u32)?;
            emit_u16(&mut out[start + 4..start + 6], message_type)?;
            emit_u16(&mut out[start + 6..start + 8], self.header.flags)?;
            emit_u32(
                &mut out[start + 8..start + 12],
                self.header.sequence_number,
            )?;
            emit_u32(
                &mut out[start + 12..header_end],
                self.header.port_number,
            )?;
            Ok(())
        })();

        if let Err(error) = result {
            out.truncate(start);
            return Err(error);
        }
        Ok(())
    }
}

impl<I> NetlinkSerializable for NetlinkMessage<I>
where
    I: NetlinkSerializable,
{
    fn message_type(&self) -> u16 {
        self.payload.message_type()
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

    use std::{convert::Infallible, mem::size_of, num::NonZeroI32};

    fn emit<T: Emitable>(value: &T) -> Vec<u8> {
        let mut out = Vec::new();
        value.emit_into(&mut out).unwrap();
        out
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct FakeNetlinkInnerMessage;

    impl Emitable for FakeNetlinkInnerMessage {
        fn emit_into(&self, _out: &mut Vec<u8>) -> Result<(), EncodeError> {
            unimplemented!("unused by tests")
        }
    }

    impl NetlinkDeserializable for FakeNetlinkInnerMessage {
        type Error = Infallible;

        fn deserialize(
            _header: &NetlinkHeader,
            _payload: &[u8],
        ) -> Result<Self, Self::Error> {
            unimplemented!("unused by tests")
        }
    }

    impl NetlinkSerializable for FakeNetlinkInnerMessage {
        fn message_type(&self) -> u16 {
            unimplemented!("unused by tests")
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

        let done_buf = DoneBuffer::new(&buf[NETLINK_HEADER_LEN..]);
        assert_eq!(done_buf.code(), done_msg.code);
        assert_eq!(done_buf.extended_ack(), &done_msg.extended_ack);

        let got = NetlinkMessage::parse(&NetlinkBuffer::new(&buf)).unwrap();
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
            NetlinkHeader::parse(&NetlinkBuffer::new_checked(&buf).unwrap())
                .unwrap();
        assert_eq!(parsed.length, NETLINK_HEADER_LEN as u32);
        assert_eq!(parsed.message_type, NLMSG_NOOP);
        assert_eq!(parsed.flags, 0x0001);
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.port_number, 7);
    }

    #[test]
    fn serialize_into_appends_to_existing_buffer() {
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
        msg.serialize_into(&mut out).unwrap();
        assert_eq!(out[0], 0xaa);
        assert_eq!(&out[1..], emit(&msg));
    }

    #[test]
    fn test_error() {
        // SAFETY: value is non-zero.
        const ERROR_CODE: NonZeroI32 = NonZeroI32::new(-8765).unwrap();

        let header = NetlinkHeader::default();
        let error_msg = ErrorMessage {
            code: Some(ERROR_CODE),
            header: vec![],
        };
        let mut want = NetlinkMessage::new(
            header,
            NetlinkPayload::<FakeNetlinkInnerMessage>::Error(error_msg.clone()),
        );

        let buf = emit(&want);
        assert_eq!(buf.len(), NETLINK_HEADER_LEN + emit(&error_msg).len());

        let error_buf = ErrorBuffer::new(&buf[NETLINK_HEADER_LEN..]);
        assert_eq!(error_buf.code(), error_msg.code);

        let got = NetlinkMessage::parse(&NetlinkBuffer::new(&buf)).unwrap();
        want.header.length = buf.len() as u32;
        want.header.message_type = NLMSG_ERROR;
        assert_eq!(got, want);
    }
}
