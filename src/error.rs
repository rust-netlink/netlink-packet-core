// SPDX-License-Identifier: MIT

use std::{fmt, io, num::NonZeroI32};

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::DecodeError;

use crate::utils::nla::{DefaultNla, Nla, NlaBuffer, NlasIterator};
use crate::utils::parsers::parse_string;
use crate::{Emitable, Field, NetlinkBuffer, NetlinkHeader, Parseable, Rest};

const CODE: Field = 0..4;
const ORIGINAL_REQUEST_HEADER: Field = 4..20;
const ORIGINAL_REQUEST_LENGTH: Field = 4..8;
const OPTIONAL_PARTS: Rest = 20..;
const MIN_ERROR_MESSAGE_LEN: usize = OPTIONAL_PARTS.start;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct ErrorBuffer<T> {
    buffer: T,
    has_request_payload: bool,
}

impl<T: AsRef<[u8]>> ErrorBuffer<T> {
    pub fn new(buffer: T, has_request_payload: bool) -> ErrorBuffer<T> {
        ErrorBuffer {
            buffer,
            has_request_payload,
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn new_checked(
        buffer: T,
        has_request_payload: bool,
    ) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer, has_request_payload);
        packet.check_buffer_length()?;
        Ok(packet)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < MIN_ERROR_MESSAGE_LEN {
            Err(format!(
                "invalid ErrorBuffer: length is {len} but ErrorBuffer are \
                at least {MIN_ERROR_MESSAGE_LEN} bytes"
            )
            .into())
        } else if self.has_request_payload
            && len < MIN_ERROR_MESSAGE_LEN + self.request_payload_length()
        {
            let payload_length = self.request_payload_length();
            Err(format!(
                "invalid ErrorBuffer: length is {len} but ErrorBuffer are \
                at least {MIN_ERROR_MESSAGE_LEN} bytes plus the request's payload \
                indicated as {payload_length}"
            )
            .into())
        } else {
            Ok(())
        }
    }

    /// Return the error code.
    ///
    /// Returns `None` when there is no error to report (the message is an ACK),
    /// or a `Some(e)` if there is a non-zero error code `e` to report (the
    /// message is a NACK).
    pub fn code(&self) -> Option<NonZeroI32> {
        let data = self.buffer.as_ref();
        NonZeroI32::new(NativeEndian::read_i32(&data[CODE]))
    }

    /// Return length of the original request payload.
    /// Also returns the original length if has_request_payload is not set.
    ///
    /// # Panic
    ///
    /// This panics if the length can not be converted to usize.
    pub fn request_payload_length(&self) -> usize {
        let data = self.buffer.as_ref();
        let header_length =
            ORIGINAL_REQUEST_HEADER.end - ORIGINAL_REQUEST_HEADER.start;
        NativeEndian::read_u32(&data[ORIGINAL_REQUEST_LENGTH]) as usize
            - header_length
    }

    fn extended_ack_offset(&self) -> usize {
        let mut offset = OPTIONAL_PARTS.start;
        if self.has_request_payload {
            offset += self.request_payload_length();
        }
        offset
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ErrorBuffer<&'a T> {
    /// Return a pointer to the original request's header.
    pub fn request_header(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[ORIGINAL_REQUEST_HEADER]
    }

    /// Return a pointer to the original request's payload.
    pub fn request_payload(&self) -> Option<&'a [u8]> {
        if self.has_request_payload {
            let data = self.buffer.as_ref();
            Some(
                &data[OPTIONAL_PARTS.start
                    ..OPTIONAL_PARTS.start + self.request_payload_length()],
            )
        } else {
            None
        }
    }

    pub fn extended_ack_tlvs(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        let data = self.buffer.as_ref();
        NlasIterator::new(&data[self.extended_ack_offset()..])
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> ErrorBuffer<&'a mut T> {
    /// Return a mutable pointer to the original request's header.
    pub fn request_header_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[ORIGINAL_REQUEST_HEADER]
    }

    /// Return a mutable pointer to the original request's payload.
    pub fn request_payload_mut(&mut self) -> &mut [u8] {
        let length = self.request_payload_length();
        let data = self.buffer.as_mut();
        &mut data[OPTIONAL_PARTS.start..OPTIONAL_PARTS.start + length]
    }

    /// Return a mutable pointer to the extended ACK TLVs.
    pub fn extended_ack_tlvs_mut(&mut self) -> &mut [u8] {
        let offset = self.extended_ack_offset();
        let data = self.buffer.as_mut();
        &mut data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ErrorBuffer<T> {
    /// set the error code field
    pub fn set_code(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[CODE], value)
    }
}

/// An `NLMSG_ERROR` message.
///
/// Per [RFC 3549 section 2.3.2.2], this message carries the return code for a
/// request which will indicate either success (an ACK) or failure (a NACK).
///
/// [RFC 3549 section 2.3.2.2]: https://datatracker.ietf.org/doc/html/rfc3549#section-2.3.2.2
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorMessage {
    /// The error code.
    ///
    /// Holds `None` when there is no error to report (the message is an ACK),
    /// or a `Some(e)` if there is a non-zero error code `e` to report (the
    /// message is a NACK).
    ///
    /// See [Netlink message types] for details.
    ///
    /// [Netlink message types]: https://kernel.org/doc/html/next/userspace-api/netlink/intro.html#netlink-message-types
    pub code: Option<NonZeroI32>,
    /// The original request's header.
    pub request_header: NetlinkHeader,
    /// The original request's payload.
    pub request_payload: Option<Vec<u8>>,
    /// Extended ACK TLVs
    pub extended_ack: Vec<ExtendedAckAttribute>,
}

impl Emitable for ErrorMessage {
    fn buffer_len(&self) -> usize {
        let mut len = MIN_ERROR_MESSAGE_LEN;

        if let Some(p) = &self.request_payload {
            len += p.len();
        }

        len + self.extended_ack.as_slice().buffer_len()
    }
    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer =
            ErrorBuffer::new(buffer, self.request_payload.is_some());
        buffer.set_code(self.raw_code());
        self.request_header.emit(buffer.request_header_mut());
        if let Some(p) = &self.request_payload {
            buffer.request_payload_mut().copy_from_slice(p)
        }
        self.extended_ack
            .as_slice()
            .emit(buffer.extended_ack_tlvs_mut());
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<ErrorBuffer<&'buffer T>>
    for ErrorMessage
{
    fn parse(
        buf: &ErrorBuffer<&'buffer T>,
    ) -> Result<ErrorMessage, DecodeError> {
        let buffer = &NetlinkBuffer::new(buf.request_header());
        let request_header =
            <NetlinkHeader as Parseable<NetlinkBuffer<&[u8]>>>::parse(buffer)
                .context("failed to parse netlink header")?;

        let request_payload = buf.request_payload().map(|v| v.to_vec());

        Ok(ErrorMessage {
            code: buf.code(),
            request_header,
            request_payload,
            extended_ack: Vec::<ExtendedAckAttribute>::parse(buf)
                .context("failed to parse extended ACK")?,
        })
    }
}

impl<'buffer, T: AsRef<[u8]> + 'buffer> Parseable<ErrorBuffer<&'buffer T>>
    for Vec<ExtendedAckAttribute>
{
    fn parse(
        buf: &ErrorBuffer<&'buffer T>,
    ) -> Result<Vec<ExtendedAckAttribute>, DecodeError> {
        let mut extended_ack = vec![];
        for ext_ack_buf in buf.extended_ack_tlvs() {
            extended_ack.push(ExtendedAckAttribute::parse(&ext_ack_buf?)?);
        }
        Ok(extended_ack)
    }
}

impl ErrorMessage {
    /// Returns the raw error code.
    pub fn raw_code(&self) -> i32 {
        self.code.map_or(0, NonZeroI32::get)
    }

    /// According to [`netlink(7)`](https://linux.die.net/man/7/netlink)
    /// the `NLMSG_ERROR` return Negative errno or 0 for acknowledgements.
    ///
    /// convert into [`std::io::Error`](https://doc.rust-lang.org/std/io/struct.Error.html)
    /// using the absolute value from errno code
    pub fn to_io(&self) -> io::Error {
        io::Error::from_raw_os_error(self.raw_code().abs())
    }
}

impl fmt::Display for ErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_io(), f)
    }
}

impl From<ErrorMessage> for io::Error {
    fn from(e: ErrorMessage) -> io::Error {
        e.to_io()
    }
}

const NLMSGERR_ATTR_MSG: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ExtendedAckAttribute {
    Msg(String),
    Other(DefaultNla),
}

impl Nla for ExtendedAckAttribute {
    fn value_len(&self) -> usize {
        match *self {
            Self::Msg(ref string) => string.as_bytes().len() + 1,
            Self::Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Msg(ref string) => {
                buffer[..string.as_bytes().len()]
                    .copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
            }
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Msg(_) => NLMSGERR_ATTR_MSG,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for ExtendedAckAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NLMSGERR_ATTR_MSG => Self::Msg(
                parse_string(payload).context("invalid error message")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("failed parsing unhandled type")?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    const RTM_GETLINK: u16 = 18;

    #[test]
    fn into_inner() {
        let bytes = vec![
            0, 0, 0, 0, 40, 0, 0, 0, 18, 0, 1, 3, 0x34, 0x0e, 0xf9, 0x5a, 0, 0,
            0, 0,
        ];
        let msg = ErrorBuffer::new_checked(&bytes, false);
        let inner = msg.unwrap().into_inner();
        assert_eq!(bytes, *inner);
    }

    #[test]
    fn into_io_error() {
        let io_err = io::Error::from_raw_os_error(95);
        let err_msg = ErrorMessage {
            code: NonZeroI32::new(-95),
            request_header: NetlinkHeader {
                length: 40,
                message_type: RTM_GETLINK,
                sequence_number: 1_526_271_540,
                flags: NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH,
                port_number: 0,
            },
            request_payload: None,
            extended_ack: vec![],
        };

        let to_io: io::Error = err_msg.to_io();

        assert_eq!(err_msg.to_string(), io_err.to_string());
        assert_eq!(to_io.raw_os_error(), io_err.raw_os_error());
        assert_eq!(
            io::Error::from(err_msg).raw_os_error(),
            io_err.raw_os_error()
        );
    }

    #[test]
    fn parse_ack() {
        let bytes = vec![
            0, 0, 0, 0, 40, 0, 0, 0, 18, 0, 1, 3, 0x34, 0x0e, 0xf9, 0x5a, 0, 0,
            0, 0,
        ];
        let msg = ErrorBuffer::new_checked(&bytes, false)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");
        assert_eq!(
            ErrorMessage {
                code: None,
                request_header: NetlinkHeader {
                    length: 40,
                    message_type: RTM_GETLINK,
                    sequence_number: 1_526_271_540,
                    flags: NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH,
                    port_number: 0,
                },
                request_payload: None,
                extended_ack: vec![],
            },
            msg
        );
        assert_eq!(msg.raw_code(), 0);
    }

    #[test]
    fn parse_nack() {
        // SAFETY: value is non-zero.
        const ERROR_CODE: NonZeroI32 =
            unsafe { NonZeroI32::new_unchecked(-1234) };
        let mut bytes = vec![
            0, 0, 0, 0, 40, 0, 0, 0, 18, 0, 1, 3, 0x34, 0x0e, 0xf9, 0x5a, 0, 0,
            0, 0,
        ];
        NativeEndian::write_i32(&mut bytes, ERROR_CODE.get());
        let msg = ErrorBuffer::new_checked(&bytes, false)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");
        assert_eq!(
            ErrorMessage {
                code: Some(ERROR_CODE),
                request_header: NetlinkHeader {
                    length: 40,
                    message_type: RTM_GETLINK,
                    sequence_number: 1_526_271_540,
                    flags: NLM_F_ROOT | NLM_F_REQUEST | NLM_F_MATCH,
                    port_number: 0,
                },
                request_payload: None,
                extended_ack: vec![],
            },
            msg
        );
        assert_eq!(msg.raw_code(), ERROR_CODE.get());
    }

    #[test]
    fn parse_extended_ack() {
        let raw = vec![
            0, 0, 0, 0, 248, 0, 0, 0, 36, 0, 5, 5, 2, 0, 0, 0, 0, 0, 0, 0, 85,
            0, 1, 0, 115, 99, 104, 95, 116, 97, 112, 114, 105, 111, 58, 32, 83,
            105, 122, 101, 32, 116, 97, 98, 108, 101, 32, 110, 111, 116, 32,
            115, 112, 101, 99, 105, 102, 105, 101, 100, 44, 32, 102, 114, 97,
            109, 101, 32, 108, 101, 110, 103, 116, 104, 32, 101, 115, 116, 105,
            109, 97, 116, 105, 111, 110, 115, 32, 109, 97, 121, 32, 98, 101,
            32, 105, 110, 97, 99, 99, 117, 114, 97, 116, 101, 0, 0, 0, 0,
        ];
        let msg = ErrorBuffer::new_checked(&raw, false)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");

        let expected = ErrorMessage {
                code: None,
                request_header: NetlinkHeader {
                    length: 248,
                    message_type: 36,
                    sequence_number: 2,
                    flags: 1285,
                    port_number: 0,
                },
                request_payload: None,
                extended_ack: vec![ExtendedAckAttribute::Msg("sch_taprio: Size table not specified, frame length estimations may be inaccurate".to_string())],
            };

        assert_eq!(msg, expected);
        assert_eq!(msg.raw_code(), 0);

        let mut buf = vec![0; expected.buffer_len()];
        expected.emit(&mut buf);

        assert_eq!(buf, raw);
    }

    #[test]
    fn parse_nack_with_payload() {
        let raw = vec![
            0xed, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05,
            0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
            0x74, 0x61, 0x70, 0x72, 0x69, 0x6f, 0x00, 0x00, 0xc8, 0x00, 0x02,
            0x00, 0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x03, 0x00, 0x00, 0xca, 0x9a, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x58,
            0x00, 0x02, 0x80, 0x1c, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x08, 0x00, 0x04, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x1c, 0x00,
            0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
            0xe0, 0x93, 0x04, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x56,
            0x00, 0x01, 0x00, 0x03, 0x02, 0x02, 0x01, 0x00, 0x02, 0x02, 0x02,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let msg = ErrorBuffer::new_checked(&raw, true)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");

        let expected = ErrorMessage {
            code: Some(std::num::NonZeroI32::new(-19).unwrap()),
            request_header: NetlinkHeader {
                length: 248,
                message_type: 36,
                sequence_number: 2,
                flags: 1285,
                port_number: 0,
            },
            request_payload: Some(vec![
                0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0,
                0, 0, 11, 0, 1, 0, 116, 97, 112, 114, 105, 111, 0, 0, 200, 0,
                2, 0, 8, 0, 10, 0, 2, 0, 0, 0, 12, 0, 3, 0, 0, 202, 154, 59, 0,
                0, 0, 0, 88, 0, 2, 128, 28, 0, 1, 0, 5, 0, 2, 0, 0, 0, 0, 0, 8,
                0, 3, 0, 1, 0, 0, 0, 8, 0, 4, 0, 224, 147, 4, 0, 28, 0, 1, 0,
                5, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 3, 0, 0, 0, 8, 0, 4, 0,
                224, 147, 4, 0, 28, 0, 1, 0, 5, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3,
                0, 4, 0, 0, 0, 8, 0, 4, 0, 128, 26, 6, 0, 86, 0, 1, 0, 3, 2, 2,
                1, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            extended_ack: vec![],
        };

        assert_eq!(msg, expected);
        assert_eq!(msg.raw_code(), -19);

        let mut buf = vec![0; expected.buffer_len()];
        expected.emit(&mut buf);

        assert_eq!(buf, raw);
    }

    #[test]
    #[should_panic(
        expected = "length is 15 but ErrorBuffer are at least 20 bytes"
    )]
    fn buffer_too_short() {
        let bytes =
            vec![0, 0, 0, 0, 40, 0, 0, 0, 18, 0, 1, 3, 0x34, 0x0e, 0xf9];
        ErrorBuffer::new_checked(&bytes, false).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "length is 231 but ErrorBuffer are at least 20 bytes plus the request's payload indicated as 232"
    )]
    fn buffer_too_short_for_payload() {
        let bytes = vec![
            0xed, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05,
            0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
            0x74, 0x61, 0x70, 0x72, 0x69, 0x6f, 0x00, 0x00, 0xc8, 0x00, 0x02,
            0x00, 0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x03, 0x00, 0x00, 0xca, 0x9a, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x58,
            0x00, 0x02, 0x80, 0x1c, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x08, 0x00, 0x04, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x1c, 0x00,
            0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
            0xe0, 0x93, 0x04, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x56,
            0x00, 0x01, 0x00, 0x03, 0x02, 0x02, 0x01, 0x00, 0x02, 0x02, 0x02,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        ErrorBuffer::new_checked(&bytes, true).unwrap();
    }

    #[test]
    #[should_panic(expected = "failed to parse extended ACK")]
    fn parse_invalid_extended_ack() {
        let raw = vec![
            0, 0, 0, 0, 248, 0, 0, 0, 36, 0, 5, 5, 2, 0, 0, 0, 0, 0, 0, 0, 10,
            0, 2, 0, 115,
        ];
        ErrorBuffer::new_checked(&raw, false)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");
    }

    #[test]
    fn parse_extended_ack_with_unknown_type() {
        let raw = vec![
            0, 0, 0, 0, 248, 0, 0, 0, 36, 0, 5, 5, 2, 0, 0, 0, 0, 0, 0, 0, 5,
            0, 2, 0, 115, 0, 0, 0,
        ];
        let msg = ErrorBuffer::new_checked(&raw, false)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");

        let expected = ErrorMessage {
            code: None,
            request_header: NetlinkHeader {
                length: 248,
                message_type: 36,
                sequence_number: 2,
                flags: 1285,
                port_number: 0,
            },
            request_payload: None,
            extended_ack: vec![ExtendedAckAttribute::Other(DefaultNla::new(
                2,
                vec![115],
            ))],
        };

        assert_eq!(msg, expected);

        let mut buf = vec![0; expected.buffer_len()];
        expected.emit(&mut buf);

        assert_eq!(buf, raw);
    }
}
