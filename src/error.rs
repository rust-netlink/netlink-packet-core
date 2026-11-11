// SPDX-License-Identifier: MIT

use std::{fmt, io, num::NonZeroI32};

use crate::{
    append_bytes, append_i32, parse_i32, Emitable, Field, Parseable, Rest,
    NLA_HEADER_SIZE,
};

const CODE: Field = 0..4;
const PAYLOAD: Rest = 4..;
const ERROR_HEADER_LEN: usize = PAYLOAD.start;

pub trait ErrorContext<T: std::fmt::Display> {
    /// Attach context to an error.
    fn context(self, msg: T) -> Self;

    /// Attach context lazily, so the message is only built when
    /// there is actually an error to attach it to.
    fn with_context<F>(self, f: F) -> Self
    where
        F: FnOnce() -> T,
        Self: Sized,
    {
        self.context(f())
    }
}

/// The category of a [`DecodeError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The input buffer is smaller than the value being decoded.
    BufferTooSmall,
    /// A length field is inconsistent with the input buffer.
    InvalidLength,
    /// The value is invalid for its protocol or attribute type.
    InvalidValue,
    /// The value is not valid UTF-8.
    InvalidUtf8,
    /// Please report this bug to the rust-netlink team.
    Bug,
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::InvalidValue => f.write_str("invalid value"),
            Self::InvalidUtf8 => f.write_str("invalid utf-8"),
            Self::Bug => f.write_str("bug"),
        }
    }
}

/// Error returned when decoding a netlink value fails.
///
/// This is the fallible counterpart of [`EncodeError`](crate::EncodeError),
/// used by [`Parseable`](crate::Parseable) and
/// [`NetlinkDeserializable`](crate::NetlinkDeserializable).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecodeError {
    kind: DecodeErrorKind,
    msg: String,
}

impl DecodeError {
    pub fn new(kind: DecodeErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }

    pub fn kind(&self) -> DecodeErrorKind {
        self.kind
    }

    pub fn is_buffer_too_small(&self) -> bool {
        self.kind == DecodeErrorKind::BufferTooSmall
    }

    pub fn is_invalid_length(&self) -> bool {
        self.kind == DecodeErrorKind::InvalidLength
    }
}

impl<T: std::fmt::Display> ErrorContext<T> for DecodeError {
    fn context(self, msg: T) -> Self {
        Self {
            kind: self.kind,
            msg: format!("{} caused by {}", msg, self.msg),
        }
    }
}

impl<T, M> ErrorContext<M> for Result<T, DecodeError>
where
    M: std::fmt::Display,
{
    fn context(self, msg: M) -> Result<T, DecodeError> {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e.context(msg)),
        }
    }

    /// Only render the error on the Err case
    fn with_context<F>(self, f: F) -> Result<T, DecodeError>
    where
        F: FnOnce() -> M,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e.context(f())),
        }
    }
}

impl From<&str> for DecodeError {
    fn from(msg: &str) -> Self {
        Self::new(DecodeErrorKind::InvalidValue, msg)
    }
}

impl From<String> for DecodeError {
    fn from(msg: String) -> Self {
        Self::new(DecodeErrorKind::InvalidValue, msg)
    }
}

impl From<std::string::FromUtf8Error> for DecodeError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::new(
            DecodeErrorKind::InvalidUtf8,
            format!("invalid UTF-8 sequence: {err}"),
        )
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

impl std::error::Error for DecodeError {}

/// The category of an [`EncodeError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeErrorKind {
    /// The value cannot be represented in the netlink wire format, for
    /// example because it exceeds the 16-bit attribute length or the 32-bit
    /// message length.
    TooLarge,
    /// The value is invalid for its protocol or attribute type.
    InvalidValue,
    /// The destination buffer is smaller than the encoded value.
    BufferTooSmall,
    /// Please report this bug to rust-netlink team or request new enum
    /// variant.
    Bug,
}

impl fmt::Display for EncodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("value too large"),
            Self::InvalidValue => f.write_str("invalid value"),
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::Bug => f.write_str("bug"),
        }
    }
}

/// Error returned when encoding a netlink value fails.
///
/// This is the fallible counterpart of [`DecodeError`](crate::DecodeError),
/// used by [`Emitable`](crate::Emitable) and
/// [`Nla`](crate::Nla).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EncodeError {
    pub kind: EncodeErrorKind,
    pub msg: String,
}

impl EncodeError {
    pub fn new(kind: EncodeErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }

    pub fn too_large(msg: impl Into<String>) -> Self {
        Self {
            kind: EncodeErrorKind::TooLarge,
            msg: msg.into(),
        }
    }

    pub fn nla_value_too_long(
        kind: u16,
        len: usize,
        maximum_length: usize,
    ) -> Self {
        Self::too_large(format!(
            "netlink attribute type {kind} value is too long: {len} > \
             {maximum_length} bytes"
        ))
    }

    pub fn buffer_too_small(buffer_len: usize, minimum_length: usize) -> Self {
        Self {
            kind: EncodeErrorKind::BufferTooSmall,
            msg: format!(
                "buffer has length {buffer_len}, but at least \
                 {minimum_length} bytes are required"
            ),
        }
    }

    pub fn length_overflow(what: &str) -> Self {
        Self::too_large(format!("{what} length overflow"))
    }

    pub fn message_too_long(len: usize, maximum_length: usize) -> Self {
        Self::too_large(format!(
            "netlink message is too long: {len} > {maximum_length} bytes"
        ))
    }

    pub fn kind(&self) -> EncodeErrorKind {
        self.kind
    }

    pub fn is_too_large(&self) -> bool {
        self.kind == EncodeErrorKind::TooLarge
    }
}

impl<T: std::fmt::Display> ErrorContext<T> for EncodeError {
    fn context(self, msg: T) -> Self {
        Self {
            kind: self.kind,
            msg: format!("{} caused by {}", msg, self.msg),
        }
    }
}

impl<T, M> ErrorContext<M> for Result<T, EncodeError>
where
    M: std::fmt::Display,
{
    fn context(self, msg: M) -> Result<T, EncodeError> {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e.context(msg)),
        }
    }

    fn with_context<F>(self, f: F) -> Result<T, EncodeError>
    where
        F: FnOnce() -> M,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e.context(f())),
        }
    }
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

impl std::error::Error for EncodeError {}

impl DecodeError {
    pub fn invalid_buffer(
        name: &str,
        received: usize,
        minimum_length: usize,
    ) -> Self {
        Self::new(
            DecodeErrorKind::BufferTooSmall,
            format!(
                "Invalid buffer {name}. Expected at least {minimum_length} \
                 bytes, received {received} bytes"
            ),
        )
    }

    pub fn invalid_mac_address(received: usize) -> Self {
        Self::new(
            DecodeErrorKind::InvalidValue,
            format!(
                "Invalid MAC address. Expected 6 bytes, received {received} \
                 bytes"
            ),
        )
    }

    pub fn invalid_ip_address(received: usize) -> Self {
        Self::new(
            DecodeErrorKind::InvalidValue,
            format!(
                "Invalid IP address. Expected 4 or 16 bytes, received \
                 {received} bytes"
            ),
        )
    }

    pub fn invalid_number(expected: usize, received: usize) -> Self {
        Self::new(
            DecodeErrorKind::InvalidValue,
            format!(
                "Invalid number. Expected {expected} bytes, received \
                 {received} bytes"
            ),
        )
    }

    pub fn nla_buffer_too_small(buffer_len: usize, nla_len: usize) -> Self {
        Self::new(
            DecodeErrorKind::BufferTooSmall,
            format!(
                "buffer has length {buffer_len}, but an NLA header is \
                 {nla_len} bytes"
            ),
        )
    }

    pub fn nla_length_mismatch(buffer_len: usize, nla_len: usize) -> Self {
        Self::new(
            DecodeErrorKind::InvalidLength,
            format!(
                "buffer has length: {buffer_len}, but the NLA is {nla_len} \
                 bytes"
            ),
        )
    }

    pub fn nla_invalid_length(buffer_len: usize, nla_len: usize) -> Self {
        Self::new(
            DecodeErrorKind::InvalidLength,
            format!(
                "NLA has invalid length: {nla_len} (should be at least \
                 {NLA_HEADER_SIZE} bytes, buffer is {buffer_len} bytes)"
            ),
        )
    }

    pub fn buffer_too_small(buffer_len: usize, value_len: usize) -> Self {
        Self::new(
            DecodeErrorKind::BufferTooSmall,
            format!(
                "Buffer too small: {buffer_len} (should be at least \
                 {value_len} bytes)"
            ),
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct ErrorBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ErrorBuffer<T> {
    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Check that the buffer is large enough to contain an error code and
    /// create an `ErrorBuffer` from it.
    pub fn new(buffer: T) -> Result<Self, DecodeError> {
        let packet = ErrorBuffer { buffer };
        packet
            .check_buffer_length()
            .context("invalid ErrorBuffer length")?;
        Ok(packet)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < ERROR_HEADER_LEN {
            Err(DecodeError::new(
                DecodeErrorKind::BufferTooSmall,
                format!(
                    "invalid ErrorBuffer: length is {len} but ErrorBuffer are \
                     at least {ERROR_HEADER_LEN} bytes"
                ),
            ))
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
        NonZeroI32::new(parse_i32(&data[CODE]).unwrap())
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ErrorBuffer<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> ErrorBuffer<&mut T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ErrorBuffer<T> {
    /// set the error code field
    pub fn set_code(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        data[CODE].copy_from_slice(&value.to_ne_bytes());
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
    pub header: Vec<u8>,
}

impl Emitable for ErrorMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_i32(out, self.raw_code());
        append_bytes(out, &self.header);
        Ok(())
    }
}

impl<T: AsRef<[u8]>> Parseable<ErrorBuffer<&T>> for ErrorMessage {
    fn parse(buf: &ErrorBuffer<&T>) -> Result<ErrorMessage, DecodeError> {
        // FIXME: The payload of an error is basically a truncated packet, which
        // requires custom logic to parse correctly. For now we just
        // return it as a Vec<u8> let header: NetlinkHeader = {
        //     NetlinkBuffer::new(self.payload())
        //         .context("failed to parse netlink header")?
        //         .parse()
        //         .context("failed to parse nelink header")?
        // };
        Ok(ErrorMessage {
            code: buf.code(),
            header: buf.payload().to_vec(),
        })
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
        // Use `saturating_abs()` as `i32::MIN` has no positive `i32`
        // representation and `abs()` would panic on such malformed
        // netlink error code.
        io::Error::from_raw_os_error(self.raw_code().saturating_abs())
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

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reports_decode_error_kind() {
        let err = ErrorBuffer::new(vec![0; ERROR_HEADER_LEN - 1]).unwrap_err();
        assert_eq!(err.kind(), crate::DecodeErrorKind::BufferTooSmall);
    }

    #[test]
    fn encode_error_display_includes_kind() {
        assert_eq!(EncodeErrorKind::TooLarge.to_string(), "value too large");
        assert_eq!(EncodeErrorKind::InvalidValue.to_string(), "invalid value");
        assert_eq!(
            EncodeErrorKind::BufferTooSmall.to_string(),
            "buffer too small"
        );
        assert_eq!(EncodeErrorKind::Bug.to_string(), "bug");

        let error = EncodeError::too_large("attribute is 70000 bytes");
        assert_eq!(
            error.to_string(),
            "value too large: attribute is 70000 bytes"
        );
    }

    #[test]
    fn into_io_error() {
        let io_err = io::Error::from_raw_os_error(95);
        let err_msg = ErrorMessage {
            code: NonZeroI32::new(-95),
            header: vec![],
        };

        let to_io: io::Error = err_msg.to_io();

        assert_eq!(err_msg.to_string(), io_err.to_string());
        assert_eq!(to_io.raw_os_error(), io_err.raw_os_error());
    }

    #[test]
    fn parse_ack() {
        let bytes = vec![0, 0, 0, 0];
        let msg = ErrorBuffer::new(&bytes)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");
        assert_eq!(
            ErrorMessage {
                code: None,
                header: Vec::new()
            },
            msg
        );
        assert_eq!(msg.raw_code(), 0);
    }

    #[test]
    fn parse_nack() {
        let error_code = NonZeroI32::new(-1234).unwrap();
        let mut bytes = vec![0, 0, 0, 0];
        bytes.copy_from_slice(&error_code.get().to_ne_bytes());
        let msg = ErrorBuffer::new(&bytes)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");
        assert_eq!(
            ErrorMessage {
                code: Some(error_code),
                header: Vec::new()
            },
            msg
        );
        assert_eq!(msg.raw_code(), error_code.get());
    }

    #[test]
    fn nack_with_min_code_not_panic() {
        let mut bytes = vec![0, 0, 0, 0];
        bytes.copy_from_slice(&i32::MIN.to_ne_bytes());
        let msg = ErrorBuffer::new(&bytes)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .expect("failed to parse NLMSG_ERROR");
        assert_eq!(msg.code, NonZeroI32::new(i32::MIN));
        assert_eq!(msg.raw_code(), i32::MIN);

        let io_err = msg.to_io();
        assert_eq!(io_err.raw_os_error(), Some(i32::MAX));
        // `Display` goes through `to_io()`, must not panic either.
        assert_eq!(msg.to_string(), io_err.to_string());
    }
}
