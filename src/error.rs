// SPDX-License-Identifier: MIT

use std::{fmt, io, num::NonZeroI32};

use crate::{
    append_bytes, append_i32, append_u32, buffer::NETLINK_HEADER_LEN,
    parse_i32, parse_string, parse_u32, DefaultNla, Emitable, Field, Nla,
    NlaBuffer, NlasIterator, Parseable, Rest, NLA_F_NESTED, NLA_HEADER_SIZE,
    NLM_F_ACK_TLVS, NLM_F_CAPPED,
};

const CODE: Field = 0..4;
const PAYLOAD: Rest = 4..;
const ERROR_HEADER_LEN: usize = PAYLOAD.start;

/// Error message string.
const NLMSGERR_ATTR_MSG: u16 = 1;
/// Offset of the invalid attribute in the original message, counting from the
/// beginning of the header.
const NLMSGERR_ATTR_OFFS: u16 = 2;
/// Arbitrary subsystem specific cookie, used to identify a created object or
/// operation.
const NLMSGERR_ATTR_COOKIE: u16 = 3;
/// Policy for a rejected attribute.
const NLMSGERR_ATTR_POLICY: u16 = 4;
/// Type of a missing required attribute.
const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;
/// Offset of the nest where the required attribute was missing.
const NLMSGERR_ATTR_MISS_NEST: u16 = 6;

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

/// An attribute from the extended ACK trailer of an `NLMSG_ERROR` message.
///
/// The kernel appends these attributes when the `NETLINK_EXT_ACK` socket
/// option is enabled. Attribute types are defined by `enum nlmsgerr_attrs` in
/// `linux/netlink.h`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ExtendedAckAttribute {
    /// A human readable error message.
    Msg(String),
    /// Offset of the invalid attribute in the original message, counting from
    /// the beginning of the netlink header.
    Offset(u32),
    /// Arbitrary subsystem specific binary cookie.
    Cookie(Vec<u8>),
    /// Policy for a rejected attribute.
    ///
    /// The policy is a nested attribute; its children are kept as generic
    /// [`DefaultNla`] values.
    Policy(Vec<DefaultNla>),
    /// Type of a missing required attribute.
    MissingType(u32),
    /// Offset of the nest where a required attribute was missing.
    MissingNest(u32),
    /// An attribute type this crate does not know about.
    Other(DefaultNla),
}

impl Nla for ExtendedAckAttribute {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Msg(msg) => {
                append_bytes(out, msg.as_bytes());
                out.push(0);
            }
            Self::Offset(value)
            | Self::MissingType(value)
            | Self::MissingNest(value) => append_u32(out, *value),
            Self::Cookie(cookie) => append_bytes(out, cookie),
            Self::Policy(nlas) => {
                for nla in nlas {
                    nla.emit(out)?;
                }
            }
            Self::Other(nla) => nla.emit_value(out)?,
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Msg(_) => NLMSGERR_ATTR_MSG,
            Self::Offset(_) => NLMSGERR_ATTR_OFFS,
            Self::Cookie(_) => NLMSGERR_ATTR_COOKIE,
            Self::Policy(_) => NLMSGERR_ATTR_POLICY | NLA_F_NESTED,
            Self::MissingType(_) => NLMSGERR_ATTR_MISS_TYPE,
            Self::MissingNest(_) => NLMSGERR_ATTR_MISS_NEST,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for ExtendedAckAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            NLMSGERR_ATTR_MSG => Self::Msg(
                parse_string(buf.value())
                    .context("invalid NLMSGERR_ATTR_MSG value")?,
            ),
            NLMSGERR_ATTR_OFFS => Self::Offset(
                parse_u32(buf.value())
                    .context("invalid NLMSGERR_ATTR_OFFS value")?,
            ),
            NLMSGERR_ATTR_COOKIE => Self::Cookie(buf.value().to_vec()),
            NLMSGERR_ATTR_POLICY => Self::Policy(
                Vec::<DefaultNla>::parse(buf)
                    .context("invalid NLMSGERR_ATTR_POLICY value")?,
            ),
            NLMSGERR_ATTR_MISS_TYPE => Self::MissingType(
                parse_u32(buf.value())
                    .context("invalid NLMSGERR_ATTR_MISS_TYPE value")?,
            ),
            NLMSGERR_ATTR_MISS_NEST => Self::MissingNest(
                parse_u32(buf.value())
                    .context("invalid NLMSGERR_ATTR_MISS_NEST value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct ErrorBuffer<T> {
    buffer: T,
    flags: u16,
}

impl<T: AsRef<[u8]>> ErrorBuffer<T> {
    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Check that the buffer is large enough to contain an error code and
    /// create an `ErrorBuffer` from it.
    ///
    /// The buffer is parsed without knowledge of the netlink header flags, so
    /// extended ACK attributes cannot be separated from the echoed original
    /// request. Use [`ErrorBuffer::new_with_flags`] with the flags of the
    /// enclosing `NLMSG_ERROR` message to parse extended ACKs.
    pub fn new(buffer: T) -> Result<Self, DecodeError> {
        Self::new_with_flags(buffer, 0)
    }

    /// Create an `ErrorBuffer` from an `NLMSG_ERROR` payload and the flags of
    /// the enclosing netlink header.
    ///
    /// The flags are used to locate the extended ACK attributes: the kernel
    /// sets [`NLM_F_ACK_TLVS`](crate::NLM_F_ACK_TLVS) when attributes are
    /// present and [`NLM_F_CAPPED`](crate::NLM_F_CAPPED) when the echoed
    /// original request was truncated to its header.
    pub fn new_with_flags(buffer: T, flags: u16) -> Result<Self, DecodeError> {
        let packet = ErrorBuffer { buffer, flags };
        packet
            .check_buffer_length()
            .context("invalid ErrorBuffer length")?;
        Ok(packet)
    }

    /// Return the flags of the enclosing netlink header.
    pub fn flags(&self) -> u16 {
        self.flags
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

    /// Return the echoed original request bytes.
    ///
    /// When the enclosing message has neither
    /// [`NLM_F_ACK_TLVS`](crate::NLM_F_ACK_TLVS) nor
    /// [`NLM_F_CAPPED`](crate::NLM_F_CAPPED) set, this is the whole payload
    /// after the error code, which keeps the historical behavior.
    pub fn original_request(&self) -> Result<&'a [u8], DecodeError> {
        Ok(self.split()?.0)
    }

    /// Return the extended ACK attribute bytes, or an empty slice when the
    /// enclosing message has no [`NLM_F_ACK_TLVS`](crate::NLM_F_ACK_TLVS)
    /// flag.
    pub fn extended_ack(&self) -> Result<&'a [u8], DecodeError> {
        Ok(self.split()?.1)
    }

    fn split(&self) -> Result<(&'a [u8], &'a [u8]), DecodeError> {
        let payload = self.payload();

        if self.flags & NLM_F_ACK_TLVS == 0 {
            return Ok((payload, &[]));
        }

        if payload.len() < NETLINK_HEADER_LEN {
            return Err(DecodeError::new(
                DecodeErrorKind::BufferTooSmall,
                format!(
                    "extended ACK attributes require an embedded netlink \
                     header of {NETLINK_HEADER_LEN} bytes, but only {} bytes \
                     are present",
                    payload.len()
                ),
            ));
        }

        let original_len = if self.flags & NLM_F_CAPPED != 0 {
            NETLINK_HEADER_LEN
        } else {
            let len = parse_u32(&payload[..4])
                .context("invalid embedded netlink header length")?
                as usize;
            if len < NETLINK_HEADER_LEN {
                return Err(DecodeError::new(
                    DecodeErrorKind::InvalidLength,
                    format!(
                        "embedded netlink message length is {len}, but it \
                         must be at least {NETLINK_HEADER_LEN} bytes"
                    ),
                ));
            }
            // The kernel appends the echoed request padded to NLMSG_ALIGN.
            len.checked_add(3).map_or(len, |len| len & !3)
        };

        if original_len > payload.len() {
            return Err(DecodeError::new(
                DecodeErrorKind::InvalidLength,
                format!(
                    "embedded netlink message is {original_len} bytes, but \
                     only {} bytes follow the error code",
                    payload.len()
                ),
            ));
        }

        Ok((&payload[..original_len], &payload[original_len..]))
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
    /// The echoed original request, without the extended ACK attributes.
    ///
    /// When the enclosing message has neither
    /// [`NLM_F_ACK_TLVS`](crate::NLM_F_ACK_TLVS) nor
    /// [`NLM_F_CAPPED`](crate::NLM_F_CAPPED) set, this contains all the bytes
    /// that follow the error code, as in previous versions.
    pub header: Vec<u8>,
    /// Extended ACK attributes, if the enclosing message has the
    /// [`NLM_F_ACK_TLVS`](crate::NLM_F_ACK_TLVS) flag.
    pub extended_ack: Vec<ExtendedAckAttribute>,
}

impl Emitable for ErrorMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_i32(out, self.raw_code());
        append_bytes(out, &self.header);
        self.extended_ack.emit(out)
    }
}

impl<T: AsRef<[u8]>> Parseable<ErrorBuffer<&T>> for ErrorMessage {
    fn parse(buf: &ErrorBuffer<&T>) -> Result<ErrorMessage, DecodeError> {
        let (header, extended_ack) = buf.split()?;
        let extended_ack = NlasIterator::new(extended_ack)?
            .map(|nla| ExtendedAckAttribute::parse(&nla))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse extended ACK attributes")?;
        Ok(ErrorMessage {
            code: buf.code(),
            header: header.to_vec(),
            extended_ack,
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

    /// Return the human readable message from the extended ACK attributes, if
    /// the kernel provided one.
    pub fn extended_ack_message(&self) -> Option<&str> {
        self.extended_ack
            .iter()
            .find_map(|attribute| match attribute {
                ExtendedAckAttribute::Msg(msg) => Some(msg.as_str()),
                _ => None,
            })
    }
}

impl fmt::Display for ErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_io(), f)?;
        if let Some(msg) = self.extended_ack_message() {
            write!(f, ": {msg}")?;
        }
        Ok(())
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
            extended_ack: vec![],
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
                header: Vec::new(),
                extended_ack: Vec::new(),
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
                header: Vec::new(),
                extended_ack: Vec::new(),
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

#[cfg(test)]
mod extended_ack_tests {
    use super::*;
    use crate::{append_i32, Emitable, Nla};

    fn embedded_request(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = NETLINK_HEADER_LEN + payload.len();
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(payload);
        out
    }

    fn error_payload(
        code: i32,
        request: &[u8],
        attributes: &[ExtendedAckAttribute],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        append_i32(&mut out, code);
        out.extend_from_slice(request);
        for attribute in attributes {
            attribute.emit(&mut out).unwrap();
        }
        out
    }

    fn parse<T: AsRef<[u8]>>(
        payload: &T,
        flags: u16,
    ) -> Result<ErrorMessage, DecodeError> {
        let buf = ErrorBuffer::new_with_flags(payload, flags)?;
        ErrorMessage::parse(&buf)
    }

    #[test]
    fn parse_extended_ack_message() {
        let request = embedded_request(&[]);
        let attributes =
            vec![ExtendedAckAttribute::Msg("invalid argument".into())];
        let payload = error_payload(-22, &request, &attributes);

        let msg = parse(&payload, NLM_F_CAPPED | NLM_F_ACK_TLVS).unwrap();
        assert_eq!(msg.code, NonZeroI32::new(-22));
        assert_eq!(msg.header, request);
        assert_eq!(msg.extended_ack, attributes);
        assert_eq!(msg.extended_ack_message(), Some("invalid argument"));
    }

    #[test]
    fn parse_offset_and_policy() {
        let request = embedded_request(&[1, 2, 3, 4]);
        let policy = vec![DefaultNla::new(1, 42u32.to_ne_bytes().to_vec())];
        let attributes = vec![
            ExtendedAckAttribute::Offset(20),
            ExtendedAckAttribute::Policy(policy),
        ];
        let payload = error_payload(-22, &request, &attributes);

        let msg = parse(&payload, NLM_F_ACK_TLVS).unwrap();
        assert_eq!(msg.header, request);
        assert_eq!(msg.extended_ack, attributes);

        // The original request is not mistaken for an extended ACK attribute.
        assert_eq!(msg.extended_ack.len(), 2);
    }

    #[test]
    fn non_capped_request_length_is_aligned() {
        let request = embedded_request(&[1, 2, 3]);
        let attributes = vec![ExtendedAckAttribute::Msg("oops".into())];
        let mut payload = Vec::new();
        append_i32(&mut payload, -22);
        payload.extend_from_slice(&request);
        // NLMSG_ALIGN padding after the echoed request.
        payload.push(0);
        for attribute in &attributes {
            attribute.emit(&mut payload).unwrap();
        }

        let msg = parse(&payload, NLM_F_ACK_TLVS).unwrap();
        assert_eq!(msg.header, payload[4..24]);
        assert_eq!(msg.extended_ack, attributes);
    }

    #[test]
    fn parse_missing_type_and_nest() {
        let request = embedded_request(&[]);
        let attributes = vec![
            ExtendedAckAttribute::MissingType(7),
            ExtendedAckAttribute::MissingNest(16),
        ];
        let payload = error_payload(-22, &request, &attributes);

        let msg = parse(&payload, NLM_F_CAPPED | NLM_F_ACK_TLVS).unwrap();
        assert_eq!(msg.extended_ack, attributes);
    }

    #[test]
    fn parse_unknown_attribute() {
        let request = embedded_request(&[]);
        let attributes = vec![ExtendedAckAttribute::Other(DefaultNla::new(
            0x1234,
            vec![9, 9],
        ))];
        let payload = error_payload(-22, &request, &attributes);

        let msg = parse(&payload, NLM_F_CAPPED | NLM_F_ACK_TLVS).unwrap();
        assert_eq!(msg.extended_ack, attributes);
    }

    #[test]
    fn malformed_extended_ack_is_an_error() {
        let mut request = embedded_request(&[]);
        request[..4]
            .copy_from_slice(&(NETLINK_HEADER_LEN as u32).to_ne_bytes());
        let mut payload = Vec::new();
        append_i32(&mut payload, -22);
        payload.extend_from_slice(&request);
        // An attribute header claiming a length smaller than the header.
        payload.extend_from_slice(&[2, 0, NLMSGERR_ATTR_MSG as u8, 0]);

        let err = parse(&payload, NLM_F_CAPPED | NLM_F_ACK_TLVS).unwrap_err();
        assert_eq!(err.kind(), DecodeErrorKind::InvalidLength);
    }

    #[test]
    fn without_flags_trailer_stays_in_header() {
        let request = embedded_request(&[]);
        let attributes =
            vec![ExtendedAckAttribute::Msg("invalid argument".into())];
        let payload = error_payload(-22, &request, &attributes);

        let msg = ErrorBuffer::new(&payload)
            .and_then(|buf| ErrorMessage::parse(&buf))
            .unwrap();
        assert_eq!(msg.header, payload[4..]);
        assert!(msg.extended_ack.is_empty());
    }

    #[test]
    fn display_includes_extended_ack_message() {
        let request = embedded_request(&[]);
        let attributes =
            vec![ExtendedAckAttribute::Msg("bad attribute".into())];
        let payload = error_payload(-22, &request, &attributes);
        let msg = parse(&payload, NLM_F_CAPPED | NLM_F_ACK_TLVS).unwrap();

        assert_eq!(
            msg.to_string(),
            format!("{}: bad attribute", io::Error::from_raw_os_error(22))
        );
    }

    #[test]
    fn emit_round_trip() {
        let request = embedded_request(&[1, 2, 3, 4]);
        let attributes = vec![
            ExtendedAckAttribute::Offset(20),
            ExtendedAckAttribute::Cookie(vec![0xaa, 0xbb]),
            ExtendedAckAttribute::Policy(vec![DefaultNla::new(
                2,
                vec![1, 2, 3, 4],
            )]),
            ExtendedAckAttribute::MissingType(7),
            ExtendedAckAttribute::MissingNest(16),
            ExtendedAckAttribute::Msg("oops".into()),
        ];
        let payload = error_payload(-22, &request, &attributes);
        let msg = parse(&payload, NLM_F_ACK_TLVS).unwrap();

        let mut emitted = Vec::new();
        msg.emit(&mut emitted).unwrap();
        assert_eq!(emitted, payload);
    }
}
