// SPDX-License-Identifier: MIT

use crate::{
    nla_total_size, DecodeError, EncodeError, NetlinkHeader, NLA_F_NESTED,
    NLA_F_NET_BYTEORDER, NLA_HEADER_SIZE, NLA_MAX_VALUE_LEN, NLA_TYPE_MASK,
};

/// A `NetlinkDeserializable` type can be deserialized from a buffer
pub trait NetlinkDeserializable: Sized {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Deserialize the given buffer into `Self`.
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error>;
}

/// A type that can be serialized into netlink wire bytes.
///
/// Implementations append to an existing [`Vec<u8>`] and return an
/// [`EncodeError`] instead of panicking. On error they must truncate `out`
/// back to its original length, so a reused buffer is not left partially
/// written.
pub trait Emitable {
    /// Append the serialized value to `out`.
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError>;
}

/// A top-level netlink message payload.
///
/// This provides the message type needed for the netlink header in addition to
/// the fallible byte emission from [`Emitable`].
pub trait NetlinkSerializable: Emitable {
    /// Return the netlink message type of this payload.
    fn message_type(&self) -> u16;
}

/// A netlink attribute.
///
/// Implementations append only the attribute *value* to `out`; the provided
/// [`Nla::emit_nla_into`] method reserves the attribute header, writes the
/// length, type and flag bits, and adds alignment padding. Implementations
/// must return an [`EncodeError`] instead of panicking on invalid input.
pub trait Nla {
    /// Append the attribute value to `out`.
    ///
    /// The value is appended without any NLA header or padding. Nested
    /// attributes should be appended with [`Emitable::emit_into`] or
    /// [`emit_nlas_into`](crate::emit_nlas_into). On error, implementations
    /// must truncate `out` back to its original length.
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError>;

    /// Return the attribute type, including the flag bits.
    fn kind(&self) -> u16;

    /// Append this attribute, including its header and padding, to `out`.
    ///
    /// This validates the 16-bit attribute length and restores `out` to its
    /// original length on error.
    fn emit_nla_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        let header_end = start
            .checked_add(NLA_HEADER_SIZE)
            .ok_or_else(|| EncodeError::length_overflow("netlink attribute"))?;
        out.resize(header_end, 0);

        let result = (|| -> Result<(), EncodeError> {
            self.emit_value_into(out)?;

            let value_len =
                out.len().checked_sub(header_end).ok_or_else(|| {
                    EncodeError::new(
                        "netlink attribute value emitter truncated the buffer \
                         below the attribute header",
                    )
                })?;
            let total_len = nla_total_size(value_len).map_err(|_| {
                EncodeError::nla_value_too_long(
                    self.kind(),
                    value_len,
                    NLA_MAX_VALUE_LEN,
                )
            })?;
            let end = start.checked_add(total_len).ok_or_else(|| {
                EncodeError::length_overflow("netlink attribute")
            })?;
            out.resize(end, 0);

            let nla_len = NLA_HEADER_SIZE + value_len;
            out[start..start + 2]
                .copy_from_slice(&(nla_len as u16).to_ne_bytes());
            let kind = self.kind();
            let mut attr_type = kind & NLA_TYPE_MASK;
            if self.is_network_byteorder() {
                attr_type |= NLA_F_NET_BYTEORDER;
            }
            if self.is_nested() {
                attr_type |= NLA_F_NESTED;
            }
            out[start + 2..header_end]
                .copy_from_slice(&attr_type.to_ne_bytes());
            Ok(())
        })();

        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    #[inline]
    fn is_nested(&self) -> bool {
        (self.kind() & NLA_F_NESTED) != 0
    }

    #[inline]
    fn is_network_byteorder(&self) -> bool {
        (self.kind() & NLA_F_NET_BYTEORDER) != 0
    }
}

/// A `Parseable` type can be used to deserialize data from the type `T` for
/// which it is implemented.
pub trait Parseable<T>
where
    Self: Sized,
    T: ?Sized,
{
    /// Deserialize the current type.
    fn parse(buf: &T) -> Result<Self, DecodeError>;
}

/// A `Parseable` type can be used to deserialize data from the type `T` for
/// which it is implemented.
pub trait ParseableParametrized<T, P>
where
    Self: Sized,
    T: ?Sized,
{
    /// Deserialize the current type.
    fn parse_with_param(buf: &T, params: P) -> Result<Self, DecodeError>;
}
