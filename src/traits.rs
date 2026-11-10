// SPDX-License-Identifier: MIT

use crate::{
    nla_total_size, DecodeError, EncodeError, EncodeErrorKind, NetlinkHeader,
    NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLA_HEADER_SIZE, NLA_MAX_VALUE_LEN,
    NLA_TYPE_MASK,
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
/// [`EncodeError`] instead of panicking. [`Emitable::emit_value`] is the raw
/// implementation hook: it only appends bytes and does not handle rollback.
/// Call [`Emitable::emit`] to append a value transactionally.
pub trait Emitable {
    /// Append the serialized value to `out`.
    ///
    /// Implementations must only append bytes. They must not truncate or
    /// overwrite bytes that were already present in `out`.
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError>;

    /// Append the serialized value to `out`, rolling back on error.
    ///
    /// This records the original length, calls [`Emitable::emit_value`], and
    /// truncates `out` back to its original length if emission fails. A
    /// successful emission that leaves `out` shorter than its original length
    /// is reported as an [`EncodeErrorKind::Bug`].
    fn emit(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        let result = self.emit_value(out);
        if result.is_err() {
            out.truncate(start);
            return result;
        }
        if out.len() < start {
            return Err(EncodeError::new(
                EncodeErrorKind::Bug,
                "value emitter truncated the buffer below its starting length",
            ));
        }
        Ok(())
    }
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
/// [`Nla::emit`] method reserves the attribute header, writes the length,
/// type and flag bits, adds alignment padding, and rolls back on error.
/// Implementations must return an [`EncodeError`] instead of panicking on
/// invalid input.
///
/// Implementers should use [`Nla::emit`] rather than write the attribute
/// header themselves, so that the length validation and rollback are
/// retained. [`Nla::emit`] rolls back `out` on error; as long as
/// [`Nla::emit_value`] only appends, a failed emission leaves `out` in its
/// original state.
pub trait Nla {
    /// Append the attribute value to `out`.
    ///
    /// The value is appended without any NLA header or padding. Nested
    /// attributes should be appended with [`Emitable::emit`]. Implementations
    /// must only append bytes: they must not truncate or overwrite bytes
    /// already present in `out`. Rollback on error is handled by
    /// [`Nla::emit`], so `emit_value` implementations do not need to
    /// restore `out` themselves.
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError>;

    /// Return the attribute type word.
    ///
    /// Implementations should include the [`NLA_F_NESTED`] and/or
    /// [`NLA_F_NET_BYTEORDER`] flag bits when those flags apply.
    /// [`Nla::is_nested`] and [`Nla::is_network_byteorder`] derive their
    /// default results from these bits, and [`Nla::emit`] re-adds them to
    /// the emitted type field.
    ///
    /// Implementations that prefer to return only the attribute type may
    /// override those flag methods instead. Callers that need the bare
    /// attribute type can mask the result with
    /// [`NLA_TYPE_MASK`](crate::NLA_TYPE_MASK).
    fn kind(&self) -> u16;

    /// Append this attribute, including its header and padding, to `out`.
    ///
    /// This validates the 16-bit attribute length and restores `out` to its
    /// original length on error. Implementations that override this method
    /// must keep equivalent validation and rollback behavior.
    fn emit(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        let header_end = start
            .checked_add(NLA_HEADER_SIZE)
            .ok_or_else(|| EncodeError::length_overflow("netlink attribute"))?;
        out.resize(header_end, 0);

        let result = (|| -> Result<(), EncodeError> {
            self.emit_value(out)?;

            let value_len =
                out.len().checked_sub(header_end).ok_or_else(|| {
                    EncodeError::new(
                        EncodeErrorKind::Bug,
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

            // NOTE: `nla_total_size(value_len)` returned `Ok` above, which
            // bounds `value_len` to `NLA_MAX_VALUE_LEN`, so this addition and
            // the `u16` cast below cannot overflow.
            let nla_len = NLA_HEADER_SIZE + value_len;
            let kind = self.kind();
            let mut attr_type = kind & NLA_TYPE_MASK;
            if self.is_network_byteorder() {
                attr_type |= NLA_F_NET_BYTEORDER;
            }
            if self.is_nested() {
                attr_type |= NLA_F_NESTED;
            }
            out[start..start + 2]
                .copy_from_slice(&(nla_len as u16).to_ne_bytes());
            out[start + 2..header_end]
                .copy_from_slice(&attr_type.to_ne_bytes());
            Ok(())
        })();

        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    /// Return whether this attribute should have [`NLA_F_NESTED`] set.
    ///
    /// The default implementation derives the flag from [`Nla::kind`].
    /// Implementations should normally return the flag bit from
    /// [`Nla::kind`]; they may instead override this method when they keep
    /// [`Nla::kind`] as the bare attribute type.
    #[inline]
    fn is_nested(&self) -> bool {
        (self.kind() & NLA_F_NESTED) != 0
    }

    /// Return whether this attribute should have [`NLA_F_NET_BYTEORDER`] set.
    ///
    /// The default implementation derives the flag from [`Nla::kind`].
    /// Implementations should normally return the flag bit from
    /// [`Nla::kind`]; they may instead override this method when they keep
    /// [`Nla::kind`] as the bare attribute type.
    #[inline]
    fn is_network_byteorder(&self) -> bool {
        (self.kind() & NLA_F_NET_BYTEORDER) != 0
    }
}

/// A `Parseable` type can be used to deserialize data from the type `T` for
/// which it is implemented.
///
/// The conventional input types are:
///
/// - [`NlaBuffer<'a>`](crate::NlaBuffer): parse one netlink attribute,
///   including its header. Container attributes expose their children through
///   [`NlaBuffer::nlas`](crate::NlaBuffer::nlas).
/// - `[u8]`: parse a raw payload, such as a netlink message body or a value
///   that is not wrapped in an [`NlaBuffer`](crate::NlaBuffer).
///
/// `Vec<T>` also implements `Parseable` for both input types, parsing each
/// child attribute as `T`. This avoids per-protocol list wrapper types.
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

#[cfg(test)]
mod tests {
    use super::*;

    struct ClearingEmitter;

    impl Emitable for ClearingEmitter {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            out.clear();
            Ok(())
        }
    }

    #[test]
    fn emit_value_truncating_below_start_is_an_error() {
        let mut out = vec![0xaa];
        let error = ClearingEmitter.emit(&mut out).unwrap_err();
        assert_eq!(error.kind(), EncodeErrorKind::Bug);
    }
}
