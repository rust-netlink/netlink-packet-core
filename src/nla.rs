// SPDX-License-Identifier: MIT

use crate::{
    append_bytes,
    traits::{Emitable, Nla, Parseable, ParseableParametrized},
    DecodeError, EncodeError,
};

/// Identify the bits that represent the "nested" flag of a netlink attribute.
pub const NLA_F_NESTED: u16 = 0x8000;
/// Identify the bits that represent the "byte order" flag of a netlink
/// attribute.
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
/// Identify the bits that represent the type of a netlink attribute.
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NET_BYTEORDER | NLA_F_NESTED);
/// NlA(RTA) align size
pub const NLA_ALIGNTO: usize = 4;
/// NlA(RTA) header size. (unsigned short rta_len) + (unsigned short rta_type)
pub const NLA_HEADER_SIZE: usize = 4;
/// Maximum length of an attribute value.
///
/// The kernel stores the attribute length in a `u16` that includes the
/// four-byte header, so the value itself can be at most 65531 bytes.
pub const NLA_MAX_VALUE_LEN: usize = u16::MAX as usize - NLA_HEADER_SIZE;

macro_rules! nla_align {
    ($len: expr) => {
        ($len + $crate::NLA_ALIGNTO - 1) & !($crate::NLA_ALIGNTO - 1)
    };
}

/// Return the total size of an attribute, including its header and padding.
///
/// Returns [`EncodeError`] when `value_len` cannot be represented in the
/// 16-bit attribute length field.
pub fn nla_total_size(value_len: usize) -> Result<usize, EncodeError> {
    if value_len > NLA_MAX_VALUE_LEN {
        return Err(EncodeError::too_large(format!(
            "netlink attribute value is too long: {value_len} > \
             {NLA_MAX_VALUE_LEN} bytes"
        )));
    }
    // NOTE: the check above bounds `value_len`, so this addition and the
    // alignment addition inside `nla_align!` cannot overflow.
    Ok(nla_align!(value_len + NLA_HEADER_SIZE))
}

/// The on-the-wire NLA header.
///
/// Kept private so that the header layout is not part of the public API.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct NlaHeader {
    length: u16,
    kind: u16,
}

/// A zero-copy, validated view of a single netlink attribute.
///
/// `NlaBuffer` can only be created through [`NlaBuffer::new`], which parses
/// and validates the attribute header. As a result, all accessors are
/// infallible and cannot panic.
///
/// # Migration from the old `NlaBuffer<T>`
///
/// The type used to own or mutably borrow its storage and offered an
/// unchecked `new()` plus `new_checked()`. It now borrows `&[u8]`:
///
/// ```
/// use netlink_packet_core::NlaBuffer;
///
/// let bytes = [0x05, 0x00, 0x01, 0x00, 0xaa, 0x00, 0x00, 0x00];
/// // Old: let nla = NlaBuffer::new_checked(&bytes[..]).unwrap();
/// let nla = NlaBuffer::new(&bytes[..]).unwrap();
/// assert_eq!(nla.value(), &[0xaa]);
/// ```
///
/// The mutable API (`inner_mut()`, `value_mut()`, `set_kind()`,
/// `set_length()`, `set_nested_flag()`, `set_network_byte_order_flag()`) was
/// removed. Build attributes with [`Nla::emit`] instead. `into_inner()` and
/// `inner()` were also removed: use [`NlaBuffer::value`] for the payload and
/// the header getters (`length()`, `kind()`, `nested_flag()`,
/// `network_byte_order_flag()`) for the header. `check_buffer_length()` was
/// folded into [`NlaBuffer::new`], which is now the fallible constructor.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NlaBuffer<'a> {
    header: NlaHeader,
    value: &'a [u8],
}

impl<'a> NlaBuffer<'a> {
    /// Parse and validate a netlink attribute.
    ///
    /// The buffer must start with a complete [`NLA_HEADER_SIZE`] byte header.
    /// It may contain padding after the attribute, and `length()` does not
    /// include that padding. Any `AsRef<[u8]>` is accepted, such as `&[u8]`,
    /// `&Vec<u8>`, or a reference to a fixed-size array.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when:
    ///
    /// - the buffer is shorter than [`NLA_HEADER_SIZE`], reported by
    ///   [`DecodeError::nla_buffer_too_small`];
    /// - the header's length field is smaller than [`NLA_HEADER_SIZE`],
    ///   reported by [`DecodeError::nla_invalid_length`];
    /// - the header's length field is larger than the buffer, reported by
    ///   [`DecodeError::nla_length_mismatch`].
    ///
    /// [`DecodeError::nla_buffer_too_small`]: crate::DecodeError::nla_buffer_too_small
    /// [`DecodeError::nla_invalid_length`]: crate::DecodeError::nla_invalid_length
    /// [`DecodeError::nla_length_mismatch`]: crate::DecodeError::nla_length_mismatch
    pub fn new<T>(buffer: &'a T) -> Result<NlaBuffer<'a>, DecodeError>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let buffer = buffer.as_ref();
        let buffer_len = buffer.len();
        // NOTE: parse the four-byte header with `u16::from_ne_bytes` instead
        // of a struct-casting crate such as `zerocopy`. After the length
        // check below, indexing `0..4` cannot panic, so this is already safe
        // and panic-free. The rest of the rust-netlink crates decode integer
        // fields from byte slices the same way (see `crate::parsers`), and
        // keeping netlink-packet-core dependency-free avoids the `zerocopy`
        // and `zerocopy-derive` build cost for such a tiny header.
        if buffer_len < NLA_HEADER_SIZE {
            return Err(DecodeError::nla_buffer_too_small(
                buffer_len,
                NLA_HEADER_SIZE,
            ));
        }
        let header = NlaHeader {
            length: u16::from_ne_bytes([buffer[0], buffer[1]]),
            kind: u16::from_ne_bytes([buffer[2], buffer[3]]),
        };

        let nla_len = header.length as usize;
        if nla_len < NLA_HEADER_SIZE {
            return Err(DecodeError::nla_invalid_length(buffer_len, nla_len));
        }
        if nla_len > buffer_len {
            return Err(DecodeError::nla_length_mismatch(buffer_len, nla_len));
        }

        let value = &buffer[NLA_HEADER_SIZE..nla_len];
        Ok(NlaBuffer { header, value })
    }

    /// Return the `type` field, without the flag bits.
    pub fn kind(&self) -> u16 {
        self.header.kind & NLA_TYPE_MASK
    }

    pub fn nested_flag(&self) -> bool {
        (self.header.kind & NLA_F_NESTED) != 0
    }

    pub fn network_byte_order_flag(&self) -> bool {
        (self.header.kind & NLA_F_NET_BYTEORDER) != 0
    }

    /// Return the `length` field. The `length` field corresponds to the length
    /// of the nla header (type and length fields, and the value field).
    /// However, it does not account for the potential padding that follows
    /// the value field.
    pub fn length(&self) -> u16 {
        self.header.length
    }

    /// Return the length of the `value` field.
    pub fn value_length(&self) -> usize {
        self.value.len()
    }

    /// Return the `value` field.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Iterate over the attributes contained in this attribute's value.
    ///
    /// This is intended for nested attributes. The [`NLA_F_NESTED`] flag is
    /// not required because some producers omit it; use
    /// [`NlaBuffer::nested_flag`] when the caller needs to check it.
    pub fn nlas(&self) -> NlasIterator<'a> {
        NlasIterator::new(self.value)
    }

    /// Parse the child attributes with `f`, skipping children for which `f`
    /// returns `Ok(None)`.
    ///
    /// Use this for nested lists that need filtering, per-kind dispatch, or
    /// parsing state shared across children: `f` may capture mutable state.
    /// For plain lists, implement [`Parseable`] for the element type and use
    /// `Vec<T>` directly.
    pub fn parse_nlas_with<T, F>(&self, mut f: F) -> Result<Vec<T>, DecodeError>
    where
        F: FnMut(NlaBuffer<'a>) -> Result<Option<T>, DecodeError>,
    {
        let mut out = Vec::new();
        for nla in self.nlas() {
            if let Some(item) = f(nla?)? {
                out.push(item);
            }
        }
        Ok(out)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DefaultNla {
    kind: u16,
    value: Vec<u8>,
}

impl DefaultNla {
    pub fn new(kind: u16, value: Vec<u8>) -> Self {
        Self { kind, value }
    }

    /// Return the raw attribute value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Nla for DefaultNla {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, &self.value);
        Ok(())
    }

    fn kind(&self) -> u16 {
        self.kind
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for DefaultNla {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let mut kind = buf.kind();

        if buf.network_byte_order_flag() {
            kind |= NLA_F_NET_BYTEORDER;
        }

        if buf.nested_flag() {
            kind |= NLA_F_NESTED;
        }

        Ok(DefaultNla {
            kind,
            value: buf.value().to_vec(),
        })
    }
}

impl<T: Nla> Emitable for [T] {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        for nla in self {
            nla.emit(out)?;
        }
        Ok(())
    }
}

impl<T: Nla> Emitable for &[T] {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        <[T] as Emitable>::emit_value(*self, out)
    }
}

impl<T: Nla> Emitable for Vec<T> {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        <[T] as Emitable>::emit_value(self.as_slice(), out)
    }
}

/// Emit a collection of netlink attributes into a newly allocated buffer.
pub fn emit_nlas<T: Nla>(nlas: &[T]) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    nlas.emit(&mut out)?;
    Ok(out)
}

/// An iterator that iteratates over nlas without decoding them. This is useful
/// when looking for specific nlas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlasIterator<'a> {
    position: usize,
    buffer: &'a [u8],
}

impl<'a> NlasIterator<'a> {
    /// Create an iterator over the netlink attributes in `buffer`.
    ///
    /// Any `AsRef<[u8]>` is accepted, such as `&[u8]`, `&Vec<u8>`, or a
    /// reference to a fixed-size array.
    pub fn new<T>(buffer: &'a T) -> Self
    where
        T: AsRef<[u8]> + ?Sized,
    {
        NlasIterator {
            position: 0,
            buffer: buffer.as_ref(),
        }
    }
}

impl<'a> Iterator for NlasIterator<'a> {
    type Item = Result<NlaBuffer<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.buffer.len() {
            return None;
        }

        // NOTE: the check above ensures `position < buffer.len()`.
        match NlaBuffer::new(&self.buffer[self.position..]) {
            Ok(nla_buffer) => {
                // NOTE: `length()` is a `u16`, so the addition inside
                // `nla_align!` cannot overflow `usize`; `saturating_add`
                // cannot overflow either.
                self.position = self
                    .position
                    .saturating_add(nla_align!(nla_buffer.length() as usize));
                Some(Ok(nla_buffer))
            }
            Err(e) => {
                // Make sure next time we call `next()`, we return None. We
                // don't try to continue iterating after we
                // failed to return a buffer.
                self.position = self.buffer.len();
                Some(Err(e))
            }
        }
    }
}

/// Parse a `Vec<T>` from a single netlink attribute by parsing each child
/// attribute as `T`.
///
/// This removes the need for per-protocol wrapper structs (such as the old
/// `VecLinkXdp`) when the nested value is a plain list of attributes.
impl<'a, T> Parseable<NlaBuffer<'a>> for Vec<T>
where
    T: Parseable<NlaBuffer<'a>>,
{
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        buf.nlas().map(|nla| T::parse(&nla?)).collect()
    }
}

/// Parse a `Vec<T>` from a raw payload containing a sequence of netlink
/// attributes.
///
/// This is the raw-payload counterpart of the `NlaBuffer` implementation
/// above, for message bodies and nested values that are not already wrapped in
/// an [`NlaBuffer`].
impl<T> Parseable<[u8]> for Vec<T>
where
    T: for<'a> Parseable<NlaBuffer<'a>>,
{
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        NlasIterator::new(buf).map(|nla| T::parse(&nla?)).collect()
    }
}

/// Parse a `Vec<T>` from a single netlink attribute, forwarding `param` to
/// each child attribute.
///
/// This removes wrapper types whose only job is to parse a parametrized nested
/// list (for example the old `VecRouteLwTunnelEncap`).
impl<'a, T, P> ParseableParametrized<NlaBuffer<'a>, P> for Vec<T>
where
    T: ParseableParametrized<NlaBuffer<'a>, P>,
    P: Clone,
{
    fn parse_with_param(
        buf: &NlaBuffer<'a>,
        param: P,
    ) -> Result<Self, DecodeError> {
        buf.nlas()
            .map(|nla| T::parse_with_param(&nla?, param.clone()))
            .collect()
    }
}

/// Parse a `Vec<T>` from a raw payload containing a sequence of netlink
/// attributes, forwarding `param` to each attribute.
///
/// This is the raw-payload counterpart of the `NlaBuffer` implementation
/// above, for message bodies that are not already wrapped in an
/// [`NlaBuffer`]. It removes the need for manual `Vec<T>` parsing in message
/// parsers.
impl<T, P> ParseableParametrized<[u8], P> for Vec<T>
where
    T: for<'a> ParseableParametrized<NlaBuffer<'a>, P>,
    P: Clone,
{
    fn parse_with_param(buf: &[u8], param: P) -> Result<Self, DecodeError> {
        NlasIterator::new(buf)
            .map(|nla| T::parse_with_param(&nla?, param.clone()))
            .collect()
    }
}

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_byteorder() {
        // The IPSET_ATTR_TIMEOUT attribute should have the network byte order
        // flag set. IPSET_ATTR_TIMEOUT(3600)
        static TEST_ATTRIBUTE: &[u8] =
            &[0x08, 0x00, 0x06, 0x40, 0x00, 0x00, 0x0e, 0x10];
        let buffer = NlaBuffer::new(TEST_ATTRIBUTE).unwrap();
        let buffer_is_net = buffer.network_byte_order_flag();
        let buffer_is_nest = buffer.nested_flag();

        let nla = DefaultNla::parse(&buffer).unwrap();
        let mut emitted_buffer = Vec::new();
        nla.emit(&mut emitted_buffer).unwrap();

        let attr_is_net = Nla::is_network_byteorder(&nla);
        let attr_is_nest = Nla::is_nested(&nla);

        let emit = NlaBuffer::new(&emitted_buffer).unwrap();
        let emit_is_net = emit.network_byte_order_flag();
        let emit_is_nest = emit.nested_flag();

        assert_eq!(
            [buffer_is_net, buffer_is_nest],
            [attr_is_net, attr_is_nest]
        );
        assert_eq!([attr_is_net, attr_is_nest], [emit_is_net, emit_is_nest]);
    }

    #[test]
    fn nested_and_network_byteorder() {
        let kind = 0x0005 | NLA_F_NESTED | NLA_F_NET_BYTEORDER;
        let nla = DefaultNla::new(kind, vec![0x00, 0x00, 0x0e, 0x10]);
        assert!(Nla::is_nested(&nla));
        assert!(Nla::is_network_byteorder(&nla));

        let mut emitted_buffer = Vec::new();
        nla.emit(&mut emitted_buffer).unwrap();

        let emit = NlaBuffer::new(&emitted_buffer).unwrap();
        assert_eq!(emit.kind(), 0x0005);
        assert!(emit.nested_flag());
        assert!(emit.network_byte_order_flag());

        // The parse -> emit round trip must preserve both flags.
        let reparsed = DefaultNla::parse(&emit).unwrap();
        assert_eq!(Nla::kind(&reparsed), kind);
        let mut reemitted_buffer = Vec::new();
        reparsed.emit(&mut reemitted_buffer).unwrap();
        assert_eq!(emitted_buffer, reemitted_buffer);
    }

    #[test]
    fn nla_buffer_rejects_too_small_buffer() {
        assert!(NlaBuffer::new(&[]).is_err());
        assert!(NlaBuffer::new(&[0u8]).is_err());
        assert!(NlaBuffer::new(&[0u8; 3]).is_err());
    }

    #[test]
    fn nla_buffer_rejects_invalid_length() {
        // The length field says 3, which is smaller than the header.
        let mut buffer = [0u8; 4];
        buffer[..2].copy_from_slice(&3u16.to_ne_bytes());
        assert!(NlaBuffer::new(&buffer).is_err());

        // The length field says 8 but the buffer is only 4 bytes.
        let mut buffer = [0u8; 4];
        buffer[..2].copy_from_slice(&8u16.to_ne_bytes());
        assert!(NlaBuffer::new(&buffer).is_err());
    }

    #[test]
    fn nla_buffer_accepts_padding() {
        let buffer = [0x05, 0x00, 0x07, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        let nla = NlaBuffer::new(&buffer).unwrap();
        assert_eq!(nla.length(), 5);
        assert_eq!(nla.value_length(), 1);
        assert_eq!(nla.kind(), 7);
        assert_eq!(nla.value(), &[0xaa]);
    }

    #[test]
    fn nla_buffer_accepts_maximum_length() {
        let mut buffer = vec![0u8; u16::MAX as usize];
        buffer[..2].copy_from_slice(&u16::MAX.to_ne_bytes());
        buffer[2..4].copy_from_slice(&0x1234u16.to_ne_bytes());

        let nla = NlaBuffer::new(&buffer).unwrap();
        assert_eq!(nla.length(), u16::MAX);
        assert_eq!(nla.value_length(), u16::MAX as usize - NLA_HEADER_SIZE);
        assert_eq!(nla.value().len(), u16::MAX as usize - NLA_HEADER_SIZE);
        assert_eq!(nla.kind(), 0x1234);
    }

    #[test]
    fn nla_buffer_and_iterator_accept_as_ref() {
        let buffer = [0x05u8, 0x00, 0x01, 0x00, 0xaa, 0x00, 0x00, 0x00];
        let vec = buffer.to_vec();
        let from_array = NlaBuffer::new(&buffer).unwrap();
        let from_vec = NlaBuffer::new(&vec).unwrap();

        assert_eq!(from_array.value(), from_vec.value());
        assert_eq!(NlasIterator::new(&buffer).count(), 1);
        assert_eq!(NlasIterator::new(&vec).count(), 1);
    }

    #[test]
    fn nla_buffer_iterates_nested_attributes() {
        let mut value = Vec::new();
        DefaultNla::new(1, vec![0xaa]).emit(&mut value).unwrap();
        DefaultNla::new(2, vec![0xbb, 0xcc])
            .emit(&mut value)
            .unwrap();

        let mut parent = Vec::new();
        DefaultNla::new(NLA_F_NESTED | 9, value)
            .emit(&mut parent)
            .unwrap();

        let nla = NlaBuffer::new(&parent).unwrap();
        assert!(nla.nested_flag());

        let children: Vec<_> = nla.nlas().map(|nla| nla.unwrap()).collect();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].kind(), 1);
        assert_eq!(children[0].value(), &[0xaa]);
        assert_eq!(children[1].kind(), 2);
        assert_eq!(children[1].value(), &[0xbb, 0xcc]);
    }

    #[test]
    fn vec_parseable_from_nla_buffer_and_bytes() {
        let mut value = Vec::new();
        DefaultNla::new(1, vec![0xaa]).emit(&mut value).unwrap();
        DefaultNla::new(2, vec![0xbb, 0xcc])
            .emit(&mut value)
            .unwrap();

        let mut parent = Vec::new();
        DefaultNla::new(NLA_F_NESTED | 9, value.clone())
            .emit(&mut parent)
            .unwrap();

        let nla = NlaBuffer::new(&parent).unwrap();
        let from_nla: Vec<DefaultNla> = Parseable::parse(&nla).unwrap();
        let from_bytes: Vec<DefaultNla> = Parseable::parse(&value[..]).unwrap();

        for parsed in [from_nla, from_bytes] {
            assert_eq!(parsed.len(), 2);
            assert_eq!(parsed[0].kind(), 1);
            assert_eq!(parsed[0].value(), &[0xaa]);
            assert_eq!(parsed[1].kind(), 2);
            assert_eq!(parsed[1].value(), &[0xbb, 0xcc]);
        }
    }

    #[test]
    fn parse_nlas_with_filters_and_shares_state() {
        let mut value = Vec::new();
        DefaultNla::new(1, vec![0xaa]).emit(&mut value).unwrap();
        DefaultNla::new(2, vec![0xbb]).emit(&mut value).unwrap();

        let mut parent = Vec::new();
        DefaultNla::new(NLA_F_NESTED | 9, value)
            .emit(&mut parent)
            .unwrap();
        let nla = NlaBuffer::new(&parent).unwrap();

        let mut seen = 0;
        let parsed: Vec<DefaultNla> = nla
            .parse_nlas_with(|child| {
                seen += 1;
                if child.kind() == 1 {
                    Ok(Some(DefaultNla::parse(&child)?))
                } else {
                    Ok(None)
                }
            })
            .unwrap();

        assert_eq!(seen, 2);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value(), &[0xaa]);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ParamNla(u16);

    impl<'a> ParseableParametrized<NlaBuffer<'a>, u16> for ParamNla {
        fn parse_with_param(
            _buf: &NlaBuffer<'a>,
            param: u16,
        ) -> Result<Self, DecodeError> {
            Ok(Self(param))
        }
    }

    #[test]
    fn vec_parseable_parametrized_forwards_param() {
        let mut value = Vec::new();
        DefaultNla::new(1, vec![0xaa]).emit(&mut value).unwrap();
        DefaultNla::new(2, vec![0xbb]).emit(&mut value).unwrap();

        let mut parent = Vec::new();
        DefaultNla::new(NLA_F_NESTED | 9, value.clone())
            .emit(&mut parent)
            .unwrap();
        let nla = NlaBuffer::new(&parent).unwrap();

        let from_nla: Vec<ParamNla> =
            Vec::parse_with_param(&nla, 7u16).unwrap();
        let from_bytes: Vec<ParamNla> =
            Vec::parse_with_param(&value[..], 7u16).unwrap();
        assert_eq!(from_nla, vec![ParamNla(7), ParamNla(7)]);
        assert_eq!(from_bytes, from_nla);
    }

    #[test]
    fn nla_buffer_accessors_never_panic() {
        // Exercise every truncation of a valid attribute and a range of
        // declared lengths. `new` is the only fallible entry point.
        let mut valid = Vec::new();
        DefaultNla::new(NLA_F_NESTED | NLA_F_NET_BYTEORDER | 1, vec![1, 2, 3])
            .emit(&mut valid)
            .unwrap();

        for len in 0..=valid.len() {
            if let Ok(nla) = NlaBuffer::new(&valid[..len]) {
                let _ = nla.length();
                let _ = nla.value_length();
                let _ = nla.kind();
                let _ = nla.nested_flag();
                let _ = nla.network_byte_order_flag();
                let _ = nla.value();
            }
        }

        for declared in 0u16..=16 {
            let mut buffer = valid.clone();
            buffer[..2].copy_from_slice(&declared.to_ne_bytes());
            if let Ok(nla) = NlaBuffer::new(&buffer) {
                let _ = nla.value();
            }
        }
    }

    fn get_len() -> usize {
        // usize::MAX
        18446744073709551615
    }

    #[test]
    fn kind_is_not_ambiguous() {
        use crate::*;

        let nla = DefaultNla::new(1, vec![]);
        assert_eq!(nla.kind(), 1);
    }

    #[test]
    fn nla_total_size_is_checked() {
        assert_eq!(nla_total_size(0).unwrap(), 4);
        assert_eq!(nla_total_size(3).unwrap(), 8);
        assert_eq!(nla_total_size(NLA_MAX_VALUE_LEN).unwrap(), 65536);
        assert!(nla_total_size(NLA_MAX_VALUE_LEN + 1).is_err());
    }

    struct FlagOverrideNla;

    impl Nla for FlagOverrideNla {
        fn emit_value(&self, _out: &mut Vec<u8>) -> Result<(), EncodeError> {
            Ok(())
        }

        fn kind(&self) -> u16 {
            1
        }

        fn is_nested(&self) -> bool {
            true
        }

        fn is_network_byteorder(&self) -> bool {
            true
        }
    }

    struct TruncatingNla;

    impl Nla for TruncatingNla {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            let len = out.len();
            out.truncate(len.saturating_sub(2));
            Ok(())
        }

        fn kind(&self) -> u16 {
            1
        }
    }

    #[test]
    fn nla_value_truncating_below_header_is_an_error() {
        let mut out = vec![0xaa];
        let error = TruncatingNla.emit(&mut out).unwrap_err();
        assert_eq!(error.kind(), crate::EncodeErrorKind::Bug);
        assert_eq!(out, vec![0xaa]);
    }

    #[test]
    fn emit_nla_uses_flag_overrides() {
        let mut out = Vec::new();
        FlagOverrideNla.emit(&mut out).unwrap();
        let nla = NlaBuffer::new(&out).unwrap();
        assert!(nla.nested_flag());
        assert!(nla.network_byte_order_flag());
    }

    #[test]
    fn emit_nla_slice() {
        let nlas = vec![
            DefaultNla::new(1, vec![1, 2, 3]),
            DefaultNla::new(2, vec![]),
        ];
        let mut buffer = Vec::new();
        nlas.as_slice().emit(&mut buffer).unwrap();
        assert_eq!(buffer, emit_nlas(&nlas).unwrap());
    }

    #[test]
    fn nla_limits_and_buffer() {
        let nla = DefaultNla::new(1, vec![0; NLA_MAX_VALUE_LEN]);
        let mut buffer = Vec::new();
        nla.emit(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 65536);
        assert_eq!(&buffer[..2], &u16::MAX.to_ne_bytes());

        let too_large = DefaultNla::new(1, vec![0; NLA_MAX_VALUE_LEN + 1]);
        let error = too_large.emit(&mut Vec::new()).unwrap_err();
        assert!(error.is_too_large());
    }

    #[test]
    fn emit_appends_to_existing_buffer() {
        let nla = DefaultNla::new(1, vec![1, 2, 3]);
        let mut out = vec![0xaa];
        nla.emit(&mut out).unwrap();
        assert_eq!(out[0], 0xaa);
        assert_eq!(&out[1..], emit_nlas(std::slice::from_ref(&nla)).unwrap());

        let too_large = DefaultNla::new(1, vec![0; NLA_MAX_VALUE_LEN + 1]);
        let mut out = vec![0xaa];
        assert!(too_large.emit(&mut out).is_err());
        assert_eq!(out, vec![0xaa]);
    }

    #[test]
    fn test_align() {
        assert_eq!(nla_align!(13), 16);
        assert_eq!(nla_align!(16), 16);
        assert_eq!(nla_align!(0), 0);
        assert_eq!(nla_align!(1), 4);
        assert_eq!(nla_align!(get_len() - 4), usize::MAX - 3);
    }
    #[test]
    #[should_panic]
    fn test_align_overflow() {
        assert_eq!(nla_align!(get_len() - 3), usize::MAX);
    }

    #[test]
    fn emit_nlas_rolls_back_after_later_failure() {
        let nlas = vec![
            DefaultNla::new(1, vec![1, 2, 3]),
            DefaultNla::new(2, vec![0; NLA_MAX_VALUE_LEN + 1]),
        ];
        let mut out = vec![0xaa];
        let error = nlas.emit(&mut out).unwrap_err();
        assert!(error.is_too_large());
        assert_eq!(out, vec![0xaa]);
    }

    #[test]
    fn test_nlas_iterator() {
        // sample NFTA_LIST_ELEM from nftables, with nested nlas at the end
        static NESTED_NLAS: &[u8] = &[
            0x0c, 0x00, 0x01, 0x00, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72,
            0x00, 0x1c, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x47, 0xda, 0x7a, 0x03, 0x1b, 0x0c, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x8e, 0x14, 0x56, 0x39,
        ];
        let mut iter = NlasIterator::new(NESTED_NLAS);
        // DecodeError does not implement PartialEq, hence
        // unwrap() and is_none()
        assert_eq!(iter.next().unwrap().unwrap().value(), &NESTED_NLAS[4..12]);
        assert_eq!(iter.next().unwrap().unwrap().value(), &NESTED_NLAS[16..]);
        assert!(iter.next().is_none());

        // this sholud be an Err()
        let truncated = &NESTED_NLAS[..NESTED_NLAS.len() - 1];
        assert!(NlasIterator::new(truncated).last().unwrap().is_err());

        let last = {
            // it should be possible to pass &[u8] through
            // NlasIterator and return one of its output &[u8]s without facing
            // compiler error about lifetimes and returning borrows from
            // something that is limited to this scope
            let last = NlasIterator::new(NESTED_NLAS).last();
            last.unwrap().unwrap().value()
        };
        assert_eq!(last, &NESTED_NLAS[16..]);
    }
}
