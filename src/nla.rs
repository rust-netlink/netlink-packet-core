// SPDX-License-Identifier: MIT

use crate::{
    append_bytes, emit_u16, parse_u16,
    traits::{Emitable, Nla, Parseable},
    DecodeError, EncodeError,
};
use core::ops::Range;

/// Represent a multi-bytes field with a fixed size in a packet
type Field = Range<usize>;

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
    Ok(nla_align!(value_len + NLA_HEADER_SIZE))
}

const LENGTH: Field = 0..2;
const TYPE: Field = 2..4;
#[allow(non_snake_case)]
fn VALUE(length: usize) -> Field {
    TYPE.end..TYPE.end + length
}

// with Copy, NlaBuffer<&'buffer T> can be copied, which turns out to be pretty
// conveninent. And since it's boils down to copying a reference it's pretty
// cheap
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NlaBuffer<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> NlaBuffer<T> {
    pub fn new(buffer: T) -> NlaBuffer<T> {
        NlaBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<NlaBuffer<T>, DecodeError> {
        let buffer = Self::new(buffer);
        buffer.check_buffer_length()?;
        Ok(buffer)
    }

    pub fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < TYPE.end {
            Err(DecodeError::nla_buffer_too_small(len, TYPE.end))
        } else if len < self.length() as usize {
            Err(DecodeError::nla_length_mismatch(
                len,
                self.length() as usize,
            ))
        } else if (self.length() as usize) < TYPE.end {
            Err(DecodeError::nla_invalid_length(len, self.length() as usize))
        } else {
            Ok(())
        }
    }

    /// Consume the buffer, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return a reference to the underlying buffer
    pub fn inner(&mut self) -> &T {
        &self.buffer
    }

    /// Return a mutable reference to the underlying buffer
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.buffer
    }

    /// Return the `type` field
    pub fn kind(&self) -> u16 {
        let data = self.buffer.as_ref();
        parse_u16(&data[TYPE]).unwrap() & NLA_TYPE_MASK
    }

    pub fn nested_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (parse_u16(&data[TYPE]).unwrap() & NLA_F_NESTED) != 0
    }

    pub fn network_byte_order_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (parse_u16(&data[TYPE]).unwrap() & NLA_F_NET_BYTEORDER) != 0
    }

    /// Return the `length` field. The `length` field corresponds to the length
    /// of the nla header (type and length fields, and the value field).
    /// However, it does not account for the potential padding that follows
    /// the value field.
    pub fn length(&self) -> u16 {
        let data = self.buffer.as_ref();
        parse_u16(&data[LENGTH]).unwrap()
    }

    /// Return the length of the `value` field
    ///
    /// # Panic
    ///
    /// This panics if the length field value is less than the attribut header
    /// size.
    pub fn value_length(&self) -> usize {
        self.length() as usize - TYPE.end
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NlaBuffer<T> {
    /// Set the `type` field
    pub fn set_kind(&mut self, kind: u16) {
        let data = self.buffer.as_mut();
        emit_u16(&mut data[TYPE], kind & NLA_TYPE_MASK).unwrap()
    }

    pub fn set_nested_flag(&mut self) {
        // Do not use `self.kind()` as it masks out the NLA flag bits,
        // which would clear an already set NLA_F_NET_BYTEORDER.
        let data = self.buffer.as_mut();
        let kind = parse_u16(&data[TYPE]).unwrap();
        emit_u16(&mut data[TYPE], kind | NLA_F_NESTED).unwrap()
    }

    pub fn set_network_byte_order_flag(&mut self) {
        // Do not use `self.kind()` as it masks out the NLA flag bits,
        // which would clear an already set NLA_F_NESTED.
        let data = self.buffer.as_mut();
        let kind = parse_u16(&data[TYPE]).unwrap();
        emit_u16(&mut data[TYPE], kind | NLA_F_NET_BYTEORDER).unwrap()
    }

    /// Set the `length` field
    pub fn set_length(&mut self, length: u16) {
        let data = self.buffer.as_mut();
        emit_u16(&mut data[LENGTH], length).unwrap()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NlaBuffer<&'a T> {
    /// Return the `value` field
    pub fn value(&self) -> &'a [u8] {
        &self.buffer.as_ref()[VALUE(self.value_length())]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NlaBuffer<&mut T> {
    /// Return the `value` field
    pub fn value_mut(&mut self) -> &mut [u8] {
        let length = VALUE(self.value_length());
        &mut self.buffer.as_mut()[length]
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
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, &self.value);
        Ok(())
    }

    fn kind(&self) -> u16 {
        self.kind
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for DefaultNla
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
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

impl<T: Nla> Emitable for &[T] {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        emit_nlas_into(self, out)
    }
}

/// Append a collection of fallible attributes to `out`.
pub fn emit_nlas_into<T: Nla>(
    nlas: &[T],
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start = out.len();
    for nla in nlas {
        if let Err(error) = nla.emit_nla_into(out) {
            out.truncate(start);
            return Err(error);
        }
    }
    Ok(())
}

/// Emit a collection of fallible attributes into a newly allocated buffer.
pub fn emit_nlas<T: Nla>(nlas: &[T]) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    emit_nlas_into(nlas, &mut out)?;
    Ok(out)
}

/// An iterator that iteratates over nlas without decoding them. This is useful
/// when looking for specific nlas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlasIterator<T> {
    position: usize,
    buffer: T,
}

impl<T> NlasIterator<T> {
    pub fn new(buffer: T) -> Self {
        NlasIterator {
            position: 0,
            buffer,
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized + 'buffer> Iterator
    for NlasIterator<&'buffer T>
{
    type Item = Result<NlaBuffer<&'buffer [u8]>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.buffer.as_ref().len() {
            return None;
        }

        match NlaBuffer::new_checked(&self.buffer.as_ref()[self.position..]) {
            Ok(nla_buffer) => {
                self.position += nla_align!(nla_buffer.length() as usize);
                Some(Ok(nla_buffer))
            }
            Err(e) => {
                // Make sure next time we call `next()`, we return None. We
                // don't try to continue iterating after we
                // failed to return a buffer.
                self.position = self.buffer.as_ref().len();
                Some(Err(e))
            }
        }
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
        let buffer = NlaBuffer::new(TEST_ATTRIBUTE);
        let buffer_is_net = buffer.network_byte_order_flag();
        let buffer_is_nest = buffer.nested_flag();

        let nla = DefaultNla::parse(&buffer).unwrap();
        let mut emitted_buffer = Vec::new();
        nla.emit_nla_into(&mut emitted_buffer).unwrap();

        let attr_is_net = Nla::is_network_byteorder(&nla);
        let attr_is_nest = Nla::is_nested(&nla);

        let emit = NlaBuffer::new(emitted_buffer);
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
        nla.emit_nla_into(&mut emitted_buffer).unwrap();

        let emit = NlaBuffer::new(&emitted_buffer);
        assert_eq!(emit.kind(), 0x0005);
        assert!(emit.nested_flag());
        assert!(emit.network_byte_order_flag());

        // The parse -> emit round trip must preserve both flags.
        let reparsed = DefaultNla::parse(&emit).unwrap();
        assert_eq!(Nla::kind(&reparsed), kind);
        let mut reemitted_buffer = Vec::new();
        reparsed.emit_nla_into(&mut reemitted_buffer).unwrap();
        assert_eq!(emitted_buffer, reemitted_buffer);
    }

    #[test]
    fn set_flags_preserve_each_other() {
        for set_nested_first in [true, false] {
            let mut buf = vec![0u8; 8];
            {
                let mut nla = NlaBuffer::new(&mut buf);
                nla.set_kind(0x0005);
                nla.set_length(8);
                if set_nested_first {
                    nla.set_nested_flag();
                    nla.set_network_byte_order_flag();
                } else {
                    nla.set_network_byte_order_flag();
                    nla.set_nested_flag();
                }
            }
            let nla = NlaBuffer::new(&buf[..]);
            assert_eq!(nla.kind(), 0x0005);
            assert!(nla.nested_flag(), "nested first: {set_nested_first}");
            assert!(
                nla.network_byte_order_flag(),
                "nested first: {set_nested_first}"
            );
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
        fn emit_value_into(
            &self,
            _out: &mut Vec<u8>,
        ) -> Result<(), EncodeError> {
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
        fn emit_value_into(
            &self,
            out: &mut Vec<u8>,
        ) -> Result<(), EncodeError> {
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
        let error = TruncatingNla.emit_nla_into(&mut out).unwrap_err();
        assert_eq!(error.kind(), crate::EncodeErrorKind::Other);
        assert_eq!(out, vec![0xaa]);
    }

    #[test]
    fn emit_nla_uses_flag_overrides() {
        let mut out = Vec::new();
        FlagOverrideNla.emit_nla_into(&mut out).unwrap();
        let nla = NlaBuffer::new(out);
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
        nlas.as_slice().emit_into(&mut buffer).unwrap();
        assert_eq!(buffer, emit_nlas(&nlas).unwrap());
    }

    #[test]
    fn nla_limits_and_buffer() {
        let nla = DefaultNla::new(1, vec![0; NLA_MAX_VALUE_LEN]);
        let mut buffer = Vec::new();
        nla.emit_nla_into(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 65536);
        assert_eq!(&buffer[..2], &u16::MAX.to_ne_bytes());

        let too_large = DefaultNla::new(1, vec![0; NLA_MAX_VALUE_LEN + 1]);
        let error = too_large.emit_nla_into(&mut Vec::new()).unwrap_err();
        assert!(error.is_too_large());
    }

    #[test]
    fn emit_into_appends_to_existing_buffer() {
        let nla = DefaultNla::new(1, vec![1, 2, 3]);
        let mut out = vec![0xaa];
        nla.emit_nla_into(&mut out).unwrap();
        assert_eq!(out[0], 0xaa);
        assert_eq!(&out[1..], emit_nlas(std::slice::from_ref(&nla)).unwrap());

        let too_large = DefaultNla::new(1, vec![0; NLA_MAX_VALUE_LEN + 1]);
        let mut out = vec![0xaa];
        assert!(too_large.emit_nla_into(&mut out).is_err());
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
