// SPDX-License-Identifier: MIT

use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{DecodeError, EncodeError};

pub fn parse_mac(payload: &[u8]) -> Result<[u8; 6], DecodeError> {
    if payload.len() != 6 {
        return Err(DecodeError::invalid_mac_address(payload.len()));
    }
    let mut address: [u8; 6] = [0; 6];
    for (i, byte) in payload.iter().enumerate() {
        address[i] = *byte;
    }
    Ok(address)
}

pub fn parse_ipv6(payload: &[u8]) -> Result<[u8; 16], DecodeError> {
    if payload.len() != 16 {
        return Err(DecodeError::invalid_ip_address(payload.len()));
    }
    let mut address: [u8; 16] = [0; 16];
    for (i, byte) in payload.iter().enumerate() {
        address[i] = *byte;
    }
    Ok(address)
}

pub fn parse_ip(payload: &[u8]) -> Result<IpAddr, DecodeError> {
    match payload.len() {
        4 => Ok(
            Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3])
                .into(),
        ),
        16 => Ok(Ipv6Addr::from([
            payload[0],
            payload[1],
            payload[2],
            payload[3],
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ])
        .into()),
        other => Err(DecodeError::invalid_ip_address(other)),
    }
}

pub fn parse_string(payload: &[u8]) -> Result<String, DecodeError> {
    // Kernel netlink strings are NUL terminated: discard everything
    // from the first NUL byte onward. Tolerate a missing terminating
    // NUL as iproute2 is a bit inconsistent with null-terminated
    // strings.
    let end = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    let s = String::from_utf8(payload[..end].to_vec())?;
    Ok(s)
}

pub fn parse_u8(payload: &[u8]) -> Result<u8, DecodeError> {
    if payload.len() != 1 {
        return Err(DecodeError::invalid_number(1, payload.len()));
    }
    Ok(payload[0])
}

pub fn parse_i8(payload: &[u8]) -> Result<i8, DecodeError> {
    if payload.len() != 1 {
        return Err(DecodeError::invalid_number(1, payload.len()));
    }
    Ok(payload[0] as i8)
}

pub fn emit_u8(buf: &mut [u8], value: u8) -> Result<(), EncodeError> {
    emit_bytes(buf, &[value])
}

pub fn emit_i8(buf: &mut [u8], value: i8) -> Result<(), EncodeError> {
    emit_bytes(buf, &[value as u8])
}

pub fn emit_bytes(buf: &mut [u8], value: &[u8]) -> Result<(), EncodeError> {
    if buf.len() < value.len() {
        return Err(EncodeError::buffer_too_small(buf.len(), value.len()));
    }
    buf[..value.len()].copy_from_slice(value);
    Ok(())
}

pub fn append_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub fn append_i8(out: &mut Vec<u8>, value: i8) {
    out.push(value as u8);
}

pub fn append_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value);
}

macro_rules! gen_int_parser {
    (
        $(
            $parse:ident, $parse_be:ident, $parse_le:ident,
            $append:ident, $emit:ident,
            $append_le:ident, $emit_le:ident,
            $append_be:ident, $emit_be:ident,
            $data_type:ty,
        )+
    ) => {
        $(
            pub fn $parse(payload: &[u8]) -> Result<$data_type, DecodeError> {
                if payload.len() != size_of::<$data_type>() {
                    return Err(DecodeError::invalid_number(
                        size_of::<$data_type>(),
                        payload.len(),
                    ));
                }
                let mut data = [0u8; size_of::<$data_type>()];
                data.copy_from_slice(payload);
                Ok(<$data_type>::from_ne_bytes(data))
            }

            pub fn $parse_be(payload: &[u8]) -> Result<$data_type, DecodeError> {
                if payload.len() != size_of::<$data_type>() {
                    return Err(DecodeError::invalid_number(
                        size_of::<$data_type>(),
                        payload.len(),
                    ));
                }
                let mut data = [0u8; size_of::<$data_type>()];
                data.copy_from_slice(payload);
                Ok(<$data_type>::from_be_bytes(data))
            }

            pub fn $parse_le(payload: &[u8]) -> Result<$data_type, DecodeError> {
                if payload.len() != size_of::<$data_type>() {
                    return Err(DecodeError::invalid_number(
                        size_of::<$data_type>(),
                        payload.len(),
                    ));
                }
                let mut data = [0u8; size_of::<$data_type>()];
                data.copy_from_slice(payload);
                Ok(<$data_type>::from_le_bytes(data))
            }

            pub fn $append(out: &mut Vec<u8>, value: $data_type) {
                out.extend_from_slice(&value.to_ne_bytes());
            }

            pub fn $emit(
                buf: &mut [u8],
                value: $data_type,
            ) -> Result<(), EncodeError> {
                if buf.len() < size_of::<$data_type>() {
                    return Err(EncodeError::buffer_too_small(
                        buf.len(),
                        size_of::<$data_type>(),
                    ));
                }
                buf[..size_of::<$data_type>()]
                    .copy_from_slice(&value.to_ne_bytes());
                Ok(())
            }

            pub fn $append_le(out: &mut Vec<u8>, value: $data_type) {
                out.extend_from_slice(&value.to_le_bytes());
            }

            pub fn $emit_le(
                buf: &mut [u8],
                value: $data_type,
            ) -> Result<(), EncodeError> {
                if buf.len() < size_of::<$data_type>() {
                    return Err(EncodeError::buffer_too_small(
                        buf.len(),
                        size_of::<$data_type>(),
                    ));
                }
                buf[..size_of::<$data_type>()]
                    .copy_from_slice(&value.to_le_bytes());
                Ok(())
            }

            pub fn $append_be(out: &mut Vec<u8>, value: $data_type) {
                out.extend_from_slice(&value.to_be_bytes());
            }

            pub fn $emit_be(
                buf: &mut [u8],
                value: $data_type,
            ) -> Result<(), EncodeError> {
                if buf.len() < size_of::<$data_type>() {
                    return Err(EncodeError::buffer_too_small(
                        buf.len(),
                        size_of::<$data_type>(),
                    ));
                }
                buf[..size_of::<$data_type>()]
                    .copy_from_slice(&value.to_be_bytes());
                Ok(())
            }
        )+
    }
}

gen_int_parser!(
    parse_u16,
    parse_u16_be,
    parse_u16_le,
    append_u16,
    emit_u16,
    append_u16_le,
    emit_u16_le,
    append_u16_be,
    emit_u16_be,
    u16,
    parse_u32,
    parse_u32_be,
    parse_u32_le,
    append_u32,
    emit_u32,
    append_u32_le,
    emit_u32_le,
    append_u32_be,
    emit_u32_be,
    u32,
    parse_u64,
    parse_u64_be,
    parse_u64_le,
    append_u64,
    emit_u64,
    append_u64_le,
    emit_u64_le,
    append_u64_be,
    emit_u64_be,
    u64,
    parse_u128,
    parse_u128_be,
    parse_u128_le,
    append_u128,
    emit_u128,
    append_u128_le,
    emit_u128_le,
    append_u128_be,
    emit_u128_be,
    u128,
    parse_i16,
    parse_i16_be,
    parse_i16_le,
    append_i16,
    emit_i16,
    append_i16_le,
    emit_i16_le,
    append_i16_be,
    emit_i16_be,
    i16,
    parse_i32,
    parse_i32_be,
    parse_i32_le,
    append_i32,
    emit_i32,
    append_i32_le,
    emit_i32_le,
    append_i32_be,
    emit_i32_be,
    i32,
    parse_i64,
    parse_i64_be,
    parse_i64_le,
    append_i64,
    emit_i64,
    append_i64_le,
    emit_i64_le,
    append_i64_be,
    emit_i64_be,
    i64,
    parse_i128,
    parse_i128_be,
    parse_i128_le,
    append_i128,
    emit_i128,
    append_i128_le,
    emit_i128_le,
    append_i128_be,
    emit_i128_be,
    i128,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_int_helpers() {
        let mut buf = [0u8; 4];
        emit_u32(&mut buf, 0x1234_5678).unwrap();
        assert_eq!(parse_u32(&buf).unwrap(), 0x1234_5678);

        let error = emit_u32(&mut [], 1).unwrap_err();
        assert!(matches!(
            error.kind(),
            crate::EncodeErrorKind::BufferTooSmall
        ));

        emit_u32(&mut buf, 42).unwrap();
        assert_eq!(parse_u32(&buf).unwrap(), 42);

        let mut byte = [0u8; 1];
        emit_i8(&mut byte, -1).unwrap();
        assert_eq!(parse_i8(&byte).unwrap(), -1);
        emit_u8(&mut byte, 7).unwrap();
        assert_eq!(parse_u8(&byte).unwrap(), 7);
    }

    #[test]
    fn test_append_int_helpers() {
        let mut out = Vec::new();
        append_u8(&mut out, 0x12);
        append_i8(&mut out, -1);
        append_u16_le(&mut out, 0x3456);
        append_u32_be(&mut out, 0x789a_bcde);
        append_i32(&mut out, -2);
        append_bytes(&mut out, b"ab");

        assert_eq!(out[0], 0x12);
        assert_eq!(out[1], 0xff);
        assert_eq!(&out[2..4], &0x3456u16.to_le_bytes());
        assert_eq!(&out[4..8], &0x789a_bcdeu32.to_be_bytes());
        assert_eq!(&out[8..12], &(-2i32).to_ne_bytes());
        assert_eq!(&out[12..], b"ab");
    }

    #[test]
    fn test_parse_string() {
        assert_eq!(parse_string(b"").unwrap(), "");
        assert_eq!(parse_string(b"eth0").unwrap(), "eth0");
        assert_eq!(parse_string(b"eth0\0").unwrap(), "eth0");
        // Discard anything after the first NUL.
        assert_eq!(parse_string(b"eth0\0trash").unwrap(), "eth0");
        assert_eq!(parse_string(b"eth0\0\0").unwrap(), "eth0");
        assert_eq!(parse_string(b"\0").unwrap(), "");
        assert_eq!(parse_string(b"\0trash").unwrap(), "");
        assert!(parse_string(b"\xff\xfe").is_err());
    }
}
