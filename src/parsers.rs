// SPDX-License-Identifier: MIT

use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::DecodeError;

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

pub fn append_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub fn append_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value);
}

macro_rules! gen_int_parser {
    ($data_type:ty, $parse:ident, $append:ident) => {
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

        pub fn $append(out: &mut Vec<u8>, value: $data_type) {
            out.extend_from_slice(&value.to_ne_bytes());
        }
    };
}

macro_rules! gen_int_parser_be {
    (
        $data_type:ty, $parse:ident, $parse_be:ident,
        $append:ident, $append_be:ident
    ) => {
        gen_int_parser!($data_type, $parse, $append);

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

        pub fn $append_be(out: &mut Vec<u8>, value: $data_type) {
            out.extend_from_slice(&value.to_be_bytes());
        }
    };
}

macro_rules! gen_int_parser_le_parse {
    ($data_type:ty, $parse_le:ident) => {
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
    };
}

gen_int_parser_be!(u16, parse_u16, parse_u16_be, append_u16, append_u16_be);
gen_int_parser_le_parse!(u16, parse_u16_le);
gen_int_parser_be!(u32, parse_u32, parse_u32_be, append_u32, append_u32_be);
gen_int_parser_be!(u64, parse_u64, parse_u64_be, append_u64, append_u64_be);
gen_int_parser!(i32, parse_i32, append_i32);
gen_int_parser!(i64, parse_i64, append_i64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_int_helpers() {
        assert_eq!(parse_u32(&42u32.to_ne_bytes()).unwrap(), 42);
        assert_eq!(parse_u16_be(&0x1234u16.to_be_bytes()).unwrap(), 0x1234);
        assert_eq!(parse_u16_le(&0x1234u16.to_le_bytes()).unwrap(), 0x1234);
        assert_eq!(parse_i64(&(-3i64).to_ne_bytes()).unwrap(), -3);

        let error = parse_u32(&[0u8; 3]).unwrap_err();
        assert!(matches!(error.kind(), crate::DecodeErrorKind::InvalidValue));
    }

    #[test]
    fn test_append_int_helpers() {
        let mut out = Vec::new();
        append_u8(&mut out, 0x12);
        append_u16(&mut out, 0x3456);
        append_u16_be(&mut out, 0x789a);
        append_u32_be(&mut out, 0xbcde_f012);
        append_i32(&mut out, -2);
        append_i64(&mut out, -3);
        append_bytes(&mut out, b"ab");

        assert_eq!(out[0], 0x12);
        assert_eq!(&out[1..3], &0x3456u16.to_ne_bytes());
        assert_eq!(&out[3..5], &0x789au16.to_be_bytes());
        assert_eq!(&out[5..9], &0xbcde_f012u32.to_be_bytes());
        assert_eq!(&out[9..13], &(-2i32).to_ne_bytes());
        assert_eq!(&out[13..21], &(-3i64).to_ne_bytes());
        assert_eq!(&out[21..], b"ab");
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
