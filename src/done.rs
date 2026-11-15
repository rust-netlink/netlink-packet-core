// SPDX-License-Identifier: MIT

use crate::{
    append_bytes, append_i32, error::NLMSGERR_ATTR_MSG, parse_i32, DecodeError,
    DecodeErrorKind, Emitable, EncodeError, ErrorContext, Field, NlasIterator,
    Parseable, Rest,
};

const CODE: Field = 0..4;
const EXTENDED_ACK: Rest = 4..;
pub(crate) const DONE_HEADER_LEN: usize = EXTENDED_ACK.start;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DoneBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> DoneBuffer<T> {
    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Check that the buffer is large enough to contain a `Done` header and
    /// create a `DoneBuffer` from it.
    pub fn new(buffer: T) -> Result<Self, DecodeError> {
        let packet = DoneBuffer { buffer };
        packet
            .check_buffer_length()
            .context("invalid DoneBuffer length")?;
        Ok(packet)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < DONE_HEADER_LEN {
            Err(DecodeError::new(
                DecodeErrorKind::BufferTooSmall,
                format!(
                    "invalid DoneBuffer: length is {len} but DoneBuffer are \
                     at least {DONE_HEADER_LEN} bytes"
                ),
            ))
        } else {
            Ok(())
        }
    }

    /// Return the error code
    pub fn code(&self) -> i32 {
        let data = self.buffer.as_ref();
        parse_i32(&data[CODE]).unwrap()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> DoneBuffer<&'a T> {
    /// Return a pointer to the extended ack attributes.
    ///
    /// The kernel appends these attributes after the error code when the
    /// `NETLINK_EXT_ACK` socket option is enabled. Use
    /// [`DoneMessage::extended_ack_message`] to get the kernel message.
    pub fn extended_ack(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[EXTENDED_ACK]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> DoneBuffer<T> {
    /// set the error code field
    pub fn set_code(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        data[CODE].copy_from_slice(&value.to_ne_bytes());
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DoneMessage {
    pub code: i32,
    /// Raw extended ACK attributes appended after [`Self::code`].
    ///
    /// The kernel only appends attributes when the `NETLINK_EXT_ACK` socket
    /// option is enabled.
    pub extended_ack: Vec<u8>,
}

impl DoneMessage {
    /// Return the human readable message from the extended ACK attributes, if
    /// the kernel provided one.
    pub fn extended_ack_message(&self) -> Option<&str> {
        for attribute in NlasIterator::new(&self.extended_ack).ok()? {
            if attribute.kind() == NLMSGERR_ATTR_MSG {
                let value = attribute.value();
                let end = value
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(value.len());
                return std::str::from_utf8(&value[..end]).ok();
            }
        }
        None
    }
}

impl Emitable for DoneMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_i32(out, self.code);
        append_bytes(out, &self.extended_ack);
        Ok(())
    }
}

impl<T: AsRef<[u8]>> Parseable<DoneBuffer<&T>> for DoneMessage {
    fn parse(buf: &DoneBuffer<&T>) -> Result<DoneMessage, DecodeError> {
        Ok(DoneMessage {
            code: buf.code(),
            extended_ack: buf.extended_ack().to_vec(),
        })
    }
}

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn new_reports_decode_error_kind() {
        let err = DoneBuffer::new(vec![0; DONE_HEADER_LEN - 1]).unwrap_err();
        assert_eq!(err.kind(), crate::DecodeErrorKind::BufferTooSmall);
    }

    #[test]
    fn serialize_and_parse() {
        let expected = DoneMessage {
            code: 5,
            extended_ack: vec![1, 2, 3],
        };

        let mut buf = Vec::new();
        expected.emit(&mut buf).unwrap();
        assert_eq!(buf.len(), size_of::<i32>() + expected.extended_ack.len());

        let done_buf = DoneBuffer::new(&buf).unwrap();
        assert_eq!(done_buf.code(), expected.code);
        assert_eq!(done_buf.extended_ack(), &expected.extended_ack);

        let got = DoneMessage::parse(&done_buf).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn parse_real_nlmon_ext_ack_capture() {
        // Captured with nlmon while sending an RTM_GETLINK dump request with
        // strict checking enabled and an unsupported ifi_index filter. The
        // kernel replied with NLMSG_DONE carrying NLMSGERR_ATTR_MSG.
        #[rustfmt::skip]
        static PAYLOAD: [u8; 60] = [
            0xea, 0xff, 0xff, 0xff, 0x38, 0x00, 0x01, 0x00,
            0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x20, 0x62,
            0x79, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
            0x20, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x20, 0x6e,
            0x6f, 0x74, 0x20, 0x73, 0x75, 0x70, 0x70, 0x6f,
            0x72, 0x74, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72,
            0x20, 0x6c, 0x69, 0x6e, 0x6b, 0x20, 0x64, 0x75,
            0x6d, 0x70, 0x73, 0x00,
        ];

        let buf = DoneBuffer::new(&PAYLOAD).unwrap();
        assert_eq!(buf.code(), -22);
        assert_eq!(buf.extended_ack(), &PAYLOAD[4..]);

        let msg = DoneMessage::parse(&buf).unwrap();
        assert_eq!(msg.code, -22);
        assert_eq!(msg.extended_ack, PAYLOAD[4..].to_vec());
        assert_eq!(
            msg.extended_ack_message(),
            Some("Filter by device index not supported for link dumps")
        );
    }

    #[test]
    fn extended_ack_message_without_attributes() {
        let msg = DoneMessage::default();
        assert_eq!(msg.extended_ack_message(), None);
    }
}
