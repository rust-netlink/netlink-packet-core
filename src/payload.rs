// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use crate::{DoneMessage, ErrorMessage, NetlinkMessagePayload};

/// The message is ignored.
pub(crate) const NLMSG_NOOP: u16 = 1;
/// The message signals an error and the payload contains a nlmsgerr structure.
/// This can be looked at as a NACK and typically it is from FEC to CPC.
pub(crate) const NLMSG_ERROR: u16 = 2;
/// The message terminates a multipart message.
pub(crate) const NLMSG_DONE: u16 = 3;
/// Data lost.
pub(crate) const NLMSG_OVERRUN: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NetlinkPayload<I> {
    Done(DoneMessage),
    Error(ErrorMessage),
    Noop,
    Overrun(Vec<u8>),
    InnerMessage(I),
}

impl<I> NetlinkPayload<I>
where
    I: NetlinkMessagePayload,
{
    pub fn message_type(&self) -> u16 {
        match self {
            NetlinkPayload::Done(_) => NLMSG_DONE,
            NetlinkPayload::Error(_) => NLMSG_ERROR,
            NetlinkPayload::Noop => NLMSG_NOOP,
            NetlinkPayload::Overrun(_) => NLMSG_OVERRUN,
            NetlinkPayload::InnerMessage(message) => message.message_type(),
        }
    }
}
