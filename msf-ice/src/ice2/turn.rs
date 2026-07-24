use std::net::SocketAddr;

use bytes::{Buf, Bytes};
use msf_stun::{InvalidMessage, Message, MessageClass, Method};
use zerocopy::{network_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::ice2::{
    stun::{IncomingMessage, STUN},
    transport::Packet,
};

/// TURN client.
#[derive(Clone)]
pub struct TURN {
    stun: STUN,
}

impl TURN {
    /// Create a new TURN client.
    pub fn new(stun: STUN) -> Self {
        Self { stun }
    }

    /// Process a given channel data frame and the corresponding data packet if
    /// the channel is valid.
    pub fn process_channel_data(&self, data: ChannelData) -> Option<Packet> {
        // TODO: check if a given peer matches an existing allocation
        // TODO: check if the channel exists
        // TODO: return the data as a packet (base_addr will be the relayed
        //   address and the remote_addr will be the remote peer)

        None
    }

    /// Process a given incoming message.
    ///
    /// The method will reject the message if it is not a valid TURN data
    /// indication. Otherwise, it will return the data as a packet or `None`
    /// if the corresponding allocation does not exist.
    pub fn process_incoming_message(
        &self,
        msg: IncomingMessage,
    ) -> Result<Option<Packet>, IncomingMessage> {
        // NOTE: We don't process any requests or responses here. This is a
        //   TURN client, so no requests are expected and all responses are
        //   handled by the STUN context.
        if msg.class() == MessageClass::Indication {
            self.process_indication(msg)
        } else {
            Err(msg)
        }
    }

    /// Process a given TURN data indication.
    fn process_indication(&self, msg: IncomingMessage) -> Result<Option<Packet>, IncomingMessage> {
        if !msg.is_rfc5389_message() || msg.method() != Method::Data {
            return Err(msg);
        }

        // TODO: check if a given peer matches an existing allocation
        // TODO: return the data as a packet (base_addr will be the relayed
        //   address and the remote_addr will be the remote peer)

        Ok(None)
    }
}

/// TURN allocation handle.
///
/// Keep the allocation handle around to ensure that the allocation is not
/// released while it is still in use.
#[derive(Clone)]
pub struct TURNAllocation {}

impl TURNAllocation {
    /// Get the TURN server address.
    pub fn turn_server(&self) -> SocketAddr {
        unimplemented!()
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        unimplemented!()
    }

    /// Get the relayed address.
    pub fn relayed_addr(&self) -> SocketAddr {
        unimplemented!()
    }

    /// Construct an outgoing packet that can be passed to the TURN server for
    /// relaying to a given remote peer address.
    pub async fn construct_outgoing_packet(
        &self,
        base_addr: SocketAddr,
        remote_addr: SocketAddr,
        data: &[u8],
    ) -> Packet {
        // NOTE: we assume that all relayed addresses are unique
        // TODO: the new packet will use the same base_addr, the remote_addr
        //   will be the address of the TURN server
        // TODO: create TURN permission for the remote_addr if it does not
        //   exist

        unimplemented!("TODO")
    }
}

/// Invalid TURN frame error.
pub enum InvalidFrame {
    InvalidHeader,
    PartialContent,
    InvalidMessage(InvalidMessage),
}

impl From<InvalidMessage> for InvalidFrame {
    fn from(err: InvalidMessage) -> Self {
        Self::InvalidMessage(err)
    }
}

/// Incoming TURN frame.
pub enum IncomingFrame {
    Message(IncomingMessage),
    ChannelData(ChannelData),
}

impl IncomingFrame {
    /// Try to parse an incoming TURN frame from a given packet.
    pub fn from_packet(packet: Packet, rfc_5766_compatible: bool) -> Result<Self, InvalidFrame> {
        let base_addr = packet.base_addr();
        let remote_addr = packet.remote_addr();

        let mut buf = packet.into_data();

        let header = match FrameHeader::read_from_prefix(&buf) {
            Ok((h, _)) => h,
            Err(_) => return Err(InvalidFrame::InvalidHeader),
        };

        let prefix = header.prefix.get();
        let length = header.length.get() as usize;
        let padded_length = (length + 3) & !3;

        let is_invalid = (prefix < 0x4000 && length != padded_length)
            || (prefix >= 0x5000 && !rfc_5766_compatible)
            || prefix >= 0x8000;

        if is_invalid {
            Err(InvalidFrame::InvalidHeader)
        } else if buf.len() < (4 + padded_length) {
            Err(InvalidFrame::PartialContent)
        } else if prefix < 0x4000 {
            let frame = buf.split_to(4 + padded_length);

            let msg = Message::from_frame(frame)?;

            if msg.is_rfc5389_message() {
                let msg = IncomingMessage::new(base_addr, remote_addr, msg);

                Ok(IncomingFrame::Message(msg))
            } else {
                Err(InvalidFrame::InvalidMessage(InvalidMessage::InvalidHeader))
            }
        } else {
            // skip the frame header
            buf.advance(4);

            let data = ChannelData {
                base_addr,
                remote_addr,
                channel: prefix,
                data: buf.split_to(length),
            };

            Ok(IncomingFrame::ChannelData(data))
        }
    }
}

/// TURN channel data.
#[derive(Clone)]
pub struct ChannelData {
    base_addr: SocketAddr,
    remote_addr: SocketAddr,
    channel: u16,
    data: Bytes,
}

/// TURN frame header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct FrameHeader {
    prefix: U16,
    length: U16,
}
