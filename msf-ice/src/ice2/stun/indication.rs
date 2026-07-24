use std::{io, net::SocketAddr};

use bytes::Bytes;
use msf_stun::{MessageBuilder, Method};

use crate::ice2::transport::{OutgoingPacketDispatcher, Packet};

/// STUN indication builder.
pub struct IndicationBuilder<'a> {
    builder: MessageBuilder<'a>,
    dispatcher: OutgoingPacketDispatcher,
}

impl<'a> IndicationBuilder<'a> {
    /// Create a new builder.
    pub(super) fn new(method: Method, dispatcher: OutgoingPacketDispatcher) -> Self {
        Self {
            builder: MessageBuilder::indication(method, rand::random()),
            dispatcher,
        }
    }

    /// Set the XOR-PEER-ADDRESS attribute.
    pub fn xor_peer_address(mut self, address: SocketAddr) -> Self {
        self.builder.xor_peer_address(address);
        self
    }

    /// Set the DATA attribute.
    pub fn data(mut self, data: &'a [u8]) -> Self {
        self.builder.data(data);
        self
    }

    /// Build the indication.
    pub fn build(self) -> Indication {
        Indication {
            indication: self.builder.build(),
            dispatcher: self.dispatcher,
        }
    }
}

/// STUN indication.
pub struct Indication {
    indication: Bytes,
    dispatcher: OutgoingPacketDispatcher,
}

impl Indication {
    /// Send the indication from a given base address to a given remote
    /// address.
    pub async fn send(self, base_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<()> {
        self.dispatcher
            .send(Packet::new(base_addr, remote_addr, self.indication))
            .await
    }
}
