use std::{io, net::SocketAddr};

use bytes::Bytes;
use msf_stun::{MessageBuilder, MessageIntegrityAlgorithm};

use crate::ice2::transport::{OutgoingPacketDispatcher, Packet};

/// STUN response builder.
pub struct ResponseBuilder<'a> {
    builder: MessageBuilder<'a>,
    dispatcher: OutgoingPacketDispatcher,
}

impl<'a> ResponseBuilder<'a> {
    /// Create a new response builder.
    pub(super) fn new(builder: MessageBuilder<'a>, dispatcher: OutgoingPacketDispatcher) -> Self {
        Self {
            builder,
            dispatcher,
        }
    }

    /// Set the UNKNOWN-ATTRIBUTES attribute.
    pub fn unknown_attributes(mut self, unknown_attributes: &'a [u16]) -> Self {
        self.builder.unknown_attributes(unknown_attributes);
        self
    }

    /// Set the XOR-MAPPED-ADDRESS attribute.
    pub fn xor_mapped_address(mut self, addr: SocketAddr) -> Self {
        self.builder.xor_mapped_address(addr);
        self
    }

    /// Set the FINGERPRINT attribute.
    pub fn fingerprint(mut self, enable: bool) -> Self {
        self.builder.fingerprint(enable);
        self
    }

    /// Set key for the MESSAGE-INTEGRITY(-SHA256) attribute.
    pub fn message_integrity_key(mut self, key: &'a [u8]) -> Self {
        self.builder.message_integrity_key(key);
        self
    }

    /// Set the algorithm for the MESSAGE-INTEGRITY(-SHA256) attribute.
    pub fn message_integrity_algorithm(mut self, algorithm: MessageIntegrityAlgorithm) -> Self {
        self.builder.message_integrity_algorithm(algorithm);
        self
    }

    /// Build the response.
    pub fn build(self) -> Response {
        Response {
            dispatcher: self.dispatcher,
            response: self.builder.build(),
        }
    }
}

/// STUN response.
pub struct Response {
    dispatcher: OutgoingPacketDispatcher,
    response: Bytes,
}

impl Response {
    /// Send the response from a given base address to a given remote address.
    pub async fn send(self, base_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<()> {
        self.dispatcher
            .send(Packet::new(base_addr, remote_addr, self.response))
            .await
    }
}
