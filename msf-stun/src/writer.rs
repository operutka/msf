use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
};

use bytes::BytesMut;
use zerocopy::{
    network_endian::{U16, U32},
    IntoBytes,
};

use crate::{
    attribute::{common, ErrorCode, PasswordAlgorithm, SerializeAttribute},
    MessageClass, MessageHeader, Method, TransactionID,
};

#[cfg(feature = "ice")]
use crate::attribute::ice;

#[cfg(feature = "turn")]
use crate::attribute::{
    turn, AddressErrorCode, AddressFamily, ChannelNumber, EvenPort, TransportProtocol, ICMP,
};

/// STUN message buffer.
pub struct MessageBuffer<'a> {
    buffer: &'a mut BytesMut,
}

impl<'a> MessageBuffer<'a> {
    /// Create a new message buffer.
    pub fn new(buffer: &'a mut BytesMut) -> Self {
        Self { buffer }
    }
}

impl MessageBuffer<'_> {
    /// Create a new message writer.
    pub fn create_message(
        &mut self,
        class: MessageClass,
        method: Method,
        magic_cookie: u32,
        transaction_id: TransactionID,
    ) -> MessageWriter<'_> {
        let start = self.buffer.len();

        let mut writer = MessageWriter {
            buffer: self.buffer,
            start,
        };

        let class = class.into_message_type();
        let method = method.into_message_type();

        let message_type = class | method;

        writer.reserve(20);

        let header = MessageHeader {
            message_type: U16::new(message_type),
            message_length: U16::new(0),
            magic_cookie: U32::new(magic_cookie),
            transaction_id,
        };

        writer.extend_from_slice(header.as_bytes());

        writer
    }
}

/// STUN message writer.
pub struct MessageWriter<'a> {
    buffer: &'a mut BytesMut,
    start: usize,
}

impl Drop for MessageWriter<'_> {
    fn drop(&mut self) {
        let msg = &mut self.buffer[self.start..];

        let len = msg.len() - 20;

        super::set_message_length(msg, len as u16);
    }
}

impl MessageWriter<'_> {
    /// Finalize the message.
    pub fn finalize(self) {
        // This is just a noop method that triggers the drop of the message
        // writer, which will finalize the message.
    }

    /// Write the error code attribute.
    pub fn put_error_code(&mut self, error_code: &ErrorCode) {
        error_code.serialize(common::ATTR_TYPE_ERROR_CODE, self);
    }

    /// Write the unknown attributes attribute.
    pub fn put_unknown_attributes(&mut self, attributes: &[u16]) {
        attributes.serialize(common::ATTR_TYPE_UNKNOWN_ATTRIBUTES, self);
    }

    /// Write the alternate server attribute.
    pub fn put_alternate_server(&mut self, addr: SocketAddr) {
        addr.serialize(common::ATTR_TYPE_ALTERNATE_SERVER, self);
    }

    /// Write the alternate domain attribute.
    pub fn put_alternate_domain(&mut self, domain: &str) {
        domain.serialize(common::ATTR_TYPE_ALTERNATE_DOMAIN, self);
    }

    /// Write the mapped address attribute.
    pub fn put_mapped_address(&mut self, addr: SocketAddr) {
        addr.serialize(common::ATTR_TYPE_MAPPED_ADDRESS, self);
    }

    /// Write the xor mapped address attribute.
    pub fn put_xor_mapped_address(&mut self, addr: SocketAddr) {
        self.get_xor_address(addr)
            .serialize(common::ATTR_TYPE_XOR_MAPPED_ADDRESS, self);
    }

    /// Write the username attribute.
    pub fn put_username(&mut self, username: &str) {
        username.serialize(common::ATTR_TYPE_USERNAME, self);
    }

    /// Write the userhash attribute.
    pub fn put_userhash(&mut self, userhash: &[u8; 32]) {
        userhash
            .as_ref()
            .serialize(common::ATTR_TYPE_USERHASH, self);
    }

    /// Write the realm attribute.
    pub fn put_realm(&mut self, realm: &str) {
        realm.serialize(common::ATTR_TYPE_REALM, self);
    }

    /// Write the nonce attribute.
    pub fn put_nonce(&mut self, nonce: &str) {
        nonce.serialize(common::ATTR_TYPE_NONCE, self);
    }

    /// Write the password algorithms attribute.
    pub fn put_password_algorithms(&mut self, algorithms: &[PasswordAlgorithm]) {
        algorithms.serialize(common::ATTR_TYPE_PASSWORD_ALGORITHMS, self);
    }

    /// Write the password algorithm attribute.
    pub fn put_password_algorithm(&mut self, algorithm: &PasswordAlgorithm) {
        algorithm.serialize(common::ATTR_TYPE_PASSWORD_ALGORITHM, self);
    }

    /// Write the software attribute.
    pub fn put_software(&mut self, software: &str) {
        software.serialize(common::ATTR_TYPE_SOFTWARE, self);
    }

    /// Write the message integrity attribute.
    pub fn put_message_integrity(&mut self, key: &[u8]) {
        super::calculate_message_integrity(key, &self.buffer[self.start..])
            .as_ref()
            .serialize(common::ATTR_TYPE_MESSAGE_INTEGRITY, self);
    }

    /// Write the message integrity SHA-256 attribute.
    pub fn put_message_integrity_sha256(&mut self, key: &[u8]) {
        super::calculate_message_integrity_sha256(key, &self.buffer[self.start..])
            .as_ref()
            .serialize(common::ATTR_TYPE_MESSAGE_INTEGRITY_SHA256, self);
    }

    /// Write the fingerprint attribute.
    pub fn put_fingerprint(&mut self) {
        super::calculate_fingerprint(&self.buffer[self.start..])
            .serialize(common::ATTR_TYPE_FINGERPRINT, self);
    }

    /// Get the XOR-ed address for a given transport address.
    fn get_xor_address(&self, addr: SocketAddr) -> SocketAddr {
        let mut u16_xor_bits = [0u8; 2];
        let mut u32_xor_bits = [0u8; 4];
        let mut u128_xor_bits = [0u8; 16];

        let msg = &self.buffer[self.start..];

        u16_xor_bits.copy_from_slice(&msg[4..6]);
        u32_xor_bits.copy_from_slice(&msg[4..8]);
        u128_xor_bits.copy_from_slice(&msg[4..20]);

        let u16_xor_bits = u16::from_be_bytes(u16_xor_bits);
        let u32_xor_bits = u32::from_be_bytes(u32_xor_bits);
        let u128_xor_bits = u128::from_be_bytes(u128_xor_bits);

        match addr {
            SocketAddr::V4(addr) => {
                let ip = u32::from(*addr.ip()) ^ u32_xor_bits;
                let port = addr.port() ^ u16_xor_bits;

                SocketAddr::from((Ipv4Addr::from(ip), port))
            }
            SocketAddr::V6(addr) => {
                let ip = u128::from(*addr.ip()) ^ u128_xor_bits;
                let port = addr.port() ^ u16_xor_bits;

                SocketAddr::from((Ipv6Addr::from(ip), port))
            }
        }
    }
}

#[cfg(feature = "ice")]
impl MessageWriter<'_> {
    /// Write the ICE candidate priority attribute.
    pub fn put_priority(&mut self, priority: u32) {
        priority.serialize(ice::ATTR_TYPE_PRIORITY, self);
    }

    /// Write the ICE use candidate attribute.
    pub fn put_use_candidate(&mut self) {
        SerializeAttribute::serialize(&(), ice::ATTR_TYPE_USE_CANDIDATE, self);
    }

    /// Write the ICE controlled attribute.
    pub fn put_ice_controlled(&mut self, n: u64) {
        n.serialize(ice::ATTR_TYPE_ICE_CONTROLLED, self);
    }

    /// Write the ICE controlling attribute.
    pub fn put_ice_controlling(&mut self, n: u64) {
        n.serialize(ice::ATTR_TYPE_ICE_CONTROLLING, self);
    }
}

#[cfg(feature = "turn")]
impl MessageWriter<'_> {
    /// Write the channel number attribute.
    pub fn put_channel_number(&mut self, channel_number: ChannelNumber) {
        channel_number.serialize(turn::ATTR_TYPE_CHANNEL_NUMBER, self);
    }

    /// Write the lifetime attribute.
    pub fn put_lifetime(&mut self, lifetime: u32) {
        lifetime.serialize(turn::ATTR_TYPE_LIFETIME, self);
    }

    /// Write the xor peer address attribute.
    pub fn put_xor_peer_address(&mut self, addr: SocketAddr) {
        self.get_xor_address(addr)
            .serialize(turn::ATTR_TYPE_XOR_PEER_ADDRESS, self);
    }

    /// Write the data attribute.
    pub fn put_data(&mut self, data: &[u8]) {
        data.serialize(turn::ATTR_TYPE_DATA, self);
    }

    /// Write the xor relayed address attribute.
    pub fn put_xor_relayed_address(&mut self, addr: SocketAddr) {
        self.get_xor_address(addr)
            .serialize(turn::ATTR_TYPE_XOR_RELAYED_ADDRESS, self);
    }

    /// Write the requested address family attribute.
    pub fn put_requested_address_family(&mut self, family: AddressFamily) {
        family.serialize(turn::ATTR_TYPE_REQUESTED_ADDRESS_FAMILY, self);
    }

    /// Write the even port attribute.
    pub fn put_even_port(&mut self, even_port: EvenPort) {
        even_port.serialize(turn::ATTR_TYPE_EVEN_PORT, self);
    }

    /// Write the requested transport attribute.
    pub fn put_requested_transport(&mut self, protocol: TransportProtocol) {
        protocol.serialize(turn::ATTR_TYPE_REQUESTED_TRANSPORT, self);
    }

    /// Write the dont fragment attribute.
    pub fn put_dont_fragment(&mut self) {
        SerializeAttribute::serialize(&(), turn::ATTR_TYPE_DONT_FRAGMENT, self);
    }

    /// Write the reservation token attribute.
    pub fn put_reservation_token(&mut self, token: u64) {
        token.serialize(turn::ATTR_TYPE_RESERVATION_TOKEN, self);
    }

    /// Write the additional address family attribute.
    pub fn put_additional_address_family(&mut self, family: AddressFamily) {
        family.serialize(turn::ATTR_TYPE_ADDITIONAL_ADDRESS_FAMILY, self);
    }

    /// Write the address error code attribute.
    pub fn put_address_error_code(&mut self, error_code: &AddressErrorCode) {
        error_code.serialize(turn::ATTR_TYPE_ADDRESS_ERROR_CODE, self);
    }

    /// Write the ICMP attribute.
    pub fn put_icmp(&mut self, icmp: &ICMP) {
        icmp.serialize(turn::ATTR_TYPE_ICMP, self);
    }
}

impl Deref for MessageWriter<'_> {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        self.buffer
    }
}

impl DerefMut for MessageWriter<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::BytesMut;

    use super::MessageBuffer;

    use crate::{MessageClass, Method, RFC_5389_MAGIC_COOKIE};

    #[test]
    fn test_empty_message_length() {
        let mut buf = BytesMut::new();

        let mut mb = MessageBuffer::new(&mut buf);

        let writer = mb.create_message(
            MessageClass::Request,
            Method::Binding,
            RFC_5389_MAGIC_COOKIE,
            [0u8; 12],
        );

        writer.finalize();

        assert_eq!(buf.len(), 20);

        assert_eq!(&buf[2..4], &[0x00, 0x00]);
        assert_eq!(&buf[4..8], &u32::to_be_bytes(RFC_5389_MAGIC_COOKIE));
    }

    #[test]
    fn test_sequential_messages() {
        let mut buf = BytesMut::new();

        let mut mb = MessageBuffer::new(&mut buf);

        let writer = mb.create_message(
            MessageClass::Request,
            Method::Binding,
            RFC_5389_MAGIC_COOKIE,
            [0u8; 12],
        );

        writer.finalize();

        let mut writer = mb.create_message(
            MessageClass::Success,
            Method::Binding,
            RFC_5389_MAGIC_COOKIE,
            [0u8; 12],
        );

        writer.put_software("x");
        writer.finalize();

        assert_eq!(buf.len(), 20 + 20 + 8);
        // the first message is has again an empty body
        assert_eq!(&buf[2..4], &[0x00, 0x00]);
        // the second message carries an 8-byte software attribute
        assert_eq!(&buf[22..24], &[0x00, 0x08]);
    }

    #[test]
    fn test_xor_mapped_address_bytes() {
        let mut buf = BytesMut::new();

        let mut mb = MessageBuffer::new(&mut buf);

        let mut writer = mb.create_message(
            MessageClass::Success,
            Method::Binding,
            RFC_5389_MAGIC_COOKIE,
            [0u8; 12],
        );

        writer.put_xor_mapped_address(SocketAddr::from(([192, 0, 2, 1], 32853)));
        writer.finalize();

        assert_eq!(buf.len(), 32);

        assert_eq!(&buf[2..4], &[0x00, 0x0c]);
        assert_eq!(&buf[20..24], &[0x00, 0x20, 0x00, 0x08]);
        // family + XOR-ed port
        assert_eq!(&buf[24..26], &[0x00, 0x01]);
        assert_eq!(&buf[26..28], &[0xa1, 0x47]);
        // XOR-ed address
        assert_eq!(&buf[28..32], &[0xe1, 0x12, 0xa6, 0x43]);
    }
}
