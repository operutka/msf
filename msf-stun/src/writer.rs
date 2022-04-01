use std::{
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
};

use bytes::{BufMut, Bytes, BytesMut};

use crate::{attribute, ErrorCode, MessageClass, Method, TransactionID};

/// STUN message writer.
pub struct MessageWriter {
    buffer: BytesMut,
}

impl MessageWriter {
    /// Create a new message writer.
    pub fn new(
        class: MessageClass,
        method: Method,
        magic_cookie: u32,
        transaction_id: TransactionID,
    ) -> Self {
        let class = class.into_message_type();
        let method = method.into_message_type();

        let message_type = class | method;

        let mut buffer = BytesMut::with_capacity(20);

        buffer.put_u16(message_type);
        buffer.put_u16(0);
        buffer.put_u32(magic_cookie);
        buffer.put_slice(&transaction_id);

        Self { buffer }
    }

    /// Finalize and return the message.
    pub fn finalize(mut self) -> Bytes {
        let len = self.buffer.len() - 20;

        super::set_message_length(&mut self.buffer, len as u16);

        self.buffer.freeze()
    }

    /// Write the error code attribute.
    pub fn put_error_code(&mut self, error_code: &ErrorCode) {
        let code = error_code.code();
        let msg = error_code.message();

        let len = 4 + msg.len();

        let class = code / 100;
        let nr = code % 100;

        self.put_attribute_header(attribute::ATTR_TYPE_ERROR_CODE, len as u16);
        self.put_u16(0);
        self.put_u8(class as u8);
        self.put_u8(nr as u8);
        self.put_slice(msg.as_bytes());
        self.put_padding();
    }

    /// Write the unknown attributes attribute.
    pub fn put_unknown_attributes(&mut self, attributes: &[u16]) {
        let len = attributes.len() << 1;

        self.put_attribute_header(attribute::ATTR_TYPE_UNKNOWN_ATTRIBUTES, len as u16);

        for attribute in attributes {
            self.put_u16(*attribute);
        }

        self.put_padding();
    }

    /// Write the alternate server attribute.
    pub fn put_alternate_server(&mut self, addr: SocketAddr) {
        let (family, len) = match addr {
            SocketAddr::V4(_) => (1, 8),
            SocketAddr::V6(_) => (2, 20),
        };

        self.put_attribute_header(attribute::ATTR_TYPE_ALTERNATE_SERVER, len);
        self.put_u8(0);
        self.put_u8(family);
        self.put_u16(addr.port());

        match addr.ip() {
            IpAddr::V4(addr) => self.put_slice(&addr.octets()),
            IpAddr::V6(addr) => self.put_slice(&addr.octets()),
        }
    }

    /// Write the mapped address attribute.
    pub fn put_mapped_address(&mut self, addr: SocketAddr) {
        let (family, len) = match addr {
            SocketAddr::V4(_) => (1, 8),
            SocketAddr::V6(_) => (2, 20),
        };

        self.put_attribute_header(attribute::ATTR_TYPE_MAPPED_ADDRESS, len);
        self.put_u8(0);
        self.put_u8(family);
        self.put_u16(addr.port());

        match addr.ip() {
            IpAddr::V4(addr) => self.put_slice(&addr.octets()),
            IpAddr::V6(addr) => self.put_slice(&addr.octets()),
        }
    }

    /// Write the xor mapped address attribute.
    pub fn put_xor_mapped_address(&mut self, addr: SocketAddr) {
        let (family, len) = match addr {
            SocketAddr::V4(_) => (1, 8),
            SocketAddr::V6(_) => (2, 20),
        };

        let mut u16_xor_bits = [0u8; 2];
        let mut u32_xor_bits = [0u8; 4];
        let mut u128_xor_bits = [0u8; 16];

        u16_xor_bits.copy_from_slice(&self.buffer[4..6]);
        u32_xor_bits.copy_from_slice(&self.buffer[4..8]);
        u128_xor_bits.copy_from_slice(&self.buffer[4..20]);

        let u16_xor_bits = u16::from_be_bytes(u16_xor_bits);
        let u32_xor_bits = u32::from_be_bytes(u32_xor_bits);
        let u128_xor_bits = u128::from_be_bytes(u128_xor_bits);

        self.put_attribute_header(attribute::ATTR_TYPE_XOR_MAPPED_ADDRESS, len);
        self.put_u8(0);
        self.put_u8(family);
        self.put_u16(addr.port() ^ u16_xor_bits);

        match addr.ip() {
            IpAddr::V4(addr) => self.put_u32(u32::from(addr) ^ u32_xor_bits),
            IpAddr::V6(addr) => self.put_u128(u128::from(addr) ^ u128_xor_bits),
        }
    }

    /// Write the username attribute.
    pub fn put_username(&mut self, username: &str) {
        self.put_str_attribute(attribute::ATTR_TYPE_USERNAME, username);
    }

    /// Write the realm attribute.
    pub fn put_realm(&mut self, username: &str) {
        self.put_str_attribute(attribute::ATTR_TYPE_REALM, username);
    }

    /// Write the nonce attribute.
    pub fn put_nonce(&mut self, username: &str) {
        self.put_str_attribute(attribute::ATTR_TYPE_NONCE, username);
    }

    /// Write the software attribute.
    pub fn put_software(&mut self, username: &str) {
        self.put_str_attribute(attribute::ATTR_TYPE_SOFTWARE, username);
    }

    /// Write the ICE candidate priority attribute.
    #[cfg(feature = "ice")]
    pub fn put_priority(&mut self, priority: u32) {
        self.put_u32_attribute(attribute::ATTR_TYPE_PRIORITY, priority);
    }

    /// Write the ICE use candidate attribute.
    #[cfg(feature = "ice")]
    pub fn put_use_candidate(&mut self) {
        self.put_attribute_header(attribute::ATTR_TYPE_USE_CANDIDATE, 0);
    }

    /// Write the ICE controlled attribute.
    #[cfg(feature = "ice")]
    pub fn put_ice_controlled(&mut self, n: u64) {
        self.put_u64_attribute(attribute::ATTR_TYPE_ICE_CONTROLLED, n);
    }

    /// Write the ICE controlling attribute.
    #[cfg(feature = "ice")]
    pub fn put_ice_controlling(&mut self, n: u64) {
        self.put_u64_attribute(attribute::ATTR_TYPE_ICE_CONTROLLING, n);
    }

    /// Write the message integrity attribute.
    pub fn put_message_integrity(&mut self, key: &[u8]) {
        self.put_bytes_attribute(
            attribute::ATTR_TYPE_MESSAGE_INTEGRITY,
            &super::calculate_message_integrity(key, &self.buffer),
        );
    }

    /// Write the fingerprint attribute.
    pub fn put_fingerprint(&mut self) {
        self.put_u32_attribute(
            attribute::ATTR_TYPE_FINGERPRINT,
            super::calculate_fingerprint(&self.buffer),
        );
    }

    /// Write an attribute header.
    fn put_attribute_header(&mut self, attr_type: u16, attr_length: u16) {
        self.put_u16(attr_type);
        self.put_u16(attr_length);
    }

    /// Write an u32 attribute.
    fn put_u32_attribute(&mut self, attr_type: u16, val: u32) {
        self.put_attribute_header(attr_type, 4);
        self.put_u32(val);
    }

    /// Write an u64 attribute.
    #[cfg(feature = "ice")]
    fn put_u64_attribute(&mut self, attr_type: u16, val: u64) {
        self.put_attribute_header(attr_type, 8);
        self.put_u64(val);
    }

    /// Write a string attribute.
    fn put_str_attribute(&mut self, attr_type: u16, s: &str) {
        self.put_bytes_attribute(attr_type, s.as_bytes());
    }

    /// Write a binary attribute.
    fn put_bytes_attribute(&mut self, attr_type: u16, bytes: &[u8]) {
        self.put_attribute_header(attr_type, bytes.len() as u16);
        self.put_slice(bytes);
        self.put_padding();
    }

    /// Make sure that the message length is a multiple of four.
    fn put_padding(&mut self) {
        // get number of bytes missing to the next aligned position
        let padding = 4 - (self.buffer.len() & 3);

        if padding < 4 {
            self.put_slice(&[0u8; 3][..padding]);
        }
    }
}

impl Deref for MessageWriter {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for MessageWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}
