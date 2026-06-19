use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{BufMut, BytesMut};
use zerocopy::{network_endian::U16, IntoBytes};

use crate::attribute::{
    AttributeHeader, ErrorCode, ErrorCodeHeader, MappedAddrHeader, MappedIpv4Addr, MappedIpv6Addr,
    PasswordAlgorithm, PasswordAlgorithmHeader,
};

/// Trait for types that can be serialized as STUN attributes.
pub trait SerializeAttribute {
    /// Serialize the value as a STUN attribute with a given type into the
    /// provided buffer.
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut);
}

impl SerializeAttribute for () {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        buffer.reserve(4);
        buffer.put_attribute_header(attribute_type, 0);
    }
}

impl SerializeAttribute for u32 {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        buffer.reserve(8);
        buffer.put_attribute_header(attribute_type, 4);
        buffer.put_u32(*self);
    }
}

impl SerializeAttribute for u64 {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        buffer.reserve(12);
        buffer.put_attribute_header(attribute_type, 8);
        buffer.put_u64(*self);
    }
}

impl SerializeAttribute for SocketAddr {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let len = match self {
            SocketAddr::V4(_) => 8,
            SocketAddr::V6(_) => 20,
        };

        buffer.reserve(4 + len);
        buffer.put_attribute_header(attribute_type, len as u16);
        buffer.put_mapped_addr(self);
    }
}

impl SerializeAttribute for ErrorCode {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let code = self.code();
        let msg = self.message();

        let len = 4 + msg.len();

        let padding = (4 - (len & 3)) & 3;

        buffer.reserve(4 + len + padding);
        buffer.put_attribute_header(attribute_type, len as u16);
        buffer.put_error_code_header(code);
        buffer.extend_from_slice(msg.as_bytes());
        buffer.extend_from_slice(&[0u8; 3][..padding]);
    }
}

impl SerializeAttribute for PasswordAlgorithm {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        std::slice::from_ref(self).serialize(attribute_type, buffer);
    }
}

impl SerializeAttribute for &[PasswordAlgorithm] {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let len = self.len() << 2;

        buffer.reserve(4 + len);

        buffer.put_attribute_header(attribute_type, len as u16);

        for alg in self.iter() {
            buffer.put_password_algorithm_header(alg);
        }
    }
}

impl SerializeAttribute for &str {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        self.as_bytes().serialize(attribute_type, buffer);
    }
}

impl SerializeAttribute for &[u8] {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let len = self.len();

        let padding = (4 - (len & 3)) & 3;

        buffer.reserve(4 + len + padding);
        buffer.put_attribute_header(attribute_type, len as u16);
        buffer.extend_from_slice(self);
        buffer.extend_from_slice(&[0u8; 3][..padding]);
    }
}

impl SerializeAttribute for &[u16] {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let len = self.len() << 1;

        let padding = (4 - (len & 3)) & 3;

        buffer.reserve(4 + len + padding);

        buffer.put_attribute_header(attribute_type, len as u16);

        for elem in self.iter() {
            buffer.put_u16(*elem);
        }

        buffer.extend_from_slice(&[0u8; 3][..padding]);
    }
}

/// Helper trait for writing STUN attributes.
trait BytesMutExt {
    /// Put a STUN attribute header into the byte stream.
    fn put_attribute_header(&mut self, attribute_type: u16, attribute_length: u16);

    /// Put a STUN mapped address into the byte stream.
    fn put_mapped_addr(&mut self, addr: &SocketAddr);

    /// Put a STUN mapped address header into the byte stream.
    fn put_mapped_addr_header(&mut self, family: u8);

    /// Put a STUN mapped IPv4 address into the byte stream.
    fn put_mapped_ipv4_addr(&mut self, addr: &SocketAddrV4);

    /// Put a STUN mapped IPv6 address into the byte stream.
    fn put_mapped_ipv6_addr(&mut self, addr: &SocketAddrV6);

    /// Put a STUN error code header into the byte stream.
    fn put_error_code_header(&mut self, code: u16);

    /// Put a STUN password algorithm header into the byte stream.
    fn put_password_algorithm_header(&mut self, algorithm: &PasswordAlgorithm);
}

impl BytesMutExt for BytesMut {
    fn put_attribute_header(&mut self, attribute_type: u16, attribute_length: u16) {
        let header = AttributeHeader {
            attribute_type: U16::new(attribute_type),
            attribute_length: U16::new(attribute_length),
        };

        self.extend_from_slice(header.as_bytes());
    }

    fn put_mapped_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                self.put_mapped_addr_header(1);
                self.put_mapped_ipv4_addr(addr);
            }
            SocketAddr::V6(addr) => {
                self.put_mapped_addr_header(2);
                self.put_mapped_ipv6_addr(addr);
            }
        }
    }

    fn put_mapped_addr_header(&mut self, family: u8) {
        let header = MappedAddrHeader { padding: 0, family };

        self.extend_from_slice(header.as_bytes());
    }

    fn put_mapped_ipv4_addr(&mut self, addr: &SocketAddrV4) {
        let ip = addr.ip();
        let port = addr.port();

        let addr = MappedIpv4Addr {
            port: U16::new(port),
            addr: ip.octets(),
        };

        self.extend_from_slice(addr.as_bytes());
    }

    fn put_mapped_ipv6_addr(&mut self, addr: &SocketAddrV6) {
        let ip = addr.ip();
        let port = addr.port();

        let addr = MappedIpv6Addr {
            port: U16::new(port),
            addr: ip.octets(),
        };

        self.extend_from_slice(addr.as_bytes());
    }

    fn put_error_code_header(&mut self, code: u16) {
        let header = ErrorCodeHeader {
            padding: [0u8; 2],
            class: (code / 100) as u8,
            number: (code % 100) as u8,
        };

        self.extend_from_slice(header.as_bytes());
    }

    fn put_password_algorithm_header(&mut self, algorithm: &PasswordAlgorithm) {
        let header = PasswordAlgorithmHeader {
            algorithm: U16::new(algorithm.id()),
            parameters_length: U16::ZERO,
        };

        self.extend_from_slice(header.as_bytes());
    }
}
