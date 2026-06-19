use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Buf, Bytes};
use zerocopy::{network_endian::U16, FromBytes, SizeError};

use crate::attribute::{
    Attribute, AttributeError, AttributeHeader, ErrorCode, ErrorCodeHeader, MappedAddrHeader,
    MappedIpv4Addr, MappedIpv6Addr, PasswordAlgorithm, PasswordAlgorithmHeader, Sha256Hash, Text,
    ATTR_TYPE_ALTERNATE_DOMAIN, ATTR_TYPE_ALTERNATE_SERVER, ATTR_TYPE_ERROR_CODE,
    ATTR_TYPE_FINGERPRINT, ATTR_TYPE_MAPPED_ADDRESS, ATTR_TYPE_MESSAGE_INTEGRITY,
    ATTR_TYPE_MESSAGE_INTEGRITY_SHA256, ATTR_TYPE_NONCE, ATTR_TYPE_PASSWORD_ALGORITHM,
    ATTR_TYPE_PASSWORD_ALGORITHMS, ATTR_TYPE_REALM, ATTR_TYPE_SOFTWARE,
    ATTR_TYPE_UNKNOWN_ATTRIBUTES, ATTR_TYPE_USERHASH, ATTR_TYPE_USERNAME,
    ATTR_TYPE_XOR_MAPPED_ADDRESS,
};

#[cfg(feature = "ice")]
use crate::attribute::{
    ATTR_TYPE_ICE_CONTROLLED, ATTR_TYPE_ICE_CONTROLLING, ATTR_TYPE_PRIORITY,
    ATTR_TYPE_USE_CANDIDATE,
};

/// Try to get a STUN attribute from a given byte stream.
pub fn try_get_attribute_from_bytes(
    bytes: &mut Bytes,
    long_transaction_id: [u8; 16],
) -> Result<Attribute, AttributeError> {
    bytes.try_get_attribute(long_transaction_id)
}

/// Helper trait for reading STUN attributes.
trait BytesExt {
    /// Try to get a STUN attribute from the byte stream.
    fn try_get_attribute(
        &mut self,
        long_transaction_id: [u8; 16],
    ) -> Result<Attribute, AttributeError>;

    /// Try to get a STUN attribute header from the byte stream.
    fn try_get_attribute_header(&mut self) -> Result<AttributeHeader, AttributeError>;

    /// Try to get a XOR-mapped address from the byte stream.
    fn try_get_xor_mapped_addr(
        &mut self,
        long_transaction_id: [u8; 16],
    ) -> Result<SocketAddr, AttributeError>;

    /// Try to get a mapped address from the byte stream.
    fn try_get_mapped_addr(&mut self) -> Result<SocketAddr, AttributeError>;

    /// Try to get a mapped address header from the byte stream.
    fn try_get_mapped_addr_header(&mut self) -> Result<MappedAddrHeader, AttributeError>;

    /// Try to get a mapped IPv4 address from the byte stream.
    fn try_get_mapped_ipv4_addr(&mut self) -> Result<SocketAddrV4, AttributeError>;

    /// Try to get a mapped IPv6 address from the byte stream.
    fn try_get_mapped_ipv6_addr(&mut self) -> Result<SocketAddrV6, AttributeError>;

    /// Try to get an error code from the byte stream.
    fn try_get_error_code(&mut self) -> Result<ErrorCode, AttributeError>;

    /// Try to get an error code header from the byte stream.
    fn try_get_error_code_header(&mut self) -> Result<ErrorCodeHeader, AttributeError>;

    /// Try to get a text value from the byte stream.
    fn try_get_text(&mut self, len: usize) -> Result<Text, AttributeError>;

    /// Try to get a list of password algorithms from the byte stream.
    fn try_get_password_algorithms(&mut self) -> Result<Vec<PasswordAlgorithm>, AttributeError>;

    /// Try to get a password algorithm from the byte stream.
    fn try_get_password_algorithm(&mut self) -> Result<PasswordAlgorithm, AttributeError>;

    /// Try to get a password algorithm header from the byte stream.
    fn try_get_password_algorithm_header(
        &mut self,
    ) -> Result<PasswordAlgorithmHeader, AttributeError>;

    /// Try to get a SHA-256 hash from the byte stream.
    fn try_get_sha256_hash(&mut self, len: usize) -> Result<Sha256Hash, AttributeError>;

    /// Try to get a byte array of a given length from the byte stream.
    fn try_get_byte_array<const N: usize>(&mut self) -> Result<[u8; N], AttributeError>;

    /// Try to get a list of unknown attributes from the byte stream.
    fn try_get_unknown_attributes(&mut self) -> Result<Vec<u16>, AttributeError>;

    /// Try to get a list of u16 values of a given length from the byte stream.
    fn try_get_u16_vec(&mut self, len: usize) -> Result<Vec<u16>, AttributeError>;
}

impl BytesExt for Bytes {
    fn try_get_attribute(
        &mut self,
        long_transaction_id: [u8; 16],
    ) -> Result<Attribute, AttributeError> {
        let header = self.try_get_attribute_header()?;

        if self.len() < header.padded_value_length() {
            return Err(AttributeError::InvalidAttribute);
        }

        let mut value = self.slice(..header.value_length());

        self.advance(header.padded_value_length());

        use Attribute::*;

        let res = match header.attribute_type.get() {
            ATTR_TYPE_MAPPED_ADDRESS => MappedAddress(value.try_get_mapped_addr()?),
            ATTR_TYPE_XOR_MAPPED_ADDRESS => {
                XorMappedAddress(value.try_get_xor_mapped_addr(long_transaction_id)?)
            }
            ATTR_TYPE_USERNAME => Username(value.try_get_text(value.len())?),
            ATTR_TYPE_USERHASH => Userhash(value.try_get_byte_array()?),
            ATTR_TYPE_MESSAGE_INTEGRITY => MessageIntegrity(value.try_get_byte_array()?),
            ATTR_TYPE_MESSAGE_INTEGRITY_SHA256 => {
                MessageIntegritySha256(value.try_get_sha256_hash(value.len())?)
            }
            ATTR_TYPE_FINGERPRINT => value
                .try_get_u32()
                .map(Fingerprint)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            ATTR_TYPE_ERROR_CODE => ErrorCode(value.try_get_error_code()?),
            ATTR_TYPE_REALM => Realm(value.try_get_text(value.len())?),
            ATTR_TYPE_NONCE => Nonce(value.try_get_text(value.len())?),
            ATTR_TYPE_PASSWORD_ALGORITHMS => {
                PasswordAlgorithms(value.try_get_password_algorithms()?)
            }
            ATTR_TYPE_PASSWORD_ALGORITHM => PasswordAlgorithm(value.try_get_password_algorithm()?),
            ATTR_TYPE_UNKNOWN_ATTRIBUTES => UnknownAttributes(value.try_get_unknown_attributes()?),
            ATTR_TYPE_SOFTWARE => Software(value.try_get_text(value.len())?),
            ATTR_TYPE_ALTERNATE_SERVER => AlternateServer(value.try_get_mapped_addr()?),
            ATTR_TYPE_ALTERNATE_DOMAIN => AlternateDomain(value.try_get_text(value.len())?),

            #[cfg(feature = "ice")]
            ATTR_TYPE_PRIORITY => value
                .try_get_u32()
                .map(Priority)
                .map_err(|_| AttributeError::InvalidAttribute)?,

            #[cfg(feature = "ice")]
            ATTR_TYPE_USE_CANDIDATE => UseCandidate,

            #[cfg(feature = "ice")]
            ATTR_TYPE_ICE_CONTROLLED => value
                .try_get_u64()
                .map(ICEControlled)
                .map_err(|_| AttributeError::InvalidAttribute)?,

            #[cfg(feature = "ice")]
            ATTR_TYPE_ICE_CONTROLLING => value
                .try_get_u64()
                .map(ICEControlling)
                .map_err(|_| AttributeError::InvalidAttribute)?,

            t => return Err(AttributeError::UnknownAttribute(t)),
        };

        if !value.is_empty() {
            return Err(AttributeError::InvalidAttribute);
        }

        Ok(res)
    }

    fn try_get_attribute_header(&mut self) -> Result<AttributeHeader, AttributeError> {
        let (header, _) = AttributeHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }

    fn try_get_xor_mapped_addr(
        &mut self,
        long_transaction_id: [u8; 16],
    ) -> Result<SocketAddr, AttributeError> {
        let mut magic_cookie = [0u8; 4];

        magic_cookie.copy_from_slice(&long_transaction_id[..4]);

        let u128_xor_bits = u128::from_be_bytes(long_transaction_id);
        let u32_xor_bits = u32::from_be_bytes(magic_cookie);
        let u16_xor_bits = (u32_xor_bits >> 16) as u16;

        let addr = match self.try_get_mapped_addr()? {
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
        };

        Ok(addr)
    }

    fn try_get_mapped_addr(&mut self) -> Result<SocketAddr, AttributeError> {
        let header = self.try_get_mapped_addr_header()?;

        let res = match header.family {
            1 => SocketAddr::V4(self.try_get_mapped_ipv4_addr()?),
            2 => SocketAddr::V6(self.try_get_mapped_ipv6_addr()?),
            _ => return Err(AttributeError::InvalidAttribute),
        };

        Ok(res)
    }

    fn try_get_mapped_addr_header(&mut self) -> Result<MappedAddrHeader, AttributeError> {
        let (header, _) = MappedAddrHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }

    fn try_get_mapped_ipv4_addr(&mut self) -> Result<SocketAddrV4, AttributeError> {
        let (addr, _) =
            MappedIpv4Addr::read_from_prefix(self).map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&addr));

        Ok(addr.into())
    }

    fn try_get_mapped_ipv6_addr(&mut self) -> Result<SocketAddrV6, AttributeError> {
        let (addr, _) =
            MappedIpv6Addr::read_from_prefix(self).map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&addr));

        Ok(addr.into())
    }

    fn try_get_error_code(&mut self) -> Result<ErrorCode, AttributeError> {
        let header = self.try_get_error_code_header()?;

        if header.number >= 100 {
            return Err(AttributeError::InvalidAttribute);
        }

        let class = (header.class & 7) as u16;
        let number = header.number as u16;

        let code = 100 * class + number;

        let msg = self.try_get_text(self.len())?;

        Ok(ErrorCode::new(code, msg))
    }

    fn try_get_error_code_header(&mut self) -> Result<ErrorCodeHeader, AttributeError> {
        let (header, _) = ErrorCodeHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }

    fn try_get_text(&mut self, len: usize) -> Result<Text, AttributeError> {
        if self.len() < len {
            return Err(AttributeError::InvalidAttribute);
        }

        self.split_to(len)
            .try_into()
            .map_err(|_| AttributeError::InvalidAttribute)
    }

    fn try_get_password_algorithms(&mut self) -> Result<Vec<PasswordAlgorithm>, AttributeError> {
        let mut algorithms = Vec::new();

        while !self.is_empty() {
            algorithms.push(self.try_get_password_algorithm()?);
        }

        Ok(algorithms)
    }

    fn try_get_password_algorithm(&mut self) -> Result<PasswordAlgorithm, AttributeError> {
        let header = self.try_get_password_algorithm_header()?;

        let parameters_length = header.parameters_length.get() as usize;

        let padded_parameters_length = (parameters_length + 3) & !3;

        if self.len() < padded_parameters_length {
            return Err(AttributeError::InvalidAttribute);
        }

        // NOTE: We silently ignore the parameters because the MD5 and SHA-256
        //   algorithms do not define any parameters. The specification isn't
        //   clear about how to treat present parameters if the algorithm does
        //   not define any.

        self.advance(padded_parameters_length);

        match header.algorithm.get() {
            0x0001 => Ok(PasswordAlgorithm::Md5),
            0x0002 => Ok(PasswordAlgorithm::Sha256),
            _ => Err(AttributeError::InvalidAttribute),
        }
    }

    fn try_get_password_algorithm_header(
        &mut self,
    ) -> Result<PasswordAlgorithmHeader, AttributeError> {
        let (header, _) = PasswordAlgorithmHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }

    fn try_get_sha256_hash(&mut self, len: usize) -> Result<Sha256Hash, AttributeError> {
        let hash = match len {
            16 => Sha256Hash::Truncated16(self.try_get_byte_array()?),
            20 => Sha256Hash::Truncated20(self.try_get_byte_array()?),
            24 => Sha256Hash::Truncated24(self.try_get_byte_array()?),
            28 => Sha256Hash::Truncated28(self.try_get_byte_array()?),
            32 => Sha256Hash::Full(self.try_get_byte_array()?),
            _ => return Err(AttributeError::InvalidAttribute),
        };

        Ok(hash)
    }

    fn try_get_byte_array<const N: usize>(&mut self) -> Result<[u8; N], AttributeError> {
        let (array, _) =
            <[u8; N]>::read_from_prefix(self).map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&array));

        Ok(array)
    }

    fn try_get_unknown_attributes(&mut self) -> Result<Vec<u16>, AttributeError> {
        if (self.len() & 1) != 0 {
            return Err(AttributeError::InvalidAttribute);
        }

        let len = self.len() >> 1;

        self.try_get_u16_vec(len)
    }

    fn try_get_u16_vec(&mut self, len: usize) -> Result<Vec<u16>, AttributeError> {
        let res = <[U16]>::ref_from_bytes_with_elems(self, len)
            .map_err(SizeError::from)
            .map_err(|_| AttributeError::InvalidAttribute)?
            .iter()
            .map(|u| u.get())
            .collect();

        self.advance(len << 1);

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::Bytes;

    use crate::attribute::{Attribute, AttributeError, PasswordAlgorithm, Sha256Hash};

    /// Parse a single attribute from a raw attribute slice.
    fn parse(bytes: &[u8], long_transaction_id: [u8; 16]) -> Result<Attribute, AttributeError> {
        Attribute::from_bytes(&mut Bytes::copy_from_slice(bytes), long_transaction_id)
    }

    /// Check whether a result is the `InvalidAttribute` error.
    fn is_invalid(res: Result<Attribute, AttributeError>) -> bool {
        matches!(res, Err(AttributeError::InvalidAttribute))
    }

    #[test]
    fn test_parse_mapped_address_v4() {
        let input = &[
            0x00, 0x01, 0x00, 0x08, // attribute header
            0x00, 0x01, // mapped address header
            0x80, 0x55, // port
            192, 0, 2, 1, // IP address
        ];

        let Ok(Attribute::MappedAddress(addr)) = parse(input, [0u8; 16]) else {
            panic!("expected a mapped address");
        };

        assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 32853)));
    }

    #[test]
    fn test_parse_mapped_address_v6() {
        let input = &[
            0x00, 0x01, 0x00, 0x14, // attribute header
            0x00, 0x02, // mapped address header
            0x80, 0x55, // port
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // IP address
        ];

        let Ok(Attribute::MappedAddress(addr)) = parse(input, [0u8; 16]) else {
            panic!("expected a mapped address");
        };

        let ip = u128::to_be_bytes(0x2001_0db8_0000_0000_0000_0000_0000_0001);

        assert_eq!(addr, SocketAddr::from((ip, 32853)));
    }

    #[test]
    fn test_parse_mapped_address_invalid_family() {
        let input = &[
            0x00, 0x01, 0x00, 0x08, // attribute header
            0x00, 0x03, // mapped address header (invalid family)
            0x80, 0x55, // port
            192, 0, 2, 1, // IP address
        ];

        assert!(is_invalid(parse(input, [0u8; 16],)));
    }

    #[test]
    fn test_parse_mapped_address_trailing_bytes() {
        // a value longer than what the address actually occupies must be
        // rejected
        let input = &[
            0x00, 0x01, 0x00, 0x0c, // attribute header
            0x00, 0x01, // mapped address header
            0x80, 0x55, // port
            192, 0, 2, 1, // IP address
            0, 0, 0, 0, // trailing bytes
        ];

        assert!(is_invalid(parse(input, [0u8; 16])));
    }

    #[test]
    fn test_parse_xor_mapped_address_v4() {
        let mut tid = [0u8; 16];

        tid[..4].copy_from_slice(&u32::to_be_bytes(0x2112a442));

        let input = &[
            0x00, 0x20, 0x00, 0x08, // attribute header
            0x00, 0x01, // mapped address header
            0xa1, 0x47, // XOR-ed port
            0xe1, 0x12, 0xa6, 0x43, // XOR-ed IP address
        ];

        let Ok(Attribute::XorMappedAddress(addr)) = parse(input, tid) else {
            panic!("expected a XOR-mapped address");
        };

        assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 32853)));
    }

    #[test]
    fn test_parse_username() {
        let mut input = Vec::new();

        input.extend_from_slice(&[0x00, 0x06, 0x00, 0x04]);
        input.extend_from_slice(b"test");

        let Ok(Attribute::Username(val)) = parse(&input, [0u8; 16]) else {
            panic!("expected a username");
        };

        assert_eq!(val.as_str(), "test");
    }

    #[test]
    fn test_parse_username_padded() {
        let mut input = Vec::new();

        input.extend_from_slice(&[0x00, 0x06, 0x00, 0x03]);
        input.extend_from_slice(b"abc\0");

        let mut input = Bytes::from(input);

        let Ok(Attribute::Username(val)) = Attribute::from_bytes(&mut input, [0u8; 16]) else {
            panic!("expected a username");
        };

        assert_eq!(val.as_str(), "abc");

        assert!(input.is_empty());
    }

    #[test]
    fn test_parse_username_invalid_utf8() {
        assert!(is_invalid(parse(
            &[0x00, 0x06, 0x00, 0x01, 0xff, 0, 0, 0],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_parse_error_code() {
        let mut input = Vec::new();

        input.extend_from_slice(&[0x00, 0x09, 0x00, 0x0b]);
        input.extend_from_slice(&[0, 0, 4, 20]);
        input.extend_from_slice(b"Unknown\0");

        let Ok(Attribute::ErrorCode(ec)) = parse(&input, [0u8; 16]) else {
            panic!("expected an error code");
        };

        assert_eq!(ec.code(), 420);
        assert_eq!(ec.message(), "Unknown");
    }

    #[test]
    fn test_parse_error_code_invalid_number() {
        assert!(is_invalid(parse(
            &[0x00, 0x09, 0x00, 0x04, 0, 0, 4, 100],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_parse_unknown_attributes() {
        let input = &[0x00, 0x0a, 0x00, 0x04, 0x00, 0x01, 0x00, 0x06];

        let Ok(Attribute::UnknownAttributes(v)) = parse(input, [0u8; 16]) else {
            panic!("expected unknown attributes");
        };

        assert_eq!(&v[..], &[0x0001, 0x0006]);
    }

    #[test]
    fn test_parse_unknown_attributes_odd_length() {
        assert!(is_invalid(parse(
            &[0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x02, 0x00],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_parse_password_algorithm() {
        let input = &[0x00, 0x1d, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00];

        let Ok(Attribute::PasswordAlgorithm(alg)) = parse(input, [0u8; 16]) else {
            panic!("expected a password algorithm");
        };

        assert!(matches!(alg, PasswordAlgorithm::Md5));
    }

    #[test]
    fn test_parse_password_algorithms() {
        let input = &[
            0x80, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        ];

        let Ok(Attribute::PasswordAlgorithms(algs)) = parse(input, [0u8; 16]) else {
            panic!("expected password algorithms");
        };

        assert_eq!(algs.len(), 2);

        assert!(matches!(algs[0], PasswordAlgorithm::Md5));
        assert!(matches!(algs[1], PasswordAlgorithm::Sha256));
    }

    #[test]
    fn test_parse_message_integrity() {
        let hash = [0x22; 20];

        let mut input = vec![0x00, 0x08, 0x00, 0x14];

        input.extend_from_slice(&hash);

        let Ok(Attribute::MessageIntegrity(h)) = parse(&input, [0u8; 16]) else {
            panic!("expected message integrity");
        };

        assert_eq!(h, hash);
    }

    #[test]
    fn test_parse_message_integrity_sha256() {
        let hashes = [
            Sha256Hash::Truncated16([0x11; 16]),
            Sha256Hash::Truncated20([0x22; 20]),
            Sha256Hash::Truncated24([0x33; 24]),
            Sha256Hash::Truncated28([0x44; 28]),
            Sha256Hash::Full([0x55; 32]),
        ];

        for hash in hashes {
            let hash = match &hash {
                Sha256Hash::Truncated16(val) => &val[..],
                Sha256Hash::Truncated20(val) => &val[..],
                Sha256Hash::Truncated24(val) => &val[..],
                Sha256Hash::Truncated28(val) => &val[..],
                Sha256Hash::Full(val) => &val[..],
            };

            let mut input = vec![0x00, 0x1c, 0x00, hash.len() as u8];

            input.extend_from_slice(hash);

            let Ok(Attribute::MessageIntegritySha256(h)) = parse(&input, [0u8; 16]) else {
                panic!("expected SHA-256 message integrity");
            };

            let h = match &h {
                Sha256Hash::Truncated16(val) => &val[..],
                Sha256Hash::Truncated20(val) => &val[..],
                Sha256Hash::Truncated24(val) => &val[..],
                Sha256Hash::Truncated28(val) => &val[..],
                Sha256Hash::Full(val) => &val[..],
            };

            assert_eq!(h, hash);
        }

        let invalid_lengths = [12, 15, 33, 36];

        for invalid_length in invalid_lengths {
            let mut input = vec![0x00, 0x1c, 0x00, invalid_length as u8];

            input.resize(4 + invalid_length, 0xab);

            assert!(is_invalid(parse(&input, [0u8; 16])));
        }
    }

    #[test]
    fn test_parse_userhash() {
        let mut input = vec![0x00, 0x1e, 0x00, 0x20];

        input.extend_from_slice(&[0x11; 32]);

        let Ok(Attribute::Userhash(h)) = parse(&input, [0u8; 16]) else {
            panic!("expected a userhash");
        };

        assert_eq!(h, [0x11u8; 32]);
    }

    #[test]
    fn test_parse_fingerprint() {
        let input = &[0x80, 0x28, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];

        let Ok(Attribute::Fingerprint(crc)) = parse(input, [0u8; 16]) else {
            panic!("expected a fingerprint");
        };

        assert_eq!(crc, 0xdeadbeef);
    }

    #[test]
    fn test_parse_alternate_domain() {
        let mut input = vec![0x80, 0x03, 0x00, 0x03];

        input.extend_from_slice(b"a.b\0");

        let Ok(Attribute::AlternateDomain(t)) = parse(&input, [0u8; 16]) else {
            panic!("expected an alternate domain");
        };

        assert_eq!(t.as_str(), "a.b");
    }

    #[test]
    fn test_parse_truncated_header() {
        assert!(is_invalid(parse(&[0x00, 0x01], [0u8; 16])));
    }

    #[test]
    fn test_parse_value_exceeds_buffer() {
        // declared length is 8 but only 4 value bytes are present
        let mut input = vec![0x00, 0x06, 0x00, 0x08];

        input.extend_from_slice(b"test");

        assert!(is_invalid(parse(&input, [0u8; 16])));
    }

    #[test]
    fn test_parse_unknown_attribute_type() {
        let input = &[0x70, 0x00, 0x00, 0x00];

        let res = parse(input, [0u8; 16]);

        assert!(matches!(res, Err(AttributeError::UnknownAttribute(0x7000))));
    }

    #[cfg(feature = "ice")]
    #[test]
    fn test_parse_ice_attributes() {
        let input = &[0x00, 0x24, 0x00, 0x04, 0, 0, 0, 5];

        let Ok(Attribute::Priority(p)) = parse(input, [0u8; 16]) else {
            panic!("expected a priority");
        };

        assert_eq!(p, 5);

        let input = &[0x00, 0x25, 0x00, 0x00];

        let Ok(Attribute::UseCandidate) = parse(input, [0u8; 16]) else {
            panic!("expected a use-candidate");
        };

        let input = &[0x80, 0x29, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 7];

        let Ok(Attribute::ICEControlled(n)) = parse(input, [0u8; 16]) else {
            panic!("expected an ice-controlled");
        };

        assert_eq!(n, 7);

        let input = &[0x80, 0x2a, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 9];

        let Ok(Attribute::ICEControlling(n)) = parse(input, [0u8; 16]) else {
            panic!("expected an ice-controlling");
        };

        assert_eq!(n, 9);
    }
}
