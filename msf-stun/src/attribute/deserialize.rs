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
