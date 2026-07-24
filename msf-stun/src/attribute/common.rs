use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::Deref,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use zerocopy::{
    network_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned,
};

use crate::attribute::{Attribute, AttributeError, InternalBytesMutExt as _, SerializeAttribute};

pub const ATTR_TYPE_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_TYPE_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_TYPE_USERNAME: u16 = 0x0006;
pub const ATTR_TYPE_USERHASH: u16 = 0x001E;
pub const ATTR_TYPE_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_TYPE_MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
pub const ATTR_TYPE_FINGERPRINT: u16 = 0x8028;
pub const ATTR_TYPE_ERROR_CODE: u16 = 0x0009;
pub const ATTR_TYPE_REALM: u16 = 0x0014;
pub const ATTR_TYPE_NONCE: u16 = 0x0015;
pub const ATTR_TYPE_PASSWORD_ALGORITHMS: u16 = 0x8002;
pub const ATTR_TYPE_PASSWORD_ALGORITHM: u16 = 0x001D;
pub const ATTR_TYPE_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_TYPE_SOFTWARE: u16 = 0x8022;
pub const ATTR_TYPE_ALTERNATE_SERVER: u16 = 0x8023;
pub const ATTR_TYPE_ALTERNATE_DOMAIN: u16 = 0x8003;

/// SHA-1 hash type.
pub type Sha1Hash = [u8; 20];

/// SHA-256 hash type.
pub type FullSha256Hash = [u8; 32];

/// SHA-256 hash length.
#[derive(Default, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Sha256Length {
    Truncated16 = 16,
    Truncated20 = 20,
    Truncated24 = 24,
    Truncated28 = 28,
    #[default]
    Full = 32,
}

/// SHA-256 hash type.
#[derive(Copy, Clone)]
pub enum Sha256Hash {
    Truncated16([u8; 16]),
    Truncated20([u8; 20]),
    Truncated24([u8; 24]),
    Truncated28([u8; 28]),
    Full(FullSha256Hash),
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Truncated16(hash) => hash,
            Self::Truncated20(hash) => hash,
            Self::Truncated24(hash) => hash,
            Self::Truncated28(hash) => hash,
            Self::Full(hash) => hash,
        }
    }
}

/// Attribute text value.
#[derive(Clone)]
pub struct Text {
    inner: Bytes,
}

impl Text {
    /// Create a text value from a given string.
    #[inline]
    pub const fn from_static_str(s: &'static str) -> Self {
        Self {
            inner: Bytes::from_static(s.as_bytes()),
        }
    }

    /// Return the text value as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: The inner `Bytes` value is guaranteed to represent a valid
        //   UTF-8 string.
        unsafe { std::str::from_utf8_unchecked(&self.inner) }
    }
}

impl Deref for Text {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<&str> for Text {
    #[inline]
    fn from(s: &str) -> Self {
        Self::from(String::from(s))
    }
}

impl From<String> for Text {
    #[inline]
    fn from(s: String) -> Self {
        Self {
            inner: Bytes::from(s),
        }
    }
}

impl TryFrom<Bytes> for Text {
    type Error = std::str::Utf8Error;

    #[inline]
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        std::str::from_utf8(&value)?;

        let res = Self { inner: value };

        Ok(res)
    }
}

/// Error code attribute.
#[derive(Clone)]
pub struct ErrorCode {
    code: u16,
    msg: Text,
}

impl ErrorCode {
    pub const BAD_REQUEST: Self = Self::new_static(400, "Bad Request");
    pub const UNAUTHORIZED: Self = Self::new_static(401, "Unauthorized");
    pub const UNKNOWN_ATTRIBUTES: Self = Self::new_static(420, "Unknown Attributes");

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    pub const ALLOCATION_MISMATCH: Self = Self::new_static(437, "Allocation Mismatch");

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    pub const UNSUPPORTED_TRANSPORT_PROTOCOL: Self =
        Self::new_static(442, "Unsupported Transport Protocol");

    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    pub const ROLE_CONFLICT: Self = Self::new_static(487, "Role Conflict");

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    pub const INSUFFICIENT_CAPACITY: Self = Self::new_static(508, "Insufficient Capacity");

    /// Create a new error code with a given numeric code and a message.
    #[inline]
    pub const fn new_static(code: u16, msg: &'static str) -> Self {
        Self {
            code,
            msg: Text::from_static_str(msg),
        }
    }

    /// Create a new error code with a given numeric code and a message.
    pub fn new<T>(code: u16, msg: T) -> Self
    where
        T: Into<Text>,
    {
        Self {
            code,
            msg: msg.into(),
        }
    }

    /// Get the error code number.
    #[inline]
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Get the error message.
    #[inline]
    pub fn message(&self) -> &str {
        &self.msg
    }
}

/// Error code attribute header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct ErrorCodeHeader {
    padding: [u8; 2],
    class: u8,
    number: u8,
}

/// Password algorithm.
#[derive(Clone)]
pub enum PasswordAlgorithm {
    Md5,
    Sha256,
}

impl PasswordAlgorithm {
    /// Get the password algorithm ID.
    fn id(&self) -> u16 {
        match *self {
            Self::Md5 => 0x0001,
            Self::Sha256 => 0x0002,
        }
    }
}

/// Password algorithm attribute header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct PasswordAlgorithmHeader {
    algorithm: U16,
    parameters_length: U16,
}

/// Mapped address attribute header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct MappedAddrHeader {
    padding: u8,
    family: u8,
}

/// Mapped IPv4 address.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct MappedIpv4Addr {
    port: U16,
    addr: [u8; 4],
}

impl From<MappedIpv4Addr> for SocketAddrV4 {
    fn from(addr: MappedIpv4Addr) -> Self {
        let ip = Ipv4Addr::from_octets(addr.addr);

        let port = addr.port.get();

        SocketAddrV4::new(ip, port)
    }
}

/// Mapped IPv6 address.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct MappedIpv6Addr {
    port: U16,
    addr: [u8; 16],
}

impl From<MappedIpv6Addr> for SocketAddrV6 {
    fn from(addr: MappedIpv6Addr) -> Self {
        let ip = Ipv6Addr::from_octets(addr.addr);

        let port = addr.port.get();

        SocketAddrV6::new(ip, port, 0, 0)
    }
}

/// Helper trait for reading common attribute values from a byte stream.
pub trait BytesExt {
    /// Try to get an common attribute value from the byte stream.
    fn try_get_common_attribute_value(
        &mut self,
        attribute_type: u16,
        long_transaction_id: [u8; 16],
    ) -> Result<Option<Attribute>, AttributeError>;

    /// Try to get a mapped address from the byte stream.
    fn try_get_mapped_addr(&mut self) -> Result<SocketAddr, AttributeError>;

    /// Try to get a XOR-mapped address from the byte stream.
    fn try_get_xor_mapped_addr(
        &mut self,
        long_transaction_id: [u8; 16],
    ) -> Result<SocketAddr, AttributeError>;

    /// Try to get an error code from the byte stream.
    fn try_get_error_code(&mut self) -> Result<ErrorCode, AttributeError>;

    /// Try to get a text value from the byte stream.
    fn try_get_text(&mut self, len: usize) -> Result<Text, AttributeError>;

    /// Try to get a list of password algorithms from the byte stream.
    fn try_get_password_algorithms(&mut self) -> Result<Vec<PasswordAlgorithm>, AttributeError>;

    /// Try to get a password algorithm from the byte stream.
    fn try_get_password_algorithm(&mut self) -> Result<PasswordAlgorithm, AttributeError>;

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
    fn try_get_common_attribute_value(
        &mut self,
        attribute_type: u16,
        long_transaction_id: [u8; 16],
    ) -> Result<Option<Attribute>, AttributeError> {
        let res = match attribute_type {
            ATTR_TYPE_MAPPED_ADDRESS => Attribute::MappedAddress(self.try_get_mapped_addr()?),
            ATTR_TYPE_XOR_MAPPED_ADDRESS => {
                Attribute::XorMappedAddress(self.try_get_xor_mapped_addr(long_transaction_id)?)
            }
            ATTR_TYPE_USERNAME => Attribute::Username(self.try_get_text(self.len())?),
            ATTR_TYPE_USERHASH => Attribute::Userhash(self.try_get_byte_array()?),
            ATTR_TYPE_MESSAGE_INTEGRITY => Attribute::MessageIntegrity(self.try_get_byte_array()?),
            ATTR_TYPE_MESSAGE_INTEGRITY_SHA256 => {
                Attribute::MessageIntegritySha256(self.try_get_sha256_hash(self.len())?)
            }
            ATTR_TYPE_FINGERPRINT => self
                .try_get_u32()
                .map(Attribute::Fingerprint)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            ATTR_TYPE_ERROR_CODE => Attribute::ErrorCode(self.try_get_error_code()?),
            ATTR_TYPE_REALM => Attribute::Realm(self.try_get_text(self.len())?),
            ATTR_TYPE_NONCE => Attribute::Nonce(self.try_get_text(self.len())?),
            ATTR_TYPE_PASSWORD_ALGORITHMS => {
                Attribute::PasswordAlgorithms(self.try_get_password_algorithms()?)
            }
            ATTR_TYPE_PASSWORD_ALGORITHM => {
                Attribute::PasswordAlgorithm(self.try_get_password_algorithm()?)
            }
            ATTR_TYPE_UNKNOWN_ATTRIBUTES => {
                Attribute::UnknownAttributes(self.try_get_unknown_attributes()?)
            }
            ATTR_TYPE_SOFTWARE => Attribute::Software(self.try_get_text(self.len())?),
            ATTR_TYPE_ALTERNATE_SERVER => Attribute::AlternateServer(self.try_get_mapped_addr()?),
            ATTR_TYPE_ALTERNATE_DOMAIN => {
                Attribute::AlternateDomain(self.try_get_text(self.len())?)
            }
            _ => return Ok(None),
        };

        Ok(Some(res))
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

/// Helper trait for reading common attribute values from a byte stream.
trait InternalBytesExt {
    /// Try to get a mapped address header from the byte stream.
    fn try_get_mapped_addr_header(&mut self) -> Result<MappedAddrHeader, AttributeError>;

    /// Try to get a mapped IPv4 address from the byte stream.
    fn try_get_mapped_ipv4_addr(&mut self) -> Result<SocketAddrV4, AttributeError>;

    /// Try to get a mapped IPv6 address from the byte stream.
    fn try_get_mapped_ipv6_addr(&mut self) -> Result<SocketAddrV6, AttributeError>;

    /// Try to get an error code header from the byte stream.
    fn try_get_error_code_header(&mut self) -> Result<ErrorCodeHeader, AttributeError>;

    /// Try to get a password algorithm header from the byte stream.
    fn try_get_password_algorithm_header(
        &mut self,
    ) -> Result<PasswordAlgorithmHeader, AttributeError>;
}

impl InternalBytesExt for Bytes {
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

    fn try_get_error_code_header(&mut self) -> Result<ErrorCodeHeader, AttributeError> {
        let (header, _) = ErrorCodeHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }

    fn try_get_password_algorithm_header(
        &mut self,
    ) -> Result<PasswordAlgorithmHeader, AttributeError> {
        let (header, _) = PasswordAlgorithmHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }
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
trait InternalBytesMutExt {
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

impl InternalBytesMutExt for BytesMut {
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::{Bytes, BytesMut};

    use crate::attribute::{
        common::{ErrorCode, PasswordAlgorithm, Sha256Hash, Text},
        Attribute, AttributeError, SerializeAttribute,
    };

    /// Parse a single attribute from a raw attribute slice.
    fn parse(bytes: &[u8], long_transaction_id: [u8; 16]) -> Result<Attribute, AttributeError> {
        Attribute::from_bytes(&mut Bytes::copy_from_slice(bytes), long_transaction_id)
    }

    /// Check whether a result is the `InvalidAttribute` error.
    fn is_invalid(res: Result<Attribute, AttributeError>) -> bool {
        matches!(res, Err(AttributeError::InvalidAttribute))
    }

    #[test]
    fn test_text() {
        let t = Text::try_from(Bytes::from_static(b"bytes")).unwrap();

        assert_eq!(t.as_str(), "bytes");

        assert!(Text::try_from(Bytes::from_static(&[0xff, 0xfe])).is_err());
    }

    #[test]
    fn test_serialize_empty() {
        let mut b = BytesMut::new();

        SerializeAttribute::serialize(&(), 0x0025, &mut b);

        assert_eq!(&b[..], &[0x00, 0x25, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_u32() {
        let mut b = BytesMut::new();

        let n = 0x1234_5678u32;

        n.serialize(0x0024, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x24, 0x00, 0x04]);
        assert_eq!(&b[4..], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_serialize_u64() {
        let mut b = BytesMut::new();

        let n = 0x0102_0304_0506_0708u64;

        n.serialize(0x8029, &mut b);

        assert_eq!(&b[..4], &[0x80, 0x29, 0x00, 0x08]);
        assert_eq!(&b[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_serialize_socket_addr_v4() {
        let mut b = BytesMut::new();

        let addr = SocketAddr::from(([192, 0, 2, 1], 32853));

        addr.serialize(0x0001, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x01, 0x00, 0x08]);
        assert_eq!(&b[4..8], &[0x00, 0x01, 0x80, 0x55]);
        assert_eq!(&b[8..], &[192, 0, 2, 1]);
    }

    #[test]
    fn test_serialize_socket_addr_v6() {
        let mut b = BytesMut::new();

        let ip = u128::to_be_bytes(0x2001_0db8_0000_0000_0000_0000_0000_0001);

        let addr = SocketAddr::from((ip, 32853));

        addr.serialize(0x0001, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x01, 0x00, 0x14]);
        assert_eq!(&b[4..8], &[0x00, 0x02, 0x80, 0x55]);
        assert_eq!(&b[8..], &ip);
    }

    #[test]
    fn test_serialize_error_code_unaligned() {
        let mut b = BytesMut::new();

        let code = ErrorCode::new_static(420, "Unknown");

        code.serialize(0x0009, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x09, 0x00, 0x0b]);
        assert_eq!(&b[4..8], &[0x00, 0x00, 0x04, 0x14]);
        assert_eq!(&b[8..], b"Unknown\0");
    }

    #[test]
    fn test_serialize_error_code_aligned() {
        let mut b = BytesMut::new();

        // with a four-byte message, the attribute value is already aligned and
        // no padding should be added
        let code = ErrorCode::new_static(400, "Bad!");

        code.serialize(0x0009, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x09, 0x00, 0x08]);
        assert_eq!(&b[4..8], &[0x00, 0x00, 0x04, 0x00]);
        assert_eq!(&b[8..], b"Bad!");
    }

    #[test]
    fn test_serialize_password_algorithm() {
        let mut b = BytesMut::new();

        let alg = PasswordAlgorithm::Md5;

        alg.serialize(0x001d, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x1d, 0x00, 0x04]);
        assert_eq!(&b[4..], &[0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_password_algorithms() {
        let mut b = BytesMut::new();

        let algs: &[PasswordAlgorithm] = &[PasswordAlgorithm::Md5, PasswordAlgorithm::Sha256];

        algs.serialize(0x8002, &mut b);

        assert_eq!(&b[..4], &[0x80, 0x02, 0x00, 0x08]);
        assert_eq!(&b[4..8], &[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(&b[8..], &[0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_str_aligned() {
        let mut b = BytesMut::new();

        let s = "test";

        s.serialize(0x0006, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x06, 0x00, 0x04]);
        assert_eq!(&b[4..], b"test");
    }

    #[test]
    fn test_serialize_str_unaligned() {
        let mut b = BytesMut::new();

        let s = "abc";

        s.serialize(0x0006, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x06, 0x00, 0x03]);
        assert_eq!(&b[4..], b"abc\0");
    }

    #[test]
    fn test_serialize_bytes() {
        let mut b = BytesMut::new();

        let data: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x01];

        data.serialize(0x0008, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x08, 0x00, 0x05]);
        assert_eq!(&b[4..9], data);
        assert_eq!(&b[9..], &[0, 0, 0]);
    }

    #[test]
    fn test_serialize_u16_list_even() {
        let mut b = BytesMut::new();

        let v: &[u16] = &[0x0001, 0x0006];

        v.serialize(0x000a, &mut b);

        assert_eq!(&b[..], &[0x00, 0x0a, 0x00, 0x04, 0x00, 0x01, 0x00, 0x06]);
    }

    #[test]
    fn test_serialize_u16_list_odd() {
        let mut b = BytesMut::new();

        let v: &[u16] = &[0x0001, 0x0006, 0x000a];

        v.serialize(0x000a, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x0a, 0x00, 0x06]);
        assert_eq!(&b[4..10], &[0x00, 0x01, 0x00, 0x06, 0x00, 0x0a]);
        assert_eq!(&b[10..], &[0, 0]);
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
}
