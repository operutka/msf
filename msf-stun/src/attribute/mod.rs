mod collection;
mod deserialize;
mod serialize;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::Deref,
};

use bytes::Bytes;
use zerocopy::{network_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub use self::{collection::Attributes, serialize::SerializeAttribute};

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

#[cfg(feature = "ice")]
pub const ATTR_TYPE_PRIORITY: u16 = 0x0024;

#[cfg(feature = "ice")]
pub const ATTR_TYPE_USE_CANDIDATE: u16 = 0x0025;

#[cfg(feature = "ice")]
pub const ATTR_TYPE_ICE_CONTROLLED: u16 = 0x8029;

#[cfg(feature = "ice")]
pub const ATTR_TYPE_ICE_CONTROLLING: u16 = 0x802A;

/// Attribute error.
pub enum AttributeError {
    InvalidAttribute,
    UnknownAttribute(u16),
}

/// STUN message attribute.
#[derive(Clone)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    Username(Text),
    Userhash(FullSha256Hash),
    MessageIntegrity(Sha1Hash),
    MessageIntegritySha256(Sha256Hash),
    Fingerprint(u32),
    ErrorCode(ErrorCode),
    Realm(Text),
    Nonce(Text),
    PasswordAlgorithms(Vec<PasswordAlgorithm>),
    PasswordAlgorithm(PasswordAlgorithm),
    UnknownAttributes(Vec<u16>),
    Software(Text),
    AlternateServer(SocketAddr),
    AlternateDomain(Text),

    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    Priority(u32),

    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    UseCandidate,

    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    ICEControlled(u64),

    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    ICEControlling(u64),
}

impl Attribute {
    /// Consume the next attribute from a given buffer.
    pub(crate) fn from_bytes(
        data: &mut Bytes,
        long_transaction_id: [u8; 16],
    ) -> Result<Self, AttributeError> {
        deserialize::try_get_attribute_from_bytes(data, long_transaction_id)
    }
}

/// Attribute header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct AttributeHeader {
    attribute_type: U16,
    attribute_length: U16,
}

impl AttributeHeader {
    /// Get length of the attribute value.
    fn value_length(&self) -> usize {
        self.attribute_length.get() as usize
    }

    /// Get length of the attribute value including padding.
    fn padded_value_length(&self) -> usize {
        (self.attribute_length.get() as usize + 3) & !3
    }
}

/// SHA-1 hash type.
pub type Sha1Hash = [u8; 20];

/// SHA-256 hash type.
pub type FullSha256Hash = [u8; 32];

/// SHA-256 hash type.
#[derive(Copy, Clone)]
pub enum Sha256Hash {
    Truncated16([u8; 16]),
    Truncated20([u8; 20]),
    Truncated24([u8; 24]),
    Truncated28([u8; 28]),
    Full(FullSha256Hash),
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

    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    pub const ROLE_CONFLICT: Self = Self::new_static(487, "Role Conflict");

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
