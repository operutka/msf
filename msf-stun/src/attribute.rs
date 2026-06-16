use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
};

use bytes::{Buf, Bytes};
use zerocopy::{network_endian::U16, FromBytes, Immutable, KnownLayout, SizeError, Unaligned};

pub const ATTR_TYPE_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_TYPE_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_TYPE_USERNAME: u16 = 0x0006;
pub const ATTR_TYPE_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_TYPE_FINGERPRINT: u16 = 0x8028;
pub const ATTR_TYPE_ERROR_CODE: u16 = 0x0009;
pub const ATTR_TYPE_REALM: u16 = 0x0014;
pub const ATTR_TYPE_NONCE: u16 = 0x0015;
pub const ATTR_TYPE_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_TYPE_SOFTWARE: u16 = 0x8022;
pub const ATTR_TYPE_ALTERNATE_SERVER: u16 = 0x8023;

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

/// Attribute header.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AttributeHeader {
    attribute_type: U16,
    attribute_length: U16,
}

impl AttributeHeader {
    /// Consumer attribute header from a given buffer and parse it.
    fn from_bytes(data: &mut Bytes) -> Result<Self, AttributeError> {
        let (res, _) =
            Self::read_from_prefix(data).map_err(|_| AttributeError::InvalidAttribute)?;

        data.advance(std::mem::size_of_val(&res));

        Ok(res)
    }

    /// Get length of the attribute value.
    fn value_length(&self) -> usize {
        self.attribute_length.get() as usize
    }

    /// Get length of the attribute value including padding.
    fn padded_value_length(&self) -> usize {
        (self.attribute_length.get() as usize + 3) & !3
    }
}

/// STUN message attribute.
#[derive(Clone)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    Username(Text),
    MessageIntegrity([u8; 20]),
    Fingerprint(u32),
    ErrorCode(ErrorCode),
    Realm(Text),
    Nonce(Text),
    UnknownAttributes(Vec<u16>),
    Software(Text),
    AlternateServer(SocketAddr),

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
    pub fn from_bytes(
        data: &mut Bytes,
        long_transaction_id: [u8; 16],
    ) -> Result<Self, AttributeError> {
        let header = AttributeHeader::from_bytes(data)?;

        if data.len() < header.padded_value_length() {
            return Err(AttributeError::InvalidAttribute);
        }

        let mut value = data.slice(..header.value_length());

        data.advance(header.padded_value_length());

        let res = match header.attribute_type.get() {
            ATTR_TYPE_MAPPED_ADDRESS => Self::mapped_address_from_bytes(&mut value)?,
            ATTR_TYPE_XOR_MAPPED_ADDRESS => {
                Self::xor_mapped_address_from_bytes(&mut value, long_transaction_id)?
            }
            ATTR_TYPE_USERNAME => Self::username_from_bytes(&mut value)?,
            ATTR_TYPE_MESSAGE_INTEGRITY => Self::message_integrity_from_bytes(&mut value)?,
            ATTR_TYPE_FINGERPRINT => Self::fingerprint_from_bytes(&mut value)?,
            ATTR_TYPE_ERROR_CODE => Self::error_code_from_bytes(&mut value)?,
            ATTR_TYPE_REALM => Self::realm_from_bytes(&mut value)?,
            ATTR_TYPE_NONCE => Self::nonce_from_bytes(&mut value)?,
            ATTR_TYPE_UNKNOWN_ATTRIBUTES => Self::unknown_attributes_from_bytes(&mut value)?,
            ATTR_TYPE_SOFTWARE => Self::software_from_bytes(&mut value)?,
            ATTR_TYPE_ALTERNATE_SERVER => Self::alternate_server_from_bytes(&mut value)?,

            #[cfg(feature = "ice")]
            ATTR_TYPE_PRIORITY => Self::priority_from_bytes(&mut value)?,

            #[cfg(feature = "ice")]
            ATTR_TYPE_USE_CANDIDATE => Self::use_candidate_from_bytes(&mut value)?,

            #[cfg(feature = "ice")]
            ATTR_TYPE_ICE_CONTROLLED => Self::ice_controlled_from_bytes(&mut value)?,

            #[cfg(feature = "ice")]
            ATTR_TYPE_ICE_CONTROLLING => Self::ice_controlling_from_bytes(&mut value)?,

            t => return Err(AttributeError::UnknownAttribute(t)),
        };

        if !value.is_empty() {
            return Err(AttributeError::InvalidAttribute);
        }

        Ok(res)
    }

    /// Parse mapped address.
    fn mapped_address_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        MappedAddr::from_bytes(value)
            .map(SocketAddr::from)
            .map(Self::MappedAddress)
    }

    /// Parse XOR mapped address.
    fn xor_mapped_address_from_bytes(
        value: &mut Bytes,
        long_transaction_id: [u8; 16],
    ) -> Result<Self, AttributeError> {
        let mut magic_cookie = [0u8; 4];

        magic_cookie.copy_from_slice(&long_transaction_id[..4]);

        let u128_xor_bits = u128::from_be_bytes(long_transaction_id);
        let u32_xor_bits = u32::from_be_bytes(magic_cookie);
        let u16_xor_bits = (u32_xor_bits >> 16) as u16;

        let addr = match MappedAddr::from_bytes(value)? {
            MappedAddr::V4(addr) => {
                let ip = u32::from_be_bytes(addr.addr) ^ u32_xor_bits;

                let port = addr.port.get() ^ u16_xor_bits;

                SocketAddr::from((Ipv4Addr::from(ip), port))
            }
            MappedAddr::V6(addr) => {
                let ip = u128::from_be_bytes(addr.addr) ^ u128_xor_bits;

                let port = addr.port.get() ^ u16_xor_bits;

                SocketAddr::from((Ipv6Addr::from(ip), port))
            }
        };

        Ok(Self::XorMappedAddress(addr))
    }

    /// Parse username.
    fn username_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Text::from_bytes(value).map(Self::Username)
    }

    /// Parse message integrity.
    fn message_integrity_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        let (hash, _) =
            <[u8; 20]>::read_from_prefix(value).map_err(|_| AttributeError::InvalidAttribute)?;

        value.advance(std::mem::size_of_val(&hash));

        Ok(Self::MessageIntegrity(hash))
    }

    /// Parse fingerprint.
    fn fingerprint_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        value
            .try_get_u32()
            .map(Self::Fingerprint)
            .map_err(|_| AttributeError::InvalidAttribute)
    }

    /// Parse error code.
    fn error_code_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        ErrorCode::from_bytes(value).map(Self::ErrorCode)
    }

    /// Parse realm.
    fn realm_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Text::from_bytes(value).map(Self::Realm)
    }

    /// Parse nonce.
    fn nonce_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Text::from_bytes(value).map(Self::Nonce)
    }

    /// Parse unknown attributes.
    fn unknown_attributes_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if (value.len() & 1) != 0 {
            return Err(AttributeError::InvalidAttribute);
        }

        let len = value.len() >> 1;

        let res = <[U16]>::ref_from_bytes_with_elems(value, len)
            .map_err(SizeError::from)
            .map_err(|_| AttributeError::InvalidAttribute)?
            .iter()
            .map(|u| u.get())
            .collect();

        value.advance(len << 1);

        Ok(Self::UnknownAttributes(res))
    }

    /// Parse software.
    fn software_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Text::from_bytes(value).map(Self::Software)
    }

    /// Parse alternate server.
    fn alternate_server_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        MappedAddr::from_bytes(value)
            .map(SocketAddr::from)
            .map(Self::AlternateServer)
    }

    /// Parse priority.
    #[cfg(feature = "ice")]
    fn priority_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        value
            .try_get_u32()
            .map(Self::Priority)
            .map_err(|_| AttributeError::InvalidAttribute)
    }

    /// Parse use candidate.
    #[cfg(feature = "ice")]
    fn use_candidate_from_bytes(_: &mut Bytes) -> Result<Self, AttributeError> {
        Ok(Self::UseCandidate)
    }

    /// Parse ICE controlled.
    #[cfg(feature = "ice")]
    fn ice_controlled_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        value
            .try_get_u64()
            .map(Self::ICEControlled)
            .map_err(|_| AttributeError::InvalidAttribute)
    }

    /// Parse ICE controlling.
    #[cfg(feature = "ice")]
    fn ice_controlling_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        value
            .try_get_u64()
            .map(Self::ICEControlling)
            .map_err(|_| AttributeError::InvalidAttribute)
    }
}

/// Collection of attributes.
#[derive(Clone)]
pub struct Attributes {
    inner: Vec<Attribute>,
}

impl Attributes {
    /// Create an empty collection of attributes.
    pub(crate) const fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Create a new collection of attributes.
    pub(crate) const fn new(attributes: Vec<Attribute>) -> Self {
        Self { inner: attributes }
    }

    /// Get the error code attribute.
    #[inline]
    pub fn get_error_code(&self) -> Option<&ErrorCode> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::ErrorCode(status) => Some(status),
            _ => None,
        })
    }

    /// Get the unknown attributes attribute.
    #[inline]
    pub fn get_unknown_attributes(&self) -> Option<&[u16]> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::UnknownAttributes(attrs) => Some(attrs.as_ref()),
            _ => None,
        })
    }

    /// Get the alternate server attribute.
    #[inline]
    pub fn get_alternate_server(&self) -> Option<SocketAddr> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::AlternateServer(addr) => Some(*addr),
            _ => None,
        })
    }

    /// Get the mapped address attribute.
    #[inline]
    pub fn get_mapped_address(&self) -> Option<SocketAddr> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::MappedAddress(addr) => Some(*addr),
            _ => None,
        })
    }

    /// Get the XOR mapped address attribute.
    #[inline]
    pub fn get_xor_mapped_address(&self) -> Option<SocketAddr> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::XorMappedAddress(addr) => Some(*addr),
            _ => None,
        })
    }

    /// Get either the XOR mapped address attribute or the mapped address
    /// attribute if the XOR mapped attribute does not exist.
    #[inline]
    pub fn get_any_mapped_address(&self) -> Option<SocketAddr> {
        if let Some(addr) = self.get_xor_mapped_address() {
            Some(addr)
        } else {
            self.get_mapped_address()
        }
    }

    /// Get the username attribute.
    #[inline]
    pub fn get_username(&self) -> Option<&str> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::Username(username) => Some(username.as_str()),
            _ => None,
        })
    }

    /// Get the realm attribute.
    #[inline]
    pub fn get_realm(&self) -> Option<&str> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::Realm(realm) => Some(realm.as_str()),
            _ => None,
        })
    }

    /// Get the nonce attribute.
    #[inline]
    pub fn get_nonce(&self) -> Option<&str> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::Nonce(nonce) => Some(nonce.as_str()),
            _ => None,
        })
    }

    /// Get the software attribute.
    #[inline]
    pub fn get_software(&self) -> Option<&str> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::Software(software) => Some(software.as_str()),
            _ => None,
        })
    }

    /// Get ICE candidate priority.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn get_priority(&self) -> Option<u32> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::Priority(n) => Some(*n),
            _ => None,
        })
    }

    /// Get the use ICE candidate attribute.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn get_use_candidate(&self) -> bool {
        self.inner
            .iter()
            .any(|attr| matches!(attr, Attribute::UseCandidate))
    }

    /// Get the ICE controlled attribute.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn get_ice_controlled(&self) -> Option<u64> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::ICEControlled(n) => Some(*n),
            _ => None,
        })
    }

    /// Get the ICE controlling attribute.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn get_ice_controlling(&self) -> Option<u64> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::ICEControlling(n) => Some(*n),
            _ => None,
        })
    }
}

impl Deref for Attributes {
    type Target = [Attribute];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Attribute text value.
#[derive(Clone)]
pub struct Text {
    inner: Bytes,
}

impl Text {
    /// Parse text value from a given buffer.
    fn from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Self::try_from(value.split_to(value.len())).map_err(|_| AttributeError::InvalidAttribute)
    }

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

    /// Parse error code from a given buffer.
    fn from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        let (header, _) = ErrorCodeHeader::read_from_prefix(value)
            .ok()
            .filter(|(h, _)| h.number < 100)
            .ok_or(AttributeError::InvalidAttribute)?;

        value.advance(std::mem::size_of_val(&header));

        let class = (header.class & 7) as u16;
        let number = header.number as u16;

        let code = 100 * class + number;

        let msg = Text::from_bytes(value)?;

        Ok(Self::new(code, msg))
    }

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
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ErrorCodeHeader {
    _padding: [u8; 2],
    class: u8,
    number: u8,
}

/// Mapped address attribute.
enum MappedAddr {
    V4(MappedIpv4Addr),
    V6(MappedIpv6Addr),
}

impl MappedAddr {
    /// Parse mapped address from a given buffer.
    fn from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        let (header, _) = MappedAddrHeader::read_from_prefix(value)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        value.advance(std::mem::size_of_val(&header));

        match header.family {
            1 => {
                let (addr, _) = MappedIpv4Addr::read_from_prefix(value)
                    .map_err(|_| AttributeError::InvalidAttribute)?;

                value.advance(std::mem::size_of_val(&addr));

                Ok(Self::V4(addr))
            }
            2 => {
                let (addr, _) = MappedIpv6Addr::read_from_prefix(value)
                    .map_err(|_| AttributeError::InvalidAttribute)?;

                value.advance(std::mem::size_of_val(&addr));

                Ok(Self::V6(addr))
            }
            _ => Err(AttributeError::InvalidAttribute),
        }
    }
}

impl From<MappedAddr> for SocketAddr {
    fn from(addr: MappedAddr) -> Self {
        match addr {
            MappedAddr::V4(addr) => addr.into(),
            MappedAddr::V6(addr) => addr.into(),
        }
    }
}

/// Mapped address attribute header.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct MappedAddrHeader {
    _padding: u8,
    family: u8,
}

/// Mapped IPv4 address.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct MappedIpv4Addr {
    port: U16,
    addr: [u8; 4],
}

impl From<MappedIpv4Addr> for SocketAddr {
    fn from(addr: MappedIpv4Addr) -> Self {
        let ip = Ipv4Addr::from_octets(addr.addr);

        let port = addr.port.get();

        SocketAddr::from((ip, port))
    }
}

/// Mapped IPv6 address.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct MappedIpv6Addr {
    port: U16,
    addr: [u8; 16],
}

impl From<MappedIpv6Addr> for SocketAddr {
    fn from(addr: MappedIpv6Addr) -> Self {
        let ip = Ipv6Addr::from_octets(addr.addr);

        let port = addr.port.get();

        SocketAddr::from((ip, port))
    }
}
