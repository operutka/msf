use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
};

use bytes::{Buf, Bytes};

use crate::ErrorCode;

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
struct AttributeHeader {
    attribute_type: u16,
    attribute_length: u16,
}

impl AttributeHeader {
    /// Consumer attribute header from a given buffer and parse it.
    fn from_bytes(data: &mut Bytes) -> Result<Self, AttributeError> {
        if data.len() < 4 {
            return Err(AttributeError::InvalidAttribute);
        }

        let res = Self {
            attribute_type: data.get_u16(),
            attribute_length: data.get_u16(),
        };

        Ok(res)
    }

    /// Get length of the attribute value.
    fn value_length(&self) -> usize {
        self.attribute_length as usize
    }

    /// Get length of the attribute value including padding.
    fn padded_value_length(&self) -> usize {
        (self.attribute_length as usize + 3) & !3
    }
}

/// STUN message attribute.
#[derive(Clone)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    Username(String),
    MessageIntegrity([u8; 20]),
    Fingerprint(u32),
    ErrorCode(ErrorCode),
    Realm(String),
    Nonce(String),
    UnknownAttributes(Vec<u16>),
    Software(String),
    AlternateServer(SocketAddr),

    #[cfg(feature = "ice")]
    Priority(u32),

    #[cfg(feature = "ice")]
    UseCandidate,

    #[cfg(feature = "ice")]
    ICEControlled(u64),

    #[cfg(feature = "ice")]
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

        let res = match header.attribute_type {
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
        if value.len() < 4 {
            return Err(AttributeError::InvalidAttribute);
        }

        value.advance(1);

        let family = value.get_u8();
        let port = value.get_u16();

        let expected = match family {
            1 => 4,
            2 => 16,
            _ => return Err(AttributeError::InvalidAttribute),
        };

        if value.len() < expected {
            return Err(AttributeError::InvalidAttribute);
        }

        let addr = match family {
            1 => IpAddr::from(Ipv4Addr::from(value.get_u32())),
            2 => IpAddr::from(Ipv6Addr::from(value.get_u128())),
            _ => unreachable!(),
        };

        Ok(Self::MappedAddress(SocketAddr::from((addr, port))))
    }

    /// Parse XOR mapped address.
    fn xor_mapped_address_from_bytes(
        value: &mut Bytes,
        long_transaction_id: [u8; 16],
    ) -> Result<Self, AttributeError> {
        if value.len() < 4 {
            return Err(AttributeError::InvalidAttribute);
        }

        value.advance(1);

        let mut magic_cookie = [0u8; 4];

        magic_cookie.copy_from_slice(&long_transaction_id[..4]);

        let u128_xor_bits = u128::from_be_bytes(long_transaction_id);
        let u32_xor_bits = u32::from_be_bytes(magic_cookie);
        let u16_xor_bits = (u32_xor_bits >> 16) as u16;

        let family = value.get_u8();
        let port = value.get_u16() ^ u16_xor_bits;

        let expected = match family {
            1 => 4,
            2 => 16,
            _ => return Err(AttributeError::InvalidAttribute),
        };

        if value.len() < expected {
            return Err(AttributeError::InvalidAttribute);
        }

        let addr = match family {
            1 => IpAddr::from(Ipv4Addr::from(value.get_u32() ^ u32_xor_bits)),
            2 => IpAddr::from(Ipv6Addr::from(value.get_u128() ^ u128_xor_bits)),
            _ => unreachable!(),
        };

        Ok(Self::XorMappedAddress(SocketAddr::from((addr, port))))
    }

    /// Parse username.
    fn username_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Self::string_from_bytes(value).map(Self::Username)
    }

    /// Parse message integrity.
    fn message_integrity_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if value.len() < 20 {
            return Err(AttributeError::InvalidAttribute);
        }

        let mut hash = [0u8; 20];

        hash.copy_from_slice(&value[..20]);

        value.advance(20);

        Ok(Self::MessageIntegrity(hash))
    }

    /// Parse fingerprint.
    fn fingerprint_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if value.len() < 4 {
            return Err(AttributeError::InvalidAttribute);
        }

        let crc = value.get_u32();

        Ok(Self::Fingerprint(crc))
    }

    /// Parse error code.
    fn error_code_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if value.len() < 4 {
            return Err(AttributeError::InvalidAttribute);
        }

        value.advance(2);

        let class = (value.get_u8() & 7) as u16;
        let num = value.get_u8() as u16;

        if num > 99 {
            return Err(AttributeError::InvalidAttribute);
        }

        let msg = Self::string_from_bytes(value)?;

        Ok(Self::ErrorCode(ErrorCode::new(class * 100 + num, msg)))
    }

    /// Parse realm.
    fn realm_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Self::string_from_bytes(value).map(Self::Realm)
    }

    /// Parse nonce.
    fn nonce_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Self::string_from_bytes(value).map(Self::Nonce)
    }

    /// Parse unknown attributes.
    fn unknown_attributes_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if (value.len() & 1) != 0 {
            return Err(AttributeError::InvalidAttribute);
        }

        let mut res = Vec::with_capacity(value.len() >> 1);

        while !value.is_empty() {
            res.push(value.get_u16());
        }

        Ok(Self::UnknownAttributes(res))
    }

    /// Parse software.
    fn software_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        Self::string_from_bytes(value).map(Self::Software)
    }

    /// Parse alternate server.
    fn alternate_server_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        match Self::mapped_address_from_bytes(value)? {
            Self::MappedAddress(addr) => Ok(Self::AlternateServer(addr)),
            _ => unreachable!(),
        }
    }

    /// Parse priority.
    #[cfg(feature = "ice")]
    fn priority_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if value.len() < 4 {
            return Err(AttributeError::InvalidAttribute);
        }

        Ok(Self::Priority(value.get_u32()))
    }

    /// Parse use candidate.
    #[cfg(feature = "ice")]
    fn use_candidate_from_bytes(_: &mut Bytes) -> Result<Self, AttributeError> {
        Ok(Self::UseCandidate)
    }

    /// Parse ICE controlled.
    #[cfg(feature = "ice")]
    fn ice_controlled_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if value.len() < 8 {
            return Err(AttributeError::InvalidAttribute);
        }

        Ok(Self::ICEControlled(value.get_u64()))
    }

    /// Parse ICE controlling.
    #[cfg(feature = "ice")]
    fn ice_controlling_from_bytes(value: &mut Bytes) -> Result<Self, AttributeError> {
        if value.len() < 8 {
            return Err(AttributeError::InvalidAttribute);
        }

        Ok(Self::ICEControlling(value.get_u64()))
    }

    /// Parse a string.
    fn string_from_bytes(value: &mut Bytes) -> Result<String, AttributeError> {
        let res = std::str::from_utf8(value)
            .map(|s| s.to_string())
            .map_err(|_| AttributeError::InvalidAttribute)?;

        value.clear();

        Ok(res)
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
    #[inline]
    pub fn get_priority(&self) -> Option<u32> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::Priority(n) => Some(*n),
            _ => None,
        })
    }

    /// Get the use ICE candidate attribute.
    #[cfg(feature = "ice")]
    #[inline]
    pub fn get_use_candidate(&self) -> bool {
        self.inner
            .iter()
            .any(|attr| matches!(attr, Attribute::UseCandidate))
    }

    /// Get the ICE controlled attribute.
    #[cfg(feature = "ice")]
    #[inline]
    pub fn get_ice_controlled(&self) -> Option<u64> {
        self.inner.iter().find_map(|attr| match attr {
            Attribute::ICEControlled(n) => Some(*n),
            _ => None,
        })
    }

    /// Get the ICE controlling attribute.
    #[cfg(feature = "ice")]
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
