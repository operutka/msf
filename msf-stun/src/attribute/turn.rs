use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::attribute::{
    common::BytesExt as _, Attribute, AttributeError, ErrorCode, InternalBytesMutExt as _,
    SerializeAttribute, Text,
};

pub const ATTR_TYPE_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_TYPE_LIFETIME: u16 = 0x000D;
pub const ATTR_TYPE_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_TYPE_DATA: u16 = 0x0013;
pub const ATTR_TYPE_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_TYPE_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTR_TYPE_EVEN_PORT: u16 = 0x0018;
pub const ATTR_TYPE_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_TYPE_DONT_FRAGMENT: u16 = 0x001A;
pub const ATTR_TYPE_RESERVATION_TOKEN: u16 = 0x0022;
pub const ATTR_TYPE_ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
pub const ATTR_TYPE_ADDRESS_ERROR_CODE: u16 = 0x8001;
pub const ATTR_TYPE_ICMP: u16 = 0x8004;

/// Address family.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressFamily {
    /// IPv4 address family.
    IPv4 = 0x01,
    /// IPv6 address family.
    IPv6 = 0x02,
}

/// Transport protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportProtocol {
    /// UDP transport protocol.
    UDP = 17,
}

/// Even port attribute value.
#[derive(Copy, Clone)]
pub struct EvenPort {
    r: bool,
}

impl EvenPort {
    /// Create a new even port attribute value with a given R bit.
    #[inline]
    pub const fn new(r: bool) -> Self {
        Self { r }
    }

    /// Get the R bit.
    #[inline]
    pub fn r(&self) -> bool {
        self.r
    }
}

/// Channel number attribute value.
#[derive(Copy, Clone)]
pub struct ChannelNumber {
    channel_number: u16,
}

impl ChannelNumber {
    /// Create a new channel number attribute value with a given channel number.
    #[inline]
    pub const fn new(channel_number: u16) -> Self {
        Self { channel_number }
    }

    /// Get the channel number.
    #[inline]
    pub fn channel_number(&self) -> u16 {
        self.channel_number
    }
}

/// Address error code.
#[derive(Clone)]
pub struct AddressErrorCode {
    family: AddressFamily,
    inner: ErrorCode,
}

impl AddressErrorCode {
    /// Create a new addresss error code with a given address family, numeric
    /// code and a message.
    #[inline]
    pub const fn new_static(family: AddressFamily, code: u16, msg: &'static str) -> Self {
        Self {
            family,
            inner: ErrorCode::new_static(code, msg),
        }
    }

    /// Create a new address error code with a given address family, numeric
    /// code and a message.
    pub fn new<T>(family: AddressFamily, code: u16, msg: T) -> Self
    where
        T: Into<Text>,
    {
        Self {
            family,
            inner: ErrorCode::new(code, msg),
        }
    }

    /// Get the address family.
    #[inline]
    pub fn family(&self) -> AddressFamily {
        self.family
    }
}

impl Deref for AddressErrorCode {
    type Target = ErrorCode;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// ICMP attribute value.
#[derive(Copy, Clone)]
pub struct ICMP {
    icmp_type: u8,
    icmp_code: u16,
    error_data: u32,
}

impl ICMP {
    /// Create a new ICMP attribute value with a given ICMP type, code and
    /// error data.
    #[inline]
    pub const fn new(icmp_type: u8, icmp_code: u16, error_data: u32) -> Self {
        Self {
            icmp_type,
            icmp_code,
            error_data,
        }
    }

    /// Get the ICMP type.
    #[inline]
    pub fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    /// Get the ICMP code.
    #[inline]
    pub fn icmp_code(&self) -> u16 {
        self.icmp_code
    }

    /// Get the ICMP error data.
    #[inline]
    pub fn error_data(&self) -> u32 {
        self.error_data
    }
}

/// Address error code attribute header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct AddressErrorCodeHeader {
    family: u8,
    padding: u8,
    class: u8,
    number: u8,
}

/// ICMP attribute header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct ICMPHeader {
    reserved: [u8; 2],
    type_and_code: U16,
    error_data: U32,
}

/// Helper trait for reading TURN attribute values from a byte stream.
pub trait BytesExt {
    /// Try to get a TURN attribute value from the byte stream.
    fn try_get_turn_attribute_value(
        &mut self,
        attribute_type: u16,
        long_transaction_id: [u8; 16],
    ) -> Result<Option<Attribute>, AttributeError>;

    /// Try to get a channel number attribute value from the byte stream.
    fn try_get_channel_number(&mut self) -> Result<ChannelNumber, AttributeError>;

    /// Try to get an address family from the byte stream.
    fn try_get_address_family(&mut self) -> Result<AddressFamily, AttributeError>;

    /// Try to get an even port attribute value from the byte stream.
    fn try_get_even_port(&mut self) -> Result<EvenPort, AttributeError>;

    /// Try to get a transport protocol from the byte stream.
    fn try_get_transport_protocol(&mut self) -> Result<TransportProtocol, AttributeError>;

    /// Try to get an address error code from the byte stream.
    fn try_get_address_error_code(&mut self) -> Result<AddressErrorCode, AttributeError>;

    /// Try to get an ICMP attribute value from the byte stream.
    fn try_get_icmp(&mut self) -> Result<ICMP, AttributeError>;
}

impl BytesExt for Bytes {
    fn try_get_turn_attribute_value(
        &mut self,
        attribute_type: u16,
        long_transaction_id: [u8; 16],
    ) -> Result<Option<Attribute>, AttributeError> {
        let res = match attribute_type {
            ATTR_TYPE_CHANNEL_NUMBER => Attribute::ChannelNumber(self.try_get_channel_number()?),
            ATTR_TYPE_LIFETIME => self
                .try_get_u32()
                .map(Attribute::Lifetime)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            ATTR_TYPE_XOR_PEER_ADDRESS => {
                Attribute::XorPeerAddress(self.try_get_xor_mapped_addr(long_transaction_id)?)
            }
            ATTR_TYPE_DATA => Attribute::Data(self.split_to(self.len())),
            ATTR_TYPE_XOR_RELAYED_ADDRESS => {
                Attribute::XorRelayedAddress(self.try_get_xor_mapped_addr(long_transaction_id)?)
            }
            ATTR_TYPE_REQUESTED_ADDRESS_FAMILY => {
                Attribute::RequestedAddressFamily(self.try_get_address_family()?)
            }
            ATTR_TYPE_EVEN_PORT => Attribute::EvenPort(self.try_get_even_port()?),
            ATTR_TYPE_REQUESTED_TRANSPORT => {
                Attribute::RequestedTransport(self.try_get_transport_protocol()?)
            }
            ATTR_TYPE_DONT_FRAGMENT => Attribute::DontFragment,
            ATTR_TYPE_RESERVATION_TOKEN => self
                .try_get_u64()
                .map(Attribute::ReservationToken)
                .map_err(|_| AttributeError::InvalidAttribute)?,
            ATTR_TYPE_ADDITIONAL_ADDRESS_FAMILY => {
                Attribute::AdditionalAddressFamily(self.try_get_address_family()?)
            }
            ATTR_TYPE_ADDRESS_ERROR_CODE => {
                Attribute::AddressErrorCode(self.try_get_address_error_code()?)
            }
            ATTR_TYPE_ICMP => Attribute::ICMP(self.try_get_icmp()?),
            _ => return Ok(None),
        };

        Ok(Some(res))
    }

    fn try_get_channel_number(&mut self) -> Result<ChannelNumber, AttributeError> {
        let channel_number = self
            .try_get_u32()
            .map_err(|_| AttributeError::InvalidAttribute)?;

        let res = ChannelNumber {
            channel_number: (channel_number >> 16) as u16,
        };

        Ok(res)
    }

    fn try_get_address_family(&mut self) -> Result<AddressFamily, AttributeError> {
        let family = self
            .try_get_u32()
            .map_err(|_| AttributeError::InvalidAttribute)?;

        match family >> 24 {
            0x01 => Ok(AddressFamily::IPv4),
            0x02 => Ok(AddressFamily::IPv6),
            _ => Err(AttributeError::InvalidAttribute),
        }
    }

    fn try_get_even_port(&mut self) -> Result<EvenPort, AttributeError> {
        let value = self
            .try_get_u8()
            .map_err(|_| AttributeError::InvalidAttribute)?;

        let res = EvenPort {
            r: (value & 0x80) != 0,
        };

        Ok(res)
    }

    fn try_get_transport_protocol(&mut self) -> Result<TransportProtocol, AttributeError> {
        let protocol = self
            .try_get_u32()
            .map_err(|_| AttributeError::InvalidAttribute)?;

        match protocol >> 24 {
            17 => Ok(TransportProtocol::UDP),
            _ => Err(AttributeError::InvalidAttribute),
        }
    }

    fn try_get_address_error_code(&mut self) -> Result<AddressErrorCode, AttributeError> {
        let header = self.try_get_address_error_code_header()?;

        let family = match header.family {
            0x01 => AddressFamily::IPv4,
            0x02 => AddressFamily::IPv6,
            _ => return Err(AttributeError::InvalidAttribute),
        };

        if header.number >= 100 {
            return Err(AttributeError::InvalidAttribute);
        }

        let class = (header.class & 7) as u16;
        let number = header.number as u16;

        let code = 100 * class + number;

        let msg = self.try_get_text(self.len())?;

        Ok(AddressErrorCode::new(family, code, msg))
    }

    fn try_get_icmp(&mut self) -> Result<ICMP, AttributeError> {
        let header = self.try_get_icmp_header()?;

        let res = ICMP {
            icmp_type: (header.type_and_code.get() >> 9) as u8,
            icmp_code: header.type_and_code.get() & 0x1ff,
            error_data: header.error_data.get(),
        };

        Ok(res)
    }
}

/// Helper trait for reading TURN attribute values from a byte stream.
trait InternalBytesExt {
    /// Try to get an address error code header from the byte stream.
    fn try_get_address_error_code_header(
        &mut self,
    ) -> Result<AddressErrorCodeHeader, AttributeError>;

    /// Try to get an ICMP header from the byte stream.
    fn try_get_icmp_header(&mut self) -> Result<ICMPHeader, AttributeError>;
}

impl InternalBytesExt for Bytes {
    fn try_get_address_error_code_header(
        &mut self,
    ) -> Result<AddressErrorCodeHeader, AttributeError> {
        let (header, _) = AddressErrorCodeHeader::read_from_prefix(self)
            .map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }

    fn try_get_icmp_header(&mut self) -> Result<ICMPHeader, AttributeError> {
        let (header, _) =
            ICMPHeader::read_from_prefix(self).map_err(|_| AttributeError::InvalidAttribute)?;

        self.advance(std::mem::size_of_val(&header));

        Ok(header)
    }
}

impl SerializeAttribute for ChannelNumber {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        buffer.reserve(8);
        buffer.put_attribute_header(attribute_type, 4);
        buffer.put_u32((self.channel_number as u32) << 16);
    }
}

impl SerializeAttribute for AddressFamily {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        buffer.reserve(8);
        buffer.put_attribute_header(attribute_type, 4);
        buffer.put_u32((*self as u32) << 24);
    }
}

impl SerializeAttribute for EvenPort {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let value = if self.r { 0x80 } else { 0x00 };

        buffer.reserve(8);
        buffer.put_attribute_header(attribute_type, 1);
        buffer.put_u32(value << 24);
    }
}

impl SerializeAttribute for TransportProtocol {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        buffer.reserve(8);
        buffer.put_attribute_header(attribute_type, 4);
        buffer.put_u32((*self as u32) << 24);
    }
}

impl SerializeAttribute for AddressErrorCode {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let family = self.family();
        let code = self.code();
        let msg = self.message();

        let len = 4 + msg.len();

        let padding = (4 - (len & 3)) & 3;

        buffer.reserve(4 + len + padding);
        buffer.put_attribute_header(attribute_type, len as u16);
        buffer.put_address_error_code_header(family, code);
        buffer.extend_from_slice(msg.as_bytes());
        buffer.extend_from_slice(&[0u8; 3][..padding]);
    }
}

impl SerializeAttribute for ICMP {
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut) {
        let len = 8;

        buffer.reserve(4 + len);
        buffer.put_attribute_header(attribute_type, len as u16);
        buffer.put_icmp_header(self.icmp_type, self.icmp_code, self.error_data);
    }
}

/// Helper trait for writing STUN attributes.
trait InternalBytesMutExt {
    /// Put a TURN address error code header into the byte stream.
    fn put_address_error_code_header(&mut self, family: AddressFamily, code: u16);

    /// Put a TURN ICMP header into the byte stream.
    fn put_icmp_header(&mut self, icmp_type: u8, icmp_code: u16, error_data: u32);
}

impl InternalBytesMutExt for BytesMut {
    fn put_address_error_code_header(&mut self, family: AddressFamily, code: u16) {
        let header = AddressErrorCodeHeader {
            family: family as u8,
            padding: 0,
            class: (code / 100) as u8,
            number: (code % 100) as u8,
        };

        self.extend_from_slice(header.as_bytes());
    }

    fn put_icmp_header(&mut self, icmp_type: u8, icmp_code: u16, error_data: u32) {
        let type_and_code = ((icmp_type as u16) << 9) | (icmp_code & 0x1ff);

        let header = ICMPHeader {
            reserved: [0u8; 2],
            type_and_code: U16::new(type_and_code),
            error_data: U32::new(error_data),
        };

        self.extend_from_slice(header.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::{Bytes, BytesMut};

    use crate::attribute::{
        turn::{AddressErrorCode, AddressFamily, ChannelNumber, EvenPort, TransportProtocol, ICMP},
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
    fn test_parse_channel_number() {
        let input = &[0x00, 0x0c, 0x00, 0x04, 0x40, 0x01, 0x00, 0x00];

        let Ok(Attribute::ChannelNumber(cn)) = parse(input, [0u8; 16]) else {
            panic!("expected a channel number");
        };

        assert_eq!(cn.channel_number(), 0x4001);
    }

    #[test]
    fn test_serialize_channel_number() {
        let mut b = BytesMut::new();

        ChannelNumber::new(0x4001).serialize(0x000c, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x0c, 0x00, 0x04]);
        assert_eq!(&b[4..], &[0x40, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_lifetime() {
        let input = &[0x00, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x02, 0x58];

        let Ok(Attribute::Lifetime(lifetime)) = parse(input, [0u8; 16]) else {
            panic!("expected a lifetime");
        };

        assert_eq!(lifetime, 600);
    }

    #[test]
    fn test_parse_xor_peer_address() {
        let tid = u128::to_be_bytes(0x2112a442 << 96);

        let input = &[
            0x00, 0x12, 0x00, 0x08, // attribute header
            0x00, 0x01, // mapped address header
            0xa1, 0x47, // XOR-ed port
            0xe1, 0x12, 0xa6, 0x43, // XOR-ed IP address
        ];

        let Ok(Attribute::XorPeerAddress(addr)) = parse(input, tid) else {
            panic!("expected a XOR peer address");
        };

        assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 32853)));
    }

    #[test]
    fn test_parse_data() {
        let input = &[
            0x00, 0x13, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x01, 0, 0, 0,
        ];

        let Ok(Attribute::Data(data)) = parse(input, [0u8; 16]) else {
            panic!("expected data");
        };

        assert_eq!(&data[..], &[0xde, 0xad, 0xbe, 0xef, 0x01]);
    }

    #[test]
    fn test_parse_xor_relayed_address() {
        let tid = u128::to_be_bytes(0x2112a442 << 96);

        let input = &[
            0x00, 0x16, 0x00, 0x08, // attribute header
            0x00, 0x01, // mapped address header
            0xa1, 0x47, // XOR-ed port
            0xe1, 0x12, 0xa6, 0x43, // XOR-ed IP address
        ];

        let Ok(Attribute::XorRelayedAddress(addr)) = parse(input, tid) else {
            panic!("expected a XOR relayed address");
        };

        assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 32853)));
    }

    #[test]
    fn test_parse_requested_address_family() {
        let input = &[0x00, 0x17, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];

        let Ok(Attribute::RequestedAddressFamily(family)) = parse(input, [0u8; 16]) else {
            panic!("expected a requested address family");
        };

        assert_eq!(family, AddressFamily::IPv4);
    }

    #[test]
    fn test_parse_address_family_invalid() {
        assert!(is_invalid(parse(
            &[0x00, 0x17, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_serialize_address_family() {
        let mut b = BytesMut::new();

        AddressFamily::IPv6.serialize(0x8000, &mut b);

        assert_eq!(&b[..4], &[0x80, 0x00, 0x00, 0x04]);
        assert_eq!(&b[4..], &[0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_even_port() {
        let input = &[0x00, 0x18, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00];

        let Ok(Attribute::EvenPort(even_port)) = parse(input, [0u8; 16]) else {
            panic!("expected an even port");
        };

        assert!(even_port.r());

        let input = &[0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];

        let Ok(Attribute::EvenPort(even_port)) = parse(input, [0u8; 16]) else {
            panic!("expected an even port");
        };

        assert!(!even_port.r());
    }

    #[test]
    fn test_serialize_even_port() {
        let mut b = BytesMut::new();

        EvenPort::new(true).serialize(0x0018, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x18, 0x00, 0x01]);
        assert_eq!(&b[4..], &[0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_requested_transport() {
        let input = &[0x00, 0x19, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00];

        let Ok(Attribute::RequestedTransport(protocol)) = parse(input, [0u8; 16]) else {
            panic!("expected a requested transport");
        };

        assert_eq!(protocol, TransportProtocol::UDP);
    }

    #[test]
    fn test_parse_requested_transport_invalid() {
        assert!(is_invalid(parse(
            &[0x00, 0x19, 0x00, 0x04, 0x06, 0x00, 0x00, 0x00],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_serialize_transport_protocol() {
        let mut b = BytesMut::new();

        TransportProtocol::UDP.serialize(0x0019, &mut b);

        assert_eq!(&b[..4], &[0x00, 0x19, 0x00, 0x04]);
        assert_eq!(&b[4..], &[0x11, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_dont_fragment() {
        let input = &[0x00, 0x1a, 0x00, 0x00];

        let Ok(Attribute::DontFragment) = parse(input, [0u8; 16]) else {
            panic!("expected a don't-fragment");
        };
    }

    #[test]
    fn test_parse_reservation_token() {
        let input = &[0x00, 0x22, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];

        let Ok(Attribute::ReservationToken(token)) = parse(input, [0u8; 16]) else {
            panic!("expected a reservation token");
        };

        assert_eq!(token, 0x0102_0304_0506_0708);
    }

    #[test]
    fn test_parse_additional_address_family() {
        let input = &[0x80, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];

        let Ok(Attribute::AdditionalAddressFamily(family)) = parse(input, [0u8; 16]) else {
            panic!("expected an additional address family");
        };

        assert_eq!(family, AddressFamily::IPv6);
    }

    #[test]
    fn test_parse_address_error_code() {
        let mut input = vec![0x80, 0x01, 0x00, 0x08, 0x01, 0x00, 0x04, 0x28];

        input.extend_from_slice(b"test");

        let Ok(Attribute::AddressErrorCode(aec)) = parse(&input, [0u8; 16]) else {
            panic!("expected an address error code");
        };

        assert_eq!(aec.family(), AddressFamily::IPv4);
        assert_eq!(aec.code(), 440);
        assert_eq!(aec.message(), "test");
    }

    #[test]
    fn test_parse_address_error_code_invalid_number() {
        assert!(is_invalid(parse(
            &[0x80, 0x01, 0x00, 0x04, 0x01, 0x00, 0x04, 100],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_parse_address_error_code_invalid_family() {
        assert!(is_invalid(parse(
            &[0x80, 0x01, 0x00, 0x04, 0x03, 0x00, 0x04, 0x28],
            [0u8; 16]
        )));
    }

    #[test]
    fn test_serialize_address_error_code() {
        let mut b = BytesMut::new();

        AddressErrorCode::new_static(AddressFamily::IPv4, 440, "test").serialize(0x8001, &mut b);

        assert_eq!(&b[..4], &[0x80, 0x01, 0x00, 0x08]);
        assert_eq!(&b[4..8], &[0x01, 0x00, 0x04, 0x28]);
        assert_eq!(&b[8..], b"test");
    }

    #[test]
    fn test_parse_icmp() {
        let input = &[
            0x80, 0x04, 0x00, 0x08, // attribute header
            0x00, 0x00, // reserved
            0x06, 0x04, // ICMP type (3) and code (4)
            0xde, 0xad, 0xbe, 0xef, // error data
        ];

        let Ok(Attribute::ICMP(icmp)) = parse(input, [0u8; 16]) else {
            panic!("expected an ICMP");
        };

        assert_eq!(icmp.icmp_type(), 3);
        assert_eq!(icmp.icmp_code(), 4);
        assert_eq!(icmp.error_data(), 0xdead_beef);
    }

    #[test]
    fn test_serialize_icmp() {
        let mut b = BytesMut::new();

        ICMP::new(3, 4, 0xdead_beef).serialize(0x8004, &mut b);

        assert_eq!(&b[..4], &[0x80, 0x04, 0x00, 0x08]);
        assert_eq!(&b[4..8], &[0x00, 0x00, 0x06, 0x04]);
        assert_eq!(&b[8..], &[0xde, 0xad, 0xbe, 0xef]);
    }
}
