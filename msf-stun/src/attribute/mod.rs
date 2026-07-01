mod collection;

pub mod common;

#[cfg(feature = "ice")]
pub mod ice;

#[cfg(feature = "turn")]
pub mod turn;

use std::net::SocketAddr;

use bytes::{Buf, Bytes, BytesMut};
use zerocopy::{network_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use self::common::BytesExt as _;

#[cfg(feature = "ice")]
use self::ice::BytesExt as _;

#[cfg(feature = "turn")]
use self::turn::BytesExt as _;

pub use self::{
    collection::Attributes,
    common::{
        ErrorCode, FullSha256Hash, PasswordAlgorithm, Sha1Hash, Sha256Hash, Sha256Length, Text,
    },
};

#[cfg(feature = "turn")]
pub use self::turn::{
    AddressErrorCode, AddressFamily, ChannelNumber, EvenPort, TransportProtocol, ICMP,
};

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

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    ChannelNumber(ChannelNumber),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    Lifetime(u32),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    XorPeerAddress(SocketAddr),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    Data(Bytes),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    XorRelayedAddress(SocketAddr),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    RequestedAddressFamily(AddressFamily),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    EvenPort(EvenPort),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    RequestedTransport(TransportProtocol),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    DontFragment,

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    ReservationToken(u64),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    AdditionalAddressFamily(AddressFamily),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    AddressErrorCode(AddressErrorCode),

    #[cfg(feature = "turn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "turn")))]
    ICMP(ICMP),
}

impl Attribute {
    /// Consume the next attribute from a given buffer.
    pub(crate) fn from_bytes(
        data: &mut Bytes,
        long_transaction_id: [u8; 16],
    ) -> Result<Self, AttributeError> {
        data.try_get_attribute(long_transaction_id)
    }
}

/// Trait for types that can be serialized as STUN attributes.
pub trait SerializeAttribute {
    /// Serialize the value as a STUN attribute with a given type into the
    /// provided buffer.
    fn serialize(&self, attribute_type: u16, buffer: &mut BytesMut);
}

/// Helper trait for writing STUN attributes.
trait InternalBytesMutExt {
    /// Put a STUN attribute header into the byte stream.
    fn put_attribute_header(&mut self, attribute_type: u16, attribute_length: u16);
}

impl InternalBytesMutExt for BytesMut {
    fn put_attribute_header(&mut self, attribute_type: u16, attribute_length: u16) {
        let header = AttributeHeader {
            attribute_type: U16::new(attribute_type),
            attribute_length: U16::new(attribute_length),
        };

        self.extend_from_slice(header.as_bytes());
    }
}

/// Helper trait for reading STUN attributes.
trait InternalBytesExt {
    /// Try to get a STUN attribute from the byte stream.
    fn try_get_attribute(
        &mut self,
        long_transaction_id: [u8; 16],
    ) -> Result<Attribute, AttributeError>;

    /// Try to get a STUN attribute header from the byte stream.
    fn try_get_attribute_header(&mut self) -> Result<AttributeHeader, AttributeError>;
}

impl InternalBytesExt for Bytes {
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

        let at = header.attribute_type.get();

        #[allow(unused_mut)]
        let mut res = value.try_get_common_attribute_value(at, long_transaction_id)?;

        #[cfg(feature = "ice")]
        if res.is_none() {
            res = value.try_get_ice_attribute_value(at)?;
        }

        #[cfg(feature = "turn")]
        if res.is_none() {
            res = value.try_get_turn_attribute_value(at, long_transaction_id)?;
        }

        let res = res.ok_or(AttributeError::UnknownAttribute(at))?;

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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use zerocopy::network_endian::U16;

    use super::{Attribute, AttributeError, AttributeHeader};

    /// Parse a single attribute from a raw attribute slice.
    fn parse(bytes: &[u8], long_transaction_id: [u8; 16]) -> Result<Attribute, AttributeError> {
        Attribute::from_bytes(&mut Bytes::copy_from_slice(bytes), long_transaction_id)
    }

    /// Check whether a result is the `InvalidAttribute` error.
    fn is_invalid(res: Result<Attribute, AttributeError>) -> bool {
        matches!(res, Err(AttributeError::InvalidAttribute))
    }

    #[test]
    fn test_attribute_header_lengths() {
        let cases: [(u16, usize, usize); _] = [
            (0, 0, 0),
            (1, 1, 4),
            (2, 2, 4),
            (3, 3, 4),
            (4, 4, 4),
            (5, 5, 8),
            (20, 20, 20),
            (21, 21, 24),
        ];

        for (len, value_len, padded) in cases {
            let header = AttributeHeader {
                attribute_type: U16::new(0),
                attribute_length: U16::new(len),
            };

            assert_eq!(header.value_length(), value_len);
            assert_eq!(header.padded_value_length(), padded);
        }
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
}
