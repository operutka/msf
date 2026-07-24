#![cfg_attr(docsrs, feature(doc_cfg))]

mod attribute;
mod builder;
mod writer;

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use bytes::{Buf, Bytes};
use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;
use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use self::attribute::AttributeError;

pub use self::{
    attribute::{
        Attribute, Attributes, ErrorCode, FullSha256Hash, PasswordAlgorithm, Sha1Hash, Sha256Hash,
        Sha256Length, Text,
    },
    builder::{MessageBuilder, MessageIntegrityAlgorithm},
};

#[cfg(feature = "turn")]
pub use self::attribute::{
    AddressErrorCode, AddressFamily, ChannelNumber, EvenPort, TransportProtocol, ICMP,
};

const RFC_5389_MAGIC_COOKIE: u32 = 0x2112a442;

/// Message class.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum MessageClass {
    Request = 0x0000,
    Indication = 0x0010,
    Success = 0x0100,
    Error = 0x0110,
}

impl MessageClass {
    /// Get message class from a given message type.
    fn from_message_type(msg_type: u16) -> Self {
        match msg_type & 0x0110 {
            0x0000 => Self::Request,
            0x0010 => Self::Indication,
            0x0100 => Self::Success,
            0x0110 => Self::Error,
            _ => unreachable!(),
        }
    }

    /// Get the message type bits that correspond to this message class.
    fn into_message_type(self) -> u16 {
        self as u16
    }
}

/// Method.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Method {
    Binding,
    #[cfg(feature = "turn")]
    Allocate,
    #[cfg(feature = "turn")]
    Refresh,
    #[cfg(feature = "turn")]
    Send,
    #[cfg(feature = "turn")]
    Data,
    #[cfg(feature = "turn")]
    CreatePermission,
    #[cfg(feature = "turn")]
    ChannelBind,
    Other(u16),
}

impl Method {
    /// Get method from a given message type.
    fn from_message_type(msg_type: u16) -> Self {
        match msg_type & !0xc110 {
            0x0001 => Self::Binding,
            #[cfg(feature = "turn")]
            0x0003 => Self::Allocate,
            #[cfg(feature = "turn")]
            0x0004 => Self::Refresh,
            #[cfg(feature = "turn")]
            0x0006 => Self::Send,
            #[cfg(feature = "turn")]
            0x0007 => Self::Data,
            #[cfg(feature = "turn")]
            0x0008 => Self::CreatePermission,
            #[cfg(feature = "turn")]
            0x0009 => Self::ChannelBind,
            m => Self::Other(m),
        }
    }

    /// Get the message type bits that correspond to this method.
    fn into_message_type(self) -> u16 {
        match self {
            Self::Binding => 0x0001,
            #[cfg(feature = "turn")]
            Self::Allocate => 0x0003,
            #[cfg(feature = "turn")]
            Self::Refresh => 0x0004,
            #[cfg(feature = "turn")]
            Self::Send => 0x0006,
            #[cfg(feature = "turn")]
            Self::Data => 0x0007,
            #[cfg(feature = "turn")]
            Self::CreatePermission => 0x0008,
            #[cfg(feature = "turn")]
            Self::ChannelBind => 0x0009,
            Self::Other(m) => m & !0xc110,
        }
    }
}

/// Transaction ID.
type TransactionID = [u8; 12];

/// Invalid message header error.
struct InvalidMessageHeader;

/// Message header.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
struct MessageHeader {
    message_type: U16,
    message_length: U16,
    magic_cookie: U32,
    transaction_id: TransactionID,
}

impl MessageHeader {
    /// Consume message header from a given buffer and parse it.
    fn from_bytes(data: &mut Bytes) -> Result<Self, InvalidMessageHeader> {
        let res = Self::read_from_prefix(data)
            .ok()
            .map(|(h, _)| h)
            .filter(|h| (h.message_type.get() & 0xc000) == 0)
            .ok_or(InvalidMessageHeader)?;

        data.advance(std::mem::size_of_val(&res));

        Ok(res)
    }

    /// Get the message class.
    fn message_class(&self) -> MessageClass {
        MessageClass::from_message_type(self.message_type.get())
    }

    /// Get the method.
    fn method(&self) -> Method {
        Method::from_message_type(self.message_type.get())
    }
}

/// Invalid message.
#[derive(Debug, Copy, Clone)]
pub enum InvalidMessage {
    InvalidHeader,
    InvalidAttribute,
}

impl Display for InvalidMessage {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let msg = match self {
            Self::InvalidHeader => "invalid header",
            Self::InvalidAttribute => "invalid attribute",
        };

        f.write_str(msg)
    }
}

impl Error for InvalidMessage {}

impl From<InvalidMessageHeader> for InvalidMessage {
    #[inline]
    fn from(_: InvalidMessageHeader) -> Self {
        Self::InvalidHeader
    }
}

/// Message integrity error.
#[derive(Debug, Copy, Clone)]
pub enum IntegrityError {
    Missing,
    Invalid,
}

impl Display for IntegrityError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let msg = match self {
            IntegrityError::Missing => "missing message integrity",
            IntegrityError::Invalid => "invalid message integrity",
        };

        f.write_str(msg)
    }
}

impl Error for IntegrityError {}

/// STUN message.
#[derive(Clone)]
pub struct Message {
    original: Bytes,
    class: MessageClass,
    method: Method,
    magic_cookie: u32,
    transaction_id: TransactionID,
    attributes: Attributes,
    unknown_attributes: Vec<u16>,
    message_integrity_offset: Option<usize>,
    message_integrity_sha256_offset: Option<usize>,
    fingerprint_offset: Option<usize>,
}

impl Message {
    /// Parse a STUN message from a given frame.
    pub fn from_frame(mut frame: Bytes) -> Result<Self, InvalidMessage> {
        let mut original = frame.clone();

        let header = MessageHeader::from_bytes(&mut frame)?;

        let len = header.message_length.get() as usize;

        if (len & 3) != 0 || frame.len() < len {
            return Err(InvalidMessage::InvalidHeader);
        }

        let mut res = Self {
            original: original.split_to(20 + len),
            class: header.message_class(),
            method: header.method(),
            magic_cookie: header.magic_cookie.get(),
            transaction_id: header.transaction_id,
            attributes: Attributes::empty(),
            unknown_attributes: Vec::new(),
            message_integrity_offset: None,
            message_integrity_sha256_offset: None,
            fingerprint_offset: None,
        };

        res.read_attributes()?;

        Ok(res)
    }

    /// Parse message attributes.
    fn read_attributes(&mut self) -> Result<(), InvalidMessage> {
        let mut attributes = Vec::new();

        let len = self.original.len();

        let mut body = self.original.slice(20..);

        while !body.is_empty() {
            let offset = len - body.len();

            match Attribute::from_bytes(&mut body, self.long_transaction_id()) {
                Ok(Attribute::Fingerprint(crc)) => {
                    attributes.push(Attribute::Fingerprint(crc));

                    if self.fingerprint_offset.is_none() {
                        self.fingerprint_offset = Some(offset);
                    }
                }
                Ok(Attribute::MessageIntegrity(hash)) => {
                    attributes.push(Attribute::MessageIntegrity(hash));

                    if self.message_integrity_offset.is_none() {
                        self.message_integrity_offset = Some(offset);
                    }
                }
                Ok(Attribute::MessageIntegritySha256(hash)) => {
                    attributes.push(Attribute::MessageIntegritySha256(hash));

                    if self.message_integrity_sha256_offset.is_none() {
                        self.message_integrity_sha256_offset = Some(offset);
                    }
                }
                Ok(attr) => {
                    // attributes received after message integrity must be
                    // ignored (only fingerprint is allowed)
                    if self.message_integrity_offset.is_none()
                        && self.message_integrity_sha256_offset.is_none()
                    {
                        attributes.push(attr);
                    }
                }
                Err(AttributeError::InvalidAttribute) => {
                    return Err(InvalidMessage::InvalidAttribute);
                }
                Err(AttributeError::UnknownAttribute(attr_type)) => {
                    if (attr_type & 0x8000) == 0 {
                        self.unknown_attributes.push(attr_type);
                    }
                }
            }
        }

        self.attributes = Attributes::new(attributes);

        Ok(())
    }

    /// Check if this is a STUN message as defined in RFC 5389.
    #[inline]
    pub fn is_rfc5389_message(&self) -> bool {
        self.magic_cookie == RFC_5389_MAGIC_COOKIE
    }

    /// Check if this is a STUN request.
    #[inline]
    pub fn is_request(&self) -> bool {
        matches!(self.class, MessageClass::Request)
    }

    /// Check if this is a STUN response.
    #[inline]
    pub fn is_response(&self) -> bool {
        matches!(self.class, MessageClass::Success | MessageClass::Error)
    }

    /// Get the message class.
    #[inline]
    pub fn class(&self) -> MessageClass {
        self.class
    }

    /// Get the STUN method.
    #[inline]
    pub fn method(&self) -> Method {
        self.method
    }

    /// Get value of the magic cookie as defined in RFC 5389.
    #[inline]
    pub fn magic_cookie(&self) -> u32 {
        self.magic_cookie
    }

    /// Get the transaction ID as defined in RFC 5389.
    #[inline]
    pub fn transaction_id(&self) -> [u8; 12] {
        self.transaction_id
    }

    /// Get the transaction ID as defined in RFC 3489.
    #[inline]
    pub fn long_transaction_id(&self) -> [u8; 16] {
        let mut res = [0u8; 16];

        res[..4].copy_from_slice(&self.magic_cookie.to_be_bytes());
        res[4..].copy_from_slice(&self.transaction_id);

        res
    }

    /// Get message attributes.
    #[inline]
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// Get types of unknown attributes.
    ///
    /// # Note
    /// This is not a value of the unknown attributes attribute. These are the
    /// unkown, comprehension-required attributes that we actually weren't able
    /// to parse.
    #[inline]
    pub fn unknown_attributes(&self) -> &[u16] {
        &self.unknown_attributes
    }

    /// Check the message fingerprint.
    ///
    /// The method return `true` only if the fingerprint attribute exists and
    /// the value of the fingerprint is correct.
    pub fn check_fingerprint(&self) -> bool {
        if let Some(offset) = self.fingerprint_offset {
            let fingerprint = self
                .attributes
                .iter()
                .find_map(|attr| match attr {
                    Attribute::Fingerprint(crc) => Some(crc),
                    _ => None,
                })
                .copied()
                .unwrap();

            fingerprint == calculate_fingerprint(&self.original[..offset])
        } else {
            false
        }
    }

    /// Check the message integrity.
    ///
    /// The method will return `Ok(())` if the message integrity attribute
    /// exists and the value of the message integrity is correct.
    pub fn check_message_integrity(&self, key: &[u8]) -> Result<(), IntegrityError> {
        let offset = self
            .message_integrity_offset
            .ok_or(IntegrityError::Missing)?;

        let hash = self
            .attributes
            .iter()
            .find_map(|attr| match attr {
                Attribute::MessageIntegrity(hash) => Some(hash),
                _ => None,
            })
            .copied()
            .unwrap();

        if hash == calculate_message_integrity(key, &self.original[..offset]) {
            Ok(())
        } else {
            Err(IntegrityError::Invalid)
        }
    }

    /// Check the SHA-256 message integrity.
    ///
    /// The method will return `Ok(())` if the SHA-256 message integrity
    /// attribute exists and the value of the message integrity is correct. The
    /// `min_hash_size` parameter specifies the minimum number of bytes that
    /// the hash in the message integrity attribute must have. If the hash is
    /// shorter than the specified length, the method will return
    /// `IntegrityError::Invalid`.
    pub fn check_message_integrity_sha256(
        &self,
        key: &[u8],
        min_hash_size: Sha256Length,
    ) -> Result<(), IntegrityError> {
        let offset = self
            .message_integrity_sha256_offset
            .ok_or(IntegrityError::Missing)?;

        let actual = self
            .attributes
            .iter()
            .find_map(|attr| match attr {
                Attribute::MessageIntegritySha256(hash) => Some(hash.as_ref()),
                _ => None,
            })
            .filter(|hash| hash.len() >= (min_hash_size as usize))
            .ok_or(IntegrityError::Invalid)?;

        let expected = calculate_message_integrity_sha256(key, &self.original[..offset]);

        if &expected[..actual.len()] == actual {
            Ok(())
        } else {
            Err(IntegrityError::Invalid)
        }
    }
}

/// Take the message header bytes from a given STUN message.
fn take_message_header(msg: &[u8]) -> [u8; 20] {
    assert!(msg.len() >= 20);

    let mut header = [0u8; 20];

    header.copy_from_slice(&msg[..20]);
    header
}

/// Set message length to a given STUN message.
fn set_message_length(msg: &mut [u8], len: u16) {
    assert!(msg.len() >= 20);

    msg[2] = (len >> 8) as u8;
    msg[3] = (len & 0xff) as u8;
}

/// Calculate message integrity of a given STUN message.
fn calculate_message_integrity(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut header = take_message_header(msg);

    let len = msg.len() - 20 + 24;

    set_message_length(&mut header, len as u16);

    let mut hmac = Hmac::<Sha1>::new_from_slice(key).expect("unable to initialize HMAC-SHA1");

    hmac.update(&header);
    hmac.update(&msg[20..]);

    let hash = hmac.finalize().into_bytes();

    hash.into()
}

/// Calculate message integrity of a given STUN message.
fn calculate_message_integrity_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut header = take_message_header(msg);

    let len = msg.len() - 20 + 36;

    set_message_length(&mut header, len as u16);

    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("unable to initialize HMAC-SHA256");

    hmac.update(&header);
    hmac.update(&msg[20..]);

    let hash = hmac.finalize().into_bytes();

    hash.into()
}

/// Calculate fingerprint of a given stun message.
fn calculate_fingerprint(msg: &[u8]) -> u32 {
    let mut header = take_message_header(msg);

    let len = msg.len() - 20 + 8;

    set_message_length(&mut header, len as u16);

    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);

    let mut digest = crc.digest();

    digest.update(&header);
    digest.update(&msg[20..]);

    digest.finalize() ^ 0x5354554e
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        builder::{MessageBuilder, MessageIntegrityAlgorithm},
        IntegrityError, InvalidMessage, Message, MessageClass, Method, Sha256Length,
        RFC_5389_MAGIC_COOKIE,
    };

    /// Assemble a raw STUN frame from a message type and a body of attributes.
    fn frame(message_type: u16, magic_cookie: u32, tid: [u8; 12], attrs: &[u8]) -> Bytes {
        let mut buf = Vec::with_capacity(20 + attrs.len());

        buf.extend_from_slice(&message_type.to_be_bytes());
        buf.extend_from_slice(&u16::to_be_bytes(attrs.len() as u16));
        buf.extend_from_slice(&magic_cookie.to_be_bytes());
        buf.extend_from_slice(&tid);
        buf.extend_from_slice(attrs);

        Bytes::from(buf)
    }

    #[test]
    fn test_message_class_round_trip() {
        let classes = [
            MessageClass::Request,
            MessageClass::Indication,
            MessageClass::Success,
            MessageClass::Error,
        ];

        for class in classes {
            let bits = class.into_message_type();

            let mc = MessageClass::from_message_type(bits);

            assert_eq!(mc, class);
        }
    }

    #[test]
    fn test_reject_non_stun_message() {
        // the two most significant bits of the message type must be zero
        let res = Message::from_frame(frame(0x8001, RFC_5389_MAGIC_COOKIE, [0u8; 12], &[]));

        assert!(matches!(res, Err(InvalidMessage::InvalidHeader)));
    }

    #[test]
    fn test_reject_unaligned_length() {
        let mut buf = vec![0x00, 0x01, 0x00, 0x05];

        buf.extend_from_slice(&u32::to_be_bytes(RFC_5389_MAGIC_COOKIE));
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&[0u8; 8]);

        let res = Message::from_frame(Bytes::from(buf));

        assert!(matches!(res, Err(InvalidMessage::InvalidHeader)));
    }

    #[test]
    fn test_reject_truncated_body() {
        let mut buf = vec![0x00, 0x01, 0x00, 0x08];

        buf.extend_from_slice(&u32::to_be_bytes(RFC_5389_MAGIC_COOKIE));
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&[0u8; 4]);

        let res = Message::from_frame(Bytes::from(buf));

        assert!(matches!(res, Err(InvalidMessage::InvalidHeader)));
    }

    #[test]
    fn test_reject_short_frame() {
        let res = Message::from_frame(Bytes::from_static(&[0, 1, 0, 0]));

        assert!(matches!(res, Err(InvalidMessage::InvalidHeader)));
    }

    #[test]
    fn test_parse_binding_request() {
        let msg = Message::from_frame(frame(0x0001, RFC_5389_MAGIC_COOKIE, [5u8; 12], &[]))
            .expect("message expected");

        assert!(msg.is_request());
        assert!(!msg.is_response());
        assert!(msg.is_rfc5389_message());

        assert_eq!(msg.class(), MessageClass::Request);
        assert_eq!(msg.method(), Method::Binding);
        assert_eq!(msg.magic_cookie(), RFC_5389_MAGIC_COOKIE);
        assert_eq!(msg.transaction_id(), [5u8; 12]);
    }

    #[test]
    fn test_unknown_comprehension_required_collected() {
        // 0x7000 is comprehension-required, 0x9000 is comprehension-optional
        let attrs = [0x70, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00];

        let msg = Message::from_frame(frame(0x0001, RFC_5389_MAGIC_COOKIE, [0u8; 12], &attrs))
            .expect("message expected");

        let attrs = msg.attributes();

        assert!(attrs.is_empty());

        assert_eq!(msg.unknown_attributes(), &[0x7000]);
    }

    #[test]
    fn test_attributes_after_integrity_ignored() {
        let mut attrs = Vec::new();

        // USERNAME "user" before MESSAGE-INTEGRITY -> kept
        attrs.extend_from_slice(&[0x00, 0x06, 0x00, 0x04]);
        attrs.extend_from_slice(b"user");
        // MESSAGE-INTEGRITY (arbitrary hash)
        attrs.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        attrs.extend_from_slice(&[0xaa; 20]);
        // SOFTWARE after MESSAGE-INTEGRITY -> ignored
        attrs.extend_from_slice(&[0x80, 0x22, 0x00, 0x01, b'x', 0, 0, 0]);

        let msg = Message::from_frame(frame(0x0001, RFC_5389_MAGIC_COOKIE, [0u8; 12], &attrs))
            .expect("message expected");

        let attrs = msg.attributes();

        assert_eq!(attrs.get_username(), Some("user"));
        assert_eq!(attrs.get_software(), None);
    }

    #[test]
    fn test_fingerprint_round_trip() {
        let msg = MessageBuilder::binding_request([1u8; 12])
            .software("msf")
            .fingerprint(true)
            .build();

        let msg = Message::from_frame(msg).expect("message expected");

        assert!(msg.check_fingerprint());
    }

    #[test]
    fn test_message_integrity_round_trip() {
        let key = b"key";

        let msg = MessageBuilder::binding_request([1u8; 12])
            .username("u")
            .message_integrity_key(key)
            .message_integrity_algorithm(MessageIntegrityAlgorithm::Sha1)
            .build();

        let msg = Message::from_frame(msg).expect("message expected");

        assert!(msg.check_message_integrity(key).is_ok());
        assert!(matches!(
            msg.check_message_integrity_sha256(key, Sha256Length::Full),
            Err(IntegrityError::Missing)
        ));
    }

    #[test]
    fn test_message_integrity_sha256_round_trip() {
        let key = b"key";

        let msg = MessageBuilder::binding_request([1u8; 12])
            .username("u")
            .message_integrity_key(key)
            .message_integrity_algorithm(MessageIntegrityAlgorithm::Sha256)
            .build();

        let msg = Message::from_frame(msg).expect("message expected");

        assert!(matches!(
            msg.check_message_integrity(key),
            Err(IntegrityError::Missing)
        ));

        assert!(msg
            .check_message_integrity_sha256(key, Sha256Length::Full)
            .is_ok());
    }

    #[test]
    fn test_message_integrity_unknown_round_trip() {
        let key = b"key";

        let msg = MessageBuilder::binding_request([1u8; 12])
            .username("u")
            .message_integrity_key(key)
            .message_integrity_algorithm(MessageIntegrityAlgorithm::Unknown)
            .build();

        let msg = Message::from_frame(msg).expect("message expected");

        assert!(msg.check_message_integrity(key).is_ok());
        assert!(msg
            .check_message_integrity_sha256(key, Sha256Length::Full)
            .is_ok());
    }

    #[test]
    fn test_check_message_integrity_missing() {
        let key = b"key";

        let msg = Message::from_frame(frame(0x0001, RFC_5389_MAGIC_COOKIE, [0u8; 12], &[]))
            .expect("message expected");

        assert!(matches!(
            msg.check_message_integrity(key),
            Err(IntegrityError::Missing)
        ));

        assert!(matches!(
            msg.check_message_integrity_sha256(key, Sha256Length::Full),
            Err(IntegrityError::Missing)
        ));
    }

    #[test]
    fn test_set_message_length() {
        let mut buf = [0u8; 20];

        super::set_message_length(&mut buf, 0x1234);

        assert_eq!(buf[2], 0x12);
        assert_eq!(buf[3], 0x34);
    }

    #[test]
    fn test_take_message_header() {
        let mut data = vec![0u8; 24];

        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }

        let header = super::take_message_header(&data);

        assert_eq!(header.len(), 20);
        assert_eq!(&header[..], &data[..20]);
    }
}
