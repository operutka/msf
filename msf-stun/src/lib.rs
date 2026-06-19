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
        Text,
    },
    builder::{MessageBuilder, MessageIntegrityAlgorithm},
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
    Other(u16),
}

impl Method {
    /// Get method from a given message type.
    fn from_message_type(msg_type: u16) -> Self {
        match msg_type & !0xc110 {
            0x0001 => Self::Binding,
            m => Self::Other(m),
        }
    }

    /// Get the message type bits that correspond to this method.
    fn into_message_type(self) -> u16 {
        match self {
            Self::Binding => 0x0001,
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
    /// attributes that we actually weren't able to parse.
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

    /// Check short-term credentials.
    pub fn check_st_credentials(&self, key: &[u8]) -> Result<(), IntegrityError> {
        if let Some(offset) = self.message_integrity_offset {
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
        } else {
            Err(IntegrityError::Missing)
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
