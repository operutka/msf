#![cfg_attr(docsrs, feature(doc_cfg))]

mod attribute;
mod writer;

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

use bytes::{Buf, Bytes, BytesMut};
use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, Immutable, KnownLayout, Unaligned,
};

use self::{attribute::AttributeError, writer::MessageBuffer};

pub use self::attribute::{Attribute, Attributes, ErrorCode, Text};

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
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
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
            match Attribute::from_bytes(&mut body, self.long_transaction_id()) {
                Ok(Attribute::Fingerprint(crc)) => {
                    attributes.push(Attribute::Fingerprint(crc));

                    self.fingerprint_offset = Some(len - body.len() - 8);
                }
                Ok(Attribute::MessageIntegrity(hash)) => {
                    attributes.push(Attribute::MessageIntegrity(hash));

                    self.message_integrity_offset = Some(len - body.len() - 24);
                }
                Ok(attr) => {
                    // attributes received after message integrity must be
                    // ignored (only fingerprint is allowed)
                    if self.message_integrity_offset.is_none() {
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

/// STUN message builder.
pub struct MessageBuilder {
    class: MessageClass,
    method: Method,
    magic_cookie: u32,
    transaction_id: TransactionID,

    mapped_address: Option<SocketAddr>,
    xor_mapped_address: Option<SocketAddr>,
    username: Option<String>,
    message_integrity: Option<Vec<u8>>,
    fingerprint: bool,
    error_code: Option<ErrorCode>,
    realm: Option<String>,
    nonce: Option<String>,
    unknown_attributes: Option<Vec<u16>>,
    software: Option<String>,
    alternate_server: Option<SocketAddr>,

    #[cfg(feature = "ice")]
    priority: Option<u32>,

    #[cfg(feature = "ice")]
    use_candidate: bool,

    #[cfg(feature = "ice")]
    ice_controlled: Option<u64>,

    #[cfg(feature = "ice")]
    ice_controlling: Option<u64>,
}

impl MessageBuilder {
    /// Create a new message builder.
    #[inline]
    const fn new_internal(
        class: MessageClass,
        method: Method,
        magic_cookie: u32,
        transaction_id: [u8; 12],
        error_code: Option<ErrorCode>,
    ) -> Self {
        Self {
            class,
            method,
            magic_cookie,
            transaction_id,

            mapped_address: None,
            xor_mapped_address: None,
            username: None,
            message_integrity: None,
            fingerprint: false,
            error_code,
            realm: None,
            nonce: None,
            unknown_attributes: None,
            software: None,
            alternate_server: None,

            #[cfg(feature = "ice")]
            priority: None,

            #[cfg(feature = "ice")]
            use_candidate: false,

            #[cfg(feature = "ice")]
            ice_controlled: None,

            #[cfg(feature = "ice")]
            ice_controlling: None,
        }
    }

    /// Create a new message builder.
    #[inline]
    pub const fn new(class: MessageClass, method: Method, transaction_id: [u8; 12]) -> Self {
        Self::new_internal(class, method, RFC_5389_MAGIC_COOKIE, transaction_id, None)
    }

    /// Create a new message builder for a STUN binding request.
    #[inline]
    pub const fn binding_request(transaction_id: [u8; 12]) -> Self {
        Self::new_internal(
            MessageClass::Request,
            Method::Binding,
            RFC_5389_MAGIC_COOKIE,
            transaction_id,
            None,
        )
    }

    /// Create a new message builder for a STUN response.
    #[inline]
    pub const fn response(class: MessageClass, request: &Message) -> Self {
        Self::new_internal(
            class,
            request.method,
            request.magic_cookie,
            request.transaction_id,
            None,
        )
    }

    /// Create a new message builder for a success STUN response.
    #[inline]
    pub const fn success_response(request: &Message) -> Self {
        Self::new_internal(
            MessageClass::Success,
            request.method,
            request.magic_cookie,
            request.transaction_id,
            None,
        )
    }

    /// Create a new message builder for an error STUN response.
    #[inline]
    pub const fn error_response(request: &Message, error_code: ErrorCode) -> Self {
        Self::new_internal(
            MessageClass::Error,
            request.method,
            request.magic_cookie,
            request.transaction_id,
            Some(error_code),
        )
    }

    /// Set message class.
    #[inline]
    pub fn class(&mut self, class: MessageClass) -> &mut Self {
        self.class = class;
        self
    }

    /// Set STUN method.
    #[inline]
    pub fn method(&mut self, method: Method) -> &mut Self {
        self.method = method;
        self
    }

    /// Set magic cookie as defined in RFC 5389.
    #[inline]
    pub fn magic_cookie(&mut self, cookie: u32) -> &mut Self {
        self.magic_cookie = cookie;
        self
    }

    /// Set transaction ID as defined in RFC 5389.
    #[inline]
    pub fn transaction_id(&mut self, transaction_id: [u8; 12]) -> &mut Self {
        self.transaction_id = transaction_id;
        self
    }

    /// Set transaction ID as defined in RFC 3489.
    #[inline]
    pub fn long_transaction_id(&mut self, transaction_id: [u8; 16]) -> &mut Self {
        let mut magic_cookie = [0u8; 4];
        let mut short_id = [0u8; 12];

        magic_cookie.copy_from_slice(&transaction_id[..4]);
        short_id.copy_from_slice(&transaction_id[4..]);

        self.magic_cookie = u32::from_be_bytes(magic_cookie);
        self.transaction_id = short_id;

        self
    }

    /// Set mapped address.
    #[inline]
    pub fn mapped_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.mapped_address = Some(addr);
        self
    }

    /// Set XOR mapped address.
    #[inline]
    pub fn xor_mapped_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.xor_mapped_address = Some(addr);
        self
    }

    /// Set username.
    pub fn username<T>(&mut self, username: T) -> &mut Self
    where
        T: Into<String>,
    {
        self.username = Some(username.into());
        self
    }

    /// Enable message integrity and use a given key.
    pub fn message_integrity<T>(&mut self, key: T) -> &mut Self
    where
        T: Into<Vec<u8>>,
    {
        self.message_integrity = Some(key.into());
        self
    }

    /// Enable or disable message fingerprint.
    #[inline]
    pub fn fingerprint(&mut self, enable: bool) -> &mut Self {
        self.fingerprint = enable;
        self
    }

    /// Set error code.
    #[inline]
    pub fn error_code(&mut self, error_code: ErrorCode) -> &mut Self {
        self.error_code = Some(error_code);
        self
    }

    /// Set realm.
    pub fn realm<T>(&mut self, realm: T) -> &mut Self
    where
        T: Into<String>,
    {
        self.realm = Some(realm.into());
        self
    }

    /// Set nonce.
    pub fn nonce<T>(&mut self, nonce: T) -> &mut Self
    where
        T: Into<String>,
    {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set unknown attributes.
    pub fn unknown_attributes<T>(&mut self, unknown_attributes: T) -> &mut Self
    where
        T: Into<Vec<u16>>,
    {
        self.unknown_attributes = Some(unknown_attributes.into());
        self
    }

    /// Set software.
    pub fn software<T>(&mut self, software: T) -> &mut Self
    where
        T: Into<String>,
    {
        self.software = Some(software.into());
        self
    }

    /// Set alternate server.
    #[inline]
    pub fn alternate_server(&mut self, server: SocketAddr) -> &mut Self {
        self.alternate_server = Some(server);
        self
    }

    /// Set ICE candidate priority.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn priority(&mut self, priority: u32) -> &mut Self {
        self.priority = Some(priority);
        self
    }

    /// Set the use candidate ICE flag.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn use_candidate(&mut self, enable: bool) -> &mut Self {
        self.use_candidate = enable;
        self
    }

    /// Set the ICE controlled attribute.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn ice_controlled(&mut self, n: u64) -> &mut Self {
        self.ice_controlled = Some(n);
        self
    }

    /// Set the ICE controlling attribute.
    #[cfg(feature = "ice")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ice")))]
    #[inline]
    pub fn ice_controlling(&mut self, n: u64) -> &mut Self {
        self.ice_controlling = Some(n);
        self
    }

    /// Serialize the message into a given buffer.
    pub fn serialize(&self, buffer: &mut BytesMut) {
        let mut buffer = MessageBuffer::new(buffer);

        // create a buffer with an empty header
        let mut writer = buffer.create_message(
            self.class,
            self.method,
            self.magic_cookie,
            self.transaction_id,
        );

        if let Some(status) = self.error_code.as_ref() {
            writer.put_error_code(status);
        }

        if let Some(attributes) = self.unknown_attributes.as_ref() {
            writer.put_unknown_attributes(attributes);
        }

        if let Some(alternate_server) = self.alternate_server {
            writer.put_alternate_server(alternate_server);
        }

        if let Some(addr) = self.mapped_address {
            writer.put_mapped_address(addr);
        }

        if let Some(addr) = self.xor_mapped_address {
            writer.put_xor_mapped_address(addr);
        }

        if let Some(username) = self.username.as_deref() {
            writer.put_username(username);
        }

        if let Some(realm) = self.realm.as_deref() {
            writer.put_realm(realm);
        }

        if let Some(nonce) = self.nonce.as_deref() {
            writer.put_nonce(nonce);
        }

        if let Some(software) = self.software.as_deref() {
            writer.put_software(software);
        }

        #[cfg(feature = "ice")]
        {
            if let Some(priority) = self.priority {
                writer.put_priority(priority);
            }

            if self.use_candidate {
                writer.put_use_candidate();
            }

            if let Some(n) = self.ice_controlled {
                writer.put_ice_controlled(n);
            }

            if let Some(n) = self.ice_controlling {
                writer.put_ice_controlling(n);
            }
        }

        if let Some(key) = self.message_integrity.as_ref() {
            writer.put_message_integrity(key);
        }

        if self.fingerprint {
            writer.put_fingerprint();
        }

        writer.finalize();
    }

    /// Finalize the message and return it as `Bytes`.
    pub fn build(&self) -> Bytes {
        let mut res = BytesMut::new();

        self.serialize(&mut res);

        res.freeze()
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

    assert_eq!(hash.len(), 20);

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
