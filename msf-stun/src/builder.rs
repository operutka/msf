use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};

use crate::{
    attribute::{ErrorCode, FullSha256Hash, PasswordAlgorithm},
    writer::MessageBuffer,
    Message, MessageClass, Method, TransactionID, RFC_5389_MAGIC_COOKIE,
};

/// Message integrity algorithm choice.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MessageIntegrityAlgorithm {
    Unknown,
    Sha1,
    Sha256,
}

/// STUN message builder.
pub struct MessageBuilder<'a> {
    class: MessageClass,
    method: Method,
    magic_cookie: u32,
    transaction_id: TransactionID,

    mapped_address: Option<SocketAddr>,
    xor_mapped_address: Option<SocketAddr>,
    username: Option<&'a str>,
    userhash: Option<[u8; 32]>,
    message_integrity_key: Option<&'a [u8]>,
    message_integrity_algorithm: MessageIntegrityAlgorithm,
    fingerprint: bool,
    error_code: Option<ErrorCode>,
    realm: Option<&'a str>,
    nonce: Option<&'a str>,
    password_algorithms: Option<&'a [PasswordAlgorithm]>,
    password_algorithm: Option<PasswordAlgorithm>,
    unknown_attributes: Option<&'a [u16]>,
    software: Option<&'a str>,
    alternate_server: Option<SocketAddr>,
    alternate_domain: Option<&'a str>,

    #[cfg(feature = "ice")]
    priority: Option<u32>,

    #[cfg(feature = "ice")]
    use_candidate: bool,

    #[cfg(feature = "ice")]
    ice_controlled: Option<u64>,

    #[cfg(feature = "ice")]
    ice_controlling: Option<u64>,
}

impl<'a> MessageBuilder<'a> {
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
            userhash: None,
            message_integrity_key: None,
            message_integrity_algorithm: MessageIntegrityAlgorithm::Unknown,
            fingerprint: false,
            error_code,
            realm: None,
            nonce: None,
            password_algorithms: None,
            password_algorithm: None,
            unknown_attributes: None,
            software: None,
            alternate_server: None,
            alternate_domain: None,

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
    #[inline]
    pub fn username(&mut self, username: &'a str) -> &mut Self {
        self.username = Some(username);
        self
    }

    /// Set userhash.
    #[inline]
    pub fn userhash(&mut self, userhash: FullSha256Hash) -> &mut Self {
        self.userhash = Some(userhash);
        self
    }

    /// Enable message integrity and use a given key.
    #[inline]
    pub fn message_integrity_key(&mut self, key: &'a [u8]) -> &mut Self {
        self.message_integrity_key = Some(key);
        self
    }

    /// Configure the message integrity algorithm.
    #[inline]
    pub fn message_integrity_algorithm(
        &mut self,
        algorithm: MessageIntegrityAlgorithm,
    ) -> &mut Self {
        self.message_integrity_algorithm = algorithm;
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
    #[inline]
    pub fn realm(&mut self, realm: &'a str) -> &mut Self {
        self.realm = Some(realm);
        self
    }

    /// Set nonce.
    #[inline]
    pub fn nonce(&mut self, nonce: &'a str) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set password algorithms.
    #[inline]
    pub fn password_algorithms(&mut self, algorithms: &'a [PasswordAlgorithm]) -> &mut Self {
        self.password_algorithms = Some(algorithms);
        self
    }

    /// Set password algorithm.
    #[inline]
    pub fn password_algorithm(&mut self, algorithm: PasswordAlgorithm) -> &mut Self {
        self.password_algorithm = Some(algorithm);
        self
    }

    /// Set unknown attributes.
    #[inline]
    pub fn unknown_attributes(&mut self, unknown_attributes: &'a [u16]) -> &mut Self {
        self.unknown_attributes = Some(unknown_attributes);
        self
    }

    /// Set software.
    #[inline]
    pub fn software(&mut self, software: &'a str) -> &mut Self {
        self.software = Some(software);
        self
    }

    /// Set alternate server.
    #[inline]
    pub fn alternate_server(&mut self, server: SocketAddr) -> &mut Self {
        self.alternate_server = Some(server);
        self
    }

    /// Set alternate domain.
    #[inline]
    pub fn alternate_domain(&mut self, domain: &'a str) -> &mut Self {
        self.alternate_domain = Some(domain);
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

        if let Some(attributes) = self.unknown_attributes {
            writer.put_unknown_attributes(attributes);
        }

        if let Some(alternate_server) = self.alternate_server {
            writer.put_alternate_server(alternate_server);
        }

        if let Some(alternate_domain) = self.alternate_domain {
            writer.put_alternate_domain(alternate_domain);
        }

        if let Some(addr) = self.mapped_address {
            writer.put_mapped_address(addr);
        }

        if let Some(addr) = self.xor_mapped_address {
            writer.put_xor_mapped_address(addr);
        }

        if let Some(username) = self.username {
            writer.put_username(username);
        }

        if let Some(userhash) = self.userhash.as_ref() {
            writer.put_userhash(userhash);
        }

        if let Some(realm) = self.realm {
            writer.put_realm(realm);
        }

        if let Some(nonce) = self.nonce {
            writer.put_nonce(nonce);
        }

        if let Some(algorithms) = self.password_algorithms {
            writer.put_password_algorithms(algorithms);
        }

        if let Some(algorithm) = self.password_algorithm.as_ref() {
            writer.put_password_algorithm(algorithm);
        }

        if let Some(software) = self.software {
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

        if let Some(key) = self.message_integrity_key {
            match self.message_integrity_algorithm {
                MessageIntegrityAlgorithm::Sha1 => writer.put_message_integrity(key),
                MessageIntegrityAlgorithm::Sha256 => writer.put_message_integrity_sha256(key),
                MessageIntegrityAlgorithm::Unknown => {
                    writer.put_message_integrity(key);
                    writer.put_message_integrity_sha256(key);
                }
            }
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::Bytes;

    use super::{MessageBuilder, MessageIntegrityAlgorithm};

    use crate::{
        attribute::{Attribute, ErrorCode, PasswordAlgorithm},
        InvalidMessage, Message, MessageClass, Method,
    };

    /// Helper trait.
    trait BytesExt {
        /// Parse a byte slice into a message.
        fn parse_message(&self) -> Result<Message, InvalidMessage>;
    }

    impl BytesExt for Bytes {
        fn parse_message(&self) -> Result<Message, InvalidMessage> {
            Message::from_frame(self.clone())
        }
    }

    #[test]
    fn test_binding_request() {
        let msg = MessageBuilder::binding_request([1u8; 12])
            .build()
            .parse_message()
            .unwrap();

        assert!(msg.is_request());
        assert!(!msg.is_response());
        assert!(msg.is_rfc5389_message());

        assert_eq!(msg.class(), MessageClass::Request);
        assert_eq!(msg.method(), Method::Binding);
        assert_eq!(msg.transaction_id(), [1u8; 12]);
    }

    #[test]
    fn test_mapped_address() {
        let addr = SocketAddr::from(([192, 0, 2, 1], 32853));

        let msg = MessageBuilder::binding_request([0u8; 12])
            .mapped_address(addr)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_mapped_address(), Some(addr));
        assert_eq!(attrs.get_any_mapped_address(), Some(addr));
    }

    #[test]
    fn test_xor_mapped_address_v4() {
        let addr = SocketAddr::from(([192, 0, 2, 1], 32853));

        let msg = MessageBuilder::binding_request([0u8; 12])
            .xor_mapped_address(addr)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_xor_mapped_address(), Some(addr));
        assert_eq!(attrs.get_any_mapped_address(), Some(addr));
    }

    #[test]
    fn test_xor_mapped_address_v6() {
        let ip = u128::to_be_bytes(0x2001_0db8_0000_0000_0000_0000_0000_0001);

        let addr = SocketAddr::from((ip, 32853));

        let msg = MessageBuilder::binding_request([0u8; 12])
            .xor_mapped_address(addr)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_xor_mapped_address(), Some(addr));
        assert_eq!(attrs.get_any_mapped_address(), Some(addr));
    }

    #[test]
    fn test_text_attributes() {
        let msg = MessageBuilder::binding_request([0u8; 12])
            .username("alice")
            .realm("example.org")
            .nonce("nonce-value")
            .software("msf-stun")
            .alternate_domain("alt.example.org")
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_username(), Some("alice"));
        assert_eq!(attrs.get_realm(), Some("example.org"));
        assert_eq!(attrs.get_nonce(), Some("nonce-value"));
        assert_eq!(attrs.get_software(), Some("msf-stun"));
        assert_eq!(attrs.get_alternate_domain(), Some("alt.example.org"));
    }

    #[test]
    fn test_error_code() {
        let req = MessageBuilder::binding_request([0u8; 12])
            .build()
            .parse_message()
            .unwrap();

        let msg = MessageBuilder::error_response(&req, ErrorCode::BAD_REQUEST)
            .build()
            .parse_message()
            .unwrap();

        assert_eq!(msg.class(), MessageClass::Error);

        let ec = msg
            .attributes()
            .get_error_code()
            .expect("error code expected");

        assert_eq!(ec.code(), 400);
        assert_eq!(ec.message(), "Bad Request");
    }

    #[test]
    fn test_unknown_attributes() {
        let list = [0x0001u16, 0x0006, 0x0020];

        let msg = MessageBuilder::binding_request([0u8; 12])
            .unknown_attributes(&list)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_unknown_attributes(), Some(&list[..]));
    }

    #[test]
    fn test_alternate_server() {
        let addr = SocketAddr::from(([192, 0, 2, 1], 3478));

        let msg = MessageBuilder::binding_request([0u8; 12])
            .alternate_server(addr)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_alternate_server(), Some(addr));
    }

    #[test]
    fn test_userhash() {
        let hash = [0x5au8; 32];

        let msg = MessageBuilder::binding_request([0u8; 12])
            .userhash(hash)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert_eq!(attrs.get_userhash(), Some(&hash));
    }

    #[test]
    fn test_password_algorithms() {
        let algs = [PasswordAlgorithm::Md5, PasswordAlgorithm::Sha256];

        let msg = MessageBuilder::binding_request([0u8; 12])
            .password_algorithms(&algs)
            .build()
            .parse_message()
            .unwrap();

        let out = msg
            .attributes()
            .get_password_algorithms()
            .expect("password algorithms expected");

        assert_eq!(out.len(), 2);

        assert!(matches!(out[0], PasswordAlgorithm::Md5));
        assert!(matches!(out[1], PasswordAlgorithm::Sha256));
    }

    #[test]
    fn test_password_algorithm() {
        let msg = MessageBuilder::binding_request([0u8; 12])
            .password_algorithm(PasswordAlgorithm::Sha256)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert!(matches!(
            attrs.get_password_algorithm(),
            Some(PasswordAlgorithm::Sha256)
        ));
    }

    #[test]
    fn test_fingerprint() {
        let msg = MessageBuilder::binding_request([0u8; 12])
            .software("msf")
            .fingerprint(true)
            .build()
            .parse_message()
            .unwrap();

        assert!(msg.check_fingerprint());
    }

    #[test]
    fn test_message_integrity_sha1() {
        let key = b"secret-key";

        let msg = MessageBuilder::binding_request([0u8; 12])
            .username("alice")
            .message_integrity_key(key)
            .message_integrity_algorithm(MessageIntegrityAlgorithm::Sha1)
            .build()
            .parse_message()
            .unwrap();

        assert!(msg.check_st_credentials(key).is_ok());
        assert!(msg.check_st_credentials(b"wrong-key").is_err());
    }

    #[test]
    fn test_message_integrity_default_writes_both() {
        let key = b"secret-key";

        let msg = MessageBuilder::binding_request([0u8; 12])
            .message_integrity_key(key)
            .build()
            .parse_message()
            .unwrap();

        assert!(msg.check_st_credentials(key).is_ok());

        let has_sha1 = msg
            .attributes()
            .iter()
            .any(|a| matches!(a, Attribute::MessageIntegrity(_)));

        let has_sha256 = msg
            .attributes()
            .iter()
            .any(|a| matches!(a, Attribute::MessageIntegritySha256(_)));

        assert!(has_sha1);
        assert!(has_sha256);
    }

    #[test]
    fn test_responses() {
        let req = MessageBuilder::new(MessageClass::Request, Method::Other(0x0042), [9u8; 12])
            .magic_cookie(0x1234_5678)
            .build()
            .parse_message()
            .unwrap();

        let success = MessageBuilder::success_response(&req)
            .build()
            .parse_message()
            .unwrap();

        assert_eq!(success.class(), MessageClass::Success);
        assert_eq!(success.method(), Method::Other(0x0042));
        assert_eq!(success.magic_cookie(), 0x1234_5678);
        assert_eq!(success.transaction_id(), [9u8; 12]);

        let err = MessageBuilder::error_response(&req, ErrorCode::UNAUTHORIZED)
            .build()
            .parse_message()
            .unwrap();

        assert_eq!(err.class(), MessageClass::Error);
        assert_eq!(err.method(), Method::Other(0x0042));

        let error_code = err
            .attributes()
            .get_error_code()
            .expect("error code expected");

        assert_eq!(error_code.code(), 401);

        let r = MessageBuilder::response(MessageClass::Indication, &req)
            .build()
            .parse_message()
            .unwrap();

        assert_eq!(r.class(), MessageClass::Indication);
    }

    #[test]
    fn test_long_transaction_id() {
        let mut tid = [0u8; 16];

        for i in 0..tid.len() {
            tid[i] = i as u8;
        }

        let msg = MessageBuilder::binding_request([0u8; 12])
            .long_transaction_id(tid)
            .build()
            .parse_message()
            .unwrap();

        assert_eq!(msg.long_transaction_id(), tid);
        assert_eq!(msg.magic_cookie(), u32::from_be_bytes([0, 1, 2, 3]));
    }

    #[cfg(feature = "ice")]
    #[test]
    fn test_ice_attributes() {
        let msg = MessageBuilder::binding_request([0u8; 12])
            .use_candidate(true)
            .priority(0x1234_5678)
            .ice_controlling(0xdead_beef)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert!(attrs.get_use_candidate());

        assert_eq!(attrs.get_priority(), Some(0x1234_5678));
        assert_eq!(attrs.get_ice_controlling(), Some(0xdead_beef));

        let msg = MessageBuilder::binding_request([0u8; 12])
            .ice_controlled(0x0102_0304_0506_0708)
            .build()
            .parse_message()
            .unwrap();

        let attrs = msg.attributes();

        assert!(!attrs.get_use_candidate());

        assert_eq!(attrs.get_ice_controlled(), Some(0x0102_0304_0506_0708));
    }
}
