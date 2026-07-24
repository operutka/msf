use std::{io, net::SocketAddr, time::Duration};

use bytes::Bytes;
use futures::StreamExt;
use msf_stun::{
    AddressFamily, ChannelNumber, Message, MessageBuilder, MessageClass, MessageIntegrityAlgorithm,
    Method, Sha256Length, TransportProtocol,
};

use crate::ice2::{
    stun::{IncomingMessage, ResponseHandler, ResponseReceiver, TransactionRegistration},
    transport::{OutgoingPacketDispatcher, Packet},
};

/// STUN request builder.
pub struct RequestBuilder<'a> {
    registration: TransactionRegistration,
    builder: MessageBuilder<'a>,
    dispatcher: OutgoingPacketDispatcher,
    method: Method,
    fingerprint: bool,
    message_integrity_algorithm: MessageIntegrityAlgorithm,
    message_integrity_key: Option<&'a [u8]>,
}

impl<'a> RequestBuilder<'a> {
    /// Create a new request builder.
    pub(super) fn new(
        method: Method,
        registration: TransactionRegistration,
        dispatcher: OutgoingPacketDispatcher,
    ) -> Self {
        let builder = MessageBuilder::request(method, registration.transaction_id());

        Self {
            registration,
            builder,
            dispatcher,
            method,
            fingerprint: false,
            message_integrity_algorithm: MessageIntegrityAlgorithm::Unknown,
            message_integrity_key: None,
        }
    }

    /// Set the REQUESTED-TRANSPORT attribute.
    pub fn requested_transport(mut self, protocol: TransportProtocol) -> Self {
        self.builder.requested_transport(protocol);
        self
    }

    /// Set the REQUESTED-ADDRESS-FAMILY attribute.
    pub fn requested_address_family(mut self, family: AddressFamily) -> Self {
        self.builder.requested_address_family(family);
        self
    }

    /// Set the LIFETIME attribute.
    pub fn lifetime(mut self, lifetime: u32) -> Self {
        self.builder.lifetime(lifetime);
        self
    }

    /// Set the XOR-PEER-ADDRESS attribute.
    pub fn xor_peer_address(mut self, address: SocketAddr) -> Self {
        self.builder.xor_peer_address(address);
        self
    }

    /// Set the CHANNEL-NUMBER attribute.
    pub fn channel_number(mut self, channel_number: ChannelNumber) -> Self {
        self.builder.channel_number(channel_number);
        self
    }

    /// Set the USERNAME attribute.
    pub fn username(mut self, username: &'a str) -> Self {
        self.builder.username(username);
        self
    }

    /// Set the PRIORITY attribute.
    pub fn priority(mut self, priority: u32) -> Self {
        self.builder.priority(priority);
        self
    }

    /// Set key for the MESSAGE-INTEGRITY(-SHA256) attribute.
    pub fn message_integrity_key(mut self, key: &'a [u8]) -> Self {
        self.message_integrity_key = Some(key);

        self.builder.message_integrity_key(key);
        self
    }

    /// Set the algorithm for the MESSAGE-INTEGRITY(-SHA256) attribute.
    pub fn message_integrity_algorithm(mut self, algorithm: MessageIntegrityAlgorithm) -> Self {
        self.message_integrity_algorithm = algorithm;

        self.builder.message_integrity_algorithm(algorithm);
        self
    }

    /// Set the FINGERPRINT attribute.
    pub fn fingerprint(mut self, enable: bool) -> Self {
        self.fingerprint = enable;

        self.builder.fingerprint(enable);
        self
    }

    /// Set the USE-CANDIDATE attribute.
    pub fn use_candidate(mut self, enable: bool) -> Self {
        self.builder.use_candidate(enable);
        self
    }

    /// Set the ICE-CONTROLLING attribute.
    pub fn ice_controlling(mut self, tie_breaker: u64) -> Self {
        self.builder.ice_controlling(tie_breaker);
        self
    }

    /// Set the ICE-CONTROLLED attribute.
    pub fn ice_controlled(mut self, tie_breaker: u64) -> Self {
        self.builder.ice_controlled(tie_breaker);
        self
    }

    /// Build the request.
    pub fn build(self) -> Request {
        let (handler, response_receiver) = ResponseHandler::new(self.method, self.fingerprint);

        self.registration.register_response_handler(handler);

        Request {
            _registration: self.registration,
            packet_dispatcher: self.dispatcher,
            response_receiver,
            request: self.builder.build(),
            message_integrity_algorithm: self.message_integrity_algorithm,
            message_integrity_key: self.message_integrity_key.map(Bytes::copy_from_slice),
        }
    }
}

/// STUN request.
pub struct Request {
    _registration: TransactionRegistration,
    packet_dispatcher: OutgoingPacketDispatcher,
    response_receiver: ResponseReceiver,
    request: Bytes,
    message_integrity_algorithm: MessageIntegrityAlgorithm,
    message_integrity_key: Option<Bytes>,
}

impl Request {
    /// Send the request from a given base address to a given remote address
    /// and wait for a response.
    pub async fn send(
        mut self,
        base_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> io::Result<IncomingMessage> {
        let mut invalid_message_integrity = false;
        let mut remaining_attempts = 7;
        let mut next_timeout = Duration::from_millis(500);

        let last_timeout = Duration::from_secs(16);

        while remaining_attempts > 0 {
            let data = self.request.clone();

            self.packet_dispatcher
                .send(Packet::new(base_addr, remote_addr, data))
                .await?;

            let timeout = if remaining_attempts > 1 {
                next_timeout
            } else {
                last_timeout
            };

            let addr = tokio::time::timeout(timeout, self.response_receiver.next());

            if let Ok(res) = addr.await {
                let msg = res.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;

                // NOTE: Over unreliable transport, the response should be
                //   discarded if the message integrity is invalid and
                //   retransmissions should continue.
                if self.check_message_integrity(&msg) {
                    return Ok(msg);
                }

                invalid_message_integrity = true;
            }

            remaining_attempts -= 1;
            next_timeout *= 2;
        }

        if invalid_message_integrity {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        }
    }

    /// Check message integrity of a given STUN message.
    fn check_message_integrity(&self, msg: &Message) -> bool {
        let Some(key) = self.message_integrity_key.as_ref() else {
            return true;
        };

        let attributes = msg.attributes();
        let contains_message_integrity = attributes.contains_message_integrity();
        let contains_message_integrity_sha256 = attributes.contains_message_integrity_sha256();

        if !contains_message_integrity && !contains_message_integrity_sha256 {
            // NOTE: Error responses are not necessarily authenticated.
            //   Therefore, we return `true` here for all error responses to
            //   allow further message processing.
            return msg.class() == MessageClass::Error;
        }

        let res = match self.message_integrity_algorithm {
            MessageIntegrityAlgorithm::Sha1 => msg.check_message_integrity(key),
            MessageIntegrityAlgorithm::Sha256 => {
                msg.check_message_integrity_sha256(key, Sha256Length::Full)
            }
            MessageIntegrityAlgorithm::Unknown if contains_message_integrity_sha256 => {
                msg.check_message_integrity_sha256(key, Sha256Length::Full)
            }
            MessageIntegrityAlgorithm::Unknown => msg.check_message_integrity(key),
        };

        res.is_ok()
    }
}
