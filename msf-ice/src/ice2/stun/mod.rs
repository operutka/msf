mod indication;
mod request;
mod response;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex, Weak},
};

use futures::channel::mpsc;
use msf_stun::{ErrorCode, Message, MessageBuilder, MessageClass};

pub use msf_stun::Method;

use crate::ice2::transport::OutgoingPacketDispatcher;

use self::{indication::IndicationBuilder, request::RequestBuilder, response::ResponseBuilder};

pub use self::{request::Request, response::Response};

/// Incoming STUN message annotated with a local base address and a remote
/// peer address.
pub struct IncomingMessage {
    base_addr: SocketAddr,
    remote_addr: SocketAddr,
    message: Message,
}

impl IncomingMessage {
    /// Create a new incoming message.
    pub fn new(base_addr: SocketAddr, remote_addr: SocketAddr, message: Message) -> Self {
        Self {
            base_addr,
            remote_addr,
            message,
        }
    }

    /// Get the local base address.
    pub fn base_addr(&self) -> SocketAddr {
        self.base_addr
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Deref for IncomingMessage {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// STUN context.
#[derive(Clone)]
pub struct STUN {
    inner: Arc<Mutex<InternalContext>>,
    packet_dispatcher: OutgoingPacketDispatcher,
}

impl STUN {
    /// Create a new STUN context.
    pub fn new(packet_dispatcher: OutgoingPacketDispatcher) -> Self {
        let inner = Arc::new(Mutex::new(InternalContext::new()));

        Self {
            inner,
            packet_dispatcher,
        }
    }

    /// Build a new indication.
    pub fn build_indication<'a>(&self, method: Method) -> IndicationBuilder<'a> {
        IndicationBuilder::new(method, self.packet_dispatcher.clone())
    }

    /// Build a new request.
    pub fn build_request<'a>(&self, method: Method) -> RequestBuilder<'a> {
        let id = self.inner.lock().unwrap().create_transaction();

        let registration = TransactionRegistration {
            context: Arc::downgrade(&self.inner),
            id,
        };

        RequestBuilder::new(method, registration, self.packet_dispatcher.clone())
    }

    /// Build a success response.
    pub fn build_success_response<'a>(&self, request: &Message) -> ResponseBuilder<'a> {
        let builder = MessageBuilder::success_response(request);

        let packet_dispatcher = self.packet_dispatcher.clone();

        ResponseBuilder::new(builder, packet_dispatcher)
    }

    /// Build an error response.
    pub fn build_error_response<'a>(
        &self,
        request: &Message,
        error_code: ErrorCode,
    ) -> ResponseBuilder<'a> {
        let builder = MessageBuilder::error_response(request, error_code);

        let packet_dispatcher = self.packet_dispatcher.clone();

        ResponseBuilder::new(builder, packet_dispatcher)
    }

    /// Use a given closure to send a request multiple times.
    ///
    /// If the response returned by the closure is a server error, the request
    /// will be repeated up to `attempts` times.
    pub async fn send_request_with_retries<F>(
        &self,
        attempts: u32,
        mut f: F,
    ) -> io::Result<IncomingMessage>
    where
        F: AsyncFnMut(&STUN) -> io::Result<IncomingMessage>,
    {
        let mut last_response = None;

        let mut remaining_attempts = attempts;

        while remaining_attempts > 0 {
            let response = f(self).await?;

            let class = response.class();
            let attributes = response.attributes();

            if class == MessageClass::Error {
                let retry = attributes
                    .get_error_code()
                    .map(|err| (500..600).contains(&err.code()))
                    .unwrap_or(false);

                if retry {
                    last_response = Some(response);
                } else {
                    return Ok(response);
                }
            }

            remaining_attempts -= 1;
        }

        Ok(last_response.unwrap())
    }

    /// Send Binding request from a given base address to a given STUN server.
    pub async fn send_binding_request(
        &self,
        base_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let send = self.send_request_with_retries(5, async move |stun| {
            let response = stun
                .build_request(Method::Binding)
                .build()
                .send(base_addr, remote_addr)
                .await?;

            // NOTE: The unknown attributes must be handled before retries.
            // NOTE: We ignore some reserved attributes for backwards
            //   compatibility with RFC 3489.
            let has_unknown_attributes = response
                .unknown_attributes()
                .iter()
                .copied()
                .any(|attr| !matches!(attr, 0x0002 | 0x0004 | 0x0005 | 0x000B));

            if has_unknown_attributes {
                Err(io::Error::other("invalid response"))
            } else {
                Ok(response)
            }
        });

        let response = send.await?;

        let class = response.class();
        let attributes = response.attributes();

        if class == MessageClass::Success {
            attributes
                .get_xor_mapped_address()
                .or_else(|| attributes.get_mapped_address())
                .ok_or_else(|| io::Error::other("invalid response"))
        } else if class == MessageClass::Error {
            let err = attributes
                .get_error_code()
                .ok_or_else(|| io::Error::other("invalid response"))?;

            Err(io::Error::other(err.message()))
        } else {
            unreachable!()
        }
    }

    /// Process a given incoming message.
    ///
    /// The message will be rejected if it is not a response matching any
    /// existing transaction.
    pub fn process_incoming_message(&self, msg: IncomingMessage) -> Result<(), IncomingMessage> {
        // NOTE: No requests or indications are expected here. This is just a
        //   STUN client.
        if msg.is_response() {
            self.process_response(msg)
        } else {
            Err(msg)
        }
    }

    /// Process a given STUN response.
    fn process_response(&self, msg: IncomingMessage) -> Result<(), IncomingMessage> {
        self.inner
            .lock()
            .unwrap()
            .resolve_transaction(&msg.transaction_id(), msg)
    }
}

/// Internal STUN context.
struct InternalContext {
    transactions: HashMap<TransactionId, Option<ResponseHandler>>,
}

impl InternalContext {
    /// Create a new STUN context.
    fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    /// Initiate a new transaction.
    fn create_transaction(&mut self) -> TransactionId {
        let mut id = rand::random();

        while self.transactions.contains_key(&id) {
            id = rand::random();
        }

        self.transactions.insert(id, None);

        id
    }

    /// Register response handler for a given transaction ID.
    fn register_response_handler(&mut self, id: &TransactionId, handler: ResponseHandler) {
        if let Some(slot) = self.transactions.get_mut(id) {
            *slot = Some(handler);
        }
    }

    /// Resolve transaction with a given ID.
    fn resolve_transaction(
        &mut self,
        id: &TransactionId,
        response: IncomingMessage,
    ) -> Result<(), IncomingMessage> {
        if let Some(Some(handler)) = self.transactions.get_mut(id) {
            handler.handle(response)
        } else {
            Err(response)
        }
    }

    /// Remove transaction with a given ID.
    fn remove_transaction(&mut self, id: &TransactionId) {
        self.transactions.remove(id);
    }
}

/// STUN transaction ID.
type TransactionId = [u8; 12];

/// Helper type.
type ResponseSender = mpsc::UnboundedSender<IncomingMessage>;

/// Helper type.
type ResponseReceiver = mpsc::UnboundedReceiver<IncomingMessage>;

/// STUN response handler.
struct ResponseHandler {
    method: Method,
    check_fingerprint: bool,
    sender: ResponseSender,
}

impl ResponseHandler {
    /// Create a new STUN response handler.
    fn new(method: Method, check_fingerprint: bool) -> (Self, ResponseReceiver) {
        let (sender, receiver) = mpsc::unbounded();

        let handler = Self {
            method,
            check_fingerprint,
            sender,
        };

        (handler, receiver)
    }

    /// Handle a given response.
    fn handle(&mut self, response: IncomingMessage) -> Result<(), IncomingMessage> {
        // NOTE: We always send requests with the magic cookie as defined in
        //   RFC 5389. So even if we interact with an old RFC 3489 server, all
        //   responses should still have the magic cookie set.
        let is_invalid_response = !response.is_rfc5389_message()
            || response.method() != self.method
            || (self.check_fingerprint && !response.check_fingerprint());

        if is_invalid_response {
            return Err(response);
        }

        let _ = self.sender.unbounded_send(response);

        Ok(())
    }
}

/// Transaction registration.
///
/// The transaction will be de-registered when the registration is dropped.
struct TransactionRegistration {
    context: Weak<Mutex<InternalContext>>,
    id: TransactionId,
}

impl TransactionRegistration {
    /// Get the transaction ID.
    fn transaction_id(&self) -> TransactionId {
        self.id
    }

    /// Register a given response handler.
    fn register_response_handler(&self, handler: ResponseHandler) {
        if let Some(context) = self.context.upgrade() {
            context
                .lock()
                .unwrap()
                .register_response_handler(&self.id, handler);
        }
    }
}

impl Drop for TransactionRegistration {
    fn drop(&mut self) {
        if let Some(context) = self.context.upgrade() {
            context.lock().unwrap().remove_transaction(&self.id);
        }
    }
}
