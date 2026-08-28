use std::net::SocketAddr;

use futures::future::{AbortHandle, AbortRegistration, Abortable};
use msf_stun::{
    ErrorCode, IntegrityError, MessageClass, MessageIntegrityAlgorithm, Method, Sha256Length,
};

use crate::{
    ice2::{
        candidate::{CandidateKind, LocalCandidate, RemoteCandidate},
        stun::{IncomingMessage, Request, STUN},
        utils::Credentials,
    },
    AgentRole,
};

/// Outgoing connectivity check.
pub struct OutgoingConnectivityCheck {
    id: u64,
    agent_role: AgentRole,
    tie_breaker: u64,
    abort_registration: AbortRegistration,
    local_candidate: LocalCandidate,
    remote_candidate: RemoteCandidate,
    nominated_pair: bool,
}

impl OutgoingConnectivityCheck {
    /// Create a new outgoing connectivity check.
    pub fn new(
        id: u64,
        agent_role: AgentRole,
        tie_breaker: u64,
        local_candidate: LocalCandidate,
        remote_candidate: RemoteCandidate,
        nominated_pair: bool,
    ) -> (Self, OutgoingConnectivityCheckHandle) {
        let (abort, abort_registration) = AbortHandle::new_pair();

        let handle = OutgoingConnectivityCheckHandle { id, abort };

        let res = Self {
            id,
            agent_role,
            tie_breaker,
            abort_registration,
            local_candidate,
            remote_candidate,
            nominated_pair,
        };

        (res, handle)
    }

    /// Get the corresponding data stream ID.
    pub fn data_stream(&self) -> usize {
        self.local_candidate.data_stream()
    }

    /// Create an outgoing connectivity check request.
    pub fn into_outgoing_request(
        self,
        stun: &STUN,
        local_credentials: &Credentials,
        remote_credentials: &Credentials,
    ) -> OutgoingConnectivityCheckRequest {
        let local_username = local_credentials.username();
        let remote_username = remote_credentials.username();
        let remote_password = remote_credentials.password();

        let username = format!("{remote_username}:{local_username}");

        // TODO: Get local priority preference from the local candidate and use
        //   it for calculating the peer-reflexive candidate priority (i.e. the
        //   local preference part will be the same).
        let priority = LocalCandidate::calculate_priority(
            self.local_candidate.component(),
            CandidateKind::PeerReflexive,
            self.local_candidate.base(),
        );

        let mut builder = stun
            .build_request(Method::Binding)
            .username(&username)
            .priority(priority)
            .message_integrity_key(remote_password.as_bytes())
            .message_integrity_algorithm(MessageIntegrityAlgorithm::Sha1)
            .fingerprint(true);

        if self.agent_role == AgentRole::Controlling {
            builder = builder
                .use_candidate(self.nominated_pair)
                .ice_controlling(self.tie_breaker);
        } else {
            builder = builder.ice_controlled(self.tie_breaker);
        }

        OutgoingConnectivityCheckRequest {
            id: self.id,
            agent_role: self.agent_role,
            data_stream: self.local_candidate.data_stream(),
            component: self.local_candidate.component(),
            base_addr: self.local_candidate.base(),
            remote_addr: self.remote_candidate.addr(),
            abort_registration: self.abort_registration,
            request: builder.build(),
        }
    }
}

/// Outgoing connectivity check handle.
///
/// The handle can be used to abort the connectivity check request. The request
/// will be alse aborted when the handle is dropped.
pub struct OutgoingConnectivityCheckHandle {
    id: u64,
    abort: AbortHandle,
}

impl OutgoingConnectivityCheckHandle {
    /// Get the connectivity check ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Abort the connectivity check request.
    pub fn abort(&self) {
        self.abort.abort();
    }
}

impl Drop for OutgoingConnectivityCheckHandle {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Outgoing connectivity check request.
pub struct OutgoingConnectivityCheckRequest {
    id: u64,
    agent_role: AgentRole,
    data_stream: usize,
    component: u8,
    base_addr: SocketAddr,
    remote_addr: SocketAddr,
    abort_registration: AbortRegistration,
    request: Request,
}

impl OutgoingConnectivityCheckRequest {
    /// Send the connectivity check request and wait for a response.
    pub async fn send(self) -> IncomingConnectivityCheckResponse {
        let send = self.request.send(self.base_addr, self.remote_addr);

        let result = Abortable::new(send, self.abort_registration)
            .await
            .ok()
            .map(|res| {
                let Ok(response) = res else {
                    return ConnectivityCheckResult::Failed;
                };

                let result = ConnectivityCheckResult::from_incoming_reponse(&response);

                if matches!(result, ConnectivityCheckResult::Success(_))
                    && (self.base_addr != response.base_addr()
                        || self.remote_addr != response.remote_addr())
                {
                    ConnectivityCheckResult::Failed
                } else {
                    result
                }
            })
            .unwrap_or(ConnectivityCheckResult::Aborted);

        IncomingConnectivityCheckResponse {
            id: self.id,
            agent_role: self.agent_role,
            data_stream: self.data_stream,
            component: self.component,
            result,
        }
    }
}

/// Incoming connectivity check response.
pub struct IncomingConnectivityCheckResponse {
    id: u64,
    agent_role: AgentRole,
    data_stream: usize,
    component: u8,
    result: ConnectivityCheckResult,
}

impl IncomingConnectivityCheckResponse {
    /// Get the connectivity check ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the agent role used in the connectivity check request.
    pub fn agent_role(&self) -> AgentRole {
        self.agent_role
    }

    /// Get the corresponding data stream ID.
    pub fn data_stream(&self) -> usize {
        self.data_stream
    }

    /// Get the corresponding component ID.
    pub fn component(&self) -> u8 {
        self.component
    }

    /// Get the connectivity check result.
    pub fn result(&self) -> ConnectivityCheckResult {
        self.result
    }
}

/// Connectivity check result.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ConnectivityCheckResult {
    Success(SocketAddr),
    Failed,
    RoleConflict,
    Aborted,
}

impl ConnectivityCheckResult {
    /// Get the connectivity check result from a given incoming STUN response.
    fn from_incoming_reponse(response: &IncomingMessage) -> Self {
        let class = response.class();
        let attributes = response.attributes();
        let unknown_attributes = response.unknown_attributes();

        debug_assert!(matches!(class, MessageClass::Success | MessageClass::Error));

        if !unknown_attributes.is_empty() {
            ConnectivityCheckResult::Failed
        } else if class == MessageClass::Success {
            attributes
                .get_xor_mapped_address()
                .map(ConnectivityCheckResult::Success)
                .unwrap_or(ConnectivityCheckResult::Failed)
        } else if class == MessageClass::Error {
            let is_role_conflict = attributes
                .get_error_code()
                .map(|err| err.code() == 487)
                .unwrap_or(false);

            if is_role_conflict {
                ConnectivityCheckResult::RoleConflict
            } else {
                ConnectivityCheckResult::Failed
            }
        } else {
            ConnectivityCheckResult::Failed
        }
    }
}

/// Incoming connectivity check request.
pub struct IncomingConnectivityCheckRequest {
    base_addr: SocketAddr,
    remote_addr: SocketAddr,
    remote_role: AgentRole,
    remote_tie_breaker: u64,
    data_stream: usize,
    component: u8,
    priority: u32,
    use_candidate: bool,
}

impl IncomingConnectivityCheckRequest {
    /// Parse an incoming connectivity check request from a given incoming STUN
    /// request.
    pub fn from_incoming_request(
        request: &IncomingMessage,
        data_stream: usize,
        component: u8,
        local_credentials: &Credentials,
    ) -> Result<Self, InvalidConnectivityCheckRequest> {
        request.authenticate(local_credentials)?;

        let unknown_attributes = request.unknown_attributes();

        if !unknown_attributes.is_empty() {
            return Err(InvalidConnectivityCheckRequest::UnknownAttributes);
        }

        let attributes = request.attributes();

        let (remote_role, remote_tie_breaker) = if let Some(tb) = attributes.get_ice_controlling() {
            (AgentRole::Controlling, tb)
        } else if let Some(tb) = attributes.get_ice_controlled() {
            (AgentRole::Controlled, tb)
        } else {
            return Err(InvalidConnectivityCheckRequest::MissingRole);
        };

        let priority = attributes
            .get_priority()
            .ok_or(InvalidConnectivityCheckRequest::MissingPriority)?;

        let use_candidate = attributes.contains_use_candidate();

        let res = Self {
            base_addr: request.base_addr(),
            remote_addr: request.remote_addr(),
            remote_role,
            remote_tie_breaker,
            data_stream,
            component,
            priority,
            use_candidate,
        };

        Ok(res)
    }

    /// Get the base address.
    pub fn base_addr(&self) -> SocketAddr {
        self.base_addr
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the remote agent role.
    pub fn remote_role(&self) -> AgentRole {
        self.remote_role
    }

    /// Get the remote tie-breaker value.
    pub fn remote_tie_breaker(&self) -> u64 {
        self.remote_tie_breaker
    }

    /// Get the data stream index.
    pub fn data_stream(&self) -> usize {
        self.data_stream
    }

    /// Get the component index.
    pub fn component(&self) -> u8 {
        self.component
    }

    /// Get the priority value.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Check if the USE-CANDIDATE attribute is present.
    pub fn use_candidate(&self) -> bool {
        self.use_candidate
    }
}

/// Invalid connectivity check request.
pub enum InvalidConnectivityCheckRequest {
    AuthError(AuthError),
    UnknownAttributes,
    MissingRole,
    MissingPriority,
}

impl InvalidConnectivityCheckRequest {
    /// Get the corresponding STUN error code.
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            Self::AuthError(err) => err.to_error_code(),
            Self::UnknownAttributes => ErrorCode::UNKNOWN_ATTRIBUTES,
            Self::MissingRole => ErrorCode::BAD_REQUEST,
            Self::MissingPriority => ErrorCode::BAD_REQUEST,
        }
    }
}

impl From<AuthError> for InvalidConnectivityCheckRequest {
    fn from(err: AuthError) -> Self {
        Self::AuthError(err)
    }
}

/// Helper trait.
trait IncomingMessageExt {
    /// Authenticate the incoming STUN message using given credentials.
    fn authenticate(
        &self,
        local_credentials: &Credentials,
    ) -> Result<MessageIntegrityAlgorithm, AuthError>;
}

impl IncomingMessageExt for IncomingMessage {
    fn authenticate(
        &self,
        local_credentials: &Credentials,
    ) -> Result<MessageIntegrityAlgorithm, AuthError> {
        let username = self
            .attributes()
            .get_username()
            .ok_or(AuthError::MissingUsername)?;

        let is_valid_username = username
            .split_once(':')
            .map(|(fragment, _)| fragment == local_credentials.username())
            .unwrap_or(false);

        if !is_valid_username {
            return Err(AuthError::InvalidUsername);
        }

        let password = local_credentials.password();

        let key = password.as_bytes();

        match self.check_message_integrity_sha256(key, Sha256Length::Full) {
            Ok(_) => Ok(MessageIntegrityAlgorithm::Sha256),
            Err(IntegrityError::Invalid) => Err(AuthError::InvalidMessageIntegrity),
            Err(IntegrityError::Missing) => match self.check_message_integrity(key) {
                Ok(_) => Ok(MessageIntegrityAlgorithm::Sha1),
                Err(IntegrityError::Invalid) => Err(AuthError::InvalidMessageIntegrity),
                Err(IntegrityError::Missing) => Err(AuthError::MissingMessageIntegrity),
            },
        }
    }
}

/// Authentication error.
pub enum AuthError {
    MissingUsername,
    InvalidUsername,
    MissingMessageIntegrity,
    InvalidMessageIntegrity,
}

impl AuthError {
    /// Get the corresponding STUN error code.
    fn to_error_code(&self) -> ErrorCode {
        match self {
            Self::MissingUsername | Self::MissingMessageIntegrity => ErrorCode::BAD_REQUEST,
            Self::InvalidUsername | Self::InvalidMessageIntegrity => ErrorCode::UNAUTHORIZED,
        }
    }
}
