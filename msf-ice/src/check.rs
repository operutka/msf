use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{ready, FutureExt};
use msf_stun as stun;
use tokio::time::Sleep;

use crate::{
    candidate::{CandidateKind, CandidatePair, LocalCandidate, RemoteCandidate},
    AgentRole,
};

const RTO: u64 = 500;
const RM: u64 = 16;
const RC: u32 = 7;

/// Single connectivity check.
pub struct Check {
    pair: CandidatePair,
    state: CheckState,
    task: Option<Waker>,
    nominated: bool,
}

impl Check {
    /// Create a new connectivity check.
    pub fn new(pair: CandidatePair, nominated: bool) -> Self {
        Self {
            pair,
            state: CheckState::Frozen,
            task: None,
            nominated,
        }
    }

    /// Get the current check transaction (if any).
    fn transaction(&self) -> Option<&CheckTransaction> {
        if let CheckState::InProgress(t) = &self.state {
            Some(t)
        } else {
            None
        }
    }

    /// Get the current transaction ID (if any).
    pub fn transaction_id(&self) -> Option<TransactionId> {
        self.transaction().map(|t| t.id())
    }

    /// Check if the underlying candidate pair has been nominated.
    pub fn is_nominated(&self) -> bool {
        self.nominated
    }

    /// Get the local candidate from the underlying candidate pair.
    pub fn local_candidate(&self) -> &LocalCandidate {
        self.pair.local()
    }

    /// Get the remote candidate from the underlying candidate pair.
    pub fn remote_candidate(&self) -> &RemoteCandidate {
        self.pair.remote()
    }

    /// Get the underlying candidate pair.
    pub fn candidate_pair(&self) -> &CandidatePair {
        &self.pair
    }

    /// Get the corresponding component ID.
    pub fn component(&self) -> u8 {
        self.pair.component()
    }

    /// Get priority of the underlying candidate pair.
    pub fn priority(&self, local_role: AgentRole) -> u64 {
        self.pair.priority(local_role)
    }

    /// Get foundation of the underlying candidate pair.
    pub fn foundation(&self) -> &str {
        self.pair.foundation()
    }

    /// Check if the current state is "frozen".
    pub fn is_frozen(&self) -> bool {
        matches!(self.state, CheckState::Frozen)
    }

    /// Check if the current state is "waiting".
    pub fn is_waiting(&self) -> bool {
        matches!(self.state, CheckState::Waiting)
    }

    /// Check if the current state is "success".
    pub fn is_success(&self) -> bool {
        matches!(self.state, CheckState::Succeeded)
    }

    /// Check if the current state is "success", "failed" or "cancelled".
    pub fn is_done(&self) -> bool {
        matches!(
            self.state,
            CheckState::Succeeded | CheckState::Cancelled | CheckState::Failed
        )
    }

    /// Unfreeze the check.
    ///
    /// The check must be in the "frozen" state.
    pub fn unfreeze(&mut self) {
        debug_assert!(self.is_frozen());

        self.state = CheckState::Waiting;
    }

    /// Trigger the check.
    ///
    /// Regardless of the current state, the check will be switched to the
    /// "waiting" state.
    pub fn trigger(&mut self) {
        self.state = CheckState::Waiting;
    }

    /// Finish the check ASAP.
    ///
    /// No more retransmissions will be generated. The check will be cancelled
    /// if it hasn't been scheduled yet.
    pub fn finish(&mut self) {
        match &mut self.state {
            CheckState::Frozen | CheckState::Waiting => self.state = CheckState::Cancelled,
            CheckState::InProgress(t) => t.finish(),
            _ => (),
        }

        if let Some(task) = self.task.take() {
            task.wake();
        }
    }

    /// Cancel the check.
    ///
    /// Unless the check is done, it will be switched to the "cancelled" state.
    pub fn cancel(&mut self) {
        if self.is_done() {
            return;
        }

        self.state = CheckState::Cancelled;

        if let Some(task) = self.task.take() {
            task.wake();
        }
    }

    /// Schedule the check.
    ///
    /// The check must be either in the "frozen" state or in the "waiting"
    /// state. It will be switched to the "in-progress" state and a new check
    /// transaction will be created.
    pub fn schedule(
        &mut self,
        username: &str,
        password: &str,
        agent_role: AgentRole,
        tie_breaker: u64,
    ) {
        debug_assert!(matches!(
            self.state,
            CheckState::Frozen | CheckState::Waiting
        ));

        let transaction_id = rand::random();

        // request priority must be equal to priority of a peer-reflexive
        // candidate that could be a result of this transaction
        let local = self.pair.local();
        let remote = self.pair.remote();

        let addr = local.addr();

        let priority = LocalCandidate::calculate_priority(
            remote.component(),
            CandidateKind::PeerReflexive,
            addr,
        );

        let mut builder = stun::MessageBuilder::binding_request(transaction_id);

        builder
            .username(username)
            .priority(priority)
            .message_integrity(password.as_bytes())
            .fingerprint(true);

        if agent_role == AgentRole::Controlling {
            if self.nominated {
                builder.use_candidate(true);
            }

            builder.ice_controlling(tie_breaker);
        } else {
            builder.ice_controlled(tie_breaker);
        }

        let msg = CheckMessage {
            local_addr: local.base(),
            remote_addr: remote.addr(),
            component: remote.component(),
            data: builder.build(),
        };

        let transaction = CheckTransaction::new(agent_role, transaction_id, msg);

        self.state = CheckState::InProgress(Box::new(transaction));

        if let Some(task) = self.task.take() {
            task.wake();
        }
    }

    /// Process a given STUN response.
    ///
    /// The check must be in the "in-progress" state and the current
    /// transaction ID must match the transaction ID in the STUN response.
    pub fn process_stun_response(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        response: &stun::Message,
    ) -> Result<(), CheckError> {
        let transaction = self.transaction().unwrap();

        debug_assert_eq!(transaction.id(), response.transaction_id());

        let res = if let Some(err) = response.attributes().get_error_code() {
            if err.code() == 487 {
                Err(CheckError::RoleConflict(transaction.agent_role()))
            } else {
                Err(CheckError::Failed)
            }
        } else {
            // check that the local and remote addresses are symmetric
            let local_candidate = self.pair.local();
            let remote_candidate = self.pair.remote();

            if local_addr == local_candidate.base() && remote_addr == remote_candidate.addr() {
                Ok(())
            } else {
                Err(CheckError::Failed)
            }
        };

        self.state = match &res {
            Ok(_) => CheckState::Succeeded,
            Err(CheckError::RoleConflict(_)) => CheckState::Waiting,
            Err(_) => CheckState::Failed,
        };

        res
    }

    /// Poll the check.
    ///
    /// Polling the check will yield connectivity check STUN messages or `None`
    /// if the check is done.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<CheckMessage>> {
        match &mut self.state {
            CheckState::Frozen | CheckState::Waiting => {
                let task = cx.waker();

                self.task = Some(task.clone());

                Poll::Pending
            }
            CheckState::InProgress(t) => {
                if let Some(msg) = ready!(t.poll(cx)) {
                    Poll::Ready(Some(msg))
                } else {
                    // connectivity check timeout
                    self.state = CheckState::Failed;

                    Poll::Ready(None)
                }
            }
            _ => Poll::Ready(None),
        }
    }

    /// Update the current check pushing the state machine forward if possible.
    pub fn update(&mut self, other: Check) {
        if !self.nominated && other.nominated {
            *self = other;
        } else if self.nominated == other.nominated {
            match (&self.state, &other.state) {
                (CheckState::Frozen, _) => *self = other,
                (CheckState::Waiting, CheckState::InProgress(_)) => *self = other,
                (_, CheckState::Succeeded) => *self = other,
                (_, CheckState::Failed) => *self = other,
                (_, CheckState::Cancelled) => *self = other,
                _ => (),
            }
        }
    }
}

/// Connectivity check state.
enum CheckState {
    Frozen,
    Waiting,
    InProgress(Box<CheckTransaction>),
    Succeeded,
    Failed,
    Cancelled,
}

/// Connectivity check transaction ID.
pub type TransactionId = [u8; 12];

/// Connectivity check transaction.
struct CheckTransaction {
    id: TransactionId,
    timeout: Pin<Box<Sleep>>,
    next_timeout: Duration,
    last_timeout: Duration,
    remaining_attempts: u32,
    message: CheckMessage,
    agent_role: AgentRole,
    last_attempt: Option<Instant>,
    task: Option<Waker>,
}

impl CheckTransaction {
    /// Create a new connectivity check transaction.
    fn new(agent_role: AgentRole, id: TransactionId, message: CheckMessage) -> Self {
        Self {
            id,
            timeout: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
            next_timeout: Duration::from_millis(RTO),
            last_timeout: Duration::from_millis(RTO * RM),
            remaining_attempts: RC,
            message,
            agent_role,
            last_attempt: None,
            task: None,
        }
    }

    /// Get the transaction ID.
    fn id(&self) -> TransactionId {
        self.id
    }

    /// Get the agent role used by the agent when the transaction was created.
    fn agent_role(&self) -> AgentRole {
        self.agent_role
    }

    /// Finish the transaction without generating any more connection attempts.
    fn finish(&mut self) {
        if let Some(last_attempt) = self.last_attempt {
            let deadline = std::cmp::min(
                last_attempt + self.last_timeout,
                Instant::now() + Duration::from_millis(1_000),
            );

            self.timeout.as_mut().reset(deadline.into());

            self.remaining_attempts = 0;
        } else {
            self.remaining_attempts = 1;
        }

        if let Some(task) = self.task.take() {
            task.wake();
        }
    }

    /// Poll the transaction.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<CheckMessage>> {
        let mut res = Poll::Pending;

        loop {
            let poll = self.timeout.poll_unpin(cx);

            if poll.is_pending() {
                let task = cx.waker();

                // save the task handle if necessary
                if res.is_pending() {
                    self.task = Some(task.clone());
                }

                return res;
            }

            let timeout = if self.remaining_attempts == 0 {
                return Poll::Ready(None);
            } else if self.remaining_attempts == 1 {
                self.last_timeout
            } else {
                self.next_timeout
            };

            let now = Instant::now();

            self.last_attempt = Some(now);

            let deadline = now + timeout;

            self.timeout.as_mut().reset(deadline.into());

            res = Poll::Ready(Some(self.message.clone()));

            self.remaining_attempts -= 1;
            self.next_timeout *= 2;
        }
    }
}

/// Connectivity check STUN message.
#[derive(Clone)]
pub struct CheckMessage {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    component: u8,
    data: Bytes,
}

impl CheckMessage {
    /// Get the local address from which the connectivity check must be sent.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the target address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the component ID.
    pub fn component(&self) -> u8 {
        self.component
    }

    /// Take the STUN message.
    pub fn take_data(self) -> Bytes {
        self.data
    }
}

/// Connectivity check error.
#[derive(Copy, Clone)]
pub enum CheckError {
    Failed,
    RoleConflict(AgentRole),
    UnknownTransaction(TransactionId),
}
