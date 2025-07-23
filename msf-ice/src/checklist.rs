use std::{
    collections::VecDeque,
    net::SocketAddr,
    ops::Deref,
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use msf_stun as stun;

use crate::{
    candidate::{CandidatePair, LocalCandidate, RemoteCandidate},
    check::{Check, CheckError, CheckMessage},
    session::{Credentials, Session},
    AgentRole,
};

/// ICE checklist as defined in RFC 5245.
///
/// Please note that the scheduling logic is implemented according to RFC 8445
/// (with minor adjustments) in order to make things simpler. The original RFC
/// introduced quite complicated unfreezing logic that would require
/// orchestration across all checklists in a session. Moreover, it started with
/// only a single active checklist leading to sub-optimal performance in
/// situations where frozen checklists contained a pair with a foundation not
/// present in the active checklist.
///
/// The main difference between RFC 8445 scheduling and this implementation is
/// that this implementation treats all checklists as independent units, so
/// initially there will be one waiting pair for each foundation in the
/// checklist (for every checklist). This can lead to performing multiple
/// checks for a single foundation before the foundation gets completely
/// unfrozen. However, it shouldn't cause any significant issues in practice
/// because the number of media streams (and therefore checklists) is usually
/// quite small.
///
/// In addition, a successful check won't unfreeze all pairs with the same
/// foundation across all checklists. Since all checklists have initially one
/// waiting pair for each foundation, it should be sufficient to unfreeze only
/// the corresponding foundation group within the checklist that originated the
/// check.
pub struct Checklist {
    session: Session,
    agent_role: AgentRole,
    channel: usize,
    components: usize,
    local_candidates: Vec<LocalCandidate>,
    remote_candidates: Vec<RemoteCandidate>,
    checks: Vec<Check>,
    aux: Vec<Check>,
    triggered: VecDeque<TriggeredCheck>,
    valid: Vec<ValidPair>,
    task: Option<Waker>,
    scheduling: bool,
    done: bool,
}

impl Checklist {
    /// Create a new checklist.
    pub fn new(session: Session, channel: usize, components: usize) -> Self {
        let agent_role = session.get_agent_role();

        Self {
            session,
            agent_role,
            channel,
            components,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            checks: Vec::new(),
            aux: Vec::new(),
            triggered: VecDeque::new(),
            valid: Vec::new(),
            task: None,
            scheduling: false,
            done: true,
        }
    }

    /// Add a given local candidate.
    pub fn add_local_candidate(&mut self, candidate: LocalCandidate) {
        let new = candidate;

        // just a sanity check
        let old = self.local_candidates.iter().find(|c| {
            c.component() == new.component()
                && c.kind() == new.kind()
                && c.base() == new.base()
                && c.addr() == new.addr()
        });

        if old.is_some() {
            return;
        }

        self.local_candidates.push(new);

        for index in 0..self.remote_candidates.len() {
            // we cannot iterate directly over the candidate because we need to
            // borrow self in every iteration
            let remote = &self.remote_candidates[index];

            if let Ok(pair) = CandidatePair::new(new, remote.clone()) {
                self.add_check(pair, false);
            }
        }

        self.agent_role = self.session.get_agent_role();

        self.prune_checks();
    }

    /// Add a given remote candidate.
    pub fn add_remote_candidate(&mut self, candidate: RemoteCandidate) {
        let new = candidate;

        let old = self
            .remote_candidates
            .iter_mut()
            .find(|c| c.addr() == new.addr() && c.component() == new.component());

        if let Some(old) = old {
            if new.priority() > old.priority() {
                *old = new.clone();
            } else {
                return;
            }
        } else {
            self.remote_candidates.push(new.clone());
        }

        for index in 0..self.local_candidates.len() {
            // we cannot iterate directly over the candidate because we need to
            // borrow self in every iteration
            let local = &self.local_candidates[index];

            if let Ok(pair) = CandidatePair::new(*local, new.clone()) {
                self.add_check(pair, false);
            }
        }

        self.agent_role = self.session.get_agent_role();

        self.prune_checks();
    }

    /// Schedule the next check.
    ///
    /// The method returns `true` if the call scheduled a new check or `false`
    /// in case when there were no checks to be scheduled.
    pub fn schedule_check(&mut self) -> bool {
        if !self.scheduling {
            return false;
        }

        let session = self.session.clone();

        let session = session.lock();

        let agent_role = session.get_agent_role();
        let tie_breaker = session.get_tie_breaker();
        let local_credentials = session.get_local_credentials(self.channel);

        // note: if there are no remote credentials, there are also no remote
        // candidates and, therefore, no candidate pairs to be checked
        let remote_credentials = match session.get_remote_credentials(self.channel) {
            Some(credentials) => credentials,
            None => return false,
        };

        let local_username = local_credentials.username();
        let remote_username = remote_credentials.username();
        let remote_password = remote_credentials.password();

        let username = format!("{remote_username}:{local_username}");

        self.set_agent_role(agent_role);

        let mut index = None;

        while index.is_none() {
            if let Some(triggered) = self.triggered.pop_front() {
                index = self.find_check_position(|c| {
                    let local = c.local_candidate();
                    let remote = c.remote_candidate();

                    (c.is_frozen() || c.is_waiting())
                        && local.base() == triggered.local_base
                        && remote.addr() == triggered.remote_addr
                });
            } else {
                break;
            }
        }

        if index.is_none() {
            index = self.find_check_position(|c| c.is_waiting());
        }

        if index.is_none() {
            index = self.find_check_position(|c| c.is_frozen());
        }

        // note: optimization that will prevent iterating over all checks next
        // time
        self.scheduling = index.is_some();

        let check = match index {
            Some(idx) => &mut self.checks[idx],
            None => return false,
        };

        check.schedule(&username, remote_password, agent_role, tie_breaker);

        if let Some(task) = self.task.as_ref() {
            task.wake_by_ref();
        }

        true
    }

    /// Poll the checklist.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<CheckMessage> {
        let task = cx.waker();

        self.task = Some(task.clone());

        if self.done {
            return Poll::Pending;
        }

        let mut done = true;

        for component in 0..self.components {
            match self.poll_component(cx, component as u8) {
                Poll::Pending => done = false,
                Poll::Ready(Some(msg)) => return Poll::Ready(msg),
                Poll::Ready(None) => (),
            }
        }

        // note: optimization that will prevent iterating over all checks next
        // time
        self.done = done;

        Poll::Pending
    }

    /// Poll checks for a given component.
    fn poll_component(
        &mut self,
        cx: &mut Context<'_>,
        component: u8,
    ) -> Poll<Option<CheckMessage>> {
        loop {
            let mut pending = false;

            for check in &mut self.checks {
                if check.component() == component {
                    match check.poll(cx) {
                        Poll::Pending => pending = true,
                        Poll::Ready(Some(msg)) => return Poll::Ready(Some(msg)),
                        Poll::Ready(None) => (),
                    }
                }
            }

            if pending {
                return Poll::Pending;
            } else if self.agent_role == AgentRole::Controlled {
                return Poll::Ready(None);
            }

            let has_nominated_pair = self
                .checks
                .iter()
                .any(|check| check.component() == component && check.is_nominated());

            if has_nominated_pair {
                return Poll::Ready(None);
            }

            // get the valid pair with highest priority if any
            let valid = self
                .valid
                .iter()
                .filter(|pair| pair.component() == component)
                .max_by_key(|pair| pair.priority(AgentRole::Controlling));

            // nominate the pair by triggering the check again
            if let Some(valid) = valid {
                let pair = valid.pair.clone();

                let local = pair.local();
                let remote = pair.remote();

                let local_base = local.base();
                let remote_addr = remote.addr();

                self.add_check(pair, true);
                self.prune_checks();
                self.trigger_check(local_base, remote_addr);
            } else {
                return Poll::Ready(None);
            }
        }
    }

    /// Process a given STUN request.
    pub fn process_stun_request(
        &mut self,
        component: u8,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        request: &stun::Message,
    ) -> Bytes {
        let session = self.session.clone();

        let mut session = session.lock();

        let res = request.validate_request(
            session.get_local_credentials(self.channel),
            session.get_agent_role(),
            session.get_tie_breaker(),
        );

        if let Err(StunRequestError::LocalRoleConflict(role)) = res {
            session.set_agent_role(role);
        }

        let err_response = res.err().and_then(|err| {
            err.to_error_response(request, session.get_local_credentials(self.channel))
        });

        if let Some(response) = err_response {
            return response;
        }

        let attributes = request.attributes();

        // add a new peer-reflexive remote candidate if the remote address is
        // not known
        let remote = if let Some(candidate) = self.get_remote_candidate(component, remote_addr) {
            candidate.clone()
        } else {
            let priority = attributes.get_priority();

            let candidate = RemoteCandidate::peer_reflexive(
                self.channel,
                component,
                remote_addr,
                priority.unwrap_or(0),
            );

            self.remote_candidates.push(candidate.clone());

            candidate
        };

        if let Some(local) = self.get_local_candidate(component, local_addr) {
            let local = *local;

            let nominated =
                session.get_agent_role() == AgentRole::Controlled && attributes.get_use_candidate();

            let pair = CandidatePair::new(local, remote);

            self.add_check(pair.unwrap(), nominated);
            self.prune_checks();
            self.trigger_check(local.base(), remote_addr);
        }

        let key = session
            .get_local_credentials(self.channel)
            .password()
            .as_bytes();

        stun::MessageBuilder::success_response(request)
            .fingerprint(true)
            .xor_mapped_address(remote_addr)
            .message_integrity(key)
            .build()
    }

    /// Process a given STUN response.
    pub fn process_stun_response(
        &mut self,
        component: u8,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        response: &stun::Message,
    ) -> Option<&CandidatePair> {
        self.process_stun_response_inner(component, local_addr, remote_addr, response)
            .ok()
            .flatten()
    }

    /// Process a given STUN response.
    fn process_stun_response_inner(
        &mut self,
        component: u8,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        response: &stun::Message,
    ) -> Result<Option<&CandidatePair>, CheckError> {
        let check = self
            .find_check_mut(|c| c.transaction_id() == Some(response.transaction_id()))
            .ok_or(CheckError::UnknownTransaction)?;

        let nominated = check.is_nominated();
        let source_pair = check.candidate_pair();
        let source_pair = source_pair.clone();

        if let Err(err) = check.process_stun_response(local_addr, remote_addr, response) {
            // we need to trigger the check again in case of a role conflict
            if let CheckError::RoleConflict(old) = err {
                self.session.set_agent_role(old.reverse());

                let local = source_pair.local();
                let remote = source_pair.remote();

                self.trigger_check(local.base(), remote.addr());
            }

            return Err(err);
        }

        for check in &mut self.checks {
            if check.foundation() == source_pair.foundation() && check.is_frozen() {
                check.unfreeze();
            }
        }

        let mut local = *source_pair.local();

        // note: the foundation does not matter here
        if let Some(reflexive_addr) = response.attributes().get_xor_mapped_address() {
            if local.addr() != reflexive_addr {
                local = LocalCandidate::peer_reflexive(
                    local.channel(),
                    local.component(),
                    local.base(),
                    reflexive_addr,
                );
            }
        }

        let remote = source_pair.remote();

        if let Ok(pair) = CandidatePair::new(local, remote.clone()) {
            self.add_valid_pair(pair, nominated);
        }

        Ok(self.get_nominated_pair(component))
    }

    /// Update the agent role used by this checklist.
    fn set_agent_role(&mut self, role: AgentRole) {
        if self.agent_role == role {
            return;
        }

        self.agent_role = role;

        // sort the checklist again if the agent role has changed
        self.sort_checks();
    }

    /// Get a local candidate for a given component having a given address.
    fn get_local_candidate(&self, component: u8, addr: SocketAddr) -> Option<&LocalCandidate> {
        self.local_candidates
            .iter()
            .find(|c| c.component() == component && c.addr() == addr)
    }

    /// Get a remote candidate for a given component having a given address.
    fn get_remote_candidate(&self, component: u8, addr: SocketAddr) -> Option<&RemoteCandidate> {
        self.remote_candidates
            .iter()
            .find(|c| c.component() == component && c.addr() == addr)
    }

    /// Create a new connectivity check for a given candidate pair.
    fn add_check(&mut self, pair: CandidatePair, nominated: bool) {
        let mut check = Check::new(pair, nominated);

        // we can immediately switch the pair into the waiting state if the
        // foundation is not present in the checklist or if there is at least
        // one successful check with the corresponding foundation group
        let (all, successful) = self
            .checks
            .iter()
            .filter(|c| c.foundation() == check.foundation())
            .fold((0, 0), |(all, successful), c| {
                if c.is_success() {
                    (all + 1, successful + 1)
                } else {
                    (all + 1, successful)
                }
            });

        if all == 0 || successful > 0 {
            check.unfreeze();
        }

        self.checks.push(check);

        self.scheduling = true;
        self.done = false;

        if let Some(task) = self.task.as_ref() {
            task.wake_by_ref();
        }
    }

    /// Sort the connectivity checks by their priority.
    fn sort_checks(&mut self) {
        self.checks.sort_unstable_by(|a, b| {
            let a = a.priority(self.agent_role);
            let b = b.priority(self.agent_role);

            b.cmp(&a)
        })
    }

    /// Prune the checklist.
    fn prune_checks(&mut self) {
        self.sort_checks();

        let mut checks = std::mem::take(&mut self.checks);

        // put the auxiliary vector in place of checks to avoid excessive
        // allocations (`self.aux` will be an empty `Vec` after this call)
        std::mem::swap(&mut self.checks, &mut self.aux);

        self.checks.clear();

        for check in checks.drain(..) {
            let local = check.local_candidate();
            let remote = check.remote_candidate();

            let prev = self.get_check_mut(local.base(), remote.addr());

            if let Some(prev) = prev {
                prev.update(check);
            } else {
                self.checks.push(check);
            }
        }

        // reuse the original vector as auxiliary
        self.aux = checks;
    }

    /// Get a connectivity check between a given local base address and a given
    /// remote address.
    fn get_check_mut(
        &mut self,
        local_base: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&mut Check> {
        self.find_check_mut(|c| {
            let local = c.local_candidate();
            let remote = c.remote_candidate();

            local.base() == local_base && remote.addr() == remote_addr
        })
    }

    /// Find a connectivity check matching a given predicate.
    fn find_check_mut<F>(&mut self, f: F) -> Option<&mut Check>
    where
        F: FnMut(&Check) -> bool,
    {
        self.find_check_position(f).map(|idx| &mut self.checks[idx])
    }

    /// Find position of a connectivity check matching a given predicate.
    fn find_check_position<F>(&self, f: F) -> Option<usize>
    where
        F: FnMut(&Check) -> bool,
    {
        self.checks.iter().position(f)
    }

    /// Trigger check for a given candidate pair.
    ///
    /// The triggered check will be scheduled as soon as there is a free check
    /// slot.
    fn trigger_check(&mut self, local_base: SocketAddr, remote_addr: SocketAddr) {
        // NOTE: We need to reset the state of the corresponding check to
        // "waiting". See RFC 5245, section 7.2.1.4 for more details.
        if let Some(check) = self.get_check_mut(local_base, remote_addr) {
            if !check.is_success() {
                check.trigger();
            }
        }

        self.triggered
            .push_back(TriggeredCheck::new(local_base, remote_addr));

        self.scheduling = true;
        self.done = false;

        if let Some(task) = self.task.as_ref() {
            task.wake_by_ref();
        }
    }

    /// Cancel all checks for a given component.
    fn cancel_checks(&mut self, component: u8) {
        for check in &mut self.checks {
            if check.component() == component {
                check.cancel();
            }
        }
    }

    /// Finish all checks for a given component ASAP.
    fn finish_checks(&mut self, component: u8) {
        for check in &mut self.checks {
            if check.component() == component && !check.is_nominated() {
                check.finish();
            }
        }
    }

    /// Add a new valid pair.
    fn add_valid_pair(&mut self, pair: CandidatePair, nominated: bool) {
        let local = pair.local();
        let remote = pair.remote();
        let component = pair.component();

        let existing = self.valid.iter_mut().find(|pair| {
            let l = pair.local();
            let r = pair.remote();

            l.addr() == local.addr() && r.addr() == remote.addr()
        });

        if let Some(valid) = existing {
            if pair.priority(self.agent_role) > valid.priority(self.agent_role) {
                valid.pair = pair;
            }

            valid.nominated |= nominated;
        } else {
            self.valid.push(ValidPair::new(pair, nominated));
        }

        if nominated {
            self.cancel_checks(component);
        } else if self.agent_role == AgentRole::Controlling {
            self.finish_checks(component);

            // wake-up the polling task in order to schedule nomination
            if let Some(task) = self.task.as_ref() {
                task.wake_by_ref();
            }
        }
    }

    /// Get nominated pair for a given component ID.
    fn get_nominated_pair(&self, component: u8) -> Option<&CandidatePair> {
        self.valid
            .iter()
            .find(|pair| pair.component() == component && pair.nominated)
            .map(|pair| &pair.pair)
    }
}

/// Triggered check identifier.
struct TriggeredCheck {
    local_base: SocketAddr,
    remote_addr: SocketAddr,
}

impl TriggeredCheck {
    /// Create a new triggered check ID.
    fn new(local_base: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            local_base,
            remote_addr,
        }
    }
}

/// Valid candidate pair.
struct ValidPair {
    pair: CandidatePair,
    nominated: bool,
}

impl ValidPair {
    /// Create a new valid candidate pair.
    fn new(pair: CandidatePair, nominated: bool) -> Self {
        Self { pair, nominated }
    }
}

impl Deref for ValidPair {
    type Target = CandidatePair;

    fn deref(&self) -> &Self::Target {
        &self.pair
    }
}

/// Helper trait.
trait StunMessageExt {
    /// Authenticate the request.
    fn authenticate_request(&self, credentials: &Credentials) -> Result<(), StunRequestError>;

    /// Validate the request.
    fn validate_request(
        &self,
        credentials: &Credentials,
        agent_role: AgentRole,
        tie_breaker: u64,
    ) -> Result<(), StunRequestError>;
}

impl StunMessageExt for stun::Message {
    fn authenticate_request(&self, credentials: &Credentials) -> Result<(), StunRequestError> {
        let user = credentials.username();
        let pwd = credentials.password();

        let attributes = self.attributes();

        if let Some(username) = attributes.get_username() {
            let username = username
                .split_once(':')
                .map(|(local, _)| local)
                .ok_or(StunRequestError::InvalidCredentials)?;

            if username == user {
                self.check_st_credentials(pwd.as_bytes())
                    .map_err(StunRequestError::from)
            } else {
                Err(StunRequestError::InvalidCredentials)
            }
        } else {
            Err(StunRequestError::MissingCredentials)
        }
    }

    fn validate_request(
        &self,
        credentials: &Credentials,
        agent_role: AgentRole,
        tie_breaker: u64,
    ) -> Result<(), StunRequestError> {
        self.authenticate_request(credentials)?;

        let attributes = self.attributes();
        let unknown_attributes = self.unknown_attributes();

        if !unknown_attributes.is_empty() {
            return Err(StunRequestError::UnknownAttributes);
        }

        attributes
            .get_priority()
            .ok_or(StunRequestError::MissingPriority)?;

        if let Some(n) = attributes.get_ice_controlling() {
            if agent_role == AgentRole::Controlling {
                return if tie_breaker < n {
                    Err(StunRequestError::LocalRoleConflict(AgentRole::Controlled))
                } else {
                    Err(StunRequestError::RemoteRoleConflict)
                };
            }
        }

        if let Some(n) = attributes.get_ice_controlled() {
            if agent_role == AgentRole::Controlled {
                return if tie_breaker < n {
                    Err(StunRequestError::RemoteRoleConflict)
                } else {
                    Err(StunRequestError::LocalRoleConflict(AgentRole::Controlling))
                };
            }
        }

        Ok(())
    }
}

/// STUN request error.
enum StunRequestError {
    MissingCredentials,
    InvalidCredentials,
    UnknownAttributes,
    MissingPriority,
    RemoteRoleConflict,
    LocalRoleConflict(AgentRole),
}

impl StunRequestError {
    /// Create an error response for this request.
    fn to_error_response(
        &self,
        request: &stun::Message,
        credentials: &Credentials,
    ) -> Option<Bytes> {
        let pwd = credentials.password();

        let mut builder = stun::MessageBuilder::response(stun::MessageClass::Error, request);

        builder.fingerprint(true);

        match self {
            Self::MissingCredentials => {
                builder.error_code(stun::ErrorCode::BAD_REQUEST);
            }
            Self::InvalidCredentials => {
                builder.error_code(stun::ErrorCode::UNAUTHORIZED);
            }
            Self::UnknownAttributes => {
                builder
                    .error_code(stun::ErrorCode::UNKNOWN_ATTRIBUTES)
                    .unknown_attributes(request.unknown_attributes())
                    .message_integrity(pwd.as_bytes());
            }
            Self::MissingPriority => {
                builder
                    .error_code(stun::ErrorCode::BAD_REQUEST)
                    .message_integrity(pwd.as_bytes());
            }
            Self::RemoteRoleConflict => {
                builder
                    .error_code(stun::ErrorCode::ROLE_CONFLICT)
                    .message_integrity(pwd.as_bytes());
            }
            _ => return None,
        }

        Some(builder.build())
    }
}

impl From<stun::IntegrityError> for StunRequestError {
    fn from(err: stun::IntegrityError) -> Self {
        match err {
            stun::IntegrityError::Missing => Self::MissingCredentials,
            stun::IntegrityError::Invalid => Self::InvalidCredentials,
        }
    }
}
