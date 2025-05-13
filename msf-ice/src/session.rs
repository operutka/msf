use std::{
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    candidate::{CandidateKind, LocalCandidate},
    AgentRole,
};

/// Credentials.
#[derive(Clone)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// Create random credentials.
    fn random() -> Self {
        Self {
            username: crate::utils::random_ice_string(4),
            password: crate::utils::random_ice_string(22),
        }
    }

    /// Create new credentials.
    #[inline]
    pub fn new<U, P>(username: U, password: P) -> Self
    where
        U: ToString,
        P: ToString,
    {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Get the username.
    #[inline]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password.
    #[inline]
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// ICE session.
#[derive(Clone)]
pub struct Session {
    context: Arc<Mutex<SessionContext>>,
}

impl Session {
    /// Create a new ICE session.
    pub fn new(agent_role: AgentRole, channels: usize) -> Self {
        Self {
            context: Arc::new(Mutex::new(SessionContext::new(agent_role, channels))),
        }
    }

    /// Lock the session for exclusive access.
    pub fn lock(&self) -> SessionGuard<'_> {
        SessionGuard {
            inner: self.context.lock().unwrap(),
        }
    }

    /// Get the current agent role.
    pub fn get_agent_role(&self) -> AgentRole {
        self.lock().get_agent_role()
    }

    /// Set the agent role.
    pub fn set_agent_role(&self, role: AgentRole) {
        self.lock().set_agent_role(role)
    }

    /// Get local credentials.
    pub fn get_local_credentials(&self, channel: usize) -> Credentials {
        self.lock().get_local_credentials(channel).clone()
    }

    /// Get remote credentials.
    pub fn get_remote_credentials(&self, channel: usize) -> Option<Credentials> {
        self.lock().get_remote_credentials(channel).cloned()
    }

    /// Set remote credentials.
    pub fn set_remote_credentials(&self, channel: usize, credentials: Credentials) {
        self.lock().set_remote_credentials(channel, credentials)
    }

    /// Assign a session-wide foundation to a given local candidate.
    pub fn assign_foundation(
        &self,
        candidate: &LocalCandidate,
        source_addr: Option<IpAddr>,
    ) -> u32 {
        self.lock().assign_foundation(candidate, source_addr)
    }
}

/// Session lock guard.
pub struct SessionGuard<'a> {
    inner: MutexGuard<'a, SessionContext>,
}

impl SessionGuard<'_> {
    /// Get the current agent role.
    pub fn get_agent_role(&self) -> AgentRole {
        self.inner.agent_role
    }

    /// Set agent role.
    pub fn set_agent_role(&mut self, role: AgentRole) {
        self.inner.agent_role = role;
    }

    /// Get local credentials.
    pub fn get_local_credentials(&self, channel: usize) -> &Credentials {
        let channel = &self.inner.channels[channel];

        channel.get_local_credentials()
    }

    /// Get remote credentials.
    pub fn get_remote_credentials(&self, channel: usize) -> Option<&Credentials> {
        let channel = &self.inner.channels[channel];

        channel.get_remote_credentials()
    }

    /// Set remote credentials.
    pub fn set_remote_credentials(&mut self, channel: usize, credentials: Credentials) {
        let channel = &mut self.inner.channels[channel];

        channel.set_remote_credentials(credentials);
    }

    /// Get the tie-breaker value.
    pub fn get_tie_breaker(&self) -> u64 {
        self.inner.tie_breaker
    }

    /// Assign a session-wide foundation to a given local candidate.
    ///
    /// NOTE: We expect that the transport protocol used for obtaining
    /// reflexive/relayed candidates is always UDP.
    pub fn assign_foundation(
        &mut self,
        candidate: &LocalCandidate,
        source_addr: Option<IpAddr>,
    ) -> u32 {
        let kind = candidate.kind();
        let base = candidate.base();

        assert!(kind == CandidateKind::Host || source_addr.is_some());

        let entry = FoundationEntry {
            candidate_kind: kind,
            candidate_base: base.ip(),
            source_addr,
        };

        let foundation_idx = self.inner.foundations.iter().position(|e| e == &entry);

        if let Some(index) = foundation_idx {
            index as u32
        } else {
            let index = self.inner.foundations.len();

            self.inner.foundations.push(entry);

            index as u32
        }
    }
}

/// Shared session context.
struct SessionContext {
    agent_role: AgentRole,
    tie_breaker: u64,
    channels: Vec<ChannelContext>,
    foundations: Vec<FoundationEntry>,
}

impl SessionContext {
    /// Create a new session context.
    fn new(agent_role: AgentRole, channels: usize) -> Self {
        let channel_count = channels;

        let mut channels = Vec::with_capacity(channel_count);

        channels.resize_with(channel_count, ChannelContext::new);

        Self {
            agent_role,
            tie_breaker: rand::random(),
            channels,
            foundations: Vec::new(),
        }
    }
}

/// Channel related session context.
struct ChannelContext {
    local_credentials: Credentials,
    remote_credentials: Option<Credentials>,
}

impl ChannelContext {
    /// Create a new channel context.
    fn new() -> Self {
        Self {
            local_credentials: Credentials::random(),
            remote_credentials: None,
        }
    }

    /// Get local credentials.
    fn get_local_credentials(&self) -> &Credentials {
        &self.local_credentials
    }

    /// Get remote credentials.
    fn get_remote_credentials(&self) -> Option<&Credentials> {
        self.remote_credentials.as_ref()
    }

    /// Set remote credentials.
    fn set_remote_credentials(&mut self, credentials: Credentials) {
        self.remote_credentials = Some(credentials);
    }
}

/// Foundation table entry.
#[derive(Eq, PartialEq)]
struct FoundationEntry {
    candidate_kind: CandidateKind,
    candidate_base: IpAddr,
    source_addr: Option<IpAddr>,
}
