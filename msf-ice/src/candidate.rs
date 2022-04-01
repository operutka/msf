use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

use crate::AgentRole;

/// Candidate type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relayed,
}

/// Local candidate.
#[derive(Copy, Clone)]
pub struct LocalCandidate {
    channel: usize,
    component: u8,
    kind: CandidateKind,
    base: SocketAddr,
    addr: SocketAddr,
    foundation: u32,
    priority: u32,
}

impl LocalCandidate {
    /// Calculate local candidate priority for a given component ID, candidate
    /// type and the candidate base address.
    #[inline]
    pub const fn calculate_priority(component: u8, kind: CandidateKind, base: SocketAddr) -> u32 {
        let type_preference = match kind {
            CandidateKind::Host => 126,
            CandidateKind::PeerReflexive => 110,
            CandidateKind::ServerReflexive => 100,
            CandidateKind::Relayed => 0,
        };

        let local_preference = if matches!(base, SocketAddr::V6(_)) {
            65_535
        } else {
            65_534
        };

        type_preference << 24 | local_preference << 8 | (255 - component as u32)
    }

    /// Create a new host candidate.
    #[inline]
    pub const fn host(channel: usize, component: u8, addr: SocketAddr) -> Self {
        Self {
            channel,
            component,
            kind: CandidateKind::Host,
            base: addr,
            addr,
            foundation: 0,
            priority: Self::calculate_priority(component, CandidateKind::Host, addr),
        }
    }

    /// Create a new server-reflexive candidate.
    #[inline]
    pub const fn server_reflexive(
        channel: usize,
        component: u8,
        base: SocketAddr,
        addr: SocketAddr,
    ) -> Self {
        Self {
            channel,
            component,
            kind: CandidateKind::ServerReflexive,
            base,
            addr,
            foundation: 0,
            priority: Self::calculate_priority(component, CandidateKind::ServerReflexive, base),
        }
    }

    /// Create a new peer-reflexive candidate.
    #[inline]
    pub const fn peer_reflexive(
        channel: usize,
        component: u8,
        base: SocketAddr,
        addr: SocketAddr,
    ) -> Self {
        Self {
            channel,
            component,
            kind: CandidateKind::PeerReflexive,
            base,
            addr,
            foundation: 0,
            priority: Self::calculate_priority(component, CandidateKind::PeerReflexive, base),
        }
    }

    /// Create a new relayed candidate.
    #[inline]
    pub const fn relayed(channel: usize, component: u8, addr: SocketAddr) -> Self {
        // NOTE: addr and base are the same for relayed candidates because we
        // do not use a specific local transport address to deliver data to the
        // corresponding TURN server (i.e. the local address can be arbitrary)
        Self {
            channel,
            component,
            kind: CandidateKind::Relayed,
            base: addr,
            addr,
            foundation: 0,
            priority: Self::calculate_priority(component, CandidateKind::Relayed, addr),
        }
    }

    /// Create a new candidate with a given foundation value.
    #[inline]
    pub fn with_foundation(mut self, foundation: u32) -> Self {
        self.foundation = foundation;
        self
    }

    /// Get index of the (media) channel this candidate belongs to.
    #[inline]
    pub fn channel(&self) -> usize {
        self.channel
    }

    /// Get component ID of the component this candidate belongs to.
    ///
    /// # Note
    /// Unlike the component ID definition in RFC 5245, this component ID is
    /// zero-based. In order to get the RFC 5245 component ID (e.g. to create
    /// a session description), you need to add one to this number.
    #[inline]
    pub fn component(&self) -> u8 {
        self.component
    }

    /// Get type of the candidate.
    #[inline]
    pub fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// Get the base address.
    #[inline]
    pub fn base(&self) -> SocketAddr {
        self.base
    }

    /// Get the address.
    #[inline]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get candidate priority.
    #[inline]
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Get the foundation.
    #[inline]
    pub fn foundation(&self) -> u32 {
        self.foundation
    }
}

/// Remote candidate.
#[derive(Clone)]
pub struct RemoteCandidate {
    channel: usize,
    component: u8,
    kind: CandidateKind,
    addr: SocketAddr,
    foundation: String,
    priority: u32,
}

impl RemoteCandidate {
    /// Create a new remote candidate.
    ///
    /// # Note
    /// Unlike the component ID definition in RFC 5245, this component ID is
    /// zero-based. If you're creating a new remote candidate from an RFC 5245
    /// component ID (e.g. from a session description), make sure to subtract
    /// one.
    #[inline]
    pub fn new<T>(
        channel: usize,
        component: u8,
        kind: CandidateKind,
        addr: SocketAddr,
        foundation: T,
        priority: u32,
    ) -> Self
    where
        T: ToString,
    {
        Self {
            channel,
            component,
            kind,
            addr,
            foundation: foundation.to_string(),
            priority,
        }
    }

    /// Create a new peer-reflexive remote candidate.
    #[inline]
    pub fn peer_reflexive(channel: usize, component: u8, addr: SocketAddr, priority: u32) -> Self {
        Self {
            channel,
            component,
            kind: CandidateKind::PeerReflexive,
            addr,
            foundation: addr.to_string(),
            priority,
        }
    }

    /// Get index of the (media) channel this candidate belongs to.
    #[inline]
    pub fn channel(&self) -> usize {
        self.channel
    }

    /// Get component ID of the component this candidate belongs to.
    #[inline]
    pub fn component(&self) -> u8 {
        self.component
    }

    /// Get type of the candidate.
    #[inline]
    pub fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// Get the address.
    #[inline]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get candidate priority.
    #[inline]
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Get the foundation.
    #[inline]
    pub fn foundation(&self) -> &str {
        &self.foundation
    }
}

/// Local-remote candidate pair.
#[derive(Clone)]
pub struct CandidatePair {
    local: LocalCandidate,
    remote: RemoteCandidate,
    foundation: String,
}

impl CandidatePair {
    /// Create a new candidate pair.
    pub fn new(
        local: LocalCandidate,
        remote: RemoteCandidate,
    ) -> Result<Self, InvalidCandidatePair> {
        if local.channel != remote.channel || local.component != remote.component {
            return Err(InvalidCandidatePair);
        }

        let local_addr = local.addr();

        match remote.addr() {
            SocketAddr::V4(_) if local_addr.is_ipv4() => (),
            SocketAddr::V6(_) if local_addr.is_ipv6() => (),
            _ => return Err(InvalidCandidatePair),
        }

        let foundation = format!("{}:{}", local.foundation(), remote.foundation());

        let res = Self {
            local,
            remote,
            foundation,
        };

        Ok(res)
    }

    /// Get the local candidate.
    pub fn local(&self) -> &LocalCandidate {
        &self.local
    }

    /// Get the remote candidate.
    pub fn remote(&self) -> &RemoteCandidate {
        &self.remote
    }

    /// Get the pair priority.
    pub fn priority(&self, local_role: AgentRole) -> u64 {
        let (g, d) = match local_role {
            AgentRole::Controlling => (self.local.priority(), self.remote.priority()),
            AgentRole::Controlled => (self.remote.priority(), self.local.priority()),
        };

        let min = g.min(d) as u64;
        let max = g.max(d) as u64;

        (min << 32) + (max << 1) + u64::from(g > d)
    }

    /// Get the component ID.
    pub fn component(&self) -> u8 {
        self.remote.component()
    }

    /// Get foundation of the pair.
    pub fn foundation(&self) -> &str {
        &self.foundation
    }
}

/// Invalid candidate pair.
#[derive(Debug, Copy, Clone)]
pub struct InvalidCandidatePair;

impl Display for InvalidCandidatePair {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("the given local and remote candidates do not form a pair")
    }
}

impl Error for InvalidCandidatePair {}
