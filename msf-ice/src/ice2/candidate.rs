use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    ops::Deref,
};

use bytes::Bytes;

use crate::AgentRole;

/// Candidate type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relayed,
}

/// Local candidate foundation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct LocalFoundation {
    inner: [u8; 16],
}

impl LocalFoundation {
    /// Create a new local foundation for a given candidate kind, base IP
    /// address and a STUN/TURN server IP address (if any).
    ///
    /// We calculate the foundation as an MD5 hash of the candidate kind,
    /// base IP address and the STUN/TURN IP address. We use hashing because
    /// the foundation string length during candidate exchange is limited.
    /// Even though hash collisions are possible, they aren't very likely
    /// for standard deployment and even if there is a hash collision, it
    /// shouldn't cause much trouble. It could only delay unfreezing of some
    /// candidate pairs during connectivity checks.
    fn new(kind: CandidateKind, base: IpAddr, source: Option<IpAddr>) -> Self {
        // helper function
        fn consume_ip_addr(ctx: &mut md5::Context, addr: IpAddr) {
            match addr {
                IpAddr::V4(addr) => {
                    ctx.consume(&[0x01]);
                    ctx.consume(addr.octets());
                }
                IpAddr::V6(addr) => {
                    ctx.consume(&[0x02]);
                    ctx.consume(addr.octets());
                }
            }
        }

        let mut ctx = md5::Context::new();

        let kind: u8 = match kind {
            CandidateKind::Host => 0x00,
            CandidateKind::ServerReflexive => 0x10,
            CandidateKind::PeerReflexive => 0x20,
            CandidateKind::Relayed => 0x30,
        };

        ctx.consume(&[kind]);

        consume_ip_addr(&mut ctx, base);

        if let Some(source) = source {
            consume_ip_addr(&mut ctx, source);
        }

        let digest = ctx.finalize();

        Self {
            inner: digest.into(),
        }
    }
}

impl Display for LocalFoundation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for b in self.inner {
            write!(f, "{b:02x}")?;
        }

        Ok(())
    }
}

/// Local candidate.
#[derive(Clone)]
pub struct LocalCandidate {
    data_stream: usize,
    component: u8,
    kind: CandidateKind,
    base: SocketAddr,
    addr: SocketAddr,
    foundation: LocalFoundation,
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

        // TODO: Make sure the priority is unique if there are multiple host
        //   candidates for every IP family. For example, we could calculate
        //   it as 65535 - index, where index is either local IP index, STUN
        //   server index or TURN server index.

        let local_preference = if matches!(base, SocketAddr::V6(_)) {
            65_535
        } else {
            65_534
        };

        type_preference << 24 | local_preference << 8 | (255 - component as u32)
    }

    /// Create a new host candidate.
    #[inline]
    pub fn host(data_stream: usize, component: u8, addr: SocketAddr) -> Self {
        let kind = CandidateKind::Host;
        let foundation = LocalFoundation::new(kind, addr.ip(), None);
        let priority = Self::calculate_priority(component, kind, addr);

        Self {
            data_stream,
            component,
            kind,
            base: addr,
            addr,
            foundation,
            priority,
        }
    }

    /// Create a new server-reflexive candidate.
    #[inline]
    pub fn server_reflexive(
        data_stream: usize,
        component: u8,
        base: SocketAddr,
        addr: SocketAddr,
        stun_server: SocketAddr,
    ) -> Self {
        let kind = CandidateKind::ServerReflexive;
        let foundation = LocalFoundation::new(kind, base.ip(), Some(stun_server.ip()));
        let priority = Self::calculate_priority(component, kind, base);

        Self {
            data_stream,
            component,
            kind,
            base,
            addr,
            foundation,
            priority,
        }
    }

    /// Create a new peer-reflexive candidate.
    #[inline]
    pub fn peer_reflexive(
        data_stream: usize,
        component: u8,
        base: SocketAddr,
        addr: SocketAddr,
    ) -> Self {
        let kind = CandidateKind::PeerReflexive;
        let foundation = LocalFoundation::new(kind, base.ip(), None);
        let priority = Self::calculate_priority(component, kind, base);

        Self {
            data_stream,
            component,
            kind,
            base,
            addr,
            foundation,
            priority,
        }
    }

    /// Create a new relayed candidate.
    #[inline]
    pub fn relayed(
        data_stream: usize,
        component: u8,
        addr: SocketAddr,
        turn_server: SocketAddr,
    ) -> Self {
        let kind = CandidateKind::Relayed;
        let foundation = LocalFoundation::new(kind, addr.ip(), Some(turn_server.ip()));
        let priority = Self::calculate_priority(component, kind, addr);

        Self {
            data_stream,
            component,
            kind,
            base: addr,
            addr,
            foundation,
            priority,
        }
    }

    /// Get index of the data stream this candidate belongs to.
    #[inline]
    pub fn data_stream(&self) -> usize {
        self.data_stream
    }

    /// Get component ID of the component this candidate belongs to.
    ///
    /// # Note
    /// Unlike the component ID definition in RFC 8445, this component ID is
    /// zero-based. In order to get the RFC 8445 component ID (e.g. to create
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
    ///
    /// This is the local address for host, server-reflexive and peer-reflexive
    /// candidates and the relayed address for relayed candidates as specified
    /// by RFC 8445.
    #[inline]
    pub fn base(&self) -> SocketAddr {
        self.base
    }

    /// Get the candidate address.
    ///
    /// This is the candidate address as specified by RFC 8445 (i.e. a
    /// potential point of contact for receipt of data).
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
    pub fn foundation(&self) -> &LocalFoundation {
        &self.foundation
    }
}

/// Remote candidate foundation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RemoteFoundation {
    inner: Bytes,
}

impl AsRef<str> for RemoteFoundation {
    fn as_ref(&self) -> &str {
        // SAFETY: The `RemoteFoundation` instance can be constructed only from
        //   `String` instances, so this is safe.
        unsafe { str::from_utf8_unchecked(&self.inner) }
    }
}

impl Deref for RemoteFoundation {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Display for RemoteFoundation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl From<String> for RemoteFoundation {
    fn from(s: String) -> Self {
        Self { inner: s.into() }
    }
}

/// Remote candidate.
#[derive(Clone)]
pub struct RemoteCandidate {
    data_stream: usize,
    component: u8,
    kind: CandidateKind,
    addr: SocketAddr,
    foundation: RemoteFoundation,
    priority: u32,
}

impl RemoteCandidate {
    /// Create a new remote candidate.
    ///
    /// # Note
    /// Unlike the component ID definition in RFC 8445, this component ID is
    /// zero-based. If you're creating a new remote candidate from an RFC 8445
    /// component ID (e.g. from a session description), make sure to subtract
    /// one.
    pub fn new<T>(
        data_stream: usize,
        component: u8,
        kind: CandidateKind,
        addr: SocketAddr,
        foundation: T,
        priority: u32,
    ) -> Self
    where
        T: Into<String>,
    {
        Self {
            data_stream,
            component,
            kind,
            addr,
            foundation: RemoteFoundation::from(foundation.into()),
            priority,
        }
    }

    /// Create a new peer-reflexive remote candidate.
    #[inline]
    pub fn peer_reflexive(
        data_stream: usize,
        component: u8,
        addr: SocketAddr,
        priority: u32,
    ) -> Self {
        let ip = addr.ip();

        Self {
            data_stream,
            component,
            kind: CandidateKind::PeerReflexive,
            addr,
            foundation: RemoteFoundation::from(ip.to_string()),
            priority,
        }
    }

    /// Get index of the data stream this candidate belongs to.
    #[inline]
    pub fn data_stream(&self) -> usize {
        self.data_stream
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
    pub fn foundation(&self) -> &RemoteFoundation {
        &self.foundation
    }
}

/// Local-remote candidate foundation pair.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FoundationPair {
    local: LocalFoundation,
    remote: RemoteFoundation,
}

/// Local-remote candidate pair.
#[derive(Clone)]
pub struct CandidatePair {
    local: LocalCandidate,
    remote: RemoteCandidate,
    foundation: FoundationPair,
}

impl CandidatePair {
    /// Create a new candidate pair.
    pub fn new(
        local: LocalCandidate,
        remote: RemoteCandidate,
    ) -> Result<Self, InvalidCandidatePair> {
        if local.data_stream != remote.data_stream || local.component != remote.component {
            return Err(InvalidCandidatePair);
        }

        let local_ip = local.addr.ip();
        let remote_ip = remote.addr.ip();

        let is_valid = match local_ip {
            IpAddr::V4(_) => remote_ip.is_ipv4(),
            IpAddr::V6(local_ip) => match remote_ip {
                IpAddr::V4(_) => false,
                IpAddr::V6(remote_ip) => {
                    local_ip.is_unicast_link_local() == remote_ip.is_unicast_link_local()
                }
            },
        };

        if !is_valid {
            return Err(InvalidCandidatePair);
        }

        let foundation = FoundationPair {
            local: local.foundation,
            remote: remote.foundation.clone(),
        };

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

    /// Get the component ID.
    pub fn component(&self) -> u8 {
        self.remote.component()
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

    /// Get the foundation pair.
    pub fn foundation(&self) -> &FoundationPair {
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
