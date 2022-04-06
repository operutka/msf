#[cfg(feature = "log")]
#[macro_use]
extern crate log;

#[cfg(feature = "slog")]
#[macro_use]
extern crate slog;

mod candidate;
mod channel;
mod check;
mod checklist;
mod session;
mod socket;
mod utils;

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{channel::mpsc, ready, FutureExt, StreamExt};
use tokio::time::Sleep;

#[cfg(feature = "slog")]
use slog::{Discard, Logger};

use self::{channel::Channel, session::Session};

pub use self::{
    candidate::{CandidateKind, LocalCandidate, RemoteCandidate},
    channel::{ChannelBuilder, Component},
    session::Credentials,
    socket::Packet,
};

/// ICE agent role.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum AgentRole {
    /// Agents who initiated the connection.
    Controlling,
    /// Agents who did not initiate the connection.
    Controlled,
}

impl AgentRole {
    /// Reverse the agent role.
    fn reverse(self) -> Self {
        match self {
            Self::Controlled => Self::Controlling,
            Self::Controlling => Self::Controlled,
        }
    }
}

/// ICE agent builder.
pub struct AgentBuilder {
    #[cfg(feature = "slog")]
    logger: Logger,
    agent_role: AgentRole,
    local_addresses: Vec<IpAddr>,
    channels: Vec<ChannelBuilder>,
    check_interval: Duration,
}

impl AgentBuilder {
    /// Create a new builder.
    fn new(agent_role: AgentRole) -> Self {
        Self {
            #[cfg(feature = "slog")]
            logger: Logger::root(Discard, o!()),
            agent_role,
            local_addresses: Vec::new(),
            channels: Vec::new(),
            check_interval: Duration::from_millis(50),
        }
    }

    /// Use a given logger.
    #[cfg(feature = "slog")]
    #[inline]
    pub fn logger(&mut self, logger: Logger) -> &mut Self {
        self.logger = logger;
        self
    }

    /// Add given local address.
    #[inline]
    pub fn local_address(&mut self, addr: IpAddr) -> &mut Self {
        self.local_addresses.push(addr);
        self
    }

    /// Add a new channel.
    ///
    /// The method returns a channel builder where components can be created.
    #[inline]
    pub fn channel(&mut self) -> &mut ChannelBuilder {
        let create = self
            .channels
            .last()
            .map(|last| !last.is_empty())
            .unwrap_or(true);

        if create {
            self.channels.push(Channel::builder(self.channels.len()));
        }

        self.channels.last_mut().unwrap()
    }

    /// Build the agent.
    pub fn build(mut self) -> Agent {
        self.local_addresses.sort_unstable();
        self.local_addresses.dedup();

        if self.local_addresses.is_empty() {
            self.local_addresses
                .push(IpAddr::from(Ipv4Addr::UNSPECIFIED));
        }

        let session = Session::new(self.agent_role, self.channels.len());

        #[cfg(not(feature = "slog"))]
        let channels = self
            .channels
            .into_iter()
            .filter(|channel| !channel.is_empty())
            .map(|channel| channel.build(session.clone(), &self.local_addresses))
            .collect();

        #[cfg(feature = "slog")]
        let channels = self
            .channels
            .into_iter()
            .filter(|channel| !channel.is_empty())
            .map(|channel| {
                channel.build(self.logger.clone(), session.clone(), &self.local_addresses)
            })
            .collect();

        let (local_candidate_tx, local_candidate_rx) = mpsc::unbounded();
        let (remote_candidate_tx, remote_candidate_rx) = mpsc::unbounded();

        let task = AgentTask {
            session: session.clone(),
            channels,
            remote_candidate_rx,
            local_candidate_tx: Some(local_candidate_tx),
            last_check: Instant::now(),
            next_check: Box::pin(tokio::time::sleep(self.check_interval)),
            check_interval: self.check_interval,
            check_tokens: 1,
        };

        let channel_count = task.channels.len();

        tokio::spawn(task);

        Agent {
            session,
            channels: channel_count,
            local_candidate_rx,
            remote_candidate_tx,
        }
    }
}

/// ICE agent.
///
/// # Usage
/// 0. Get all components and prepare them for data/media transmission.
/// 1. Get the local credentials for all channels and send them over to a
///    remote agent.
/// 2. Get all local candidates and send them over to the remote agent.
/// 3. Set remote credentials for all channels (required to be done before
///    adding remote candidates).
/// 4. Add remote candidates.
/// 5. If there are no more remote candidates, conclude connectivity checks.
pub struct Agent {
    session: Session,
    channels: usize,
    local_candidate_rx: mpsc::UnboundedReceiver<LocalCandidate>,
    remote_candidate_tx: mpsc::UnboundedSender<NewRemoteCandidate>,
}

impl Agent {
    /// Get an ICE agent builder.
    #[inline]
    pub fn builder(agent_role: AgentRole) -> AgentBuilder {
        AgentBuilder::new(agent_role)
    }

    /// Get the next local candidate.
    #[inline]
    pub fn poll_next_local_candidate(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<LocalCandidate>> {
        if let Some(candidate) = ready!(self.local_candidate_rx.poll_next_unpin(cx)) {
            Poll::Ready(Some(candidate))
        } else {
            Poll::Ready(None)
        }
    }

    /// Get the next local candidate.
    #[inline]
    pub async fn next_local_candidate(&mut self) -> Option<LocalCandidate> {
        futures::future::poll_fn(|cx| self.poll_next_local_candidate(cx)).await
    }

    /// Get the number of channels.
    #[inline]
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Get local credentials of a given channel.
    #[inline]
    pub fn get_local_credentials(&self, channel: usize) -> Credentials {
        self.session.get_local_credentials(channel)
    }

    /// Get remote credentials of a given channel (if known).
    #[inline]
    pub fn get_remote_credentials(&self, channel: usize) -> Option<Credentials> {
        self.session.get_remote_credentials(channel)
    }

    /// Set remote credentials for a given channel.
    #[inline]
    pub fn set_remote_credentials(&mut self, channel: usize, credentials: Credentials) {
        self.session.set_remote_credentials(channel, credentials);
    }

    /// Add a given remote candidate.
    ///
    /// # Panics
    /// The method will panic if the remote credentials for the corresponding
    /// channel have not been set.
    pub fn add_remote_candidate(
        &mut self,
        candidate: RemoteCandidate,
        username_fragment: Option<&str>,
    ) {
        let channel = candidate.channel();

        if channel >= self.channels {
            return;
        }

        self.session
            .lock()
            .get_remote_credentials(channel)
            .expect("missing remote credentials");

        self.remote_candidate_tx
            .unbounded_send(NewRemoteCandidate::new(candidate, username_fragment))
            .unwrap()
    }
}

/// Background task of the corresponding ICE agent.
struct AgentTask {
    session: Session,
    channels: Vec<Channel>,
    remote_candidate_rx: mpsc::UnboundedReceiver<NewRemoteCandidate>,
    local_candidate_tx: Option<mpsc::UnboundedSender<LocalCandidate>>,
    last_check: Instant,
    next_check: Pin<Box<Sleep>>,
    check_interval: Duration,
    check_tokens: u32,
}

impl AgentTask {
    /// Process a given remote candidate.
    fn process_remote_candidate(&mut self, candidate: NewRemoteCandidate) {
        // drop the candidate if the channel index is out of bounds or if the
        // username fragment does not match
        if let Some(channel) = self.channels.get_mut(candidate.channel()) {
            let is_from_current_session = self
                .session
                .lock()
                .get_remote_credentials(candidate.channel())
                .map(|credentials| {
                    candidate
                        .username_fragment()
                        .map(|username| username == credentials.username())
                        .unwrap_or(true)
                })
                .unwrap_or(false);

            if is_from_current_session {
                channel.process_remote_candidate(candidate.into());
            }
        }
    }

    /// Process new local candidates.
    fn process_local_candidates(&mut self, cx: &mut Context<'_>) {
        if let Some(candidate_tx) = self.local_candidate_tx.as_mut() {
            let mut resolved = 0;

            for channel in &mut self.channels {
                while let Poll::Ready(r) = channel.poll_next_local_candidate(cx) {
                    if let Some(candidate) = r {
                        candidate_tx.unbounded_send(candidate).unwrap_or_default();
                    } else {
                        // mark the channel as resolved
                        resolved += 1;

                        // ... and stop polling it
                        break;
                    }
                }
            }

            if resolved == self.channels.len() {
                self.local_candidate_tx = None;
            }
        }
    }

    /// Drive channels.
    fn drive_channels(&mut self, cx: &mut Context<'_>) {
        for channel in &mut self.channels {
            channel.drive_channel(cx);
        }
    }

    /// Schedule connectivity checks.
    fn schedule_checks(&mut self, cx: &mut Context<'_>) {
        // get the number of available tokens
        let elapsed = self.last_check.elapsed();

        let n = (elapsed.as_millis() / self.check_interval.as_millis()) as u32;

        self.check_tokens = self.check_tokens.saturating_add(n);

        self.last_check += n * self.check_interval;

        // schedule the next time event
        loop {
            let poll = self.next_check.poll_unpin(cx);

            if poll.is_pending() {
                break;
            }

            let mut next = self.last_check;

            while next < Instant::now() {
                next += self.check_interval;
            }

            let pinned = self.next_check.as_mut();

            pinned.reset(next.into());
        }

        // and schedule as many checks as possible
        for channel in &mut self.channels {
            while self.check_tokens > 0 {
                if channel.schedule_check() {
                    self.check_tokens -= 1;
                } else {
                    break;
                }
            }
        }
    }
}

impl Future for AgentTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(next) = self.remote_candidate_rx.poll_next_unpin(cx) {
            if let Some(candidate) = next {
                self.process_remote_candidate(candidate);
            } else {
                return Poll::Ready(());
            }
        }

        self.schedule_checks(cx);
        self.process_local_candidates(cx);
        self.drive_channels(cx);

        Poll::Pending
    }
}

/// New remote candidate.
struct NewRemoteCandidate {
    candidate: RemoteCandidate,
    username_fragment: Option<String>,
}

impl NewRemoteCandidate {
    /// Create a new remote candidate.
    fn new(candidate: RemoteCandidate, username_fragment: Option<&str>) -> Self {
        Self {
            username_fragment: username_fragment.map(|v| v.to_string()),
            candidate,
        }
    }

    /// Get the username fragment.
    fn username_fragment(&self) -> Option<&str> {
        self.username_fragment.as_deref()
    }
}

impl Deref for NewRemoteCandidate {
    type Target = RemoteCandidate;

    fn deref(&self) -> &Self::Target {
        &self.candidate
    }
}

impl From<NewRemoteCandidate> for RemoteCandidate {
    fn from(c: NewRemoteCandidate) -> Self {
        c.candidate
    }
}
