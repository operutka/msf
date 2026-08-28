use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut, Div},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use futures::{channel::mpsc, Stream, StreamExt};
use msf_stun::{ErrorCode, MessageClass, MessageIntegrityAlgorithm, Method};
use tokio::task::JoinHandle;

use crate::{
    ice2::{
        candidate::{CandidateKind, LocalCandidate, RemoteCandidate},
        check::{
            ConnectivityCheckResult, IncomingConnectivityCheckRequest,
            IncomingConnectivityCheckResponse, InvalidConnectivityCheckRequest,
            OutgoingConnectivityCheck, OutgoingConnectivityCheckRequest,
        },
        checklist::Checklist,
        component::ComponentHandle,
        datastream::{DataStream, DataStreamBuilder},
        stun::{IncomingMessage, Response, STUN},
        timer::{TransactionTimer, TransactionToken},
        transport::{OutgoingPacketDispatcher, Packet, Transport},
        turn::{IncomingFrame, TURN},
        utils::Credentials,
    },
    AgentRole,
};

/// ICE agent builder.
pub struct AgentBuilder {
    stun: STUN,
    turn: TURN,
    outgoing_packet_dispatcher: OutgoingPacketDispatcher,
    data_streams: Vec<DataStreamBuilder>,
}

impl AgentBuilder {
    /// Create a new agent builder.
    fn new() -> Self {
        let outgoing_packet_dispatcher = OutgoingPacketDispatcher::new();
        let stun = STUN::new(outgoing_packet_dispatcher.clone());
        let turn = TURN::new(stun.clone());

        Self {
            stun,
            turn,
            outgoing_packet_dispatcher,
            data_streams: Vec::new(),
        }
    }

    /// Add a new data stream.
    pub fn data_stream(&mut self) -> &mut DataStreamBuilder {
        let is_last_empty = self
            .data_streams
            .last()
            .map(|dsb| dsb.is_empty())
            .unwrap_or(false);

        if !is_last_empty {
            let builder = DataStreamBuilder::new(
                self.data_streams.len(),
                self.stun.clone(),
                self.outgoing_packet_dispatcher.clone(),
            );

            self.data_streams.push(builder);
        }

        let idx = self.data_streams.len() - 1;

        &mut self.data_streams[idx]
    }

    /// Build the agent and its event stream.
    ///
    /// # Arguments
    /// * `local_ip_addresses` - local IP addresses that will be used for
    ///   gathering local candidates; the IP addresses MUST follow the
    ///   requirements specified in RFC 8445, section 5.1.1.1
    /// * `stun_servers` - STUN servers that will be used for gathering
    ///   local server-reflexive candidates
    /// * `turn_servers` - TURN servers that will be used for gathering
    ///   local relayed candidates
    pub fn build(
        self,
        local_ip_addresses: &[IpAddr],
        stun_servers: &[SocketAddr],
        turn_servers: &[SocketAddr],
    ) -> (Agent, AgentEvents) {
        let (event_tx, event_rx) = mpsc::unbounded();

        let data_streams = self
            .data_streams
            .into_iter()
            .map(|dsb| dsb.build())
            .collect();

        let mutable = MutableAgentContext {
            role: AgentRole::Controlling,
            tie_breaker: rand::random(),
            data_streams,
            checklists: Vec::new(),
            checklist_queue: VecDeque::new(),
            local_bases: HashMap::new(),
            max_candidate_pairs: 100,
        };

        let context = AgentContext {
            stun: self.stun.clone(),
            turn: self.turn.clone(),
            timer: TransactionTimer::default(),
            outgoing_packet_dispatcher: self.outgoing_packet_dispatcher,
            event_tx,
            mutable: Mutex::new(mutable),
        };

        let mut agent = Agent {
            context: Arc::new(context),

            gather_candidates_task: None,
            connectivity_check_task: None,
        };

        agent.init(local_ip_addresses, stun_servers, turn_servers);

        let events = AgentEvents { events: event_rx };

        (agent, events)
    }
}

/// ICE agent event.
pub enum Event {
    Restart,
    Done,
    LocalCandidate(LocalCandidate),
    NoMoreLocalCandidates,
}

/// Helper type.
type EventTx = mpsc::UnboundedSender<Event>;

/// Helper type.
type EventRx = mpsc::UnboundedReceiver<Event>;

/// ICE agent events.
pub struct AgentEvents {
    events: EventRx,
}

impl Stream for AgentEvents {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events.poll_next_unpin(cx)
    }
}

/// ICE agent.
pub struct Agent {
    context: Arc<AgentContext>,

    gather_candidates_task: Option<JoinHandle<()>>,
    connectivity_check_task: Option<JoinHandle<()>>,
}

impl Agent {
    /// Get an agent builder.
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    /// ICE restart.
    pub async fn restart(
        &mut self,
        local_ip_addresses: &[IpAddr],
        stun_servers: &[SocketAddr],
        turn_servers: &[SocketAddr],
    ) {
        self.context.send_event(Event::Restart);

        self.stop_candidate_gathering().await;
        self.stop_connectivity_checks().await;

        self.init(local_ip_addresses, stun_servers, turn_servers);
    }

    /// Set remote credentials for a given data stream.
    pub fn set_remote_credentials(&self, data_stream: usize, credentials: Credentials) {
        self.context
            .lock()
            .set_remote_credentials(data_stream, credentials);
    }

    /// Add a given remote candidate or `None` to indicate that there will be
    /// no more remote candidates.
    pub fn add_remote_candidate(&self, candidate: Option<RemoteCandidate>) {
        let mut context = self.context.lock();

        if let Some(candidate) = candidate {
            context.add_remote_candidate(candidate);
        } else {
            context.no_more_remote_candidates();
        }
    }

    /// Initialize the agent.
    fn init(
        &mut self,
        local_ip_addresses: &[IpAddr],
        stun_servers: &[SocketAddr],
        turn_servers: &[SocketAddr],
    ) {
        let mut context = self.context.lock();

        context.restart();

        let components = context
            .data_streams
            .iter()
            .map(|ds| ds.components())
            .flatten()
            .cloned()
            .collect::<Vec<_>>();

        std::mem::drop(context);

        let local_ip_addresses = local_ip_addresses.to_vec();
        let stun_servers = stun_servers.to_vec();
        let turn_servers = turn_servers.to_vec();

        let handle = self.handle();

        let gather_local_candidates = async move {
            handle
                .gather_local_candidates(
                    &components,
                    &local_ip_addresses,
                    &stun_servers,
                    &turn_servers,
                )
                .await
        };

        self.gather_candidates_task = Some(tokio::spawn(gather_local_candidates));

        let handle = self.handle();

        let send_connectivity_checks = async move { handle.send_connectivity_checks().await };

        self.connectivity_check_task = Some(tokio::spawn(send_connectivity_checks));
    }

    /// Stop the candidate gathering task.
    async fn stop_candidate_gathering(&mut self) {
        if let Some(handle) = self.gather_candidates_task.take() {
            // abort the task
            handle.abort();

            // ... and wait until its execution stops
            handle.await.unwrap_or_default();
        }
    }

    /// Stop the connectivity checks task.
    async fn stop_connectivity_checks(&mut self) {
        if let Some(handle) = self.connectivity_check_task.take() {
            // abort the task
            handle.abort();

            // ... and wait until its execution stops
            handle.await.unwrap_or_default();
        }
    }

    /// Get an agent handle.
    fn handle(&self) -> AgentHandle {
        AgentHandle {
            context: self.context.clone(),
        }
    }
}

/// ICE agent handle.
#[derive(Clone)]
pub struct AgentHandle {
    context: Arc<AgentContext>,
}

impl AgentHandle {
    /// Process a given incoming packet.
    ///
    /// The method returns `None` if the packet is consumed internally,
    /// otherwise it returns the packet back to the caller.
    pub fn process_incoming_packet(&self, packet: Packet) -> Option<Packet> {
        self.context.process_incoming_packet(packet)
    }

    /// Gather local candidates for all components.
    async fn gather_local_candidates(
        &self,
        components: &[ComponentHandle],
        local_ip_addresses: &[IpAddr],
        stun_servers: &[SocketAddr],
        turn_servers: &[SocketAddr],
    ) {
        let futures = components.iter().cloned().map(|component| async move {
            self.gather_local_candidates_for_component(
                &component,
                local_ip_addresses,
                stun_servers,
                turn_servers,
            )
            .await
        });

        futures::stream::iter(futures)
            .buffer_unordered(components.len())
            .for_each(|_| async {})
            .await;

        self.context.no_more_local_candidates();
    }

    /// Gather local candidates for a given component.
    async fn gather_local_candidates_for_component(
        &self,
        component: &ComponentHandle,
        local_ip_addresses: &[IpAddr],
        stun_servers: &[SocketAddr],
        turn_servers: &[SocketAddr],
    ) {
        let futures = local_ip_addresses
            .iter()
            .copied()
            .filter(|ip| {
                // NOTE: This is just a failsafe. The user is responsible for
                //   following all the requirements specified in RFC 8445,
                //   section 5.1.1.1.
                !ip.is_loopback()
            })
            .map(|ip| async move {
                let data_stream = component.data_stream();
                let component_id = component.id();

                let transport =
                    Transport::udp(self.clone(), SocketAddr::from((ip, 0)), component.clone())
                        .await?;

                let local_addr = transport.local_addr();

                self.context
                    .add_transport(data_stream, component_id, transport);

                self.gather_local_server_reflexive_candidates(component, local_addr, stun_servers)
                    .await;

                self.gather_local_relayed_candidates(component, local_addr, turn_servers)
                    .await;

                Ok(()) as io::Result<()>
            });

        futures::stream::iter(futures)
            .buffer_unordered(local_ip_addresses.len())
            .for_each(|res| async move {
                if let Err(err) = res {
                    // TODO: log warning
                }
            })
            .await;
    }

    /// Gather local server reflexive candidates for a given component.
    async fn gather_local_server_reflexive_candidates(
        &self,
        component: &ComponentHandle,
        local_addr: SocketAddr,
        stun_servers: &[SocketAddr],
    ) {
        let component_id = component.id();
        let data_stream = component.data_stream();

        for &stun_server in stun_servers {
            let send = self
                .context
                .stun()
                .send_binding_request(local_addr, stun_server);

            let res = self
                .context
                .create_transaction_token()
                .perform_transaction(send);

            match res.await {
                Ok(mapped_addr) => {
                    let candidate = LocalCandidate::server_reflexive(
                        data_stream,
                        component_id,
                        local_addr,
                        mapped_addr,
                        stun_server,
                    );

                    // TODO: Implement STUN keep-alive (see RFC 8445, section 5.1.1.4).
                    //   We can create a STUNBinding object keeping a background keep-alive
                    //   task and register the object within the outgoing packet dispatcher.

                    self.context.add_local_candidate(candidate);
                }
                Err(err) => {
                    // TODO: debug log
                }
            }
        }
    }

    /// Gather local relayed candidates for a given component.
    async fn gather_local_relayed_candidates(
        &self,
        component: &ComponentHandle,
        local_addr: SocketAddr,
        turn_servers: &[SocketAddr],
    ) {
        // TODO:
        //   - create TURN allocations and keep them alive
        //   - the keep-alive handles can be stored within each
        //     local candidate (an `Arc<_>` handle that will abort
        //     the corresponding keep-alive task when all copies of
        //     the handle are dropped)
    }

    /// Send connectivity checks for all checklists.
    async fn send_connectivity_checks(&self) {
        while let Some(request) = self
            .context
            .next_outgoing_connectivity_check_request()
            .await
        {
            self.context
                .create_transaction_token()
                .await_transaction_slot()
                .await;

            let this = self.clone();

            tokio::spawn(async move {
                let response = request.send().await;

                this.context
                    .lock()
                    .process_incoming_connectivity_check_response(response);
            });
        }

        // NOTE: ICE concluded here

        let mut context = self.context.lock();

        // TODO: bind each component to the corresponding selected pair
        // TODO: retain only transports with local addresses from the used bindings

        // deleting checklists will release all the resources they hold
        // including unused STUN bindings and TURN allocations
        context.checklists.clear();
        context.checklist_queue.clear();

        self.context.send_event(Event::Done);
    }
}

/// ICE agent context.
struct AgentContext {
    stun: STUN,
    turn: TURN,
    timer: TransactionTimer,
    outgoing_packet_dispatcher: OutgoingPacketDispatcher,
    event_tx: EventTx,
    mutable: Mutex<MutableAgentContext>,
}

impl AgentContext {
    /// Get the STUN context.
    fn stun(&self) -> &STUN {
        &self.stun
    }

    /// Create a new transaction token.
    fn create_transaction_token(&self) -> TransactionToken {
        self.timer.create_transaction_token()
    }

    /// Lock the context for exclusive access.
    fn lock(&self) -> LockedAgentContext<'_> {
        LockedAgentContext {
            context: self,
            mutable: self.mutable.lock().unwrap(),
        }
    }

    /// Send an event to the event stream.
    fn send_event(&self, event: Event) {
        let _ = self.event_tx.unbounded_send(event);
    }

    /// Add a given transport.
    ///
    /// This will also add the corresponding local host candidate.
    fn add_transport(&self, data_stream: usize, component: u8, transport: Transport) {
        let addr = transport.local_addr();

        let base = LocalBaseMapping {
            data_stream,
            component,
        };

        let candidate = LocalCandidate::host(data_stream, component, addr);

        let mut locked = self.lock();

        locked.add_local_base(addr, base);
        locked.add_local_candidate(candidate);

        self.outgoing_packet_dispatcher.add_transport(transport);
    }

    /// Add a given local candidate.
    fn add_local_candidate(&self, candidate: LocalCandidate) {
        self.lock().add_local_candidate(candidate);
    }

    /// Indicate that there will be no more local candidates.
    fn no_more_local_candidates(&self) {
        self.lock().no_more_local_candidates();
    }

    /// Get the next outgoing connectivity check request.
    async fn next_outgoing_connectivity_check_request(
        &self,
    ) -> Option<OutgoingConnectivityCheckRequest> {
        futures::future::poll_fn(|cx| {
            self.lock()
                .poll_next_outgoing_connectivity_check_request(cx)
        })
        .await
    }

    /// Process a given incoming packet.
    fn process_incoming_packet(&self, packet: Packet) -> Option<Packet> {
        match IncomingFrame::from_packet(packet.clone(), false) {
            Ok(IncomingFrame::Message(msg)) => {
                let Err(msg) = self.stun.process_incoming_message(msg) else {
                    return None;
                };

                let msg = match self.turn.process_incoming_message(msg) {
                    Ok(res) => return res,
                    Err(msg) => msg,
                };

                self.process_incoming_message(msg)
                    .map(|_| None)
                    .unwrap_or(Some(packet))
            }
            Ok(IncomingFrame::ChannelData(data)) => self.turn.process_channel_data(data),
            Err(_) => Some(packet),
        }
    }

    /// Process a given incoming message.
    ///
    /// The message will be rejected if it is not a valid STUN connectivity
    /// check request or a keep-alive indication.
    fn process_incoming_message(&self, msg: IncomingMessage) -> Result<(), IncomingMessage> {
        // NOTE: We expect only connectivity checks and keep-alive messages
        //   here. The backward compatibility mode isn't allowed for
        //   connectivity checks, so the magic cookie should be present.
        // NOTE: We don't process any responses here. All responses are handled
        //   by the STUN context.
        let is_invalid_message = !msg.is_rfc5389_message()
            || msg.method() != Method::Binding
            || !msg.check_fingerprint();

        if is_invalid_message {
            return Err(msg);
        } else if msg.class() == MessageClass::Indication {
            return Ok(());
        } else if msg.class() != MessageClass::Request {
            return Err(msg);
        }

        let base_addr = msg.base_addr();
        let remote_addr = msg.remote_addr();

        let response = self
            .lock()
            .process_incoming_connectivity_check_request(msg)?;

        tokio::spawn(async move {
            response
                .send(base_addr, remote_addr)
                .await
                .unwrap_or_default();
        });

        Ok(())
    }
}

/// Locked ICE agent context.
struct LockedAgentContext<'a> {
    context: &'a AgentContext,
    mutable: MutexGuard<'a, MutableAgentContext>,
}

impl LockedAgentContext<'_> {
    /// Get the STUN context.
    fn stun(&self) -> &STUN {
        self.context.stun()
    }

    /// Add a given local candidate.
    fn add_local_candidate(&mut self, candidate: LocalCandidate) {
        if candidate.kind() == CandidateKind::Relayed {
            // NOTE: RFC 8445 specifies that if a relayed candidate is
            //   identical to a host candidate, the relayed candidate MUST be
            //   discarded. In addition, we'll also discard the candidate if
            //   it matches another existing relayed candidate.
            if self.local_bases.contains_key(&candidate.addr()) {
                return;
            }
        }

        let checklist = self
            .checklists
            .get_mut(candidate.data_stream())
            .expect("unknwon data stream");

        let res = checklist.add_local_candidate(candidate.clone());

        if res.is_ok() {
            self.context.send_event(Event::LocalCandidate(candidate));
        }

        self.remove_lower_priority_pairs();
    }

    /// Add a given remote candidate.
    fn add_remote_candidate(&mut self, candidate: RemoteCandidate) {
        let Some(checklist) = self.checklists.get_mut(candidate.data_stream()) else {
            return;
        };

        checklist.add_remote_candidate(candidate);

        self.remove_lower_priority_pairs();
    }

    /// Indicate that there will be no more local candidates.
    fn no_more_local_candidates(&mut self) {
        for checklist in &mut self.checklists {
            checklist.no_more_local_candidates();
        }

        self.context.send_event(Event::NoMoreLocalCandidates);
    }

    /// Indicate that there will be no more remote candidates.
    fn no_more_remote_candidates(&mut self) {
        for checklist in &mut self.checklists {
            checklist.no_more_remote_candidates();
        }
    }

    /// Poll the next outgoing connectivity check request.
    fn poll_next_outgoing_connectivity_check_request(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<OutgoingConnectivityCheckRequest>> {
        let mut pending = false;

        for _ in 0..self.checklists.len() {
            if let Some(idx) = self.checklist_queue.pop_front() {
                self.checklist_queue.push_back(idx);

                let checklist = &mut self.checklists[idx];

                let check = if let Some(c) = checklist.take_next_check() {
                    Poll::Ready(Some(c))
                } else {
                    let checklist = &self.checklists[idx];

                    // NOTE: We need to find a foundation that could be unforzen
                    //   if there are no other candidate pairs that could be
                    //   checked.
                    let unfreeze_foundation = checklist
                        .frozen_pair_foundations()
                        .find(|foundation| {
                            self.checklists
                                .iter()
                                .all(|cl| !cl.is_pending_foundation(foundation))
                        })
                        .cloned();

                    let checklist = &mut self.checklists[idx];

                    checklist.poll_next_check(cx, unfreeze_foundation.as_ref())
                };

                match check {
                    Poll::Ready(Some(check)) => {
                        return Poll::Ready(Some(
                            self.create_outgoing_connectivity_check_request(check),
                        ))
                    }
                    Poll::Ready(None) => (),
                    Poll::Pending => pending = true,
                }
            }
        }

        if pending {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }

    /// Create an outgoing connectivity check request.
    fn create_outgoing_connectivity_check_request(
        &self,
        check: OutgoingConnectivityCheck,
    ) -> OutgoingConnectivityCheckRequest {
        let ds = self
            .get_data_stream(check.data_stream())
            .expect("unknown data stream");

        let local_credentials = ds.local_credentials();
        let remote_credentials = ds.remote_credentials().expect("missing remote credentials");

        let stun = self.stun();

        check.into_outgoing_request(stun, local_credentials, remote_credentials)
    }

    /// Process a given incoming connectivity check response.
    fn process_incoming_connectivity_check_response(
        &mut self,
        response: IncomingConnectivityCheckResponse,
    ) {
        let result = response.result();

        if result == ConnectivityCheckResult::RoleConflict {
            self.reset_agent_role(AgentRole::reverse(response.agent_role()));
        }

        let data_stream_id = response.data_stream();
        let component_id = response.component();

        let this = &mut *self.mutable;

        let checklist = &mut this.checklists[data_stream_id];

        if let Some(foundation) = checklist.process_check_response(response) {
            for checklist in &mut this.checklists {
                checklist.unfreeze_foundation(&foundation);
            }
        }

        let checklist = &this.checklists[data_stream_id];

        if let Some(pair) = checklist.get_best_valid_pair(component_id) {
            let remote = pair.remote();
            let local = pair.local();

            let base_addr = local.base();
            let remote_addr = remote.addr();

            self.get_data_stream(data_stream_id)
                .expect("unknwon data stream")
                .components()
                .get(component_id as usize)
                .expect("unknown component")
                .bind(base_addr, remote_addr);
        }
    }

    /// Process a given incoming connectivity check request.
    fn process_incoming_connectivity_check_request(
        &mut self,
        msg: IncomingMessage,
    ) -> Result<Response, IncomingMessage> {
        let res = self.try_process_incoming_connectivity_check_request(&msg);

        let attributes = msg.attributes();

        let message_integrity_alg = if attributes.contains_message_integrity_sha256() {
            MessageIntegrityAlgorithm::Sha256
        } else {
            MessageIntegrityAlgorithm::Sha1
        };

        let message_integrity_key = self
            .get_local_base(msg.base_addr())
            .and_then(|info| self.get_data_stream(info.data_stream()))
            .expect("unknown data stream")
            .local_credentials()
            .password()
            .as_bytes();

        let builder = if let Err(err) = res {
            let mut builder = self
                .stun()
                .build_error_response(&msg, err.to_error_code())
                .fingerprint(true);

            if err.unknwon_attributes() {
                builder = builder.unknown_attributes(msg.unknown_attributes());
            }

            if !err.auth_error() {
                builder = builder
                    .message_integrity_algorithm(message_integrity_alg)
                    .message_integrity_key(message_integrity_key)
            }

            builder
        } else {
            self.stun()
                .build_success_response(&msg)
                .xor_mapped_address(msg.remote_addr())
                .fingerprint(true)
                .message_integrity_algorithm(message_integrity_alg)
                .message_integrity_key(message_integrity_key)
        };

        Ok(builder.build())
    }

    /// Try to process a given incoming connectivity check request.
    fn try_process_incoming_connectivity_check_request(
        &mut self,
        msg: &IncomingMessage,
    ) -> Result<(), IncomingConnectivityCheckRequestError> {
        let base = self
            .get_local_base(msg.base_addr())
            .expect("unknown base address");

        let data_stream = base.data_stream();
        let component = base.component();

        let local_credentials = self
            .get_data_stream(data_stream)
            .expect("unknown data stream")
            .local_credentials();

        let request = IncomingConnectivityCheckRequest::from_incoming_request(
            msg,
            data_stream,
            component,
            local_credentials,
        )?;

        let remote_role = request.remote_role();
        let remote_tie_breaker = request.remote_tie_breaker();

        self.update_agent_role(remote_role, remote_tie_breaker)?;

        let checklist = &mut self.checklists[data_stream];

        checklist.process_check_request(&request);

        Ok(())
    }
}

impl Deref for LockedAgentContext<'_> {
    type Target = MutableAgentContext;

    fn deref(&self) -> &Self::Target {
        &self.mutable
    }
}

impl DerefMut for LockedAgentContext<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mutable
    }
}

/// Mutable parts of the ICE agent context.
struct MutableAgentContext {
    role: AgentRole,
    tie_breaker: u64,
    data_streams: Vec<DataStream>,
    checklists: Vec<Checklist>,
    checklist_queue: VecDeque<usize>,
    local_bases: HashMap<SocketAddr, LocalBaseMapping>,
    max_candidate_pairs: usize,
}

impl MutableAgentContext {
    /// Add a given local base.
    fn add_local_base(&mut self, addr: SocketAddr, base: LocalBaseMapping) {
        self.local_bases.insert(addr, base);
    }

    /// Get a local base for a given address.
    fn get_local_base(&self, addr: SocketAddr) -> Option<&LocalBaseMapping> {
        self.local_bases.get(&addr)
    }

    /// Get a data stream for a given data stream ID.
    fn get_data_stream(&self, data_stream: usize) -> Option<&DataStream> {
        self.data_streams.get(data_stream)
    }

    /// Set remote credentials for a given data stream.
    fn set_remote_credentials(&mut self, data_stream: usize, credentials: Credentials) {
        if let Some(ds) = self.data_streams.get_mut(data_stream) {
            ds.set_remote_credentials(credentials);
        }
    }

    /// Change the agent role.
    ///
    /// Note that this method will also generate a new tie-breaker. It should
    /// be called if the 487 Role Conflict error code is received and the new
    /// agent role should be a reverse of the role that was used in the
    /// correspond request. This matches the client-side role conflict
    /// resolution defined in RFC 8445.
    fn reset_agent_role(&mut self, role: AgentRole) {
        self.tie_breaker = rand::random();
        self.role = role;

        for checklist in &mut self.checklists {
            checklist.set_agent_role(role, self.tie_breaker);
        }
    }

    /// Update the local agent role based on a given remote role and a remote
    /// tie-breaker.
    ///
    /// Note that this method won't change the tie-breaker value if the local
    /// role gets changed. This is because the local role gets changes only if
    /// the local and remote tie-breaker values are not equal. Therefore,
    /// there is no need to change the tie-breaker value. This matches the
    /// server-side role conflict resolution specified in RFC 8445.
    fn update_agent_role(&mut self, role: AgentRole, tie_breaker: u64) -> Result<(), RoleConflict> {
        let role = if self.role == AgentRole::Controlling && role == AgentRole::Controlling {
            if self.tie_breaker < tie_breaker {
                AgentRole::Controlled
            } else {
                return Err(RoleConflict);
            }
        } else if self.role == AgentRole::Controlled && role == AgentRole::Controlled {
            if self.tie_breaker < tie_breaker {
                return Err(RoleConflict);
            } else {
                AgentRole::Controlling
            }
        } else {
            return Ok(());
        };

        self.role = role;

        for checklist in &mut self.checklists {
            checklist.set_agent_role(role, self.tie_breaker);
        }

        Ok(())
    }

    /// Remove lower priority candidate pairs from all checklists.
    ///
    /// This is done to keep the total number of candidate pairs below the
    /// maximum allowed value (see RFC 8445, section 6.1.2.5 for more info).
    fn remove_lower_priority_pairs(&mut self) {
        let checklists = self.checklists.len();

        // sanity check
        if checklists == 0 {
            return;
        }

        let total = self
            .checklists
            .iter()
            .map(|checklist| checklist.len())
            .sum::<usize>();

        let remove = total
            .saturating_sub(self.max_candidate_pairs)
            .saturating_add(checklists - 1)
            .div(checklists);

        if remove == 0 {
            return;
        }

        for checklist in &mut self.checklists {
            checklist.clear_failed();

            let current = checklist.len();
            let target = current.saturating_sub(remove);

            checklist.truncate(target);
        }
    }

    /// Clear and initialize all checklists and the checklist queue.
    fn restart(&mut self) {
        self.checklists.clear();
        self.checklist_queue.clear();

        for ds in &self.data_streams {
            let checklist = Checklist::new(self.role, self.tie_breaker);

            self.checklists.push(checklist);
            self.checklist_queue.push_back(ds.id());
        }
    }
}

/// Role conflict error.
#[derive(Debug, Copy, Clone)]
struct RoleConflict;

/// Local base mapping.
struct LocalBaseMapping {
    data_stream: usize,
    component: u8,
}

impl LocalBaseMapping {
    /// Get the data stream ID associated with this base.
    fn data_stream(&self) -> usize {
        self.data_stream
    }

    /// Get the component ID associated with this base.
    fn component(&self) -> u8 {
        self.component
    }
}

/// Incoming connectivity check request error.
enum IncomingConnectivityCheckRequestError {
    InvalidRequest(InvalidConnectivityCheckRequest),
    RoleConflict,
}

impl IncomingConnectivityCheckRequestError {
    /// Check if the error is an authentication error.
    fn auth_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidRequest(InvalidConnectivityCheckRequest::AuthError(_))
        )
    }

    /// Check if the error is due to unknown attributes.
    fn unknwon_attributes(&self) -> bool {
        matches!(
            self,
            Self::InvalidRequest(InvalidConnectivityCheckRequest::UnknownAttributes)
        )
    }

    /// Get the corresponding STUN error code for this error.
    fn to_error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidRequest(err) => err.to_error_code(),
            Self::RoleConflict => ErrorCode::ROLE_CONFLICT,
        }
    }
}

impl From<RoleConflict> for IncomingConnectivityCheckRequestError {
    fn from(_: RoleConflict) -> Self {
        Self::RoleConflict
    }
}

impl From<InvalidConnectivityCheckRequest> for IncomingConnectivityCheckRequestError {
    fn from(err: InvalidConnectivityCheckRequest) -> Self {
        Self::InvalidRequest(err)
    }
}
