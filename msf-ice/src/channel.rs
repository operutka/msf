use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{channel::mpsc, ready, Sink, Stream, StreamExt};
use msf_stun as stun;

use crate::{
    candidate::{LocalCandidate, RemoteCandidate},
    checklist::Checklist,
    log::Logger,
    session::Session,
    socket::{Binding as SocketBinding, ICESockets, LocalBinding, Packet, ReflexiveBinding},
};

/// Channel builder.
pub struct ChannelBuilder {
    channel: usize,
    components: Vec<ComponentHandle>,
}

impl ChannelBuilder {
    /// Create a new channel builder.
    fn new(channel: usize) -> Self {
        Self {
            channel,
            components: Vec::new(),
        }
    }

    /// Check if there are any components.
    pub(crate) fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Add a new component.
    #[inline]
    pub fn component(&mut self) -> Component {
        assert!(self.components.len() < 256);

        let component_id = self.components.len() as u8;

        let (component, handle) = Component::new(self.channel, component_id);

        self.components.push(handle);

        component
    }

    /// Build the channel.
    pub(crate) fn build(
        self,
        logger: Logger,
        session: Session,
        local_addresses: &[IpAddr],
        stun_servers: &[SocketAddr],
    ) -> Channel {
        let components = self.components.len();

        debug_assert!(components > 0);

        let checklist = Checklist::new(session.clone(), self.channel, components);

        let mut component_transports = Vec::with_capacity(components);

        component_transports.resize_with(components, || {
            ComponentTransport::new(logger.clone(), local_addresses, stun_servers)
        });

        Channel {
            session,
            channel_index: self.channel,
            checklist,
            component_transports,
            component_handles: self.components,
            available_candidates: VecDeque::new(),
        }
    }
}

/// Single data/media channel.
pub struct Channel {
    session: Session,
    channel_index: usize,
    checklist: Checklist,
    component_transports: Vec<ComponentTransport>,
    component_handles: Vec<ComponentHandle>,
    available_candidates: VecDeque<LocalCandidate>,
}

impl Channel {
    /// Get a channel builder.
    pub fn builder(channel: usize) -> ChannelBuilder {
        ChannelBuilder::new(channel)
    }

    /// Get the next local candidate.
    pub fn poll_next_local_candidate(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<LocalCandidate>> {
        loop {
            if let Some(candidate) = self.available_candidates.pop_front() {
                return Poll::Ready(Some(candidate));
            } else if let Some((component, binding)) = ready!(self.poll_next_socket_binding(cx)) {
                self.process_socket_binding(component, binding);
            } else {
                return Poll::Ready(None);
            }
        }
    }

    ///
    fn poll_next_socket_binding(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(u8, SocketBinding)>> {
        let mut pending = 0;

        let transports = self.component_transports.iter_mut();

        for (index, transport) in transports.enumerate() {
            match transport.poll_next_binding(cx) {
                Poll::Ready(Some(binding)) => return Poll::Ready(Some((index as _, binding))),
                Poll::Ready(None) => (),
                Poll::Pending => pending += 1,
            }
        }

        if pending > 0 {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }

    ///
    fn process_socket_binding(&mut self, component: u8, binding: SocketBinding) {
        match binding {
            SocketBinding::Local(binding) => self.process_local_binding(component, binding),
            SocketBinding::Reflexive(binding) => self.process_reflexive_binding(component, binding),
        }
    }

    ///
    fn process_local_binding(&mut self, component: u8, binding: LocalBinding) {
        let addr = binding.addr();

        let candidate = LocalCandidate::host(self.channel_index, component, addr);

        let foundation = self.session.assign_foundation(&candidate, None);

        let candidate = candidate.with_foundation(foundation);

        self.checklist.add_local_candidate(candidate);

        let ip = addr.ip();

        if !ip.is_unspecified() {
            self.available_candidates.push_back(candidate);
        }
    }

    ///
    fn process_reflexive_binding(&mut self, component: u8, binding: ReflexiveBinding) {
        let candidate = LocalCandidate::server_reflexive(
            self.channel_index,
            component,
            binding.base(),
            binding.addr(),
        );

        let source = binding.source();

        let foundation = self
            .session
            .assign_foundation(&candidate, Some(source.ip()));

        let candidate = candidate.with_foundation(foundation);

        self.checklist.add_local_candidate(candidate);
        self.available_candidates.push_back(candidate);
    }

    /// Add a given remote candidate.
    pub fn process_remote_candidate(&mut self, candidate: RemoteCandidate) {
        // we silently drop all remote candidates with unknown component ID
        if (candidate.component() as usize) < self.component_transports.len() {
            self.checklist.add_remote_candidate(candidate);
        }
    }

    /// Schedule a connectivity check.
    ///
    /// The method returns `true` if a check was scheduled.
    pub fn schedule_check(&mut self) -> bool {
        self.checklist.schedule_check()
    }

    /// Drive the channel.
    pub fn drive_channel(&mut self, cx: &mut Context<'_>) {
        self.drive_connectivity_checks(cx);
        self.drive_input(cx);
        self.drive_output(cx);
    }

    /// Drive connectivity checks.
    fn drive_connectivity_checks(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(msg) = self.checklist.poll(cx) {
            let component = msg.component();

            let transport = &mut self.component_transports[component as usize];

            let local_addr = msg.local_addr();
            let remote_addr = msg.remote_addr();

            transport.send_using(local_addr, remote_addr, msg.take_data());
        }
    }

    /// Drive the input.
    fn drive_input(&mut self, cx: &mut Context<'_>) {
        for index in 0..self.component_transports.len() {
            loop {
                // we can't iterate directly over the transports because we
                // need to also borrow self in each iteration
                let transport = &mut self.component_transports[index];

                if let Poll::Ready(packet) = transport.poll_recv(cx) {
                    self.process_incoming_packet(index as _, packet);
                } else {
                    break;
                }
            }
        }
    }

    /// Drive the output.
    fn drive_output(&mut self, cx: &mut Context<'_>) {
        for (index, transport) in self.component_transports.iter_mut().enumerate() {
            if transport.is_bound() {
                if let Some(handle) = self.component_handles.get_mut(index) {
                    while let Poll::Ready(Some(data)) = handle.poll_next_output_packet(cx) {
                        transport.send(data);
                    }
                }
            }
        }
    }

    /// Process a given incoming packet.
    fn process_incoming_packet(&mut self, component: u8, packet: Packet) {
        let local_addr = packet.local_addr();
        let remote_addr = packet.remote_addr();
        let data = packet.data();

        if let Some(msg) = self.parse_stun_message(data) {
            self.process_stun_message(component, local_addr, remote_addr, msg);
        } else if let Some(handle) = self.component_handles.get_mut(component as usize) {
            handle.deliver_input_packet(packet);
        }
    }

    /// Try to parse a STUN message.
    fn parse_stun_message(&self, data: &Bytes) -> Option<stun::Message> {
        if let Ok(msg) = stun::Message::from_frame(data.clone()) {
            if msg.is_rfc5389_message() && msg.check_fingerprint() {
                return Some(msg);
            }
        }

        None
    }

    /// Process a given STUN message.
    fn process_stun_message(
        &mut self,
        component: u8,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        msg: stun::Message,
    ) {
        if msg.method() == stun::Method::Binding {
            if msg.is_request() {
                self.process_stun_request(component, local_addr, remote_addr, msg)
            } else if msg.is_response() {
                self.process_stun_response(component, local_addr, remote_addr, msg)
            }
        }
    }

    /// Process a given STUN request.
    fn process_stun_request(
        &mut self,
        component: u8,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        msg: stun::Message,
    ) {
        let response =
            self.checklist
                .process_stun_request(component, local_addr, remote_addr, &msg);

        let transport = &mut self.component_transports[component as usize];

        transport.send_using(local_addr, remote_addr, response);
    }

    /// Process a given STUN response.
    fn process_stun_response(
        &mut self,
        component: u8,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        msg: stun::Message,
    ) {
        if let Some(nominated) =
            self.checklist
                .process_stun_response(component, local_addr, remote_addr, &msg)
        {
            let local = nominated.local();
            let remote = nominated.remote();

            let transport = &mut self.component_transports[component as usize];

            transport.bind(local.base(), remote.addr());
        }
    }
}

/// Component stream/sink.
pub struct Component {
    channel: usize,
    component_id: u8,
    input_packet_rx: mpsc::UnboundedReceiver<Packet>,
    output_packet_tx: mpsc::Sender<Bytes>,
}

impl Component {
    /// Create a new component stream/sink.
    fn new(channel: usize, component_id: u8) -> (Self, ComponentHandle) {
        let (input_packet_tx, input_packet_rx) = mpsc::unbounded();
        let (output_packet_tx, output_packet_rx) = mpsc::channel(8);

        let transport = Self {
            channel,
            component_id,
            input_packet_rx,
            output_packet_tx,
        };

        let handle = ComponentHandle {
            input_packet_tx,
            output_packet_rx,
        };

        (transport, handle)
    }

    /// Get index of the channel this component belongs to.
    #[inline]
    pub fn channel(&self) -> usize {
        self.channel
    }

    /// Get the component ID (zero-based).
    #[inline]
    pub fn component_id(&self) -> u8 {
        self.component_id
    }
}

impl Stream for Component {
    type Item = io::Result<Packet>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.input_packet_rx.poll_next_unpin(cx) {
            Poll::Ready(Some(packet)) => Poll::Ready(Some(Ok(packet))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Bytes> for Component {
    type Error = io::Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.output_packet_tx)
            .poll_ready(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.output_packet_tx)
            .start_send(item)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.output_packet_tx)
            .poll_flush(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.output_packet_tx)
            .poll_close(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Component handle.
struct ComponentHandle {
    input_packet_tx: mpsc::UnboundedSender<Packet>,
    output_packet_rx: mpsc::Receiver<Bytes>,
}

impl ComponentHandle {
    /// Get next output packet.
    fn poll_next_output_packet(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.output_packet_rx.poll_next_unpin(cx)
    }

    /// Deliver a given input packet.
    fn deliver_input_packet(&mut self, packet: Packet) {
        self.input_packet_tx
            .unbounded_send(packet)
            .unwrap_or_default();
    }
}

/// Component transport.
struct ComponentTransport {
    sockets: ICESockets,
    binding: Option<ComponentBinding>,
}

impl ComponentTransport {
    /// Create a new component transport.
    fn new(logger: Logger, local_addresses: &[IpAddr], stun_servers: &[SocketAddr]) -> Self {
        Self {
            sockets: ICESockets::new(logger, local_addresses, stun_servers),
            binding: None,
        }
    }

    /// Check if the transport has been bound to local/remote address pair.
    fn is_bound(&self) -> bool {
        self.binding.is_some()
    }

    /// Bind the transport to a given local/remote address pair.
    fn bind(&mut self, local: SocketAddr, remote: SocketAddr) {
        self.binding = Some(ComponentBinding::new(local, remote));
    }

    /// Get the next local binding.
    fn poll_next_binding(&mut self, cx: &mut Context<'_>) -> Poll<Option<SocketBinding>> {
        self.sockets.poll_next_binding(cx)
    }

    /// Read the next packet.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Packet> {
        self.sockets.poll_recv(cx)
    }

    /// Send given data from a given local binding to a given remote host.
    fn send_using(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr, data: Bytes) {
        self.sockets.send(local_addr, remote_addr, data);
    }

    /// Send given data from the local address this transport is bound to to
    /// the remote host that this transport is connected to.
    fn send(&mut self, data: Bytes) {
        if let Some(binding) = self.binding {
            self.send_using(binding.local, binding.remote, data);
        } else if cfg!(debug_assertions) {
            panic!("unable to send given data packet, no binding");
        }
    }
}

/// Component binding.
#[derive(Copy, Clone)]
struct ComponentBinding {
    local: SocketAddr,
    remote: SocketAddr,
}

impl ComponentBinding {
    /// Create a new component binding.
    fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self { local, remote }
    }
}
