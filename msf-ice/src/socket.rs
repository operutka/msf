use std::{
    future::Future,
    io,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    ready, Sink, SinkExt, Stream, StreamExt,
};
use msf_stun as stun;
use tokio::{io::ReadBuf, net::UdpSocket, task::JoinHandle};

use crate::log::Logger;

/// Data packet.
#[derive(Clone)]
pub struct Packet {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    data: Bytes,
}

impl Packet {
    /// Get the local address where the packet was received.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the remote address where the packet was sent from.
    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get packet data.
    #[inline]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Take the packet data.
    #[inline]
    pub fn take_data(self) -> Bytes {
        self.data
    }
}

///
type InputPacket = Packet;

///
type OutputPacket = (SocketAddr, Bytes);

///
type OutputPacketTx = mpsc::UnboundedSender<OutputPacket>;

/// ICE socket manager.
pub struct ICESockets {
    logger: Logger,
    open_sockets: Vec<Socket>,
    binding_rx: mpsc::Receiver<Binding>,
    socket_rx: mpsc::Receiver<Socket>,
    packet_rx: mpsc::Receiver<Packet>,
}

impl ICESockets {
    /// Create a new socket manager.
    pub fn new(logger: Logger, local_addresses: &[IpAddr], stun_servers: &[SocketAddr]) -> Self {
        let (binding_tx, binding_rx) = mpsc::channel(4);
        let (socket_tx, socket_rx) = mpsc::channel(4);
        let (packet_tx, packet_rx) = mpsc::channel(4);

        let unspecified = &[IpAddr::from(Ipv4Addr::UNSPECIFIED)][..];

        let local_addresses = if local_addresses.is_empty() {
            unspecified
        } else {
            local_addresses
        };

        let stun_servers = Arc::new(stun_servers.to_vec());

        for addr in local_addresses {
            let logger = logger.clone();
            let addr = SocketAddr::from((*addr, 0));
            let binding_tx = binding_tx.clone();
            let packet_tx = packet_tx.clone();
            let stun_servers = stun_servers.clone();

            let mut socket_tx = socket_tx.clone();

            tokio::spawn(async move {
                let socket =
                    Socket::new(logger.clone(), addr, &stun_servers, packet_tx, binding_tx);

                match socket.await {
                    Ok(socket) => {
                        let _ = socket_tx.send(socket).await;
                    }
                    Err(err) => {
                        warn!(logger, "unable to create a new UDP socket"; "cause" => %err);
                    }
                }
            });
        }

        Self {
            logger,
            open_sockets: Vec::with_capacity(local_addresses.len()),
            binding_rx,
            socket_rx,
            packet_rx,
        }
    }

    /// Get the next local binding.
    pub fn poll_next_binding(&mut self, cx: &mut Context<'_>) -> Poll<Option<Binding>> {
        let mut pending = true;

        while let Poll::Ready(ready) = self.socket_rx.poll_next_unpin(cx) {
            if let Some(socket) = ready {
                self.open_sockets.push(socket);
            } else {
                // we can return None if necessary
                pending = false;

                break;
            }
        }

        if let Some(binding) = ready!(self.binding_rx.poll_next_unpin(cx)) {
            Poll::Ready(Some(binding))
        } else if pending {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }

    /*/// Close all sockets matching a given filter function.
    ///
    /// TODO: use this
    pub fn close_sockets<F>(&mut self, mut filter: F)
    where
        F: FnMut(SocketAddr) -> bool,
    {
        self.open_sockets.retain(|socket| !filter(socket.local_addr()));
    }*/

    /// Receive the next packet.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Packet> {
        loop {
            match self.poll_next_binding(cx) {
                Poll::Ready(Some(_)) => (),
                Poll::Ready(None) => break,
                Poll::Pending => break,
            }
        }

        if let Poll::Ready(Some(packet)) = self.packet_rx.poll_next_unpin(cx) {
            Poll::Ready(packet)
        } else {
            Poll::Pending
        }
    }

    /// Send given data from a given local binding to a given destination.
    pub fn send(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr, data: Bytes) {
        let socket = self
            .open_sockets
            .iter_mut()
            .find(|socket| socket.is_bound_to(local_addr));

        if let Some(socket) = socket {
            let _ = socket.send(remote_addr, data);
        } else {
            debug!(self.logger, "unknown socket for local binding"; "binding" => %local_addr);
        }
    }
}

///
#[derive(Copy, Clone)]
pub enum Binding {
    Local(LocalBinding),
    Reflexive(ReflexiveBinding),
}

impl Binding {
    ///
    fn local(addr: SocketAddr) -> Self {
        Self::Local(LocalBinding::new(addr))
    }

    ///
    fn reflexive(base: SocketAddr, addr: SocketAddr, source: SocketAddr) -> Self {
        Self::Reflexive(ReflexiveBinding::new(base, addr, source))
    }
}

///
#[derive(Copy, Clone)]
pub struct LocalBinding {
    addr: SocketAddr,
}

impl LocalBinding {
    ///
    fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    ///
    pub fn addr(self) -> SocketAddr {
        self.addr
    }
}

///
#[derive(Copy, Clone)]
pub struct ReflexiveBinding {
    base: SocketAddr,
    addr: SocketAddr,
    source: SocketAddr,
}

impl ReflexiveBinding {
    ///
    fn new(base: SocketAddr, addr: SocketAddr, source: SocketAddr) -> Self {
        Self { base, addr, source }
    }

    ///
    pub fn base(&self) -> SocketAddr {
        self.base
    }

    ///
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    ///
    pub fn source(&self) -> SocketAddr {
        self.source
    }
}

///
struct Socket {
    local_addr: SocketAddr,
    output_packet_tx: OutputPacketTx,
    reader: JoinHandle<()>,
    keep_alive: JoinHandle<()>,
}

impl Socket {
    ///
    async fn new<S, B>(
        logger: Logger,
        local_addr: SocketAddr,
        stun_servers: &[SocketAddr],
        input_packet_tx: S,
        mut binding_tx: B,
    ) -> io::Result<Self>
    where
        S: Sink<InputPacket> + Send + Unpin + 'static,
        B: Sink<Binding> + Send + Unpin + 'static,
    {
        let socket = UdpSocketWrapper::bind(local_addr).await?;

        let local_addr = socket.local_addr();

        let _ = binding_tx.send(Binding::local(local_addr)).await;

        let (output_packet_tx, output_packet_rx) = mpsc::unbounded();

        tokio::spawn(socket.write_all(logger.clone(), output_packet_rx));

        let mut stun_context = StunContext::new(output_packet_tx.clone());

        let ctx = stun_context.clone();

        let reader = tokio::spawn(async move {
            let _ = socket.read_all(logger, input_packet_tx, ctx).await;
        });

        let stun_servers = stun_servers
            .iter()
            .copied()
            .filter(|addr| local_addr.is_ipv4() == addr.is_ipv4())
            .collect::<Vec<_>>();

        let keep_alive = tokio::spawn(async move {
            let reflexive_addr = stun_context.get_reflexive_addr(stun_servers);

            if let Some((reflexive_addr, stun_server)) = reflexive_addr.await {
                let binding = Binding::reflexive(local_addr, reflexive_addr, stun_server);

                let _ = binding_tx.send(binding).await;

                // TODO: check the timing
                stun_context
                    .keep_alive(stun_server, Duration::from_secs(10))
                    .await;
            }
        });

        let res = Self {
            local_addr,
            output_packet_tx,
            reader,
            keep_alive,
        };

        Ok(res)
    }

    /// Check if the socket bound to a given address.
    fn is_bound_to(&self, local_addr: SocketAddr) -> bool {
        self.local_addr == local_addr
            || (local_addr.port() == 0 && self.local_addr.ip() == local_addr.ip())
    }

    /// Send given data to a given remote destination.
    fn send(&self, remote_addr: SocketAddr, data: Bytes) -> io::Result<()> {
        self.output_packet_tx
            .unbounded_send((remote_addr, data))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.keep_alive.abort();
        self.reader.abort();
    }
}

///
struct UdpSocketWrapper {
    inner: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl UdpSocketWrapper {
    ///
    async fn bind(local_addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;

        let local_addr = socket.local_addr()?;

        let res = Self {
            inner: Arc::new(socket),
            local_addr,
        };

        Ok(res)
    }

    ///
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    ///
    fn write_all<S>(&self, logger: Logger, mut stream: S) -> impl Future<Output = ()>
    where
        S: Stream<Item = OutputPacket> + Unpin,
    {
        let socket = self.inner.clone();

        async move {
            while let Some((peer, data)) = stream.next().await {
                if let Err(err) = socket.send_to(&data, peer).await {
                    // log the error
                    warn!(logger, "socket write error"; "cause" => %err);

                    // ... and terminate the loop
                    break;
                }
            }
        }
    }

    ///
    async fn read_all<S>(
        self,
        logger: Logger,
        mut sink: S,
        mut stun_context: StunContext,
    ) -> Result<(), S::Error>
    where
        S: Sink<Packet> + Unpin,
    {
        let stream = UdpSocketStream::from(self);

        let mut filtered = stream.filter_map(move |item| {
            let res = match item {
                Ok(packet) => {
                    if let Err(packet) = stun_context.process_packet(packet) {
                        Some(Ok(packet))
                    } else {
                        None
                    }
                }
                Err(err) => Some(Err(err)),
            };

            futures::future::ready(res)
        });

        while let Some(item) = filtered.next().await {
            match item {
                Ok(packet) => sink.send(packet).await?,
                Err(err) => {
                    warn!(logger, "socket read error"; "cause" => %err);
                }
            }
        }

        Ok(())
    }
}

///
struct UdpSocketStream {
    socket: Option<Arc<UdpSocket>>,
    local_addr: SocketAddr,
}

impl Stream for UdpSocketStream {
    type Item = io::Result<Packet>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(socket) = self.socket.as_ref() {
            // XXX: use MaybeUninit::uninit_array() once stabilized
            let mut buffer: [MaybeUninit<u8>; 65_536] =
                unsafe { MaybeUninit::uninit().assume_init() };

            let mut buffer = ReadBuf::uninit(&mut buffer);

            match ready!(socket.poll_recv_from(cx, &mut buffer)) {
                Ok(peer) => {
                    let packet = Packet {
                        local_addr: self.local_addr,
                        remote_addr: peer,
                        data: Bytes::copy_from_slice(buffer.filled()),
                    };

                    Poll::Ready(Some(Ok(packet)))
                }
                Err(err) => {
                    // drop the socket, we don't want to poll it again
                    self.socket = None;

                    Poll::Ready(Some(Err(err)))
                }
            }
        } else {
            Poll::Ready(None)
        }
    }
}

impl From<UdpSocketWrapper> for UdpSocketStream {
    fn from(socket: UdpSocketWrapper) -> Self {
        Self {
            socket: Some(socket.inner),
            local_addr: socket.local_addr,
        }
    }
}

// TODO: make these configurable
const RTO: u64 = 500;
const RM: u64 = 16;
const RC: u32 = 7;

///
type StunTransactionId = [u8; 12];

///
#[derive(Clone)]
struct StunContext {
    inner: Arc<Mutex<InnerStunContext>>,
    output_packet_tx: OutputPacketTx,
}

impl StunContext {
    ///
    fn new(output_packet_tx: OutputPacketTx) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerStunContext::new())),
            output_packet_tx,
        }
    }

    ///
    async fn get_reflexive_addr<I>(&mut self, stun_servers: I) -> Option<(SocketAddr, SocketAddr)>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let stun_servers = stun_servers.into_iter();

        let reflexive_addrs = futures::stream::iter(stun_servers.enumerate())
            .then(|(index, addr)| async move {
                if index > 0 {
                    tokio::time::sleep(Duration::from_millis(RTO << 1)).await;
                }

                addr
            })
            .map(|stun_server| {
                let request = self.new_binding_request(stun_server, RC);

                async move {
                    if let Ok(reflexive_addr) = request.await {
                        Some((reflexive_addr, stun_server))
                    } else {
                        None
                    }
                }
            })
            .buffered((((1 << (RC - 1)) + RM) * RTO / 1_000) as usize)
            .filter_map(|addr| futures::future::ready(addr));

        futures::pin_mut!(reflexive_addrs);

        reflexive_addrs.next().await
    }

    ///
    async fn keep_alive(&mut self, stun_server: SocketAddr, interval: Duration) {
        loop {
            tokio::time::sleep(interval).await;

            let _ = self.new_binding_request(stun_server, 1).await;
        }
    }

    ///
    fn new_binding_request(
        &mut self,
        stun_server: SocketAddr,
        attempts: u32,
    ) -> impl Future<Output = io::Result<SocketAddr>> {
        let transaction_id = rand::random();

        let (reflexive_addr_tx, reflexive_addr_rx) = oneshot::channel();

        let transaction = StunTransaction {
            context: self.clone(),
            output_packet_tx: self.output_packet_tx.clone(),
            reflexive_addr_rx,
            stun_server,
            transaction_id,
            next_timeout: Duration::from_millis(RTO),
            last_timeout: Duration::from_millis(RTO * RM),
            remaining_attempts: attempts,
        };

        let handle = StunTransactionHandle {
            transaction_id,
            reflexive_addr_tx,
        };

        self.inner.lock().unwrap().add_handle(handle);

        transaction.resolve()
    }

    ///
    fn remove_handle(&mut self, id: StunTransactionId) {
        self.inner.lock().unwrap().remove_handle(id);
    }

    ///
    fn process_packet(&mut self, packet: InputPacket) -> Result<(), InputPacket> {
        self.inner.lock().unwrap().process_packet(packet)
    }
}

///
struct InnerStunContext {
    transactions: Vec<StunTransactionHandle>,
}

impl InnerStunContext {
    ///
    fn new() -> Self {
        Self {
            transactions: Vec::new(),
        }
    }

    ///
    fn add_handle(&mut self, handle: StunTransactionHandle) {
        self.transactions.push(handle);
    }

    ///
    fn remove_handle(
        &mut self,
        transaction_id: StunTransactionId,
    ) -> Option<StunTransactionHandle> {
        self.transactions
            .iter()
            .position(|t| t.transaction_id() == transaction_id)
            .map(|i| self.transactions.swap_remove(i))
    }

    ///
    fn process_packet(&mut self, packet: InputPacket) -> Result<(), InputPacket> {
        let data = packet.data();

        if let Ok(msg) = stun::Message::from_frame(data.clone()) {
            if msg.is_rfc5389_message()
                && msg.is_response()
                && msg.method() == stun::Method::Binding
            {
                if let Some(handle) = self.remove_handle(msg.transaction_id()) {
                    let attrs = msg.attributes();

                    if let Some(addr) = attrs.get_any_mapped_address() {
                        handle.resolve(addr);
                    }

                    return Ok(());
                }
            }
        }

        Err(packet)
    }
}

///
struct StunTransaction<S, F> {
    context: StunContext,
    output_packet_tx: S,
    reflexive_addr_rx: F,
    stun_server: SocketAddr,
    transaction_id: StunTransactionId,
    next_timeout: Duration,
    last_timeout: Duration,
    remaining_attempts: u32,
}

impl<S, F, E> StunTransaction<S, F>
where
    S: Sink<OutputPacket> + Unpin,
    F: Future<Output = Result<SocketAddr, E>> + Unpin,
{
    ///
    async fn resolve(mut self) -> io::Result<SocketAddr> {
        let builder = stun::MessageBuilder::binding_request(self.transaction_id);

        let msg = builder.build();

        while self.remaining_attempts > 0 {
            self.output_packet_tx
                .send((self.stun_server, msg.clone()))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

            let timeout = if self.remaining_attempts > 1 {
                self.next_timeout
            } else {
                self.last_timeout
            };

            let addr = tokio::time::timeout(timeout, &mut self.reflexive_addr_rx);

            if let Ok(res) = addr.await {
                return res.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe));
            }

            self.remaining_attempts -= 1;
            self.next_timeout *= 2;
        }

        Err(io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl<S, F> Drop for StunTransaction<S, F> {
    fn drop(&mut self) {
        self.context.remove_handle(self.transaction_id);
    }
}

///
type ReflexiveAddrTx = oneshot::Sender<SocketAddr>;

///
struct StunTransactionHandle {
    transaction_id: StunTransactionId,
    reflexive_addr_tx: ReflexiveAddrTx,
}

impl StunTransactionHandle {
    ///
    fn transaction_id(&self) -> StunTransactionId {
        self.transaction_id
    }

    ///
    fn resolve(self, reflexive_addr: SocketAddr) {
        let _ = self.reflexive_addr_tx.send(reflexive_addr);
    }
}
