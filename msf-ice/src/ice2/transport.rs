use std::{
    collections::HashMap,
    future::Future,
    io,
    mem::MaybeUninit,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use tokio::{net::UdpSocket, task::JoinHandle};

use crate::ice2::{agent::AgentHandle, turn::TURNAllocation};

/// Data packet.
#[derive(Clone)]
pub struct Packet {
    data: Bytes,
    remote_addr: SocketAddr,
    base_addr: SocketAddr,
}

impl Packet {
    /// Create a new packet.
    pub fn new(base_addr: SocketAddr, remote_addr: SocketAddr, data: Bytes) -> Self {
        Self {
            base_addr,
            remote_addr,
            data,
        }
    }

    /// Get the local base address.
    pub fn base_addr(&self) -> SocketAddr {
        self.base_addr
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the data.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Consume the packet and return the data.
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// Incoming packet handler.
#[trait_variant::make(Send)]
pub trait IncomingPacketHandler {
    /// Handle an incoming packet or a read error.
    async fn handle(&mut self, next: io::Result<Packet>) -> io::Result<()>;
}

/// Outgoing packet dispatcher.
#[derive(Clone)]
pub struct OutgoingPacketDispatcher {
    context: Arc<Mutex<OutgoingPacketDispatcherContext>>,
}

impl OutgoingPacketDispatcher {
    /// Create a new packet dispatcher.
    pub fn new() -> Self {
        Self {
            context: Arc::new(Mutex::new(OutgoingPacketDispatcherContext::new())),
        }
    }

    /// Add a given transport to the dispatcher.
    pub fn add_transport(&self, transport: Transport) {
        self.context.lock().unwrap().add_transport(transport);
    }

    /// Retain transports that satisfy a given predicate.
    pub fn retain_transports<F>(&self, f: F)
    where
        F: FnMut(&Transport) -> bool,
    {
        self.context.lock().unwrap().retain_transports(f);
    }

    /// Add a given TURN allocation to the dispatcher.
    pub fn add_turn_allocation(&mut self, allocation: TURNAllocation) {
        self.context.lock().unwrap().add_turn_allocation(allocation);
    }

    /// Retain TURN allocations that satisfy a given predicate.
    pub fn retain_turn_allocations<F>(&mut self, mut f: F)
    where
        F: FnMut(&TURNAllocation) -> bool,
    {
        self.context.lock().unwrap().retain_turn_allocations(f);
    }

    /// Send a given packet.
    pub async fn send(&self, packet: Packet) -> io::Result<()> {
        let send = self.context.lock().unwrap().send(packet);

        send.await
    }
}

/// Internal context for the outgoing packet dispatcher.
struct OutgoingPacketDispatcherContext {
    transports: HashMap<SocketAddr, Transport>,
    turn_allocations: HashMap<SocketAddr, TURNAllocation>,
}

impl OutgoingPacketDispatcherContext {
    /// Create a new context.
    fn new() -> Self {
        Self {
            transports: HashMap::new(),
            turn_allocations: HashMap::new(),
        }
    }

    /// Add a given transport to the context.
    fn add_transport(&mut self, transport: Transport) {
        self.transports.insert(transport.local_addr(), transport);
    }

    /// Retain only transports that satisfy a given predicate.
    fn retain_transports<F>(&mut self, mut f: F)
    where
        F: FnMut(&Transport) -> bool,
    {
        self.transports.retain(|_, v| f(v));
    }

    /// Add a given TURN allocation to the context.
    fn add_turn_allocation(&mut self, allocation: TURNAllocation) {
        self.turn_allocations
            .insert(allocation.relayed_addr(), allocation);
    }

    /// Retain only TURN allocations that satisfy a given predicate.
    fn retain_turn_allocations<F>(&mut self, mut f: F)
    where
        F: FnMut(&TURNAllocation) -> bool,
    {
        self.turn_allocations.retain(|_, v| f(v));
    }

    /// Send a given packet.
    fn send(&self, mut packet: Packet) -> impl Future<Output = io::Result<()>> + use<> {
        let turn_allocation = self.turn_allocations.get(&packet.base_addr());

        let transport = if let Some(ta) = turn_allocation {
            self.transports.get(&ta.local_addr())
        } else {
            self.transports.get(&packet.base_addr())
        };

        let transport = transport.cloned();
        let turn_allocation = turn_allocation.cloned();

        async move {
            let transport = transport.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;

            if let Some(ta) = turn_allocation {
                let base_addr = packet.base_addr();
                let remote_addr = packet.remote_addr();
                let data = packet.data();

                packet = ta
                    .construct_outgoing_packet(base_addr, remote_addr, data)
                    .await;
            }

            transport.send(packet).await
        }
    }
}

/// Transport abstraction.
#[derive(Clone)]
pub struct Transport {
    context: Arc<TransportContext>,
}

impl Transport {
    /// Create a new UDP transport.
    pub async fn udp<T>(
        ice_agent: AgentHandle,
        addr: SocketAddr,
        incoming_packet_handler: T,
    ) -> io::Result<Self>
    where
        T: IncomingPacketHandler + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind(addr).await?;

        let context = TransportContext::new(ice_agent, socket, incoming_packet_handler)?;

        let res = Self {
            context: Arc::new(context),
        };

        Ok(res)
    }

    /// Get the local address of the transport.
    pub fn local_addr(&self) -> SocketAddr {
        self.context.local_addr()
    }

    /// Send a given packet using the transport.
    fn send(&self, packet: Packet) -> impl Future<Output = io::Result<()>> + use<> {
        self.context.send(packet)
    }
}

/// Internal context for the transport.
struct TransportContext {
    local_addr: SocketAddr,
    send_packet_request_tx: SendPacketRequestTx,
    reader_task: JoinHandle<()>,
}

impl TransportContext {
    /// Create a new transport context.
    fn new<T>(
        ice_agent: AgentHandle,
        socket: UdpSocket,
        incoming_packet_handler: T,
    ) -> io::Result<Self>
    where
        T: IncomingPacketHandler + Send + Sync + 'static,
    {
        let local_addr = socket.local_addr()?;

        let socket = Arc::new(socket);

        let (send_packet_request_tx, send_packet_request_rx) = mpsc::channel(4);

        let sender = UdpPacketSender {
            socket: socket.clone(),
            requests: send_packet_request_rx,
        };

        tokio::spawn(sender.send_all());

        let reader = UdpPacketReader {
            socket,
            local_addr,
            ice_agent,
            packet_handler: incoming_packet_handler,
        };

        let reader_task = tokio::spawn(reader.read_all());

        let context = Self {
            local_addr,
            send_packet_request_tx,
            reader_task,
        };

        Ok(context)
    }

    /// Get the local address of the transport.
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send a given packet.
    fn send(&self, packet: Packet) -> impl Future<Output = io::Result<()>> + use<> {
        let mut send_packet_request_tx = self.send_packet_request_tx.clone();

        async move {
            let remote_addr = packet.remote_addr();
            let data = packet.into_data();

            let (result_tx, result_rx) = oneshot::channel();

            let request = SendPacketRequest {
                target: remote_addr,
                data,
                result_tx,
            };

            let _ = send_packet_request_tx.send(request);

            result_rx
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
        }
    }
}

impl Drop for TransportContext {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

/// Request to send a packet.
struct SendPacketRequest {
    target: SocketAddr,
    data: Bytes,
    result_tx: SendPacketResultTx,
}

/// Helper type.
type SendPacketRequestTx = mpsc::Sender<SendPacketRequest>;

/// Helper type.
type SendPacketRequestRx = mpsc::Receiver<SendPacketRequest>;

/// Helper type.
type SendPacketResultTx = oneshot::Sender<io::Result<()>>;

/// UDP packet sender.
struct UdpPacketSender {
    socket: Arc<UdpSocket>,
    requests: SendPacketRequestRx,
}

impl UdpPacketSender {
    /// Send all packets received from the request channel.
    async fn send_all(mut self) {
        while let Some(request) = self.requests.next().await {
            let res = self
                .socket
                .send_to(&request.data, request.target)
                .await
                .map(|_| ());

            let _ = request.result_tx.send(res);
        }
    }
}

/// UDP packet reader.
struct UdpPacketReader<T> {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    ice_agent: AgentHandle,
    packet_handler: T,
}

impl<T> UdpPacketReader<T>
where
    T: IncomingPacketHandler,
{
    /// Read all incoming packets and pass them to the packet handler.
    async fn read_all(mut self) {
        loop {
            let next = self.read().await;

            let next_is_err = next.is_err();

            let send = self.packet_handler.handle(next);

            if send.await.is_err() || next_is_err {
                return;
            }
        }
    }
}

impl<T> UdpPacketReader<T> {
    /// Read a single incoming packet.
    async fn read(&self) -> io::Result<Packet> {
        let mut buf = MaybeUninit::<[u8; 65536]>::uninit();

        loop {
            let (len, peer) = self
                .socket
                .recv_buf_from(&mut AsMut::<[MaybeUninit<u8>]>::as_mut(&mut buf))
                .await?;

            // SAFETY: We've just initialized the first `len` bytes.
            let initialized = unsafe { &buf.assume_init_ref()[..len] };

            let data = Bytes::copy_from_slice(initialized);

            let packet = Packet::new(self.local_addr, peer, data);

            if let Some(packet) = self.ice_agent.process_incoming_packet(packet) {
                return Ok(packet);
            }
        }
    }
}
