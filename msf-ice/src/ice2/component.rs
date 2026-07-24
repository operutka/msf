use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{channel::mpsc, SinkExt, StreamExt};
use tokio::task::JoinHandle;

use crate::ice2::{
    stun::{Method, STUN},
    transport::{IncomingPacketHandler, OutgoingPacketDispatcher, Packet},
};

/// Data stream component.
///
/// The component can be used to send and receive data over an ICE connection.
pub struct Component {
    context: Arc<ComponentContext>,
    incoming: IncomingPacketRx,
    keep_alive_handle: JoinHandle<()>,
}

impl Component {
    /// Create a new component.
    pub(crate) fn new(
        id: u8,
        data_stream: usize,
        stun: STUN,
        outgoing_packet_dispatcher: OutgoingPacketDispatcher,
        keep_alive_interval: Duration,
    ) -> Self {
        let (incoming_packet_tx, incoming_packet_rx) = mpsc::channel(4);

        let context = ComponentContext::new(
            id,
            data_stream,
            stun,
            outgoing_packet_dispatcher,
            incoming_packet_tx,
            keep_alive_interval,
        );

        let context = Arc::new(context);

        let keep_alive_task = KeepAliveTask {
            context: context.clone(),
        };

        let keep_alive_handle = tokio::spawn(keep_alive_task.run());

        Self {
            context,
            incoming: incoming_packet_rx,
            keep_alive_handle,
        }
    }

    /// Get a component handle.
    pub(crate) fn handle(&self) -> ComponentHandle {
        ComponentHandle {
            context: self.context.clone(),
        }
    }

    /// Send data to the remote peer.
    pub async fn send(&mut self, data: Bytes) -> io::Result<()> {
        self.context.send(data).await
    }

    /// Receive data from the remote peer.
    pub async fn recv(&mut self) -> io::Result<Bytes> {
        self.incoming
            .next()
            .await
            .transpose()?
            .map(Packet::into_data)
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl Drop for Component {
    fn drop(&mut self) {
        self.keep_alive_handle.abort();
    }
}

/// Component handle.
#[derive(Clone)]
pub struct ComponentHandle {
    context: Arc<ComponentContext>,
}

impl ComponentHandle {
    /// Get the component ID.
    pub fn id(&self) -> u8 {
        self.context.id
    }

    /// Get the data stream ID.
    pub fn data_stream(&self) -> usize {
        self.context.data_stream
    }

    /// Bind the component to a given local base address and a remote peer
    /// address.
    pub fn bind(&self, base_addr: SocketAddr, remote_addr: SocketAddr) {
        self.context.bind(base_addr, remote_addr);
    }
}

impl IncomingPacketHandler for ComponentHandle {
    async fn handle(&mut self, next: io::Result<Packet>) -> io::Result<()> {
        self.context
            .incoming_packet_tx
            .clone()
            .send(next)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Component context.
struct ComponentContext {
    id: u8,
    data_stream: usize,
    stun: STUN,
    outgoing_packet_tx: OutgoingPacketDispatcher,
    incoming_packet_tx: IncomingPacketTx,
    mutable: Mutex<MutableComponentContext>,
}

impl ComponentContext {
    /// Create a new component context.
    fn new(
        id: u8,
        data_stream: usize,
        stun: STUN,
        outgoing_packet_tx: OutgoingPacketDispatcher,
        incoming_packet_tx: IncomingPacketTx,
        keep_alive_interval: Duration,
    ) -> Self {
        Self {
            id,
            data_stream,
            stun,
            outgoing_packet_tx,
            incoming_packet_tx,
            mutable: Mutex::new(MutableComponentContext::new(keep_alive_interval)),
        }
    }

    /// Bind the component to a given local base address and a remote peer
    /// address.
    fn bind(&self, base_addr: SocketAddr, remote_addr: SocketAddr) {
        self.mutable.lock().unwrap().bind(base_addr, remote_addr);
    }

    /// Poll the next outgoing packet route.
    fn poll_next_outgoing_packet_route(&self, cx: &mut Context<'_>) -> Poll<ComponentBinding> {
        self.mutable
            .lock()
            .unwrap()
            .poll_next_outgoing_packet_route(cx)
    }

    /// Send data to the remote peer.
    async fn send(&self, data: Bytes) -> io::Result<()> {
        let binding = futures::future::poll_fn(|cx| self.poll_next_outgoing_packet_route(cx)).await;

        let packet = Packet::new(binding.base_addr, binding.remote_addr, data);

        self.outgoing_packet_tx.send(packet).await
    }

    /// Single tick of the keep-alive task.
    async fn keep_alive_tick(&self) {
        let event = self.mutable.lock().unwrap().next_keep_alive_event();

        match event {
            KeepAliveEvent::SendKeepAlive(binding) => {
                let res = self
                    .stun
                    .build_indication(Method::Binding)
                    .build()
                    .send(binding.base_addr, binding.remote_addr)
                    .await;

                if let Err(err) = res {
                    // TODO: debug log
                }
            }
            KeepAliveEvent::SleepUntil(t) => tokio::time::sleep_until(t.into()).await,
        }
    }
}

/// Mutable part of the component context.
struct MutableComponentContext {
    binding: Option<ComponentBinding>,
    sender: Option<Waker>,
    next_keep_alive: Instant,
    keep_alive_interval: Duration,
}

impl MutableComponentContext {
    /// Create a new mutable component context.
    fn new(keep_alive_interval: Duration) -> Self {
        let now = Instant::now();

        Self {
            binding: None,
            sender: None,
            next_keep_alive: now + keep_alive_interval,
            keep_alive_interval,
        }
    }

    /// Bind the component to a given local base address and a remote peer
    /// address.
    fn bind(&mut self, base_addr: SocketAddr, remote_addr: SocketAddr) {
        let binding = ComponentBinding {
            base_addr,
            remote_addr,
        };

        self.binding = Some(binding);

        let now = Instant::now();

        self.next_keep_alive = now + self.keep_alive_interval;

        if let Some(task) = self.sender.take() {
            task.wake();
        }
    }

    /// Poll the next outgoing packet route.
    fn poll_next_outgoing_packet_route(&mut self, cx: &mut Context<'_>) -> Poll<ComponentBinding> {
        if let Some(route) = self.next_outgoing_packet_route() {
            Poll::Ready(route)
        } else {
            let task = cx.waker();

            self.sender = Some(task.clone());

            Poll::Pending
        }
    }

    /// Get the next outgoing packet route.
    fn next_outgoing_packet_route(&mut self) -> Option<ComponentBinding> {
        if let Some(binding) = self.binding.as_ref() {
            let now = Instant::now();

            self.next_keep_alive = now + self.keep_alive_interval;

            Some(*binding)
        } else {
            None
        }
    }

    /// Get the next keep-alive event.
    fn next_keep_alive_event(&mut self) -> KeepAliveEvent {
        let now = Instant::now();

        if self.next_keep_alive > now {
            KeepAliveEvent::SleepUntil(self.next_keep_alive)
        } else if let Some(route) = self.next_outgoing_packet_route() {
            KeepAliveEvent::SendKeepAlive(route)
        } else {
            KeepAliveEvent::SleepUntil(now + self.keep_alive_interval)
        }
    }
}

/// Helper type.
type IncomingPacketRx = mpsc::Receiver<io::Result<Packet>>;

/// Helper type.
type IncomingPacketTx = mpsc::Sender<io::Result<Packet>>;

/// Component binding.
#[derive(Copy, Clone)]
struct ComponentBinding {
    base_addr: SocketAddr,
    remote_addr: SocketAddr,
}

/// Keep-alive event.
enum KeepAliveEvent {
    SleepUntil(Instant),
    SendKeepAlive(ComponentBinding),
}

/// Keep-alive task.
struct KeepAliveTask {
    context: Arc<ComponentContext>,
}

impl KeepAliveTask {
    /// Run the keep-alive task.
    async fn run(self) {
        loop {
            self.context.keep_alive_tick().await;
        }
    }
}
