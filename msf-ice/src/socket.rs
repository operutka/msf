use std::{
    future::Future,
    io,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{channel::mpsc, ready, StreamExt};
use tokio::{io::ReadBuf, net::UdpSocket};

#[cfg(feature = "slog")]
use slog::Logger;

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

type InputPacket = Packet;
type OutputPacket = (SocketAddr, Bytes);

/// ICE socket manager.
pub struct ICESockets {
    #[cfg(feature = "slog")]
    logger: Logger,
    open_sockets: Vec<Socket>,
    socket_rx: mpsc::UnboundedReceiver<Socket>,
    packet_rx: mpsc::UnboundedReceiver<Packet>,
}

impl ICESockets {
    /// Create a new socket manager.
    #[cfg(not(feature = "slog"))]
    pub fn new(local_addresses: &[IpAddr]) -> Self {
        let (socket_tx, socket_rx) = mpsc::unbounded();
        let (packet_tx, packet_rx) = mpsc::unbounded();

        for addr in local_addresses {
            let addr = SocketAddr::from((*addr, 0));
            let socket_tx = socket_tx.clone();
            let packet_tx = packet_tx.clone();

            tokio::spawn(async move {
                let future = Socket::new(addr, packet_tx);

                #[allow(clippy::single_match)]
                match future.await {
                    Ok(socket) => socket_tx.unbounded_send(socket).unwrap_or_default(),

                    #[cfg(feature = "log")]
                    Err(err) => {
                        warn!("unable to create a new UDP socket: {}", err);
                    }

                    #[cfg(not(feature = "log"))]
                    Err(_) => (),
                }
            });
        }

        Self {
            open_sockets: Vec::with_capacity(local_addresses.len()),
            socket_rx,
            packet_rx,
        }
    }

    /// Create a new socket manager.
    #[cfg(feature = "slog")]
    pub fn new(logger: Logger, local_addresses: &[IpAddr]) -> Self {
        let (socket_tx, socket_rx) = mpsc::unbounded();
        let (packet_tx, packet_rx) = mpsc::unbounded();

        for addr in local_addresses {
            let addr = SocketAddr::from((*addr, 0));
            let socket_tx = socket_tx.clone();
            let packet_tx = packet_tx.clone();
            let logger = logger.clone();

            tokio::spawn(async move {
                let future = Socket::new(logger.clone(), addr, packet_tx);

                match future.await {
                    Ok(socket) => socket_tx.unbounded_send(socket).unwrap_or_default(),
                    Err(err) => {
                        warn!(logger, "unable to create a new UDP socket"; "cause" => %err);
                    }
                }
            });
        }

        Self {
            logger,
            open_sockets: Vec::with_capacity(local_addresses.len()),
            socket_rx,
            packet_rx,
        }
    }

    /// Get the next local binding.
    pub fn poll_next_binding(&mut self, cx: &mut Context<'_>) -> Poll<Option<SocketAddr>> {
        if let Some(socket) = ready!(self.socket_rx.poll_next_unpin(cx)) {
            let addr = socket.local_addr();

            self.open_sockets.push(socket);

            Poll::Ready(Some(addr))
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
                Poll::Pending => return Poll::Pending,
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
            socket.send(remote_addr, data);
        } else {
            #[cfg(feature = "log")]
            warn!("unknown socket for local binding {}", local_addr);

            #[cfg(feature = "slog")]
            warn!(
                self.logger,
                "unknown socket for local binding {}", local_addr
            );
        }
    }
}

/// Single ICE socket.
struct Socket {
    local_addr: SocketAddr,
    output_packet_tx: mpsc::UnboundedSender<OutputPacket>,
}

impl Socket {
    /// Create a new socket bound to a given local address.
    #[cfg(not(feature = "slog"))]
    async fn new(
        local_addr: SocketAddr,
        input_packet_tx: mpsc::UnboundedSender<InputPacket>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;

        let local_addr = socket.local_addr()?;

        let (output_packet_tx, output_packet_rx) = mpsc::unbounded();

        let handler = SocketHandler {
            socket,
            local_addr,
            input_packet_tx,
            output_packet_rx,
            pending_output_packet: None,
            closed: false,
        };

        let socket = Self {
            local_addr,
            output_packet_tx,
        };

        tokio::spawn(handler);

        Ok(socket)
    }

    /// Create a new socket bound to a given local address.
    #[cfg(feature = "slog")]
    async fn new(
        logger: Logger,
        local_addr: SocketAddr,
        input_packet_tx: mpsc::UnboundedSender<InputPacket>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;

        let local_addr = socket.local_addr()?;

        let (output_packet_tx, output_packet_rx) = mpsc::unbounded();

        let handler = SocketHandler {
            logger,
            socket,
            local_addr,
            input_packet_tx,
            output_packet_rx,
            pending_output_packet: None,
            closed: false,
        };

        let socket = Self {
            local_addr,
            output_packet_tx,
        };

        tokio::spawn(handler);

        Ok(socket)
    }

    /// Get the local address where the socket is bound to.
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Check if the socket bound to a given address.
    fn is_bound_to(&self, local_addr: SocketAddr) -> bool {
        let socket_local_addr = self.local_addr();

        socket_local_addr == local_addr
            || (local_addr.port() == 0 && socket_local_addr.ip() == local_addr.ip())
    }

    /// Send given data to a given remote destination.
    fn send(&self, remote_addr: SocketAddr, data: Bytes) {
        self.output_packet_tx
            .unbounded_send((remote_addr, data))
            .unwrap_or_default();
    }
}

/// Background task responsible for the socket IO.
struct SocketHandler {
    #[cfg(feature = "slog")]
    logger: Logger,
    socket: UdpSocket,
    local_addr: SocketAddr,
    input_packet_tx: mpsc::UnboundedSender<InputPacket>,
    output_packet_rx: mpsc::UnboundedReceiver<OutputPacket>,
    pending_output_packet: Option<OutputPacket>,
    closed: bool,
}

impl SocketHandler {
    /// Get the next output packet.
    fn poll_next_output_packet(&mut self, cx: &mut Context<'_>) -> Poll<Option<OutputPacket>> {
        if let Some(packet) = self.pending_output_packet.take() {
            return Poll::Ready(Some(packet));
        } else if self.closed {
            return Poll::Ready(None);
        }

        let item = ready!(self.output_packet_rx.poll_next_unpin(cx));

        if item.is_none() {
            self.closed = true;
        }

        Poll::Ready(item)
    }

    /// Send the next output packet.
    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some((target, data)) = ready!(self.poll_next_output_packet(cx)) {
            let poll = self.socket.poll_send_to(cx, &data, target);

            #[allow(clippy::single_match)]
            match &poll {
                Poll::Pending => self.pending_output_packet = Some((target, data)),

                #[cfg(feature = "log")]
                Poll::Ready(Err(err)) => {
                    warn!("socket send error: {}", err);
                }

                #[cfg(feature = "slog")]
                Poll::Ready(Err(err)) => {
                    warn!(self.logger, "socket send error"; "cause" => %err);
                }

                _ => (),
            }

            poll.map(|_| ())
        } else {
            Poll::Ready(())
        }
    }

    /// Read the next input packet.
    fn poll_input(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // XXX: use MaybeUninit::uninit_array() once stabilized
        let mut buffer: [MaybeUninit<u8>; 65_536] = unsafe { MaybeUninit::uninit().assume_init() };

        let mut buffer = ReadBuf::uninit(&mut buffer);

        #[allow(clippy::single_match)]
        match ready!(self.socket.poll_recv_from(cx, &mut buffer)) {
            Ok(peer) => {
                let packet = Packet {
                    local_addr: self.local_addr,
                    remote_addr: peer,
                    data: Bytes::copy_from_slice(buffer.filled()),
                };

                self.input_packet_tx
                    .unbounded_send(packet)
                    .unwrap_or_default();
            }

            #[cfg(feature = "log")]
            Err(err) => {
                warn!("socket read error: {}", err);
            }

            #[cfg(feature = "slog")]
            Err(err) => {
                warn!(self.logger, "socket read error"; "cause" => %err);
            }

            #[cfg(not(any(feature = "log", feature = "slog")))]
            _ => (),
        }

        Poll::Ready(())
    }
}

impl Future for SocketHandler {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let output = self.poll_output(cx);

            if self.closed {
                return Poll::Ready(());
            }

            let input = self.poll_input(cx);

            if output.is_pending() && input.is_pending() {
                return Poll::Pending;
            }
        }
    }
}
