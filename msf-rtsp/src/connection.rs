use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

#[cfg(feature = "server")]
use std::sync::Weak;

use bytes::Bytes;
use futures::{
    channel::mpsc,
    future::AbortHandle,
    sink::{Sink, SinkExt},
    stream::{Stream, StreamExt},
};

use crate::{
    Error,
    interleaved::{ChannelData, InterleavedItem},
};

/// Base RTSP connection used by client/server.
pub struct BaseRtspConnection<I, O, E> {
    connection_handle: Arc<InternalConnectionHandle<I, E>>,
    incoming_messages: IncomingMessages<I, E>,
    outgoing_messages: OutgoingMessageSender<O>,
    abort_handle: AbortHandle,
}

impl<I, O, E> BaseRtspConnection<I, O, E> {
    /// Create a new RTSP connection from a given interleaved stream/sink.
    ///
    /// A background task handling the message passing is spawned. The task
    /// stops when the connection is dropped.
    ///
    /// All response messages and the interleaved response data are distributed
    /// using a publish-subscribe channel. This implies using "unlimited"
    /// buffers to prevent the interleaved channels and the RTSP response
    /// channel from blocking each other. Therefore, all interleaved channels
    /// returned by this connection and the connection itself must be polled
    /// from to prevent response messages from piling up.
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<InterleavedItem<I>, E>>,
        S: Sink<InterleavedItem<O>, Error = E>,
        S: Send + 'static,
        I: Send + Clone + 'static,
        O: Send + 'static,
        E: From<Error> + Send + 'static,
    {
        let (mut dispatcher, dispatcher_handle, incoming_messages) =
            IncomingMessageDispatcher::new();

        let (mut outgoing_items, outgoing_messages, outgoing_data) =
            OutgoingMessageCollector::new();

        let connection_handle = InternalConnectionHandle {
            dispatcher_handle,
            outgoing_data,
        };

        let (mut sink, mut stream) = stream.split();

        let process_outgoing_items = Box::pin(async move {
            while let Some(item) = outgoing_items.next().await {
                sink.send(item).await?;
            }

            Ok(()) as Result<(), E>
        });

        let process_incoming_items = Box::pin(async move {
            while let Some(item) = stream.next().await {
                // do not poll the stream again if this is an error
                let is_err = item.is_err();

                dispatcher.dispatch(item)?;

                if is_err {
                    break;
                }
            }

            Ok(()) as Result<(), E>
        });

        let process_all = futures::future::select(process_incoming_items, process_outgoing_items);

        let (abortable, abort_handle) = futures::future::abortable(process_all);

        tokio::spawn(abortable);

        Self {
            connection_handle: Arc::new(connection_handle),
            incoming_messages,
            outgoing_messages,
            abort_handle,
        }
    }

    /// Get an interleaved RTP stream for a given channel.
    #[cfg(feature = "client")]
    #[inline]
    pub fn get_interleaved_channel(
        &self,
        channel: Option<u8>,
    ) -> Result<InterleavedChannel, Error> {
        self.connection_handle.get_interleaved_channel(channel)
    }

    /// Get connection handle.
    #[cfg(feature = "server")]
    #[inline]
    pub fn handle(&self) -> BaseRtspConnectionHandle<I, E> {
        BaseRtspConnectionHandle {
            inner: Arc::downgrade(&self.connection_handle),
        }
    }
}

impl<I, O, E> Drop for BaseRtspConnection<I, O, E> {
    #[inline]
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

impl<I, O, E> Stream for BaseRtspConnection<I, O, E> {
    type Item = Result<I, E>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming_messages.poll_next_unpin(cx)
    }
}

impl<I, O, E> Sink<O> for BaseRtspConnection<I, O, E>
where
    E: From<Error>,
{
    type Error = E;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Sink::poll_ready(Pin::new(&mut self.outgoing_messages), cx)
            .map_err(|_| E::from(Error::from_static_msg("connection lost")))
    }

    fn start_send(mut self: Pin<&mut Self>, msg: O) -> Result<(), Self::Error> {
        Pin::new(&mut self.outgoing_messages)
            .start_send(msg)
            .map_err(|_| E::from(Error::from_static_msg("connection lost")))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Sink::poll_flush(Pin::new(&mut self.outgoing_messages), cx)
            .map_err(|_| E::from(Error::from_static_msg("connection lost")))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Sink::poll_close(Pin::new(&mut self.outgoing_messages), cx)
            .map_err(|_| E::from(Error::from_static_msg("connection lost")))
    }
}

/// RTSP connection handle.
#[cfg(feature = "server")]
pub struct BaseRtspConnectionHandle<I, E> {
    inner: Weak<InternalConnectionHandle<I, E>>,
}

#[cfg(feature = "server")]
impl<I, E> BaseRtspConnectionHandle<I, E> {
    /// Get an interleaved RTP stream for a given channel.
    pub fn get_interleaved_channel(
        &self,
        channel: Option<u8>,
    ) -> Result<InterleavedChannel, Error> {
        self.inner
            .upgrade()
            .ok_or_else(|| Error::from_static_msg("connection closed"))?
            .get_interleaved_channel(channel)
    }
}

#[cfg(feature = "server")]
impl<I, E> Clone for BaseRtspConnectionHandle<I, E> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// RTSP connection handle.
struct InternalConnectionHandle<I, E> {
    dispatcher_handle: IncomingMessageDispatcherHandle<I, E>,
    outgoing_data: OutgoingDataSender,
}

impl<I, E> InternalConnectionHandle<I, E> {
    /// Get an interleaved RTP stream for a given channel.
    fn get_interleaved_channel(&self, channel: Option<u8>) -> Result<InterleavedChannel, Error> {
        let input = self.dispatcher_handle.open_channel(channel)?;
        let output = self.outgoing_data.clone();

        let channel = input.channel();

        let res = InterleavedChannel {
            channel,
            input,
            output,
        };

        Ok(res)
    }
}

/// An interleaved channel.
pub struct InterleavedChannel {
    channel: u8,
    input: IncomingDataChannel,
    output: OutgoingDataSender,
}

impl InterleavedChannel {
    /// Get the channel number.
    #[inline]
    pub fn id(&self) -> u8 {
        self.channel
    }
}

impl Stream for InterleavedChannel {
    type Item = Result<Bytes, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.input.poll_next_unpin(cx)
    }
}

impl Sink<Bytes> for InterleavedChannel {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Sink::poll_ready(Pin::new(&mut self.output), cx)
            .map_err(|_| Error::from_static_msg("connection lost"))
    }

    fn start_send(mut self: Pin<&mut Self>, data: Bytes) -> Result<(), Self::Error> {
        let data = ChannelData::new(self.channel, data);

        Pin::new(&mut self.output)
            .start_send(data)
            .map_err(|_| Error::from_static_msg("connection lost"))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Sink::poll_flush(Pin::new(&mut self.output), cx)
            .map_err(|_| Error::from_static_msg("connection lost"))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Sink::poll_close(Pin::new(&mut self.output), cx)
            .map_err(|_| Error::from_static_msg("connection lost"))
    }
}

/// Type alias.
type IncomingData = mpsc::UnboundedReceiver<Result<Bytes, Error>>;

/// Type alias.
type IncomingDataSender = mpsc::UnboundedSender<Result<Bytes, Error>>;

/// Type alias.
type IncomingMessages<T, E> = mpsc::UnboundedReceiver<Result<T, E>>;

/// Type alias.
type IncomingMessageSender<T, E> = mpsc::UnboundedSender<Result<T, E>>;

/// Incoming message dispatcher.
struct IncomingMessageDispatcher<T, E> {
    context: Arc<Mutex<IncomingMessageDispatcherContext<T, E>>>,
}

impl<T, E> IncomingMessageDispatcher<T, E> {
    /// Create a new message dispatcher.
    fn new() -> (
        Self,
        IncomingMessageDispatcherHandle<T, E>,
        IncomingMessages<T, E>,
    ) {
        let (incoming_message_sender, incoming_messages) = mpsc::unbounded();

        let context = Arc::new(Mutex::new(IncomingMessageDispatcherContext::new(
            incoming_message_sender,
        )));

        let dispatcher = Self {
            context: context.clone(),
        };

        let handle = IncomingMessageDispatcherHandle { context };

        (dispatcher, handle, incoming_messages)
    }
}

impl<T, E> IncomingMessageDispatcher<T, E>
where
    E: From<Error>,
{
    /// Dispatch a given message into the corresponding channel.
    fn dispatch(&mut self, item: Result<InterleavedItem<T>, E>) -> Result<(), Error> {
        self.context.lock().unwrap().dispatch(item)
    }
}

impl<T, E> Drop for IncomingMessageDispatcher<T, E> {
    fn drop(&mut self) {
        self.context.lock().unwrap().close();
    }
}

/// Message dispatcher handle.
struct IncomingMessageDispatcherHandle<T, E> {
    context: Arc<Mutex<IncomingMessageDispatcherContext<T, E>>>,
}

impl<T, E> IncomingMessageDispatcherHandle<T, E> {
    /// Open a new interleaved channel.
    fn open_channel(&self, channel: Option<u8>) -> Result<IncomingDataChannel, Error> {
        self.context.lock().unwrap().open_channel(channel)
    }
}

/// Message dispatcher context.
struct IncomingMessageDispatcherContext<T, E> {
    incoming_message_sender: IncomingMessageSender<T, E>,
    incoming_data_senders: HashMap<u8, IncomingDataSender>,
    next_channel_id: u8,
}

impl<T, E> IncomingMessageDispatcherContext<T, E> {
    /// Create a new context.
    fn new(incoming_message_sender: IncomingMessageSender<T, E>) -> Self {
        Self {
            incoming_message_sender,
            incoming_data_senders: HashMap::new(),
            next_channel_id: 0,
        }
    }

    /// Open a new interleaved channel.
    fn open_channel(&mut self, channel: Option<u8>) -> Result<IncomingDataChannel, Error> {
        let channel = channel.unwrap_or(self.next_channel_id);

        if let Some(channel) = self.incoming_data_senders.get(&channel) {
            if !channel.is_closed() {
                return Err(Error::from_static_msg("channel already exists"));
            }
        }

        self.next_channel_id = channel.max(self.next_channel_id) + 1;

        let (tx, rx) = mpsc::unbounded();

        self.incoming_data_senders.insert(channel, tx);

        Ok(IncomingDataChannel::new(rx, channel))
    }

    /// Close the message stream and all channels.
    fn close(&mut self) {
        self.incoming_message_sender.disconnect();
        self.incoming_data_senders.clear();
    }
}

impl<T, E> IncomingMessageDispatcherContext<T, E>
where
    E: From<Error>,
{
    /// Dispatch a given message into the corresponding channel.
    fn dispatch(&mut self, item: Result<InterleavedItem<T>, E>) -> Result<(), Error> {
        match item {
            Ok(InterleavedItem::PrimaryMessage(msg)) => {
                self.incoming_message_sender
                    .unbounded_send(Ok(msg))
                    .map_err(|_| Error::from_static_msg("broken pipe"))?;
            }
            Ok(InterleavedItem::ChannelData(data)) => {
                let channel = data.channel();
                let data = data.into_data();

                if let Some(tx) = self.incoming_data_senders.get_mut(&channel) {
                    let res = tx.unbounded_send(Ok(data));

                    if res.is_err() {
                        self.incoming_data_senders.remove(&channel);
                    }
                }
            }
            Err(err) => {
                for (_, tx) in self.incoming_data_senders.drain() {
                    let _ = tx.unbounded_send(Err(Error::from_static_msg("connection error")));
                }

                self.incoming_message_sender
                    .unbounded_send(Err(err))
                    .map_err(|_| Error::from_static_msg("broken pipe"))?;
            }
        }

        Ok(())
    }
}

/// Incoming data channel.
struct IncomingDataChannel {
    stream: IncomingData,
    channel: u8,
}

impl IncomingDataChannel {
    /// Create a new data channel.
    fn new(stream: IncomingData, channel: u8) -> Self {
        Self { stream, channel }
    }

    /// Get the channel number.
    fn channel(&self) -> u8 {
        self.channel
    }
}

impl Stream for IncomingDataChannel {
    type Item = Result<Bytes, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

/// Type alias.
type OutgoingMessages<T> = mpsc::Receiver<T>;

/// Type alias.
type OutgoingMessageSender<T> = mpsc::Sender<T>;

/// Type alias.
type OutgoingData = mpsc::Receiver<ChannelData>;

/// Type alias.
type OutgoingDataSender = mpsc::Sender<ChannelData>;

/// Outgoing message collector.
struct OutgoingMessageCollector<T> {
    outgoing_messages: OutgoingMessages<T>,
    outgoing_data: OutgoingData,
}

impl<T> OutgoingMessageCollector<T> {
    /// Create a new message collector.
    fn new() -> (Self, OutgoingMessageSender<T>, OutgoingDataSender) {
        let (outgoing_message_sender, outgoing_messages) = mpsc::channel(4);
        let (outgoing_data_sender, outgoing_data) = mpsc::channel(4);

        let collector = Self {
            outgoing_messages,
            outgoing_data,
        };

        (collector, outgoing_message_sender, outgoing_data_sender)
    }
}

impl<T> Stream for OutgoingMessageCollector<T> {
    type Item = InterleavedItem<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(item) = self.outgoing_messages.poll_next_unpin(cx) {
            Poll::Ready(item.map(InterleavedItem::PrimaryMessage))
        } else if let Poll::Ready(Some(data)) = self.outgoing_data.poll_next_unpin(cx) {
            Poll::Ready(Some(InterleavedItem::ChannelData(data)))
        } else {
            Poll::Pending
        }
    }
}
