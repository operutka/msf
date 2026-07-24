use std::time::Duration;

use crate::ice2::{
    component::{Component, ComponentHandle},
    stun::STUN,
    transport::OutgoingPacketDispatcher,
    utils::Credentials,
};

/// Data stream builder.
pub struct DataStreamBuilder {
    id: usize,
    stun: STUN,
    outgoing_packet_dispatcher: OutgoingPacketDispatcher,
    components: Vec<ComponentHandle>,
}

impl DataStreamBuilder {
    /// Create a new data stream builder.
    pub(crate) fn new(
        id: usize,
        stun: STUN,
        outgoing_packet_dispatcher: OutgoingPacketDispatcher,
    ) -> Self {
        Self {
            id,
            stun,
            outgoing_packet_dispatcher,
            components: Vec::with_capacity(1),
        }
    }

    /// Add a new component to the data stream.
    pub fn component(&mut self) -> Component {
        assert!(self.components.len() < 255);

        let component = Component::new(
            self.components.len() as u8,
            self.id,
            self.stun.clone(),
            self.outgoing_packet_dispatcher.clone(),
            Duration::from_secs(15),
        );

        self.components.push(component.handle());

        component
    }

    /// Check if the data stream has no components.
    pub(crate) fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Build the data stream.
    pub(crate) fn build(self) -> DataStream {
        DataStream {
            id: self.id,
            components: self.components,
            local_credentials: Credentials::random(),
            remote_credentials: None,
        }
    }
}

/// Data stream.
pub struct DataStream {
    id: usize,
    components: Vec<ComponentHandle>,
    local_credentials: Credentials,
    remote_credentials: Option<Credentials>,
}

impl DataStream {
    /// Get the data stream ID.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the data stream components.
    pub fn components(&self) -> &[ComponentHandle] {
        &self.components
    }

    /// Get the local credentials for the data stream.
    pub fn local_credentials(&self) -> &Credentials {
        &self.local_credentials
    }

    /// Get the remote credentials for the data stream (if set).
    pub fn remote_credentials(&self) -> Option<&Credentials> {
        self.remote_credentials.as_ref()
    }

    /// Set the remote credentials for the data stream.
    pub fn set_remote_credentials(&mut self, credentials: Credentials) {
        self.remote_credentials = Some(credentials);
    }
}
