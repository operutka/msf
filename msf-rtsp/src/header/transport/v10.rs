use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
};

use str_reader::StringReader;

use crate::{
    Error,
    header::{
        StringReaderExt,
        transport::{BaseTransportParser, InterleavedPair, PortPair},
    },
};

/// Transport header.
#[derive(Debug, Clone)]
pub struct TransportHeaderV10 {
    transport_id: Cow<'static, str>,
    ssrc: Option<u32>,
    multicast: bool,
    multicast_port_pair: Option<PortPair>,
    client_port_pair: Option<PortPair>,
    server_port_pair: Option<PortPair>,
    interleaved_pair: Option<InterleavedPair>,
    source: Option<Cow<'static, str>>,
    destination: Option<Cow<'static, str>>,
}

impl TransportHeaderV10 {
    pub const TRANSPORT_ID_RTP_AVP: &'static str = "RTP/AVP";
    pub const TRANSPORT_ID_RTP_AVP_TCP: &'static str = "RTP/AVP/TCP";
    pub const TRANSPORT_ID_RTP_AVP_UDP: &'static str = "RTP/AVP/UDP";

    /// Create a new transport header.
    #[inline]
    pub const fn new() -> Self {
        Self {
            transport_id: Cow::Borrowed(Self::TRANSPORT_ID_RTP_AVP),
            ssrc: None,
            multicast: true,
            multicast_port_pair: None,
            client_port_pair: None,
            server_port_pair: None,
            interleaved_pair: None,
            source: None,
            destination: None,
        }
    }

    /// Parse the transport header.
    pub fn parse(header: &str) -> Result<Vec<Self>, Error> {
        Self::parse_inner(header)
            .map_err(|err| Error::from_static_msg_and_cause("invalid transport header", err))
    }

    /// Parse the transport header.
    fn parse_inner(header: &str) -> Result<Vec<Self>, Error> {
        let mut reader = StringReader::new(header.trim());

        let mut res = Vec::new();

        while !reader.is_empty() {
            if !res.is_empty() {
                reader.match_rtsp_separator(',')?;
            }

            let transport = reader.parse_transport()?;

            res.push(transport);
        }

        Ok(res)
    }

    /// Get the lower transport.
    #[inline]
    pub fn transport_id(&self) -> &str {
        &self.transport_id
    }

    /// Set the lower transport.
    pub fn with_transport_id<T>(mut self, transport_id: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.transport_id = transport_id.into();
        self
    }

    /// Check if the transport is supposed to be unicast.
    #[inline]
    pub fn is_unicast(&self) -> bool {
        !self.multicast
    }

    /// Set the unicast flag.
    #[inline]
    pub const fn with_unicast(mut self, unicast: bool) -> Self {
        self.multicast = !unicast;
        self
    }

    /// Check if the transport is supposed to be multicast.
    #[inline]
    pub fn is_multicast(&self) -> bool {
        self.multicast
    }

    /// Set the multicast flag.
    #[inline]
    pub const fn with_multicast(mut self, multicast: bool) -> Self {
        self.multicast = multicast;
        self
    }

    /// Get the multicast RTP-RTCP port pair.
    #[inline]
    pub fn multicast_port_pair(&self) -> Option<PortPair> {
        self.multicast_port_pair
    }

    /// Set the multicast RTP-RTCP port pair.
    pub fn with_multicast_port_pair<T>(mut self, pair: T) -> Self
    where
        T: Into<PortPair>,
    {
        self.multicast_port_pair = Some(pair.into());
        self
    }

    /// Get client-side RTP-RTCP port pair.
    #[inline]
    pub fn client_port_pair(&self) -> Option<PortPair> {
        self.client_port_pair
    }

    /// Set the client-side RTP-RTCP port pair.
    pub fn with_client_port_pair<T>(mut self, pair: T) -> Self
    where
        T: Into<PortPair>,
    {
        self.client_port_pair = Some(pair.into());
        self
    }

    /// Get server-side RTP-RTCP port pair.
    #[inline]
    pub fn server_port_pair(&self) -> Option<PortPair> {
        self.server_port_pair
    }

    /// Set the server-side RTP-RTCP port pair.
    pub fn with_server_port_pair<T>(mut self, pair: T) -> Self
    where
        T: Into<PortPair>,
    {
        self.server_port_pair = Some(pair.into());
        self
    }

    /// Get interleaved RTP-RTCP channel pair.
    #[inline]
    pub fn interleaved_pair(&self) -> Option<InterleavedPair> {
        self.interleaved_pair
    }

    /// Set the interleaved RTP-RTCP channel pair.
    pub fn with_interleaved_pair<T>(mut self, pair: T) -> Self
    where
        T: Into<InterleavedPair>,
    {
        self.interleaved_pair = Some(pair.into());
        self
    }

    /// Get the synchronization source ID.
    #[inline]
    pub fn ssrc(&self) -> Option<u32> {
        self.ssrc
    }

    /// Set the synchronization source ID.
    #[inline]
    pub const fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = Some(ssrc);
        self
    }

    /// Get the source option.
    #[inline]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Set the source option.
    pub fn with_source<T>(mut self, source: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.source = Some(source.into());
        self
    }

    /// Get the destination option.
    #[inline]
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    /// Set the destination option.
    pub fn with_destination<T>(mut self, destination: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.destination = Some(destination.into());
        self
    }
}

impl Default for TransportHeaderV10 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Display for TransportHeaderV10 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.transport_id)?;

        if self.multicast {
            write!(f, ";multicast")?;
        } else {
            write!(f, ";unicast")?;
        }

        if let Some(pair) = self.multicast_port_pair {
            write!(f, ";port={pair}")?;
        }

        if let Some(pair) = self.client_port_pair {
            write!(f, ";client_port={pair}")?;
        }

        if let Some(pair) = self.server_port_pair {
            write!(f, ";server_port={pair}")?;
        }

        if let Some(pair) = self.interleaved_pair {
            write!(f, ";interleaved={pair}")?;
        }

        if let Some(ssrc) = self.ssrc {
            write!(f, ";ssrc={ssrc:08X}")?;
        }

        Ok(())
    }
}

/// Transport header parser.
trait TransportParser<'a> {
    /// Parse the next transport header.
    fn parse_transport(&mut self) -> Result<TransportHeaderV10, Error>;
}

impl<'a> TransportParser<'a> for StringReader<'a> {
    fn parse_transport(&mut self) -> Result<TransportHeaderV10, Error> {
        let mut res = TransportHeaderV10::new();

        let mut reader = StringReader::new(self.as_str());

        let transport_id = reader.read_transport_id()?;

        res.transport_id = Cow::Owned(transport_id.to_string());

        while reader.match_rtsp_separator(';').is_ok() {
            if reader.is_empty() {
                break;
            }

            let (key, value) = reader.read_transport_parameter()?;

            match key {
                "unicast" => res.multicast = false,
                "multicast" => res.multicast = true,
                "port" => {
                    res.multicast_port_pair = value
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid multicast port pair"))?;
                }
                "server_port" => {
                    res.server_port_pair = value
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid server port pair"))?;
                }
                "client_port" => {
                    res.client_port_pair = value
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid client port pair"))?;
                }
                "interleaved" => {
                    res.interleaved_pair = value
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid interleaved channel pair"))?;
                }
                "ssrc" => {
                    res.ssrc = value
                        .map(|v| u32::from_str_radix(v, 16))
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid ssrc parameter"))?;
                }
                _ => (),
            }
        }

        *self = reader;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::TransportHeaderV10;

    #[test]
    fn test_parser() {
        let parsed = TransportHeaderV10::parse("RTP/AVP;port=9998-9999").unwrap();

        assert_eq!(parsed.len(), 1);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV10::TRANSPORT_ID_RTP_AVP
        );
        assert!(!transport.is_unicast());
        assert_eq!(transport.multicast_port_pair().unwrap().rtp(), 9998);
        assert_eq!(transport.multicast_port_pair().unwrap().rtcp(), Some(9999));
        assert!(transport.client_port_pair().is_none());
        assert!(transport.server_port_pair().is_none());
        assert!(transport.interleaved_pair().is_none());
        assert!(transport.ssrc().is_none());

        let parsed =
            TransportHeaderV10::parse("RTP/AVP/UDP;unicast;client_port=9998-9999;server_port=8888")
                .unwrap();

        assert_eq!(parsed.len(), 1);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV10::TRANSPORT_ID_RTP_AVP_UDP
        );
        assert!(transport.is_unicast());
        assert!(transport.multicast_port_pair().is_none());
        assert_eq!(transport.client_port_pair().unwrap().rtp(), 9998);
        assert_eq!(transport.client_port_pair().unwrap().rtcp(), Some(9999));
        assert_eq!(transport.server_port_pair().unwrap().rtp(), 8888);
        assert!(transport.server_port_pair().unwrap().rtcp().is_none());
        assert!(transport.ssrc().is_none());

        let parsed =
            TransportHeaderV10::parse("RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=aBc12").unwrap();

        assert_eq!(parsed.len(), 1);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV10::TRANSPORT_ID_RTP_AVP_TCP
        );
        assert!(transport.is_unicast());
        assert!(transport.multicast_port_pair().is_none());
        assert!(transport.client_port_pair().is_none());
        assert!(transport.server_port_pair().is_none());
        assert_eq!(transport.interleaved_pair().unwrap().rtp(), 0);
        assert_eq!(
            transport.interleaved_pair().and_then(|pair| pair.rtcp()),
            Some(1)
        );
        assert_eq!(transport.ssrc(), Some(0xabc12));

        let parsed = TransportHeaderV10::parse("RTP/AVP,RTP/AVP/TCP").unwrap();

        assert_eq!(parsed.len(), 2);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV10::TRANSPORT_ID_RTP_AVP
        );

        let transport = &parsed[1];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV10::TRANSPORT_ID_RTP_AVP_TCP
        );

        let res = TransportHeaderV10::parse("RTP/AVP;");

        assert!(res.is_ok());
    }
}
