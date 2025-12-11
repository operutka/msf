use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use str_reader::StringReader;

use crate::{
    Error,
    header::{
        StringReaderExt, ValueListDisplay,
        transport::{BaseTransportParser, InterleavedPair},
    },
};

/// Transport header.
#[derive(Debug, Clone)]
pub struct TransportHeaderV20 {
    transport_id: Cow<'static, str>,
    ssrc: Option<u32>,
    multicast: bool,
    dest_addrs: Vec<TransportAddress>,
    src_addrs: Vec<TransportAddress>,
    interleaved_pair: Option<InterleavedPair>,
}

impl TransportHeaderV20 {
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
            dest_addrs: Vec::new(),
            src_addrs: Vec::new(),
            interleaved_pair: None,
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

    /// Get the destination addresses.
    #[inline]
    pub fn dest_addrs(&self) -> &[TransportAddress] {
        &self.dest_addrs
    }

    /// Set the destination addresses.
    pub fn with_dest_addrs<T>(mut self, addrs: T) -> Self
    where
        T: Into<Vec<TransportAddress>>,
    {
        self.dest_addrs = addrs.into();
        self
    }

    /// Get the source addresses.
    #[inline]
    pub fn src_addrs(&self) -> &[TransportAddress] {
        &self.src_addrs
    }

    /// Set the source addresses.
    pub fn with_src_addrs<T>(mut self, addrs: T) -> Self
    where
        T: Into<Vec<TransportAddress>>,
    {
        self.src_addrs = addrs.into();
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
}

impl Default for TransportHeaderV20 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Display for TransportHeaderV20 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.transport_id)?;

        if self.multicast {
            write!(f, ";multicast")?;
        } else {
            write!(f, ";unicast")?;
        }

        if !self.dest_addrs.is_empty() {
            write!(
                f,
                ";dest_addr={}",
                ValueListDisplay::new('/', &self.dest_addrs)
            )?;
        }

        if !self.src_addrs.is_empty() {
            write!(
                f,
                ";src_addr={}",
                ValueListDisplay::new('/', &self.src_addrs)
            )?;
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

/// Transport address.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportAddress {
    Port(u16),
    SocketAddr(SocketAddr),
    Other(Cow<'static, str>),
}

impl TransportAddress {
    /// Parse transport addresses.
    fn parse(s: &str) -> Result<Vec<TransportAddress>, Error> {
        let mut reader = StringReader::new(s.trim());

        let mut res = Vec::new();

        while !reader.is_empty() {
            if !res.is_empty() {
                reader.match_rtsp_separator('/')?;
            }

            let addr = reader.parse_transport_address()?;

            res.push(addr);
        }

        Ok(res)
    }
}

impl Display for TransportAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(port) => write!(f, "\":{port}\""),
            Self::SocketAddr(addr) => {
                let ip = addr.ip();
                let port = addr.port();

                if ip.is_unspecified() {
                    write!(f, "\":{port}\"")
                } else {
                    write!(f, "\"{addr}\"")
                }
            }
            Self::Other(addr) => {
                write!(f, "\"")?;

                for c in addr.chars() {
                    match c {
                        '"' => write!(f, "\\\"")?,
                        '\\' => write!(f, "\\\\")?,
                        c => write!(f, "{c}")?,
                    }
                }

                write!(f, "\"")
            }
        }
    }
}

/// Transport header parser.
trait TransportParser<'a> {
    /// Parse the next transport header.
    fn parse_transport(&mut self) -> Result<TransportHeaderV20, Error>;

    /// Parse the next transport address.
    fn parse_transport_address(&mut self) -> Result<TransportAddress, Error>;
}

impl<'a> TransportParser<'a> for StringReader<'a> {
    fn parse_transport(&mut self) -> Result<TransportHeaderV20, Error> {
        let mut res = TransportHeaderV20::new();

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
                "dest_addr" => {
                    res.dest_addrs = value
                        .map(TransportAddress::parse)
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid dest_addr parameter"))?
                        .unwrap_or_default();
                }
                "src_addr" => {
                    res.src_addrs = value
                        .map(TransportAddress::parse)
                        .transpose()
                        .map_err(|_| Error::from_static_msg("invalid src_addr parameter"))?
                        .unwrap_or_default();
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

    fn parse_transport_address(&mut self) -> Result<TransportAddress, Error> {
        let addr = self.parse_rtsp_quoted_string()?;

        if let Some((addr, port)) = addr.rsplit_once(':')
            && let Ok(port) = u16::from_str(port)
        {
            if addr.is_empty() {
                return Ok(TransportAddress::Port(port));
            } else if let Ok(addr) = IpAddr::from_str(addr) {
                return Ok(TransportAddress::SocketAddr(SocketAddr::from((addr, port))));
            }
        }

        Ok(TransportAddress::Other(addr.into()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        net::{Ipv4Addr, SocketAddr},
    };

    use super::{TransportAddress, TransportHeaderV20};

    #[test]
    fn test_parser() {
        let parsed = TransportHeaderV20::parse("RTP/AVP;multicast;dest_addr=\":123\"").unwrap();

        assert_eq!(parsed.len(), 1);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV20::TRANSPORT_ID_RTP_AVP
        );
        assert!(!transport.is_unicast());
        assert!(transport.src_addrs().is_empty());
        assert_eq!(transport.dest_addrs(), &[TransportAddress::Port(123)]);
        assert!(transport.interleaved_pair().is_none());
        assert!(transport.ssrc().is_none());

        let parsed = TransportHeaderV20::parse(
            "RTP/AVP/UDP;unicast;src_addr=\":123\"/\"0.0.0.0:456\";dest_addr=\"foo\"",
        )
        .unwrap();

        assert_eq!(parsed.len(), 1);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV20::TRANSPORT_ID_RTP_AVP_UDP
        );
        assert!(transport.is_unicast());
        assert_eq!(
            transport.src_addrs(),
            &[
                TransportAddress::Port(123),
                TransportAddress::SocketAddr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 456)))
            ]
        );
        assert_eq!(
            transport.dest_addrs(),
            &[TransportAddress::Other(Cow::Borrowed("foo"))]
        );
        assert!(transport.ssrc().is_none());

        let parsed =
            TransportHeaderV20::parse("RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=aBc12").unwrap();

        assert_eq!(parsed.len(), 1);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV20::TRANSPORT_ID_RTP_AVP_TCP
        );
        assert!(transport.is_unicast());
        assert!(transport.src_addrs().is_empty());
        assert!(transport.dest_addrs().is_empty());
        assert_eq!(transport.interleaved_pair().unwrap().rtp(), 0);
        assert_eq!(
            transport.interleaved_pair().and_then(|pair| pair.rtcp()),
            Some(1)
        );
        assert_eq!(transport.ssrc(), Some(0xabc12));

        let parsed = TransportHeaderV20::parse("RTP/AVP,RTP/AVP/TCP").unwrap();

        assert_eq!(parsed.len(), 2);

        let transport = &parsed[0];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV20::TRANSPORT_ID_RTP_AVP
        );

        let transport = &parsed[1];

        assert_eq!(
            transport.transport_id(),
            TransportHeaderV20::TRANSPORT_ID_RTP_AVP_TCP
        );

        let res = TransportHeaderV20::parse("RTP/AVP;");

        assert!(res.is_ok());
    }
}
