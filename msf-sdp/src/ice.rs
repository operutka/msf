//! ICE extensions.

use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
    net::{IpAddr, SocketAddr},
};

use str_reader::StringReader;

use msf_ice::{CandidateKind, LocalCandidate, RemoteCandidate};

use crate::ParseError;

/// Candidate SDP attribute.
#[derive(Clone)]
pub struct CandidateDescription<'a> {
    foundation: Cow<'a, str>,
    component_id: u16,
    transport: Cow<'a, str>,
    priority: u32,
    address: SocketAddr,
    candidate_type: CandidateKind,
    related_address: Option<SocketAddr>,
}

impl CandidateDescription<'_> {
    /// Create a new candidate description from a given local candidate.
    pub fn from_local_candidate(candidate: &LocalCandidate) -> Self {
        let related_address = if candidate.kind() == CandidateKind::Host {
            None
        } else {
            Some(candidate.base())
        };

        let foundation = candidate.foundation();

        Self {
            foundation: Cow::Owned(foundation.to_string()),
            component_id: candidate.component() as u16 + 1,
            transport: Cow::Borrowed("UDP"),
            priority: candidate.priority(),
            address: candidate.addr(),
            candidate_type: candidate.kind(),
            related_address,
        }
    }

    /// Create a new remote candidate.
    pub fn to_remote_candidate(&self, channel: usize) -> RemoteCandidate {
        RemoteCandidate::new(
            channel,
            (self.component_id - 1) as u8,
            self.candidate_type,
            self.address,
            self.foundation.to_string(),
            self.priority,
        )
    }
}

impl Display for CandidateDescription<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let candidate_type = match self.candidate_type {
            CandidateKind::Host => "host",
            CandidateKind::ServerReflexive => "srflx",
            CandidateKind::PeerReflexive => "prflx",
            CandidateKind::Relayed => "relay",
        };

        write!(
            f,
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component_id,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            candidate_type,
        )?;

        if let Some(addr) = self.related_address {
            write!(f, " raddr {} rport {}", addr.ip(), addr.port())?;
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for CandidateDescription<'a> {
    type Error = ParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let mut reader = StringReader::new(s);

        let foundation = reader.read_word();

        if foundation.is_empty() {
            return Err(ParseError::from(str_reader::ParseError::EmptyInput));
        }

        let component_id = reader.parse_word::<u16>()?;

        if component_id == 0 || component_id > 256 {
            return Err(ParseError::with_msg("invalid component ID"));
        }

        let transport = reader.read_word();

        if transport.is_empty() {
            return Err(ParseError::from(str_reader::ParseError::EmptyInput));
        }

        let priority = reader.parse_word()?;

        let addr = reader.parse_word::<IpAddr>()?;
        let port = reader.parse_word::<u16>()?;

        if reader.read_word() != "typ" {
            return Err(ParseError::from(str_reader::ParseError::NoMatch));
        }

        let candidate_type = match reader.read_word() {
            "host" => CandidateKind::Host,
            "srflx" => CandidateKind::ServerReflexive,
            "prflx" => CandidateKind::PeerReflexive,
            "relay" => CandidateKind::Relayed,
            _ => return Err(ParseError::with_msg("unknown candidate type")),
        };

        let mut related_addr = None;
        let mut related_port = None;

        if reader.as_str().starts_with("raddr") {
            if reader.read_word() != "raddr" {
                return Err(ParseError::from(str_reader::ParseError::NoMatch));
            }

            related_addr = Some(reader.parse_word::<IpAddr>()?);
        }

        if reader.as_str().starts_with("rport") {
            if reader.read_word() != "rport" {
                return Err(ParseError::from(str_reader::ParseError::NoMatch));
            }

            related_port = Some(reader.parse_word::<u16>()?);
        }

        let mut related_address = None;

        if let Some(addr) = related_addr {
            if let Some(port) = related_port {
                related_address = Some(SocketAddr::from((addr, port)));
            }
        }

        // note: skip all attributes
        loop {
            reader.skip_whitespace();

            if reader.is_empty() {
                break;
            }

            let name = reader.read_word();
            let value = reader.read_word();

            if name.is_empty() || value.is_empty() {
                return Err(ParseError::from(str_reader::ParseError::EmptyInput));
            }
        }

        let res = Self {
            foundation: foundation.into(),
            component_id,
            transport: transport.into(),
            priority,
            address: SocketAddr::from((addr, port)),
            candidate_type,
            related_address,
        };

        Ok(res)
    }
}
