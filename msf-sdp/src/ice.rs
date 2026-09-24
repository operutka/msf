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

        let tmp = StringReader::new(reader.as_str());

        if reader.read_word() == "raddr" {
            related_addr = Some(reader.parse_word::<IpAddr>()?);
        } else {
            reader = tmp;
        }

        let tmp = StringReader::new(reader.as_str());

        if reader.read_word() == "rport" {
            related_port = Some(reader.parse_word::<u16>()?);
        } else {
            reader = tmp;
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use msf_ice::{CandidateKind, LocalCandidate};

    use super::CandidateDescription;

    #[test]
    fn test_parse_host_candidate() {
        let input = "1 1 UDP 2130706431 192.0.2.1 5000 typ host";

        let candidate = CandidateDescription::try_from(input).unwrap();

        assert_eq!(candidate.to_string(), input);

        let remote = candidate.to_remote_candidate(3);

        assert_eq!(remote.foundation(), "1");
        // the component ID is zero-based in msf-ice
        assert_eq!(remote.component(), 0);
        assert_eq!(remote.kind(), CandidateKind::Host);
        assert_eq!(remote.priority(), 2130706431);
        assert_eq!(
            remote.addr(),
            "192.0.2.1:5000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_parse_server_reflexive_candidate() {
        let input = "2 2 UDP 1694498815 198.51.100.1 5001 typ srflx raddr 192.0.2.1 rport 5000";

        let candidate = CandidateDescription::try_from(input).unwrap();

        assert_eq!(candidate.to_string(), input);

        let remote = candidate.to_remote_candidate(0);

        assert_eq!(remote.component(), 1);
        assert_eq!(remote.kind(), CandidateKind::ServerReflexive);
    }

    #[test]
    fn test_parse_extension_attributes() {
        // unknown extension attributes are simply skipped
        let candidate =
            CandidateDescription::try_from("1 1 UDP 100 192.0.2.1 5000 typ relay generation 0")
                .unwrap();

        assert_eq!(
            candidate.to_string(),
            "1 1 UDP 100 192.0.2.1 5000 typ relay"
        );

        // ... even if their names start with 'raddr' or 'rport'
        let candidate =
            CandidateDescription::try_from("1 1 UDP 100 192.0.2.1 5000 typ host raddrx 1").unwrap();

        assert_eq!(candidate.to_string(), "1 1 UDP 100 192.0.2.1 5000 typ host");
    }

    #[test]
    fn test_parse_errors() {
        let cases = [
            // an empty foundation
            "",
            // an invalid component ID
            "1 0 UDP 100 192.0.2.1 5000 typ host",
            "1 257 UDP 100 192.0.2.1 5000 typ host",
            // a missing transport
            "1 1",
            // an invalid priority
            "1 1 UDP bogus 192.0.2.1 5000 typ host",
            // an invalid address
            "1 1 UDP 100 bogus 5000 typ host",
            // a missing 'typ' keyword
            "1 1 UDP 100 192.0.2.1 5000 host",
            // an unknown candidate type
            "1 1 UDP 100 192.0.2.1 5000 typ bogus",
            // an invalid related address
            "1 1 UDP 100 192.0.2.1 5000 typ srflx raddr bogus",
            // an extension attribute without a value
            "1 1 UDP 100 192.0.2.1 5000 typ host generation",
        ];

        for case in cases {
            assert!(
                CandidateDescription::try_from(case).is_err(),
                "expected a parse error: {case}"
            );
        }
    }

    #[test]
    fn test_from_local_candidate() {
        let addr = "192.0.2.1:5000".parse::<SocketAddr>().unwrap();

        let candidate = LocalCandidate::host(0, 0, addr).with_foundation(7);

        let description = CandidateDescription::from_local_candidate(&candidate);

        assert_eq!(
            description.to_string(),
            format!("7 1 UDP {} 192.0.2.1 5000 typ host", candidate.priority())
        );

        // non-host candidates report their base address as the related
        // address
        let base = "192.0.2.1:5000".parse::<SocketAddr>().unwrap();
        let reflexive = "198.51.100.1:5001".parse::<SocketAddr>().unwrap();

        let candidate = LocalCandidate::server_reflexive(0, 1, base, reflexive).with_foundation(8);

        let description = CandidateDescription::from_local_candidate(&candidate);

        assert_eq!(
            description.to_string(),
            format!(
                "8 2 UDP {} 198.51.100.1 5001 typ srflx raddr 192.0.2.1 rport 5000",
                candidate.priority()
            )
        );
    }
}
