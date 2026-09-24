mod bandwidth;
mod key;
mod origin;
mod parser;

pub mod attribute;
pub mod connection;
pub mod media;
pub mod time;

#[cfg(feature = "h264")]
pub mod h264;

#[cfg(feature = "ice")]
pub mod ice;

use std::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use self::{
    attribute::Attributes,
    parser::{
        FromSessionDescriptionLines, FromSessionDescriptionLinesLossy, SessionDescriptionLines,
        SessionDescriptionLinesLossy,
    },
    time::{TimeZoneAdjustment, TimeZoneAdjustments},
};

pub use self::{
    attribute::Attribute,
    bandwidth::{Bandwidth, BandwidthType},
    connection::{ConnectionAddress, ConnectionInfo},
    key::EncryptionKey,
    media::MediaDescription,
    origin::Origin,
    time::TimeDescription,
};

/// SDP parse error.
#[derive(Debug)]
pub struct ParseError {
    msg: String,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl ParseError {
    /// Create a plain parse error.
    pub fn plain() -> Self {
        Self {
            msg: String::new(),
            cause: None,
        }
    }

    /// Create a parse error with a given error message.
    pub fn with_msg<M>(msg: M) -> Self
    where
        M: ToString,
    {
        Self {
            msg: msg.to_string(),
            cause: None,
        }
    }

    /// Create a parse error with a given error message and a given cause.
    pub fn with_cause_and_msg<M, C>(msg: M, cause: C) -> Self
    where
        M: ToString,
        C: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            msg: msg.to_string(),
            cause: Some(cause.into()),
        }
    }

    /// Create a parse error with a given cause.
    pub fn with_cause<C>(cause: C) -> Self
    where
        C: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            msg: String::new(),
            cause: Some(cause.into()),
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Some(cause) = self.cause.as_ref() {
            if self.msg.is_empty() {
                Display::fmt(cause, f)
            } else {
                write!(f, "{}: {}", self.msg, cause)
            }
        } else if self.msg.is_empty() {
            f.write_str("parse error")
        } else {
            f.write_str(&self.msg)
        }
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = self.cause.as_ref() {
            Some(cause.as_ref())
        } else {
            None
        }
    }
}

impl From<std::convert::Infallible> for ParseError {
    fn from(_: std::convert::Infallible) -> Self {
        Self::plain()
    }
}

impl From<str_reader::ParseError> for ParseError {
    fn from(err: str_reader::ParseError) -> Self {
        Self::with_cause(err)
    }
}

impl From<std::net::AddrParseError> for ParseError {
    fn from(err: std::net::AddrParseError) -> Self {
        Self::with_cause(err)
    }
}

impl From<std::num::ParseIntError> for ParseError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::with_cause(err)
    }
}

/// Session description builder.
#[derive(Clone)]
pub struct SessionDescriptionBuilder {
    inner: SessionDescription,
}

impl SessionDescriptionBuilder {
    /// Create a new session description builder.
    fn new() -> Self {
        let inner = SessionDescription {
            version: 0,
            origin: Origin::default(),
            session_name: String::new(),
            session_information: None,
            url: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            bandwidth: Vec::new(),
            time_descriptions: Vec::new(),
            tz_adjustments: TimeZoneAdjustments::empty(),
            key: None,
            attributes: Attributes::new(),
            media: Vec::new(),
        };

        Self { inner }
    }

    /// Set the SDP version.
    #[inline]
    pub fn version(&mut self, version: u16) -> &mut Self {
        self.inner.version = version;
        self
    }

    /// Set origin.
    #[inline]
    pub fn origin(&mut self, origin: Origin) -> &mut Self {
        self.inner.origin = origin;
        self
    }

    /// Set the name of the session.
    #[inline]
    pub fn session_name<T>(&mut self, name: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.session_name = name.to_string();
        self
    }

    /// Set session information.
    #[inline]
    pub fn session_information<T>(&mut self, info: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.session_information = Some(info.to_string());
        self
    }

    /// Set URL.
    #[inline]
    pub fn url<T>(&mut self, url: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.url = Some(url.to_string());
        self
    }

    /// Add a given email address.
    #[inline]
    pub fn email<T>(&mut self, email: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.emails.push(email.to_string());
        self
    }

    /// Add a given phone number.
    #[inline]
    pub fn phone<T>(&mut self, phone: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.phones.push(phone.to_string());
        self
    }

    /// Set a given connection information.
    #[inline]
    pub fn connection(&mut self, connection: ConnectionInfo) -> &mut Self {
        self.inner.connection = Some(connection);
        self
    }

    /// Add a given bandwidth information.
    #[inline]
    pub fn bandwidth(&mut self, bandwidth: Bandwidth) -> &mut Self {
        self.inner.bandwidth.push(bandwidth);
        self
    }

    /// Add a given time description.
    #[inline]
    pub fn time_description(&mut self, td: TimeDescription) -> &mut Self {
        self.inner.time_descriptions.push(td);
        self
    }

    /// Add a given timezone adjustment.
    #[inline]
    pub fn tz_adjustment(&mut self, tz_adjustment: TimeZoneAdjustment) -> &mut Self {
        self.inner.tz_adjustments.push(tz_adjustment);
        self
    }

    /// Set a given encryption key.
    #[inline]
    pub fn encryption_key(&mut self, key: EncryptionKey) -> &mut Self {
        self.inner.key = Some(key);
        self
    }

    /// Add a given flag.
    #[inline]
    pub fn flag<T>(&mut self, name: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.attributes.push(Attribute::new_flag(name));
        self
    }

    /// Add a given attribute.
    #[inline]
    pub fn attribute<T, U>(&mut self, name: T, value: U) -> &mut Self
    where
        T: ToString,
        U: ToString,
    {
        self.inner
            .attributes
            .push(Attribute::new_attribute(name, value));
        self
    }

    /// Add a given media description.
    #[inline]
    pub fn media_description(&mut self, desc: MediaDescription) -> &mut Self {
        self.inner.media.push(desc);
        self
    }

    /// Build the session description.
    pub fn build(mut self) -> SessionDescription {
        if self.inner.session_name.is_empty() {
            self.inner.session_name = String::from("-");
        }

        if self.inner.time_descriptions.is_empty() {
            self.inner
                .time_descriptions
                .push(TimeDescription::default());
        }

        self.inner
    }
}

/// Session description.
#[derive(Clone)]
pub struct SessionDescription {
    version: u16,
    origin: Origin,
    session_name: String,
    session_information: Option<String>,
    url: Option<String>,
    emails: Vec<String>,
    phones: Vec<String>,
    connection: Option<ConnectionInfo>,
    bandwidth: Vec<Bandwidth>,
    time_descriptions: Vec<TimeDescription>,
    tz_adjustments: TimeZoneAdjustments,
    key: Option<EncryptionKey>,
    attributes: Attributes,
    media: Vec<MediaDescription>,
}

impl SessionDescription {
    /// Create an empty session description.
    fn empty() -> Self {
        Self {
            version: 0,
            origin: Origin::default(),
            session_name: String::new(),
            session_information: None,
            url: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            bandwidth: Vec::new(),
            time_descriptions: Vec::new(),
            tz_adjustments: TimeZoneAdjustments::empty(),
            key: None,
            attributes: Attributes::new(),
            media: Vec::new(),
        }
    }

    /// Get a session description builder.
    #[inline]
    pub fn builder() -> SessionDescriptionBuilder {
        SessionDescriptionBuilder::new()
    }

    /// Parse a session description from a given string while ignoring parse
    /// errors where possible.
    ///
    /// This can be used as a best effort method to parse invalid session
    /// descriptions received from 3rd party implementations. However, keep in
    /// mind that the returned session description may be missing vital
    /// information.
    pub fn from_str_lossy(s: &str) -> Self {
        let mut lines = SessionDescriptionLinesLossy::new(s);

        <Self as FromSessionDescriptionLinesLossy>::from_sdp_lines(&mut lines)
            .expect("unexpected parse error")
    }

    /// Get version of this SDP.
    #[inline]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Get the origin field.
    #[inline]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Get name of the session.
    #[inline]
    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    /// Get session information.
    #[inline]
    pub fn session_information(&self) -> Option<&str> {
        self.session_information.as_deref()
    }

    /// Get URL.
    #[inline]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Get a list of email addresses.
    #[inline]
    pub fn emails(&self) -> &[String] {
        &self.emails
    }

    /// Get a list of phone numbers.
    #[inline]
    pub fn phones(&self) -> &[String] {
        &self.phones
    }

    /// Get the session-wide connection info.
    #[inline]
    pub fn connection(&self) -> Option<&ConnectionInfo> {
        self.connection.as_ref()
    }

    /// Get bandwidth information.
    #[inline]
    pub fn bandwidth(&self) -> &[Bandwidth] {
        &self.bandwidth
    }

    /// Get time description.
    #[inline]
    pub fn time_descriptions(&self) -> &[TimeDescription] {
        &self.time_descriptions
    }

    /// Get timezone adjustments.
    #[inline]
    pub fn tz_adjustments(&self) -> &[TimeZoneAdjustment] {
        &self.tz_adjustments
    }

    /// Get the encryption key (if any).
    #[inline]
    pub fn encryption_key(&self) -> Option<&EncryptionKey> {
        self.key.as_ref()
    }

    /// Get the session-wide attributes.
    #[inline]
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// Get media descriptions.
    #[inline]
    pub fn media_descriptions(&self) -> &[MediaDescription] {
        &self.media
    }
}

impl Display for SessionDescription {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "v={}\r\n", self.version)?;
        write!(f, "o={}\r\n", self.origin)?;
        write!(f, "s={}\r\n", self.session_name)?;

        if let Some(info) = self.session_information.as_ref() {
            write!(f, "i={info}\r\n")?;
        }

        if let Some(url) = self.url.as_ref() {
            write!(f, "u={url}\r\n")?;
        }

        for email in &self.emails {
            write!(f, "e={email}\r\n")?;
        }

        for phone in &self.phones {
            write!(f, "p={phone}\r\n")?;
        }

        if let Some(connection) = self.connection.as_ref() {
            write!(f, "c={connection}\r\n")?;
        }

        for bw in &self.bandwidth {
            write!(f, "b={bw}\r\n")?;
        }

        for td in &self.time_descriptions {
            Display::fmt(td, f)?;
        }

        if !self.tz_adjustments.is_empty() {
            write!(f, "z={}\r\n", self.tz_adjustments)?;
        }

        if let Some(k) = self.key.as_ref() {
            write!(f, "k={k}\r\n")?;
        }

        for attr in self.attributes.iter() {
            write!(f, "a={attr}\r\n")?;
        }

        for media in &self.media {
            Display::fmt(media, f)?;
        }

        Ok(())
    }
}

impl FromSessionDescriptionLines for SessionDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLines) -> Result<Self, ParseError> {
        let mut sdp = SessionDescription::empty();

        while let Some((t, _)) = lines.current() {
            match t {
                'v' => sdp.version = lines.parse()?,
                'o' => sdp.origin = lines.parse()?,
                's' => sdp.session_name = lines.parse()?,
                'i' => sdp.session_information = Some(lines.parse()?),
                'u' => sdp.url = Some(lines.parse()?),
                'e' => sdp.emails.push(lines.parse()?),
                'p' => sdp.phones.push(lines.parse()?),
                'c' => sdp.connection = Some(lines.parse()?),
                'b' => sdp.bandwidth.push(lines.parse()?),
                't' => sdp.time_descriptions.push(lines.parse_multiple()?),
                'z' => sdp.tz_adjustments = lines.parse()?,
                'k' => sdp.key = Some(lines.parse()?),
                'a' => sdp.attributes.push(lines.parse()?),
                'm' => sdp.media.push(lines.parse_multiple()?),
                _ => return Err(ParseError::with_msg(format!("unknown SDP field: {t}"))),
            }
        }

        Ok(sdp)
    }
}

impl FromSessionDescriptionLinesLossy for SessionDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLinesLossy) -> Result<Self, ParseError> {
        let mut sdp = SessionDescription::empty();

        while let Some((t, _)) = lines.current() {
            match t {
                'v' => sdp.version = lines.parse().unwrap_or(0),
                'o' => sdp.origin = lines.parse().unwrap_or_default(),
                's' => sdp.session_name = lines.parse().unwrap_or_default(),
                'i' => sdp.session_information = lines.parse().ok(),
                'u' => sdp.url = lines.parse().ok(),
                'e' => {
                    if let Ok(email) = lines.parse() {
                        sdp.emails.push(email);
                    }
                }
                'p' => {
                    if let Ok(phone) = lines.parse() {
                        sdp.phones.push(phone);
                    }
                }
                'c' => sdp.connection = lines.parse().ok(),
                'b' => {
                    if let Ok(bw) = lines.parse() {
                        sdp.bandwidth.push(bw);
                    }
                }
                't' => {
                    if let Ok(td) = lines.parse_multiple() {
                        sdp.time_descriptions.push(td);
                    }
                }
                'z' => sdp.tz_adjustments = lines.parse().unwrap_or_default(),
                'k' => sdp.key = lines.parse().ok(),
                'a' => {
                    if let Ok(attr) = lines.parse() {
                        sdp.attributes.push(attr);
                    }
                }
                'm' => {
                    if let Ok(md) = lines.parse_multiple() {
                        sdp.media.push(md);
                    }
                }
                _ => lines.next(),
            }
        }

        Ok(sdp)
    }
}

impl FromStr for SessionDescription {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = SessionDescriptionLines::new(s)?;

        <Self as FromSessionDescriptionLines>::from_sdp_lines(&mut lines)
    }
}

/// Network type.
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum NetworkType {
    Internet,
    Other(String),
}

impl Display for NetworkType {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::Internet => "IN",
            Self::Other(o) => o,
        };

        f.write_str(s)
    }
}

impl FromStr for NetworkType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s.trim() {
            "IN" => Self::Internet,
            o => Self::Other(o.to_string()),
        };

        Ok(res)
    }
}

/// Address type.
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum AddressType {
    IPv4,
    IPv6,
    Other(String),
}

impl Display for AddressType {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::IPv4 => "IP4",
            Self::IPv6 => "IP6",
            Self::Other(o) => o,
        };

        f.write_str(s)
    }
}

impl FromStr for AddressType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s.trim() {
            "IP4" => Self::IPv4,
            "IP6" => Self::IPv6,
            o => Self::Other(o.to_string()),
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        attribute::RTPMap,
        connection::{ConnectionAddress, IPv4Address},
        media::MediaDescription,
        time::{
            CompactDuration, RepeatTime, TimeDescription, TimeZoneAdjustment,
            UnsignedCompactDuration,
        },
        AddressType, Bandwidth, BandwidthType, ConnectionInfo, EncryptionKey, NetworkType, Origin,
        SessionDescription,
    };

    /// Session description exercising all SDP fields defined by RFC 8866.
    ///
    /// The fields are in the canonical order, so it can be used for
    /// round-trip tests as well.
    const FULL_SDP: &str = concat!(
        "v=0\r\n",
        "o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n",
        "s=SDP Seminar\r\n",
        "i=A seminar on the session description protocol\r\n",
        "u=http://www.example.com/seminars/sdp.pdf\r\n",
        "e=j.doe@example.com (Jane Doe)\r\n",
        "p=+1 617 555-6011\r\n",
        "c=IN IP4 224.2.17.12/127\r\n",
        "b=AS:128\r\n",
        "t=2873397496 2873404696\r\n",
        "r=7d 1h 0 25h\r\n",
        "z=2882844526 -1h 2898848070 0\r\n",
        "k=prompt\r\n",
        "a=recvonly\r\n",
        "a=tool:msf\r\n",
        "m=audio 49170 RTP/AVP 0\r\n",
        "i=Audio stream\r\n",
        "b=CT:64\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "m=video 51372/2 RTP/AVP 99\r\n",
        "c=IN IP6 ff15::101/3\r\n",
        "k=base64:c2VjcmV0\r\n",
        "a=rtpmap:99 H264/90000\r\n",
    );

    #[test]
    fn test_parse_session_level_fields() {
        let sdp = FULL_SDP.parse::<SessionDescription>().unwrap();

        assert_eq!(sdp.version(), 0);

        let origin = sdp.origin();

        assert_eq!(origin.username(), "jdoe");
        assert_eq!(origin.session_id(), 2890844526);
        assert_eq!(origin.session_version(), 2890842807);
        assert!(matches!(origin.network_type(), NetworkType::Internet));
        assert!(matches!(origin.address_type(), AddressType::IPv4));
        assert_eq!(origin.unicast_address(), "10.47.16.5");

        assert_eq!(sdp.session_name(), "SDP Seminar");
        assert_eq!(
            sdp.session_information(),
            Some("A seminar on the session description protocol")
        );
        assert_eq!(sdp.url(), Some("http://www.example.com/seminars/sdp.pdf"));
        assert_eq!(sdp.emails(), ["j.doe@example.com (Jane Doe)"]);
        assert_eq!(sdp.phones(), ["+1 617 555-6011"]);

        let connection = sdp.connection().unwrap();

        assert!(matches!(connection.network_type(), NetworkType::Internet));

        let ConnectionAddress::IPv4(addr) = connection.address() else {
            panic!("IPv4 connection address expected");
        };

        assert_eq!(addr.address(), Ipv4Addr::new(224, 2, 17, 12));
        assert_eq!(addr.ttl(), Some(127));
        assert_eq!(addr.count(), None);

        assert_eq!(sdp.bandwidth().len(), 1);
        assert!(matches!(
            sdp.bandwidth()[0].bandwidth_type(),
            BandwidthType::AS
        ));
        assert_eq!(sdp.bandwidth()[0].bandwidth(), 128);

        let key = sdp.encryption_key().unwrap();

        assert_eq!(key.method(), "prompt");
        assert_eq!(key.key(), None);

        let attributes = sdp.attributes();

        assert!(attributes.contains("recvonly"));
        assert_eq!(attributes.get("recvonly").unwrap().value(), None);
        assert_eq!(attributes.get_value("tool"), Some("msf"));
    }

    #[test]
    fn test_parse_time_fields() {
        let sdp = FULL_SDP.parse::<SessionDescription>().unwrap();

        assert_eq!(sdp.time_descriptions().len(), 1);

        let td = &sdp.time_descriptions()[0];

        assert_eq!(td.start(), 2873397496);
        assert_eq!(td.stop(), 2873404696);
        assert_eq!(td.repeat_times().len(), 1);

        let repeat = &td.repeat_times()[0];

        assert_eq!(repeat.repeat_interval().as_secs(), 7 * 86_400);
        assert_eq!(repeat.active_duration().as_secs(), 3_600);

        let offsets = repeat
            .offsets()
            .iter()
            .map(UnsignedCompactDuration::as_secs)
            .collect::<Vec<_>>();

        assert_eq!(offsets, [0, 25 * 3_600]);

        let adjustments = sdp.tz_adjustments();

        assert_eq!(adjustments.len(), 2);
        assert_eq!(adjustments[0].adjustment_time(), 2882844526);
        assert_eq!(adjustments[0].offset().as_secs(), -3_600);
        assert_eq!(adjustments[1].adjustment_time(), 2898848070);
        assert_eq!(adjustments[1].offset().as_secs(), 0);
    }

    #[test]
    fn test_parse_media_descriptions() {
        let sdp = FULL_SDP.parse::<SessionDescription>().unwrap();

        assert_eq!(sdp.media_descriptions().len(), 2);

        let audio = &sdp.media_descriptions()[0];

        assert_eq!(audio.media_type(), "audio");
        assert_eq!(audio.port(), 49170);
        assert_eq!(audio.port_count(), None);
        assert_eq!(audio.protocol(), "RTP/AVP");
        assert_eq!(audio.formats(), ["0"]);
        assert_eq!(audio.title(), Some("Audio stream"));
        assert!(audio.connection().is_empty());
        assert_eq!(audio.bandwidth().len(), 1);
        assert!(matches!(
            audio.bandwidth()[0].bandwidth_type(),
            BandwidthType::CT
        ));
        assert_eq!(audio.bandwidth()[0].bandwidth(), 64);
        assert!(audio.encryption_key().is_none());

        let rtpmap = audio.attributes().get_value("rtpmap").unwrap();
        let rtpmap = RTPMap::try_from(rtpmap).unwrap();

        assert_eq!(rtpmap.payload_type(), 0);
        assert_eq!(rtpmap.encoding_name(), "PCMU");
        assert_eq!(rtpmap.clock_rate(), 8_000);

        let video = &sdp.media_descriptions()[1];

        assert_eq!(video.media_type(), "video");
        assert_eq!(video.port(), 51372);
        assert_eq!(video.port_count(), Some(2));
        assert_eq!(video.formats(), ["99"]);
        assert_eq!(video.title(), None);
        assert_eq!(video.connection().len(), 1);

        let ConnectionAddress::IPv6(addr) = video.connection()[0].address() else {
            panic!("IPv6 connection address expected");
        };

        assert_eq!(addr.address(), "ff15::101".parse::<Ipv6Addr>().unwrap());
        assert_eq!(addr.count(), Some(3));

        let key = video.encryption_key().unwrap();

        assert_eq!(key.method(), "base64");
        assert_eq!(key.key(), Some("c2VjcmV0"));
    }

    #[test]
    fn test_serialize_session_description() {
        let sdp = FULL_SDP.parse::<SessionDescription>().unwrap();

        assert_eq!(sdp.to_string(), FULL_SDP);
    }

    #[test]
    fn test_parse_ignores_line_endings_and_blank_lines() {
        let sdp = "v=0\no=- 0 0 IN IP4 127.0.0.1\n\ns=-\nt=0 0\n"
            .parse::<SessionDescription>()
            .unwrap();

        assert_eq!(sdp.session_name(), "-");
        assert_eq!(sdp.time_descriptions().len(), 1);
    }

    #[test]
    fn test_parse_errors() {
        // a line that is not a `<type>=<value>` pair
        assert!("v=0\r\nhello\r\n".parse::<SessionDescription>().is_err());

        // an unknown field type
        assert!("v=0\r\nq=foo\r\n".parse::<SessionDescription>().is_err());

        // an invalid origin
        assert!("o=jdoe 1 2 IN IP4\r\n"
            .parse::<SessionDescription>()
            .is_err());

        // a trailing field in a time description
        assert!("t=0 0 0\r\n".parse::<SessionDescription>().is_err());

        // an unknown field within a media description
        assert!("m=audio 0 RTP/AVP 0\r\nv=0\r\n"
            .parse::<SessionDescription>()
            .is_err());
    }

    #[test]
    fn test_parse_lossy() {
        let sdp = SessionDescription::from_str_lossy(concat!(
            "v=X\r\n",
            "o=broken origin\r\n",
            "s=Lossy\r\n",
            "this is not an SDP line\r\n",
            "c=IN IP4 not-an-address\r\n",
            "b=bogus\r\n",
            "t=foo bar\r\n",
            "r=also bogus\r\n",
            "q=unknown field\r\n",
            "a=recvonly\r\n",
            "m=audio bogus RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        ));

        // invalid values are replaced by their defaults...
        assert_eq!(sdp.version(), 0);
        assert_eq!(sdp.origin().username(), "-");
        assert_eq!(sdp.origin().unicast_address(), "0.0.0.0");

        // ... or dropped entirely
        assert!(sdp.connection().is_none());
        assert!(sdp.bandwidth().is_empty());

        assert_eq!(sdp.time_descriptions().len(), 1);
        assert_eq!(sdp.time_descriptions()[0].start(), 0);
        assert_eq!(sdp.time_descriptions()[0].stop(), 0);
        assert!(sdp.time_descriptions()[0].repeat_times().is_empty());

        // ... while valid fields are preserved
        assert_eq!(sdp.session_name(), "Lossy");
        assert!(sdp.attributes().contains("recvonly"));

        assert_eq!(sdp.media_descriptions().len(), 1);

        let media = &sdp.media_descriptions()[0];

        assert_eq!(media.media_type(), "audio");
        assert_eq!(media.port(), 0);
        assert_eq!(media.protocol(), "RTP/AVP");
        assert_eq!(media.formats(), ["0"]);
        assert_eq!(media.attributes().get_value("rtpmap"), Some("0 PCMU/8000"));
    }

    #[test]
    fn test_builder() {
        let origin = Origin::new(
            "alice",
            1,
            2,
            NetworkType::Internet,
            AddressType::IPv4,
            "192.0.2.1",
        );

        let mut media = MediaDescription::builder("audio", 49170, "RTP/AVP");

        media
            .format(0)
            .attribute("rtpmap", RTPMap::new(0, "PCMU", 8000));

        let mut builder = SessionDescription::builder();

        builder
            .version(0)
            .origin(origin)
            .session_information("info")
            .url("http://example.com")
            .email("alice@example.com")
            .phone("+1 617 555-6011")
            .connection(ConnectionInfo::new(
                NetworkType::Internet,
                ConnectionAddress::unicast(Ipv4Addr::new(192, 0, 2, 1)),
            ))
            .bandwidth(Bandwidth::new(BandwidthType::AS, 256))
            .tz_adjustment(TimeZoneAdjustment::new(1, CompactDuration::Hours(-1)))
            .encryption_key(EncryptionKey::new("prompt"))
            .flag("recvonly")
            .attribute("tool", "msf")
            .media_description(media.build());

        let sdp = builder.build();

        // the session name and the time description are mandatory, so the
        // builder has to fill in the defaults
        assert_eq!(sdp.session_name(), "-");
        assert_eq!(sdp.time_descriptions().len(), 1);

        let expected = concat!(
            "v=0\r\n",
            "o=alice 1 2 IN IP4 192.0.2.1\r\n",
            "s=-\r\n",
            "i=info\r\n",
            "u=http://example.com\r\n",
            "e=alice@example.com\r\n",
            "p=+1 617 555-6011\r\n",
            "c=IN IP4 192.0.2.1\r\n",
            "b=AS:256\r\n",
            "t=0 0\r\n",
            "z=1 -1h\r\n",
            "k=prompt\r\n",
            "a=recvonly\r\n",
            "a=tool:msf\r\n",
            "m=audio 49170 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        );

        assert_eq!(sdp.to_string(), expected);
    }

    #[test]
    fn test_builder_explicit_time_description() {
        let repeat = RepeatTime::new(
            UnsignedCompactDuration::Days(7),
            UnsignedCompactDuration::Hours(1),
            vec![UnsignedCompactDuration::Seconds(0)],
        );

        let mut builder = SessionDescription::builder();

        builder
            .session_name("session")
            .time_description(TimeDescription::new(1, 2, vec![repeat]));

        let sdp = builder.build();

        assert_eq!(sdp.session_name(), "session");
        assert_eq!(sdp.time_descriptions().len(), 1);
        assert!(sdp.to_string().contains("t=1 2\r\nr=7d 1h 0\r\n"));
    }

    #[test]
    fn test_network_and_address_types() {
        let sdp = "o=- 1 2 ATM NSAP 47.0001\r\n"
            .parse::<SessionDescription>()
            .unwrap();

        let origin = sdp.origin();

        assert!(matches!(origin.network_type(), NetworkType::Other(t) if t == "ATM"));
        assert!(matches!(origin.address_type(), AddressType::Other(t) if t == "NSAP"));
        assert_eq!(origin.to_string(), "- 1 2 ATM NSAP 47.0001");
    }

    #[test]
    fn test_connection_address_unicast() {
        let addr = ConnectionAddress::unicast(Ipv4Addr::new(192, 0, 2, 1));

        assert!(matches!(addr, ConnectionAddress::IPv4(_)));
        assert_eq!(addr.to_string(), "IP4 192.0.2.1");

        let addr = ConnectionAddress::unicast(Ipv6Addr::LOCALHOST);

        assert!(matches!(addr, ConnectionAddress::IPv6(_)));
        assert_eq!(addr.to_string(), "IP6 ::1");

        let addr = ConnectionAddress::from(IPv4Address::multicast(
            Ipv4Addr::new(224, 2, 17, 12),
            127,
            Some(3),
        ));

        assert_eq!(addr.to_string(), "IP4 224.2.17.12/127/3");
    }
}
