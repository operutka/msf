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
    parser::{FromSessionDescriptionLines, SessionDescriptionLines},
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

impl FromStr for SessionDescription {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = SessionDescriptionLines::new(s)?;

        SessionDescription::from_sdp_lines(&mut lines)
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
