//! Media description.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use str_reader::StringReader;

use crate::{
    attribute::{Attribute, Attributes},
    bandwidth::Bandwidth,
    connection::ConnectionInfo,
    key::EncryptionKey,
    parser::{FromSessionDescriptionLines, SessionDescriptionLines},
    ParseError,
};

/// Builder for the media description.
#[derive(Clone)]
pub struct MediaDescriptionBuilder {
    inner: MediaDescription,
}

impl MediaDescriptionBuilder {
    /// Create a new media description builder.
    const fn new(media_type: String, port: u16, protocol: String) -> Self {
        let inner = MediaDescription {
            media_type,
            port,
            port_count: None,
            protocol,
            formats: Vec::new(),
            title: None,
            bandwidth: Vec::new(),
            key: None,
            connection: Vec::new(),
            attributes: Attributes::new(),
        };

        Self { inner }
    }

    /// Set number of ports.
    #[inline]
    pub fn port_count(&mut self, port_count: u16) -> &mut Self {
        self.inner.port_count = Some(port_count);
        self
    }

    /// Add a given format.
    #[inline]
    pub fn format<T>(&mut self, fmt: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.formats.push(fmt.to_string());
        self
    }

    /// Set media title.
    #[inline]
    pub fn title<T>(&mut self, title: T) -> &mut Self
    where
        T: ToString,
    {
        self.inner.title = Some(title.to_string());
        self
    }

    /// Add a given bandwidth info.
    #[inline]
    pub fn bandwidth(&mut self, bandwidth: Bandwidth) -> &mut Self {
        self.inner.bandwidth.push(bandwidth);
        self
    }

    /// Set encryption key.
    #[inline]
    pub fn key(&mut self, key: EncryptionKey) -> &mut Self {
        self.inner.key = Some(key);
        self
    }

    /// Add a given connection info.
    #[inline]
    pub fn connection(&mut self, connection: ConnectionInfo) -> &mut Self {
        self.inner.connection.push(connection);
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

    /// Build the media description.
    #[inline]
    pub fn build(self) -> MediaDescription {
        self.inner
    }
}

/// Media format.
pub type MediaFormat = String;

/// Media description.
#[derive(Clone)]
pub struct MediaDescription {
    media_type: String,
    port: u16,
    port_count: Option<u16>,
    protocol: String,
    formats: Vec<MediaFormat>,
    title: Option<String>,
    bandwidth: Vec<Bandwidth>,
    key: Option<EncryptionKey>,
    connection: Vec<ConnectionInfo>,
    attributes: Attributes,
}

impl MediaDescription {
    /// Create a new empty media description.
    const fn new() -> Self {
        Self {
            media_type: String::new(),
            port: 0,
            port_count: None,
            protocol: String::new(),
            formats: Vec::new(),
            title: None,
            bandwidth: Vec::new(),
            key: None,
            connection: Vec::new(),
            attributes: Attributes::new(),
        }
    }

    /// Get a new media description builder.
    #[inline]
    pub fn builder<T, U>(media_type: T, port: u16, protocol: U) -> MediaDescriptionBuilder
    where
        T: ToString,
        U: ToString,
    {
        MediaDescriptionBuilder::new(media_type.to_string(), port, protocol.to_string())
    }

    /// Get the media type (e.g. "audio" or "video").
    #[inline]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Get the port number for the media.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the number of ports (if specified).
    #[inline]
    pub fn port_count(&self) -> Option<u16> {
        self.port_count
    }

    /// Get the protocol.
    #[inline]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Get the media formats.
    #[inline]
    pub fn formats(&self) -> &[MediaFormat] {
        &self.formats
    }

    /// Get the media title.
    #[inline]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Get bandwidth fields.
    #[inline]
    pub fn bandwidth(&self) -> &[Bandwidth] {
        &self.bandwidth
    }

    /// Get encryption key.
    #[inline]
    pub fn encryption_key(&self) -> Option<&EncryptionKey> {
        self.key.as_ref()
    }

    /// Get the connection info.
    #[inline]
    pub fn connection(&self) -> &[ConnectionInfo] {
        &self.connection
    }

    /// Get the attributes.
    #[inline]
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }
}

impl Display for MediaDescription {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "m={} {}", self.media_type, self.port)?;

        if let Some(count) = self.port_count {
            write!(f, "/{count}")?;
        }

        write!(f, " {}", self.protocol)?;

        for fmt in &self.formats {
            write!(f, " {fmt}")?;
        }

        f.write_str("\r\n")?;

        if let Some(title) = self.title.as_ref() {
            write!(f, "i={title}\r\n")?;
        }

        for connection in &self.connection {
            write!(f, "c={connection}\r\n")?;
        }

        for bw in &self.bandwidth {
            write!(f, "b={bw}\r\n")?;
        }

        if let Some(k) = self.key.as_ref() {
            write!(f, "k={k}\r\n")?;
        }

        for attr in self.attributes.iter() {
            write!(f, "a={attr}\r\n")?;
        }

        Ok(())
    }
}

impl FromSessionDescriptionLines for MediaDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLines) -> Result<Self, ParseError> {
        let (t, v) = lines.current().unwrap();

        debug_assert_eq!(t, 'm');

        let mut mdp = MediaDescription::new();

        let mut reader = StringReader::new(v);

        mdp.media_type = String::from(reader.read_word());

        mdp.port = reader.read_u16()?;

        reader.skip_whitespace();

        if reader.current_char() == Some('/') {
            reader.skip_char();

            mdp.port_count = Some(reader.read_u16()?);
        }

        mdp.protocol = String::from(reader.read_word());

        loop {
            reader.skip_whitespace();

            if reader.is_empty() {
                break;
            }

            mdp.formats.push(String::from(reader.read_word()));
        }

        lines.next()?;

        while let Some((t, _)) = lines.current() {
            match t {
                'm' => break,
                'i' => mdp.title = Some(lines.parse()?),
                'c' => mdp.connection.push(lines.parse()?),
                'b' => mdp.bandwidth.push(lines.parse()?),
                'k' => mdp.key = Some(lines.parse()?),
                'a' => mdp.attributes.push(lines.parse()?),
                _ => {
                    return Err(ParseError::with_msg(format!(
                        "unknown media description field: {t}",
                    )))
                }
            }
        }

        Ok(mdp)
    }
}

impl FromStr for MediaDescription {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = SessionDescriptionLines::new(s)?;

        MediaDescription::from_sdp_lines(&mut lines)
    }
}
