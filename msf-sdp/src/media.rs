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
    parser::{
        FromSessionDescriptionLines, FromSessionDescriptionLinesLossy, SessionDescriptionLines,
        SessionDescriptionLinesLossy,
    },
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

    /// Parse a given 'm' line.
    fn from_m_line(line: &str) -> Result<Self, ParseError> {
        let mut res = Self::new();

        let mut reader = StringReader::new(line);

        res.media_type = String::from(reader.read_word());

        reader.skip_whitespace();

        res.port = reader
            .read_until(|c| c.is_whitespace() || c == '/')
            .parse()?;

        reader.skip_whitespace();

        if reader.current_char() == Some('/') {
            reader.skip_char();

            res.port_count = Some(reader.read_u16()?);
        }

        res.protocol = String::from(reader.read_word());

        loop {
            reader.skip_whitespace();

            if reader.is_empty() {
                break;
            }

            res.formats.push(String::from(reader.read_word()));
        }

        Ok(res)
    }

    /// Parse a given 'm' line.
    fn from_m_line_lossy(line: &str) -> Self {
        let mut res = Self::new();

        let mut reader = StringReader::new(line);

        res.media_type = String::from(reader.read_word());

        reader.skip_whitespace();

        res.port = reader
            .read_until(|c| c.is_whitespace() || c == '/')
            .parse()
            .unwrap_or(0);

        reader.skip_whitespace();

        if reader.current_char() == Some('/') {
            reader.skip_char();

            res.port_count = reader.read_word().parse().ok();
        }

        res.protocol = String::from(reader.read_word());

        loop {
            reader.skip_whitespace();

            if reader.is_empty() {
                break;
            }

            res.formats.push(String::from(reader.read_word()));
        }

        res
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

    /// Parse a media description from a given string while ignoring parse
    /// errors where possible.
    ///
    /// This can be used as a best effort method to parse invalid media
    /// descriptions received from 3rd party implementations. However, keep in
    /// mind that the returned media description may be missing vital
    /// information. The method returns `None` if there was no `'m=...'` line
    /// in the input.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        let mut lines = SessionDescriptionLinesLossy::new(s);

        while let Some((t, _)) = lines.current() {
            if t == 'm' {
                return <Self as FromSessionDescriptionLinesLossy>::from_sdp_lines(&mut lines).ok();
            } else {
                lines.next();
            }
        }

        None
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

        let mut mdp = MediaDescription::from_m_line(v)?;

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

impl FromSessionDescriptionLinesLossy for MediaDescription {
    fn from_sdp_lines(lines: &mut SessionDescriptionLinesLossy) -> Result<Self, ParseError> {
        let (t, v) = lines.current().unwrap();

        debug_assert_eq!(t, 'm');

        let mut mdp = MediaDescription::from_m_line_lossy(v);

        // skip the current 'm' line
        lines.next();

        while let Some((t, _)) = lines.current() {
            match t {
                'm' => break,
                'i' => mdp.title = lines.parse().ok(),
                'c' => {
                    if let Ok(c) = lines.parse() {
                        mdp.connection.push(c);
                    }
                }
                'b' => {
                    if let Ok(bw) = lines.parse() {
                        mdp.bandwidth.push(bw);
                    }
                }
                'k' => mdp.key = lines.parse().ok(),
                'a' => {
                    if let Ok(attr) = lines.parse() {
                        mdp.attributes.push(attr);
                    }
                }
                _ => lines.next(),
            }
        }

        Ok(mdp)
    }
}

impl FromStr for MediaDescription {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = SessionDescriptionLines::new(s)?;

        lines
            .current()
            .filter(|(t, _)| *t == 'm')
            .ok_or_else(ParseError::plain)?;

        <Self as FromSessionDescriptionLines>::from_sdp_lines(&mut lines)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        connection::ConnectionAddress, Bandwidth, BandwidthType, ConnectionInfo, EncryptionKey,
        NetworkType,
    };

    use super::MediaDescription;

    const MEDIA: &str = concat!(
        "m=video 51372/2 RTP/AVP 99 100\r\n",
        "i=Main camera\r\n",
        "c=IN IP4 192.0.2.1\r\n",
        "b=AS:512\r\n",
        "k=clear:secret\r\n",
        "a=sendonly\r\n",
    );

    #[test]
    fn test_from_str() {
        // the trailing media description must not be consumed
        let input = format!("{MEDIA}m=audio 49170 RTP/AVP 0\r\n");

        let md = input.parse::<MediaDescription>().unwrap();

        assert_eq!(md.media_type(), "video");
        assert_eq!(md.port(), 51372);
        assert_eq!(md.port_count(), Some(2));
        assert_eq!(md.protocol(), "RTP/AVP");
        assert_eq!(md.formats(), ["99", "100"]);
        assert_eq!(md.title(), Some("Main camera"));

        assert_eq!(md.connection().len(), 1);

        let ConnectionAddress::IPv4(addr) = md.connection()[0].address() else {
            panic!("IPv4 connection address expected");
        };

        assert_eq!(addr.address(), Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(md.bandwidth().len(), 1);
        assert_eq!(md.bandwidth()[0].bandwidth(), 512);

        let key = md.encryption_key().unwrap();

        assert_eq!(key.method(), "clear");
        assert_eq!(key.key(), Some("secret"));

        assert!(md.attributes().contains("sendonly"));

        assert_eq!(md.to_string(), MEDIA);
    }

    #[test]
    fn test_from_str_errors() {
        // no media description at all
        assert!("a=recvonly\r\n".parse::<MediaDescription>().is_err());
        assert!("".parse::<MediaDescription>().is_err());

        // an invalid port
        assert!("m=video bogus RTP/AVP 99"
            .parse::<MediaDescription>()
            .is_err());

        // a field that does not belong to a media description
        assert!("m=video 0 RTP/AVP 99\r\nt=0 0\r\n"
            .parse::<MediaDescription>()
            .is_err());
    }

    #[test]
    fn test_from_str_lossy() {
        let md = MediaDescription::from_str_lossy(concat!(
            "v=0\r\n",
            "s=-\r\n",
            "m=video 51372/bogus RTP/AVP 99\r\n",
            "c=IN IP4 not-an-address\r\n",
            "a=sendonly\r\n",
        ))
        .unwrap();

        assert_eq!(md.media_type(), "video");
        assert_eq!(md.port(), 51372);
        assert_eq!(md.port_count(), None);
        assert_eq!(md.protocol(), "RTP/AVP");
        assert_eq!(md.formats(), ["99"]);
        assert!(md.connection().is_empty());
        assert!(md.attributes().contains("sendonly"));

        assert!(MediaDescription::from_str_lossy("v=0\r\ns=-\r\n").is_none());
    }

    #[test]
    fn test_builder() {
        let mut builder = MediaDescription::builder("video", 51372, "RTP/AVP");

        builder
            .port_count(2)
            .format(99)
            .format(100)
            .title("Main camera")
            .connection(ConnectionInfo::new(
                NetworkType::Internet,
                ConnectionAddress::unicast(Ipv4Addr::new(192, 0, 2, 1)),
            ))
            .bandwidth(Bandwidth::new(BandwidthType::AS, 512))
            .key(EncryptionKey::new_with_key("clear", "secret"))
            .flag("sendonly");

        assert_eq!(builder.build().to_string(), MEDIA);
    }
}
