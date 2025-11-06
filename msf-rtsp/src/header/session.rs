//! Session header and related types.

use std::{
    borrow::{Borrow, Cow},
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use crate::{Error, header::HeaderFieldValue};

/// Session header field.
#[derive(Clone)]
pub struct SessionHeader {
    inner: SessionHeaderRef<'static>,
}

impl SessionHeader {
    /// Create a new session header with a given session ID.
    pub fn new<T>(id: T) -> Self
    where
        T: Into<String>,
    {
        let inner = SessionHeaderRef {
            id: Cow::Owned(id.into()),
            timeout: None,
        };

        Self { inner }
    }

    /// Get session ID.
    #[inline]
    pub fn id(&self) -> &str {
        self.inner.id()
    }

    /// Get session timeout.
    #[inline]
    pub fn timeout(&self) -> u64 {
        self.inner.timeout()
    }

    /// Set the session timeout.
    #[inline]
    pub const fn with_timeout(mut self, timeout: u64) -> Self {
        self.inner.timeout = Some(timeout);
        self
    }
}

impl Borrow<SessionHeaderRef<'static>> for SessionHeader {
    #[inline]
    fn borrow(&self) -> &SessionHeaderRef<'static> {
        &self.inner
    }
}

impl Display for SessionHeader {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(Borrow::<SessionHeaderRef>::borrow(self), f)
    }
}

impl From<SessionHeader> for HeaderFieldValue {
    #[inline]
    fn from(value: SessionHeader) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}

impl FromStr for SessionHeader {
    type Err = Error;

    #[inline]
    fn from_str(header: &str) -> Result<Self, Self::Err> {
        SessionHeaderRef::try_from(header).map(SessionHeaderRef::into_owned)
    }
}

impl TryFrom<&HeaderFieldValue> for SessionHeader {
    type Error = Error;

    #[inline]
    fn try_from(value: &HeaderFieldValue) -> Result<Self, Self::Error> {
        SessionHeaderRef::try_from(value).map(SessionHeaderRef::into_owned)
    }
}

/// Session header reference.
#[derive(Clone)]
pub struct SessionHeaderRef<'a> {
    id: Cow<'a, str>,
    timeout: Option<u64>,
}

impl<'a> SessionHeaderRef<'a> {
    /// Create a new session header with a given session ID.
    #[inline]
    pub const fn new(id: &'a str) -> Self {
        Self {
            id: Cow::Borrowed(id),
            timeout: None,
        }
    }
}

impl SessionHeaderRef<'_> {
    /// Get the session ID.
    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the session timeout.
    #[inline]
    pub fn timeout(&self) -> u64 {
        self.timeout.unwrap_or(60)
    }

    /// Set the session timeout.
    #[inline]
    pub const fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Convert the session header into the owned representation.
    #[inline]
    pub fn into_owned(self) -> SessionHeader {
        let inner = SessionHeaderRef {
            id: Cow::Owned(self.id.into_owned()),
            timeout: self.timeout,
        };

        SessionHeader { inner }
    }

    /// Parse header parameters.
    fn parse_params(&mut self, params: &str) -> Result<(), Error> {
        for element in params.split(';') {
            let (name, value) = super::parse_header_parameter(element);

            if name.is_empty() {
                continue;
            }

            self.parse_param(name, value)?;
        }

        Ok(())
    }

    /// Parse a given parameter.
    fn parse_param(&mut self, name: &str, value: &str) -> Result<(), Error> {
        if name.eq_ignore_ascii_case("timeout") {
            self.timeout = value
                .parse()
                .map(Some)
                .map_err(|_| Error::from_static_msg("invalid timeout parameter"))?;
        }

        Ok(())
    }
}

impl Display for SessionHeaderRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)?;

        if let Some(timeout) = self.timeout {
            write!(f, ";timeout={timeout}")?;
        }

        Ok(())
    }
}

impl From<SessionHeaderRef<'_>> for HeaderFieldValue {
    #[inline]
    fn from(value: SessionHeaderRef<'_>) -> Self {
        HeaderFieldValue::from(value.to_string())
    }
}

impl<'a> TryFrom<&'a str> for SessionHeaderRef<'a> {
    type Error = Error;

    fn try_from(header: &'a str) -> Result<Self, Self::Error> {
        let (id, params) = header.split_once(';').unwrap_or((header, ""));

        let mut res = Self::new(id);

        res.parse_params(params)?;

        Ok(res)
    }
}

impl<'a> TryFrom<&'a HeaderFieldValue> for SessionHeaderRef<'a> {
    type Error = Error;

    fn try_from(value: &'a HeaderFieldValue) -> Result<Self, Self::Error> {
        value
            .to_str()
            .map_err(|_| Error::from_static_msg("header field is not UTF-8 encoded"))?
            .try_into()
    }
}
