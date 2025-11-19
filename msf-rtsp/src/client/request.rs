use std::time::Duration;

use bytes::Bytes;

use crate::{
    Error, Method, Version,
    client::{
        auth::{AuthProvider, NoAuthProvider},
        connector::{Connection, Connector, DefaultConnectionInfo, DefaultConnector},
        response::IncomingResponse,
        session::Session,
    },
    header::HeaderField,
    request::{Request, RequestBuilder, RequestPath},
    url::Url,
};

/// Outgoing RTSP request.
pub struct OutgoingRequest<'a, A = NoAuthProvider, C = DefaultConnector, I = DefaultConnectionInfo>
{
    session: &'a mut Session<A, C, I>,
    builder: RequestBuilder,
    body: Bytes,
    timeout: Option<Duration>,
}

impl<'a, A, C, I> OutgoingRequest<'a, A, C, I> {
    /// Create a new outgoing request.
    pub(crate) fn new(session: &'a mut Session<A, C, I>, method: Method, url: Url) -> Self {
        let url: String = url.into();

        let builder = Request::builder(Version::Version10, method, url.into());

        Self {
            session,
            builder,
            body: Bytes::new(),
            timeout: None,
        }
    }
}

impl<A, C, I> OutgoingRequest<'_, A, C, I> {
    /// Set the protocol version.
    #[inline]
    pub fn set_version(mut self, version: Version) -> Self {
        self.builder = self.builder.set_version(version);
        self
    }

    /// Set the request method.
    #[inline]
    pub fn set_method(mut self, method: Method) -> Self {
        self.builder = self.builder.set_method(method);
        self
    }

    /// Set the request URL.
    #[inline]
    pub fn set_url(mut self, url: Url) -> Self {
        self.builder = self.builder.set_path(RequestPath::from(String::from(url)));
        self
    }

    /// Replace the current header fields having the same name (if any).
    pub fn set_header_field<T>(mut self, field: T) -> Self
    where
        T: Into<HeaderField>,
    {
        self.builder = self.builder.set_header_field(field);
        self
    }

    /// Add a given header field.
    pub fn add_header_field<T>(mut self, field: T) -> Self
    where
        T: Into<HeaderField>,
    {
        self.builder = self.builder.add_header_field(field);
        self
    }

    /// Remove all header fields with a given name.
    pub fn remove_header_fields<N>(mut self, name: &N) -> Self
    where
        N: AsRef<[u8]> + ?Sized,
    {
        self.builder = self.builder.remove_header_fields(name);
        self
    }

    /// Set the request body.
    pub fn set_body<B>(mut self, body: B) -> Self
    where
        B: Into<Bytes>,
    {
        self.body = body.into();
        self
    }

    /// Set the request timeout.
    ///
    /// If not `None`, it overrides the default timeout of the RTSP client.
    #[inline]
    pub fn set_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<A, C, I> OutgoingRequest<'_, A, C, I>
where
    C: Connector,
    C::Connection: Connection<Info = I> + Send + 'static,
    A: AuthProvider,
{
    /// Send the request.
    pub async fn send(self) -> Result<IncomingResponse, Error> {
        let request = self
            .builder
            .set_header_field(("Content-Length", self.body.len()))
            .body(self.body);

        self.session.send_request(request, self.timeout).await
    }
}
