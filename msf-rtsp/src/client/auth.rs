//! RTSP client authentication.

use ttpkit_auth::basic::BasicAuth;

use crate::{
    Error,
    request::{Request, RequestBuilder},
    response::Response,
    url::IntoUrl,
};

/// Authentication provider for outgoing requests.
pub trait AuthProvider {
    /// Reset the internal state of the authentication provider.
    ///
    /// The provider should be ready to authenticate a new request after this
    /// call. This may be useful when a single request needs to be sent in
    /// multiple attempts (e.g. due to authentication challenges). The provider
    /// can track the state of the authentication process and the number of
    /// attempts in order to prevent infinite loops.
    #[inline]
    fn reset(&mut self) {}

    /// Authorize a given outgoing request.
    fn authorize_request(&mut self, request: Request) -> Result<Request, Error>;

    /// Process a given incoming response.
    ///
    /// The method returns `Some(response)` if the response should be further
    /// processed or `None` if the response has been consumed internally (e.g.
    /// an authentication challenge has been processed and a new request should
    /// be sent).
    fn process_response(&mut self, response: Response) -> Result<Option<Response>, Error>;
}

/// Dummy authentication provider that does nothing.
///
/// The `authorize_request` method only strips credentials from the request URL
/// (if present) in order to avoid sending them accidentally in plain text.
#[derive(Default)]
pub struct NoAuthProvider(());

impl NoAuthProvider {
    /// Create a new `NoAuthProvider` instance.
    #[inline]
    pub const fn new() -> Self {
        Self(())
    }
}

impl AuthProvider for NoAuthProvider {
    fn authorize_request(&mut self, request: Request) -> Result<Request, Error> {
        let path = request.path();

        if path.as_ref() == b"*" {
            return Ok(request);
        }

        let url: String = path
            .to_str()
            .ok()
            .map(|path| path.into_url())
            .and_then(|res| res.ok())
            .ok_or_else(|| Error::from_static_msg("invalid request URL"))?
            .with_auth(None)
            .expect("unable to strip credentials from URL")
            .into();

        let (header, body) = request.deconstruct();

        let request = RequestBuilder::from(header).set_path(url.into()).body(body);

        Ok(request)
    }

    #[inline]
    fn process_response(&mut self, response: Response) -> Result<Option<Response>, Error> {
        Ok(Some(response))
    }
}

/// Basic authentication provider.
///
/// The `authorize_request` method adds the `Authorization` header to the
/// request if the credentials are available. The credentials can be set
/// during the construction of the provider (by converting a `BasicAuth`
/// instance into `BasicAuthProvider`) or extracted from the request URL (if
/// present). Credentials extracted from the URL take precedence over the ones
/// provided during construction.
///
/// Credentials in the URL are stripped from the request before sending it.
#[derive(Default)]
pub struct BasicAuthProvider {
    auth: Option<BasicAuth>,
}

impl BasicAuthProvider {
    /// Create a new `BasicAuthProvider` instance with no initial credentials.
    #[inline]
    pub const fn new() -> Self {
        Self { auth: None }
    }
}

impl AuthProvider for BasicAuthProvider {
    fn authorize_request(&mut self, request: Request) -> Result<Request, Error> {
        let path = request.path();

        if path.as_ref() == b"*" {
            return Ok(request);
        }

        let url = path
            .to_str()
            .ok()
            .map(|path| path.into_url())
            .and_then(|res| res.ok())
            .ok_or_else(|| Error::from_static_msg("invalid request URL"))?;

        // update the credentials cache if new credentials are provided
        if let Some(username) = url.username() {
            let password = url.password();

            let auth = BasicAuth::new(username, password.unwrap_or(""));

            self.auth = Some(auth);
        }

        // strip credentials from the URL (if present)
        let url: String = url
            .with_auth(None)
            .expect("unable to strip credentials from URL")
            .into();

        let (header, body) = request.deconstruct();

        let mut builder = RequestBuilder::from(header).set_path(url.into());

        if let Some(auth) = self.auth.as_ref() {
            builder = builder.set_header_field(("Authorization", auth.to_string()));
        }

        Ok(builder.body(body))
    }

    #[inline]
    fn process_response(&mut self, response: Response) -> Result<Option<Response>, Error> {
        Ok(Some(response))
    }
}

impl From<BasicAuth> for BasicAuthProvider {
    #[inline]
    fn from(auth: BasicAuth) -> Self {
        Self { auth: Some(auth) }
    }
}
