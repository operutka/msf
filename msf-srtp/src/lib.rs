//! This crate implements DTLS-SRTP as defined in RFC 5764. The RFC is built on
//! top of:
//! * RFC 3711 (SRTP)
//! * RFC 4347 (DTLS)
//! * RFC 8122 (TLS in SDP)
//!
//! # Usage example
//! ```ignore
//! use openssl::{pkey::PKey, rsa::Rsa};
//!
//! // a UDP stream + sink
//! let stream = ...;
//!
//! // peer certificate fingerprint from SDP
//! let cert_fingerprint = "...";
//!
//! // peer setup attribute from SDP
//! let setup = "...";
//!
//! let connect = match setup {
//!     "active" | "actpass" => true,
//!     "passive" => false,
//!     _ => panic!("unsupported setup"),
//! };
//!
//! // generate a private key (can be application-wide)
//! let rsa = Rsa::generate(2048)?;
//! let key = PKey::from_rsa(rsa)?;
//!
//! let context = SrtpContext::self_signed(&key)?;
//!
//! let stream = if connect {
//!     context.connect_muxed(stream, cert_fingerprint).await?
//! } else {
//!     context.accept_muxed(stream, cert_fingerprint).await?
//! };
//! ```

mod connector;
mod fingerprint;
mod key_stream;
mod profile;
mod session;

use std::{
    fmt::{self, Display, Formatter, Write},
    future::Future,
    io, ptr,
    str::FromStr,
};

use bytes::Bytes;
use futures::{Sink, Stream};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{HasPrivate, PKeyRef},
    ssl::{Ssl, SslContext, SslMethod, SslVerifyMode},
    x509::{X509Ref, X509},
};

use self::connector::Connector;

pub use self::{
    connector::{MuxedSrtpStream, SrtcpStream, SrtpStream},
    fingerprint::{CertificateFingerprint, HashFunction, InvalidFingerprint, UnknownHashFunction},
    profile::SrtpProfileId,
};

/// SRTP error.
#[derive(Debug)]
pub struct Error {
    inner: InternalError,
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for Error {}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::from(InternalError::from(err))
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::from(InternalError::from(err))
    }
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Self {
        Self { inner: err }
    }
}

/// Internal error.
#[derive(Debug)]
enum InternalError {
    MissingProfile,
    UnsupportedProfile,
    InvalidPacketType,
    InvalidFingerprint(InvalidFingerprint),
    OpenSslError(OpenSslError),
    IOError(io::Error),
}

impl Display for InternalError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::MissingProfile => f.write_str("no SRTP profile selected"),
            Self::UnsupportedProfile => f.write_str("unsupported SRTP profile"),
            Self::InvalidPacketType => f.write_str("invalid packet type"),
            Self::InvalidFingerprint(err) => write!(f, "invalid fingerprint: {}", err),
            Self::OpenSslError(err) => write!(f, "SSL error: {}", err),
            Self::IOError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for InternalError {}

impl From<InvalidFingerprint> for InternalError {
    fn from(err: InvalidFingerprint) -> Self {
        Self::InvalidFingerprint(err)
    }
}

impl From<openssl::error::Error> for InternalError {
    fn from(err: openssl::error::Error) -> Self {
        Self::OpenSslError(err.into())
    }
}

impl From<openssl::error::ErrorStack> for InternalError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::OpenSslError(err.into())
    }
}

impl From<openssl::ssl::Error> for InternalError {
    fn from(err: openssl::ssl::Error) -> Self {
        Self::OpenSslError(err.into())
    }
}

impl From<io::Error> for InternalError {
    fn from(err: io::Error) -> Self {
        Self::IOError(err)
    }
}

/// OpenSSL error.
#[derive(Debug)]
enum OpenSslError {
    Error(openssl::error::Error),
    ErrorStack(openssl::error::ErrorStack),
    SslError(openssl::ssl::Error),
}

impl Display for OpenSslError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Error(err) => Display::fmt(err, f),
            Self::ErrorStack(err) => Display::fmt(err, f),
            Self::SslError(err) => Display::fmt(err, f),
        }
    }
}

impl std::error::Error for OpenSslError {}

impl From<openssl::error::Error> for OpenSslError {
    fn from(err: openssl::error::Error) -> Self {
        Self::Error(err)
    }
}

impl From<openssl::error::ErrorStack> for OpenSslError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::ErrorStack(err)
    }
}

impl From<openssl::ssl::Error> for OpenSslError {
    fn from(err: openssl::ssl::Error) -> Self {
        Self::SslError(err)
    }
}

/// SRTP context builder.
pub struct SrtpContextBuilder {
    profiles: Vec<SrtpProfileId>,
}

impl SrtpContextBuilder {
    /// Create a new builder.
    fn new() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }

    /// Enable a given SRTP profile.
    ///
    /// Multiple SRTP profiles can be enabled by calling this method multiple
    /// times. The order in which you enable SRTP profiles matters. The first
    /// enabled profile will have the highest priority when negotiating session
    /// parameters with a remote peer.
    ///
    /// If you don't enable any profiles, the default profiles will be enabled:
    /// * `SRTP_AES128_CM_SHA1_80`
    /// * `SRTP_AES128_CM_SHA1_32`
    #[inline]
    pub fn profile(mut self, profile: SrtpProfileId) -> Self {
        self.profiles.push(profile);
        self
    }

    /// Create a new SRTP context from a given SSL context.
    ///
    /// # Panics
    /// This methods panics if the given SSL context does not contain any
    /// private key or certificate.
    pub fn with_ssl_context(mut self, context: SslContext) -> Result<SrtpContext, Error> {
        assert!(context.certificate().is_some());
        assert!(context.private_key().is_some());

        if self.profiles.is_empty() {
            self.profiles = vec![
                SrtpProfileId::SRTP_AES128_CM_SHA1_80,
                SrtpProfileId::SRTP_AES128_CM_SHA1_32,
            ];
        }

        let mut profiles = String::new();

        let mut iter = self.profiles.iter();

        if let Some(profile) = iter.next() {
            write!(profiles, "{}", profile).unwrap();
        }

        for profile in iter {
            write!(profiles, ":{}", profile).unwrap();
        }

        let res = SrtpContext {
            ssl_context: context,
            srtp_profiles: profiles,
        };

        Ok(res)
    }

    /// Create a new SRTP context from a given private key and a corresponding
    /// certificate.
    pub fn build<T>(self, key: &PKeyRef<T>, cert: &X509Ref) -> Result<SrtpContext, Error>
    where
        T: HasPrivate,
    {
        let mut ssl_ctx_builder = SslContext::builder(SslMethod::dtls())?;

        ssl_ctx_builder.set_certificate(cert)?;
        ssl_ctx_builder.set_private_key(key)?;

        self.with_ssl_context(ssl_ctx_builder.build())
    }

    /// Create a new SRTP context with a self-signed certificate from a given
    /// private key.
    pub fn self_signed<T>(self, key: &PKeyRef<T>) -> Result<SrtpContext, Error>
    where
        T: HasPrivate,
    {
        let now = unsafe { libc::time(ptr::null_mut()) };

        let not_before = Asn1Time::from_unix(now)?;

        let mut cert_builder = X509::builder()?;

        cert_builder.set_pubkey(key)?;
        cert_builder.set_not_before(&not_before)?;
        cert_builder.sign(key, MessageDigest::sha256())?;

        let public_cert = cert_builder.build();

        self.build(key, &public_cert)
    }
}

/// SRTP context.
pub struct SrtpContext {
    ssl_context: SslContext,
    srtp_profiles: String,
}

impl SrtpContext {
    /// Get an SRTP context builder.
    #[inline]
    pub fn builder() -> SrtpContextBuilder {
        SrtpContextBuilder::new()
    }

    /// Create a new SRTP context builder that will use a given private key,
    /// certificate and default parameters.
    #[inline]
    pub fn new<T>(key: &PKeyRef<T>, cert: &X509Ref) -> Result<Self, Error>
    where
        T: HasPrivate,
    {
        Self::builder().build(key, cert)
    }

    /// Create a new SRTP context with self signed certificate from a given key
    /// and use default parameters.
    #[inline]
    pub fn self_signed<T>(key: &PKeyRef<T>) -> Result<Self, Error>
    where
        T: HasPrivate,
    {
        Self::builder().self_signed(key)
    }

    /// Create a new SRTP context from a given SSL context and use default
    /// parameters.
    ///
    /// # Panics
    /// The method panics if the given context does not contain any private key
    /// or a certificate.
    #[inline]
    pub fn from_ssl_context(context: SslContext) -> Result<Self, Error> {
        Self::builder().with_ssl_context(context)
    }

    /// Get a certificate fingerprint.
    #[inline]
    pub fn certificate_fingerprint(
        &self,
        hash_function: HashFunction,
    ) -> Result<CertificateFingerprint, Error> {
        let cert = self.ssl_context.certificate();

        CertificateFingerprint::new(cert.unwrap(), hash_function)
    }

    /// Connect to a given SRTP "server" and check that the peer certificate
    /// matches a given fingerprint.
    pub fn connect_srtp<S>(
        &self,
        stream: S,
        peer_cert_fingerprint: &str,
    ) -> impl Future<Output = Result<SrtpStream<S>, Error>>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let connector = self.new_connector(peer_cert_fingerprint);

        async move { connector?.connect_srtp(stream).await }
    }

    /// Connect to a given SRTCP "server" and check that the peer certificate
    /// matches a given fingerprint.
    pub fn connect_srtcp<S>(
        &self,
        stream: S,
        peer_cert_fingerprint: &str,
    ) -> impl Future<Output = Result<SrtcpStream<S>, Error>>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let connector = self.new_connector(peer_cert_fingerprint);

        async move { connector?.connect_srtcp(stream).await }
    }

    /// Connect to a given muxed SRTP-SRTCP "server" and check that the peer
    /// certificate matches a given fingerprint.
    pub fn connect_muxed<S>(
        &self,
        stream: S,
        peer_cert_fingerprint: &str,
    ) -> impl Future<Output = Result<MuxedSrtpStream<S>, Error>>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let connector = self.new_connector(peer_cert_fingerprint);

        async move { connector?.connect_muxed(stream).await }
    }

    /// Accept connection from a given SRTP "client" and check that the peer
    /// certificate matches a given fingerprint.
    pub fn accept_srtp<S>(
        &self,
        stream: S,
        peer_cert_fingerprint: &str,
    ) -> impl Future<Output = Result<SrtpStream<S>, Error>>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let connector = self.new_connector(peer_cert_fingerprint);

        async move { connector?.accept_srtp(stream).await }
    }

    /// Accept connection from a given SRTCP "client" and check that the peer
    /// certificate matches a given fingerprint.
    pub fn accept_srtcp<S>(
        &self,
        stream: S,
        peer_cert_fingerprint: &str,
    ) -> impl Future<Output = Result<SrtcpStream<S>, Error>>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let connector = self.new_connector(peer_cert_fingerprint);

        async move { connector?.accept_srtcp(stream).await }
    }

    /// Accept connection from a given muxed SRTP-SRTCP "client" and check that
    /// the peer certificate matches a given fingerprint.
    pub fn accept_muxed<S>(
        &self,
        stream: S,
        peer_cert_fingerprint: &str,
    ) -> impl Future<Output = Result<MuxedSrtpStream<S>, Error>>
    where
        S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
    {
        let connector = self.new_connector(peer_cert_fingerprint);

        async move { connector?.accept_muxed(stream).await }
    }

    /// Create a new connector.
    fn new_connector(&self, peer_cert_fingerprint: &str) -> Result<Connector, InternalError> {
        let expected_fingerprint = CertificateFingerprint::from_str(peer_cert_fingerprint)?;

        let mut ssl = Ssl::new(&self.ssl_context)?;

        ssl.set_tlsext_use_srtp(&self.srtp_profiles)?;

        let verify_mode = SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT;

        ssl.set_verify_callback(verify_mode, move |_, store| {
            if let Some(chain) = store.chain() {
                if let Some(cert) = chain.get(0) {
                    if let Ok(success) = expected_fingerprint.verify(cert) {
                        return success;
                    }
                }
            }

            false
        });

        Ok(Connector::new(ssl))
    }
}
