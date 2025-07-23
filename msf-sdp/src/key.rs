use std::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

/// Encryption key field.
///
/// # Note
/// This field is considered obsolete by RFC 8866.
#[derive(Clone)]
pub struct EncryptionKey {
    method: String,
    key: Option<String>,
}

impl EncryptionKey {
    /// Create a new method-only encryption key field.
    #[inline]
    pub fn new<M>(method: M) -> Self
    where
        M: ToString,
    {
        Self {
            method: method.to_string(),
            key: None,
        }
    }

    /// Create a new encryption key field.
    #[inline]
    pub fn new_with_key<M, K>(method: M, key: K) -> Self
    where
        M: ToString,
        K: ToString,
    {
        Self {
            method: method.to_string(),
            key: Some(key.to_string()),
        }
    }

    /// Get the method for obtaining the encryption key.
    #[inline]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Get the encryption key (if any).
    #[inline]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl Display for EncryptionKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.method)?;

        if let Some(k) = self.key.as_ref() {
            write!(f, ":{k}")?;
        }

        Ok(())
    }
}

impl FromStr for EncryptionKey {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (method, key) = if let Some(colon) = s.find(':') {
            let (m, r) = s.split_at(colon);

            let k = &r[1..];

            (m.to_string(), Some(k.to_string()))
        } else {
            (s.to_string(), None)
        };

        let res = Self { method, key };

        Ok(res)
    }
}
