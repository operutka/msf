/// ICE credentials.
#[derive(Clone)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// Create random credentials.
    pub fn random() -> Self {
        Self {
            username: crate::utils::random_ice_string(4),
            password: crate::utils::random_ice_string(22),
        }
    }

    /// Get the username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password.
    pub fn password(&self) -> &str {
        &self.password
    }
}
