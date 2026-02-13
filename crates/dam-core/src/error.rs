use thiserror::Error;

pub type DamResult<T> = Result<T, DamError>;

#[derive(Debug, Error)]
pub enum DamError {
    #[error("invalid reference format: {0}")]
    InvalidReference(String),

    #[error("reference not found: {0}")]
    ReferenceNotFound(String),

    #[error("invalid PII type: {0}")]
    InvalidPiiType(String),

    #[error("consent denied: {reason}")]
    ConsentDenied { reason: String },

    #[error("vault error: {0}")]
    Vault(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for DamError {
    fn from(e: serde_json::Error) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<toml::de::Error> for DamError {
    fn from(e: toml::de::Error) -> Self {
        Self::Config(e.to_string())
    }
}
