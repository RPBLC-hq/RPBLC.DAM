use thiserror::Error;

/// Alias for `Result<T, DamError>`.
pub type DamResult<T> = Result<T, DamError>;

/// Unified error type for all DAM operations.
#[derive(Debug, Error)]
pub enum DamError {
    /// A PII reference string could not be parsed (e.g. missing colon or unknown type tag).
    #[error("invalid reference format: {0}")]
    InvalidReference(String),

    /// The requested reference does not exist in the vault.
    #[error("reference not found: {0}")]
    ReferenceNotFound(String),

    /// A string could not be parsed as a known [`PiiType`](crate::PiiType).
    #[error("invalid PII type: {0}")]
    InvalidPiiType(String),

    /// Resolution was denied because no matching consent rule exists.
    #[error("consent denied: {reason}")]
    ConsentDenied { reason: String },

    /// A vault-level error (e.g. mutex poisoning).
    #[error("vault error: {0}")]
    Vault(String),

    /// An AES-256-GCM encryption or decryption failure.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// OS keychain access failed (DPAPI / macOS Keychain / libsecret).
    #[error("keychain error: {0}")]
    Keychain(String),

    /// SQLite operation failed.
    #[error("database error: {0}")]
    Database(String),

    /// Configuration loading or parsing failed.
    #[error("config error: {0}")]
    Config(String),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for errors that don't fit other variants.
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
