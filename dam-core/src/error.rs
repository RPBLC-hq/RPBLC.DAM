pub type DamResult<T> = Result<T, DamError>;

#[derive(Debug, thiserror::Error)]
pub enum DamError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Db(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("token not found: {0}")]
    TokenNotFound(String),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("module '{name}' error: {message}")]
    Module {
        name: String,
        message: String,
    },

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_io() {
        let err = DamError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_error_display_db() {
        let err = DamError::Db("connection failed".into());
        assert!(err.to_string().contains("database error"));
    }

    #[test]
    fn test_error_display_encryption() {
        let err = DamError::Encryption("bad key".into());
        assert!(err.to_string().contains("encryption error"));
    }

    #[test]
    fn test_error_display_invalid_token() {
        let err = DamError::InvalidToken("bad:ref".into());
        assert!(err.to_string().contains("invalid token"));
    }

    #[test]
    fn test_error_display_token_not_found() {
        let err = DamError::TokenNotFound("email:abc12345".into());
        assert!(err.to_string().contains("token not found"));
    }

    #[test]
    fn test_error_display_module() {
        let err = DamError::Module {
            name: "detect-pii".into(),
            message: "regex panic".into(),
        };
        let s = err.to_string();
        assert!(s.contains("detect-pii"));
        assert!(s.contains("regex panic"));
    }

    #[test]
    fn test_error_display_proxy() {
        let err = DamError::Proxy("upstream unreachable".into());
        assert!(err.to_string().contains("proxy error"));
    }

    #[test]
    fn test_error_from_serde_json() {
        let result: Result<serde_json::Value, _> = serde_json::from_str("{bad}");
        let err: DamError = result.unwrap_err().into();
        assert!(err.to_string().contains("serialization error"));
    }
}
