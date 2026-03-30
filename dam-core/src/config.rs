use std::path::PathBuf;

/// DAM configuration with zero-config defaults.
pub struct DamConfig {
    pub port: u16,
    pub home_dir: PathBuf,
    pub verbose: bool,
    /// Hosts to blind-tunnel (skip TLS interception). Substring match.
    pub exclude_hosts: Vec<String>,
}

impl Default for DamConfig {
    fn default() -> Self {
        let home_dir = std::env::var("DAM_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_home().join(".dam"));
        Self {
            port: 7828,
            home_dir,
            verbose: false,
            exclude_hosts: Vec::new(),
        }
    }
}

impl DamConfig {
    pub fn vault_db_path(&self) -> PathBuf {
        self.home_dir.join("dam.db")
    }

    pub fn consent_db_path(&self) -> PathBuf {
        self.home_dir.join("consent.db")
    }

    pub fn log_db_path(&self) -> PathBuf {
        self.home_dir.join("log.db")
    }

    pub fn key_path(&self) -> PathBuf {
        self.home_dir.join("key")
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.home_dir.join("ca.pem")
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.home_dir.join("ca-key.pem")
    }

    /// Check if a host should be excluded from TLS interception (blind-tunneled).
    pub fn should_exclude(&self, host: &str) -> bool {
        self.exclude_hosts
            .iter()
            .any(|pat| host.contains(pat.as_str()))
    }

    /// Ensure the home directory exists.
    pub fn ensure_home(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.home_dir)
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_port() {
        let cfg = DamConfig::default();
        assert_eq!(cfg.port, 7828);
    }

    #[test]
    fn test_exclude_empty_list() {
        let cfg = DamConfig::default();
        assert!(!cfg.should_exclude("api.openai.com"));
    }

    #[test]
    fn test_exclude_match() {
        let mut cfg = DamConfig::default();
        cfg.exclude_hosts = vec!["pinned.example.com".into()];
        assert!(cfg.should_exclude("pinned.example.com"));
    }

    #[test]
    fn test_exclude_substring() {
        let mut cfg = DamConfig::default();
        cfg.exclude_hosts = vec!["internal.corp".into()];
        assert!(cfg.should_exclude("api.internal.corp.net"));
    }

    #[test]
    fn test_exclude_no_match() {
        let mut cfg = DamConfig::default();
        cfg.exclude_hosts = vec!["internal.corp".into()];
        assert!(!cfg.should_exclude("api.openai.com"));
    }

    #[test]
    fn test_paths() {
        let cfg = DamConfig {
            port: 7828,
            home_dir: PathBuf::from("/tmp/test-dam"),
            verbose: false,
            exclude_hosts: Vec::new(),
        };
        assert_eq!(cfg.vault_db_path(), PathBuf::from("/tmp/test-dam/dam.db"));
        assert_eq!(cfg.log_db_path(), PathBuf::from("/tmp/test-dam/log.db"));
        assert_eq!(cfg.key_path(), PathBuf::from("/tmp/test-dam/key"));
    }
}
