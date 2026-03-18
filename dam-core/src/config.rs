use std::path::PathBuf;

/// DAM configuration with zero-config defaults.
pub struct DamConfig {
    pub port: u16,
    pub home_dir: PathBuf,
    pub verbose: bool,
}

impl Default for DamConfig {
    fn default() -> Self {
        let home_dir = std::env::var("DAM_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs_home().join(".dam")
            });
        Self {
            port: 7828,
            home_dir,
            verbose: false,
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
    fn test_paths() {
        let cfg = DamConfig {
            port: 7828,
            home_dir: PathBuf::from("/tmp/test-dam"),
            verbose: false,
        };
        assert_eq!(cfg.vault_db_path(), PathBuf::from("/tmp/test-dam/dam.db"));
        assert_eq!(cfg.log_db_path(), PathBuf::from("/tmp/test-dam/log.db"));
        assert_eq!(cfg.key_path(), PathBuf::from("/tmp/test-dam/key"));
    }
}
