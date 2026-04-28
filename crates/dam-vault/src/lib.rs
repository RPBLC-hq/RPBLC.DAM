use dam_core::{Reference, VaultReadError, VaultReader, VaultRecord, VaultWriteError, VaultWriter};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("system clock is before unix epoch")]
    Clock,
}

pub type VaultResult<T> = Result<T, VaultError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    pub key: String,
    pub value: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct Vault {
    conn: Mutex<Connection>,
}

impl Vault {
    pub fn open(path: impl AsRef<Path>) -> VaultResult<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> VaultResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> VaultResult<Self> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vault_entries (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            ",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn put(&self, key: &str, value: &str) -> VaultResult<()> {
        let now = now_unix_secs()?;
        let conn = self.conn.lock().expect("vault sqlite mutex poisoned");

        conn.execute(
            "
            INSERT INTO vault_entries (key, value, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?3)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            ",
            params![key, value, now],
        )?;

        Ok(())
    }

    pub fn get(&self, key: &str) -> VaultResult<Option<String>> {
        let conn = self.conn.lock().expect("vault sqlite mutex poisoned");

        let value = conn
            .query_row(
                "SELECT value FROM vault_entries WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;

        Ok(value)
    }

    pub fn delete(&self, key: &str) -> VaultResult<bool> {
        let conn = self.conn.lock().expect("vault sqlite mutex poisoned");
        let deleted = conn.execute("DELETE FROM vault_entries WHERE key = ?1", params![key])?;
        Ok(deleted > 0)
    }

    pub fn list(&self) -> VaultResult<Vec<VaultEntry>> {
        let conn = self.conn.lock().expect("vault sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "
            SELECT key, value, created_at, updated_at
            FROM vault_entries
            ORDER BY key ASC
            ",
        )?;

        let entries = stmt
            .query_map([], |row| {
                Ok(VaultEntry {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    pub fn count(&self) -> VaultResult<u64> {
        let conn = self.conn.lock().expect("vault sqlite mutex poisoned");
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM vault_entries", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

impl VaultWriter for Vault {
    fn write(&self, record: &VaultRecord) -> Result<(), VaultWriteError> {
        self.put(&record.reference.key(), &record.value)
            .map_err(|error| VaultWriteError::new(error.to_string()))
    }
}

impl VaultReader for Vault {
    fn read(&self, reference: &Reference) -> Result<Option<String>, VaultReadError> {
        self.get(&reference.key())
            .map_err(|error| VaultReadError::new(error.to_string()))
    }
}

fn now_unix_secs() -> VaultResult<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Clock)?;
    Ok(duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_value() {
        let vault = Vault::open_in_memory().unwrap();

        vault.put("email:alice", "alice@example.com").unwrap();

        assert_eq!(
            vault.get("email:alice").unwrap(),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn get_missing_key_returns_none() {
        let vault = Vault::open_in_memory().unwrap();

        assert_eq!(vault.get("missing").unwrap(), None);
    }

    #[test]
    fn put_existing_key_replaces_value_without_duplicate() {
        let vault = Vault::open_in_memory().unwrap();

        vault.put("email:alice", "old@example.com").unwrap();
        vault.put("email:alice", "new@example.com").unwrap();

        assert_eq!(vault.count().unwrap(), 1);
        assert_eq!(
            vault.get("email:alice").unwrap(),
            Some("new@example.com".to_string())
        );
    }

    #[test]
    fn delete_existing_key_returns_true() {
        let vault = Vault::open_in_memory().unwrap();

        vault.put("email:alice", "alice@example.com").unwrap();

        assert!(vault.delete("email:alice").unwrap());
        assert_eq!(vault.get("email:alice").unwrap(), None);
    }

    #[test]
    fn delete_missing_key_returns_false() {
        let vault = Vault::open_in_memory().unwrap();

        assert!(!vault.delete("missing").unwrap());
    }

    #[test]
    fn list_returns_entries_ordered_by_key() {
        let vault = Vault::open_in_memory().unwrap();

        vault.put("phone:bob", "+14155551234").unwrap();
        vault.put("email:alice", "alice@example.com").unwrap();

        let entries = vault.list().unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "email:alice");
        assert_eq!(entries[0].value, "alice@example.com");
        assert_eq!(entries[1].key, "phone:bob");
        assert_eq!(entries[1].value, "+14155551234");
    }

    #[test]
    fn entries_persist_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault.db");

        {
            let vault = Vault::open(&db_path).unwrap();
            vault.put("email:alice", "alice@example.com").unwrap();
        }

        let vault = Vault::open(&db_path).unwrap();
        assert_eq!(
            vault.get("email:alice").unwrap(),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn implements_vault_writer_contract() {
        let vault = Vault::open_in_memory().unwrap();
        let reference = dam_core::Reference {
            kind: dam_core::SensitiveType::Email,
            id: "7B2HkqFn9xR4mWpD3nYvKt".to_string(),
        };
        let record = dam_core::VaultRecord {
            reference: reference.clone(),
            kind: dam_core::SensitiveType::Email,
            value: "alice@example.com".to_string(),
        };

        vault.write(&record).unwrap();

        assert_eq!(
            vault.get(&reference.key()).unwrap(),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn implements_vault_reader_contract() {
        let vault = Vault::open_in_memory().unwrap();
        let reference = dam_core::Reference {
            kind: dam_core::SensitiveType::Email,
            id: "7B2HkqFn9xR4mWpD3nYvKt".to_string(),
        };
        vault.put(&reference.key(), "alice@example.com").unwrap();

        assert_eq!(
            vault.read(&reference).unwrap(),
            Some("alice@example.com".to_string())
        );

        let missing = dam_core::Reference {
            kind: dam_core::SensitiveType::Email,
            id: "2D5hXQp8nJ9kLmN4rT6vWy".to_string(),
        };
        assert_eq!(vault.read(&missing).unwrap(), None);
    }
}
