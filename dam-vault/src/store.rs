use crate::encrypt::{EncryptedEntry, EnvelopeCrypto};
use dam_core::{DamError, SensitiveDataType, Token};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata for a vault entry (no decryption performed).
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub ref_id: String,
    pub data_type: String,
    pub created_at: i64,
}

/// SQLite-backed encrypted vault storage.
///
/// All access is serialized through a `Mutex<Connection>`.
/// The database uses WAL mode for better concurrent read performance.
pub struct VaultStore {
    conn: Mutex<Connection>,
    crypto: EnvelopeCrypto,
}

impl VaultStore {
    /// Open (or create) a vault database at `db_path`.
    ///
    /// Applies the schema and enables WAL mode.
    pub fn open(db_path: &Path, kek: [u8; 32]) -> Result<Self, DamError> {
        let conn = Connection::open(db_path)
            .map_err(|e| DamError::Db(format!("open: {e}")))?;

        // Enable WAL mode
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| DamError::Db(format!("WAL mode: {e}")))?;

        // Create schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                ref_id          TEXT PRIMARY KEY,
                data_type       TEXT NOT NULL,
                ciphertext      BLOB NOT NULL,
                dek_enc         BLOB NOT NULL,
                iv              BLOB NOT NULL,
                normalized_hash TEXT NOT NULL,
                created_at      INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries(normalized_hash);
            CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(data_type);",
        )
        .map_err(|e| DamError::Db(format!("schema: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
            crypto: EnvelopeCrypto::new(kek),
        })
    }

    /// Store a sensitive value, returning a token.
    ///
    /// Deduplication: if the same normalized value+type already exists,
    /// the existing token is returned without creating a new entry.
    pub fn store(
        &self,
        data_type: SensitiveDataType,
        plaintext: &str,
    ) -> Result<Token, DamError> {
        let normalized = normalize(data_type, plaintext);
        let hash = compute_hash(data_type, &normalized);

        let conn = self.conn.lock().map_err(|e| DamError::Db(format!("lock: {e}")))?;

        // Check for duplicate
        let existing: Option<String> = conn
            .query_row(
                "SELECT ref_id FROM entries WHERE normalized_hash = ?1",
                [&hash],
                |row| row.get(0),
            )
            .ok();

        if let Some(ref_id) = existing {
            return Token::from_key(&ref_id)
                .map_err(|_| DamError::Db(format!("corrupt ref_id in DB: {ref_id}")));
        }

        // Encrypt
        let entry = self.crypto.encrypt(plaintext.as_bytes())?;

        // Generate token
        let token = Token::generate(data_type);
        let ref_id = token.key();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO entries (ref_id, data_type, ciphertext, dek_enc, iv, normalized_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                ref_id,
                data_type.tag(),
                entry.ciphertext,
                entry.dek_encrypted,
                entry.iv,
                hash,
                now,
            ],
        )
        .map_err(|e| DamError::Db(format!("insert: {e}")))?;

        Ok(token)
    }

    /// Retrieve and decrypt a value by its token.
    pub fn retrieve(&self, token: &Token) -> Result<String, DamError> {
        let ref_id = token.key();
        let conn = self.conn.lock().map_err(|e| DamError::Db(format!("lock: {e}")))?;

        let (ciphertext, dek_enc, iv): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT ciphertext, dek_enc, iv FROM entries WHERE ref_id = ?1",
                [&ref_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| DamError::TokenNotFound(ref_id.clone()))?;

        let entry = EncryptedEntry {
            ciphertext,
            dek_encrypted: dek_enc,
            iv,
        };

        let plaintext_bytes = self.crypto.decrypt(&entry)?;
        String::from_utf8(plaintext_bytes)
            .map_err(|e| DamError::Encryption(format!("UTF-8 decode: {e}")))
    }

    /// Delete a vault entry by its token.
    pub fn delete(&self, token: &Token) -> Result<(), DamError> {
        let ref_id = token.key();
        let conn = self.conn.lock().map_err(|e| DamError::Db(format!("lock: {e}")))?;

        let rows = conn
            .execute("DELETE FROM entries WHERE ref_id = ?1", [&ref_id])
            .map_err(|e| DamError::Db(format!("delete: {e}")))?;

        if rows == 0 {
            return Err(DamError::TokenNotFound(ref_id));
        }

        Ok(())
    }

    /// List vault entry metadata, optionally filtered by data type.
    ///
    /// No decryption is performed.
    pub fn list(&self, filter_type: Option<SensitiveDataType>) -> Result<Vec<VaultEntry>, DamError> {
        let conn = self.conn.lock().map_err(|e| DamError::Db(format!("lock: {e}")))?;

        let mut entries = Vec::new();

        match filter_type {
            Some(dt) => {
                let mut stmt = conn
                    .prepare("SELECT ref_id, data_type, created_at FROM entries WHERE data_type = ?1 ORDER BY created_at DESC")
                    .map_err(|e| DamError::Db(format!("prepare: {e}")))?;
                let rows = stmt
                    .query_map([dt.tag()], |row| {
                        Ok(VaultEntry {
                            ref_id: row.get(0)?,
                            data_type: row.get(1)?,
                            created_at: row.get(2)?,
                        })
                    })
                    .map_err(|e| DamError::Db(format!("query: {e}")))?;

                for row in rows {
                    entries.push(row.map_err(|e| DamError::Db(format!("row: {e}")))?);
                }
            }
            None => {
                let mut stmt = conn
                    .prepare("SELECT ref_id, data_type, created_at FROM entries ORDER BY created_at DESC")
                    .map_err(|e| DamError::Db(format!("prepare: {e}")))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(VaultEntry {
                            ref_id: row.get(0)?,
                            data_type: row.get(1)?,
                            created_at: row.get(2)?,
                        })
                    })
                    .map_err(|e| DamError::Db(format!("query: {e}")))?;

                for row in rows {
                    entries.push(row.map_err(|e| DamError::Db(format!("row: {e}")))?);
                }
            }
        }

        Ok(entries)
    }

    /// Count the total number of entries in the vault.
    pub fn count(&self) -> Result<usize, DamError> {
        let conn = self.conn.lock().map_err(|e| DamError::Db(format!("lock: {e}")))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .map_err(|e| DamError::Db(format!("count: {e}")))?;

        Ok(count as usize)
    }

    /// Check if a ref_id already exists in the store.
    pub fn exists(&self, ref_id: &str) -> Result<bool, DamError> {
        let conn = self.conn.lock().map_err(|e| DamError::Db(format!("lock: {e}")))?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE ref_id = ?1",
                [ref_id],
                |row| row.get(0),
            )
            .map_err(|e| DamError::Db(format!("exists: {e}")))?;

        Ok(count > 0)
    }
}

/// Normalize a value based on its data type.
///
/// - CreditCard / Phone / Iban: strip spaces and dashes.
/// - Everything else: return as-is.
fn normalize(data_type: SensitiveDataType, value: &str) -> String {
    match data_type {
        SensitiveDataType::CreditCard | SensitiveDataType::Phone | SensitiveDataType::Iban => {
            value.chars().filter(|c| *c != ' ' && *c != '-').collect()
        }
        _ => value.to_string(),
    }
}

/// Compute a deduplication hash: `SHA256(data_type_tag + ":" + normalized_value)`.
fn compute_hash(data_type: SensitiveDataType, normalized: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data_type.tag().as_bytes());
    hasher.update(b":");
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::generate_kek;

    fn temp_store() -> (tempfile::TempDir, VaultStore) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault_test.db");
        let kek = generate_kek();
        let store = VaultStore::open(&db_path, kek).unwrap();
        (dir, store)
    }

    #[test]
    fn test_store_and_retrieve() {
        let (_dir, store) = temp_store();

        let token = store.store(SensitiveDataType::Email, "alice@example.com").unwrap();
        assert_eq!(token.data_type, SensitiveDataType::Email);

        let value = store.retrieve(&token).unwrap();
        assert_eq!(value, "alice@example.com");
    }

    #[test]
    fn test_store_dedup_returns_same_token() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::Email, "alice@example.com").unwrap();
        let t2 = store.store(SensitiveDataType::Email, "alice@example.com").unwrap();

        assert_eq!(t1.key(), t2.key());
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_dedup_different_types_not_deduped() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::Email, "test@test.com").unwrap();
        let t2 = store.store(SensitiveDataType::Name, "test@test.com").unwrap();

        assert_ne!(t1.key(), t2.key());
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_normalize_credit_card() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::CreditCard, "4111-1111-1111-1111").unwrap();
        let t2 = store.store(SensitiveDataType::CreditCard, "4111 1111 1111 1111").unwrap();

        // Both should dedup to the same entry
        assert_eq!(t1.key(), t2.key());
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_normalize_phone() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::Phone, "+1-555-123-4567").unwrap();
        let t2 = store.store(SensitiveDataType::Phone, "+1 555 123 4567").unwrap();

        assert_eq!(t1.key(), t2.key());
    }

    #[test]
    fn test_normalize_iban() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::Iban, "DE89 3704 0044 0532 0130 00").unwrap();
        let t2 = store.store(SensitiveDataType::Iban, "DE89370400440532013000").unwrap();

        assert_eq!(t1.key(), t2.key());
    }

    #[test]
    fn test_delete() {
        let (_dir, store) = temp_store();

        let token = store.store(SensitiveDataType::Email, "del@test.com").unwrap();
        assert_eq!(store.count().unwrap(), 1);

        store.delete(&token).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_delete_not_found() {
        let (_dir, store) = temp_store();

        let token = Token::generate(SensitiveDataType::Email);
        let result = store.delete(&token);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("token not found"));
    }

    #[test]
    fn test_retrieve_not_found() {
        let (_dir, store) = temp_store();

        let token = Token::generate(SensitiveDataType::Email);
        let result = store.retrieve(&token);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("token not found"));
    }

    #[test]
    fn test_list_all() {
        let (_dir, store) = temp_store();

        store.store(SensitiveDataType::Email, "a@test.com").unwrap();
        store.store(SensitiveDataType::Phone, "+15551234567").unwrap();
        store.store(SensitiveDataType::Email, "b@test.com").unwrap();

        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_list_filtered() {
        let (_dir, store) = temp_store();

        store.store(SensitiveDataType::Email, "a@test.com").unwrap();
        store.store(SensitiveDataType::Phone, "+15551234567").unwrap();
        store.store(SensitiveDataType::Email, "b@test.com").unwrap();

        let emails = store.list(Some(SensitiveDataType::Email)).unwrap();
        assert_eq!(emails.len(), 2);

        let phones = store.list(Some(SensitiveDataType::Phone)).unwrap();
        assert_eq!(phones.len(), 1);

        let ssns = store.list(Some(SensitiveDataType::Ssn)).unwrap();
        assert!(ssns.is_empty());
    }

    #[test]
    fn test_count_empty() {
        let (_dir, store) = temp_store();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_count_after_inserts() {
        let (_dir, store) = temp_store();

        store.store(SensitiveDataType::Email, "a@test.com").unwrap();
        store.store(SensitiveDataType::Email, "b@test.com").unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_exists() {
        let (_dir, store) = temp_store();

        let token = store.store(SensitiveDataType::Email, "e@test.com").unwrap();
        assert!(store.exists(&token.key()).unwrap());
        assert!(!store.exists("email:00000000").unwrap());
    }

    #[test]
    fn test_store_and_retrieve_utf8() {
        let (_dir, store) = temp_store();

        let value = "Ren\u{00e9} M\u{00fc}ller";
        let token = store.store(SensitiveDataType::Name, value).unwrap();
        let retrieved = store.retrieve(&token).unwrap();
        assert_eq!(retrieved, value);
    }

    #[test]
    fn test_multiple_stores_different_values() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::Email, "a@test.com").unwrap();
        let t2 = store.store(SensitiveDataType::Email, "b@test.com").unwrap();

        assert_ne!(t1.key(), t2.key());
        assert_eq!(store.retrieve(&t1).unwrap(), "a@test.com");
        assert_eq!(store.retrieve(&t2).unwrap(), "b@test.com");
    }

    #[test]
    fn test_vault_entry_metadata() {
        let (_dir, store) = temp_store();

        let token = store.store(SensitiveDataType::Email, "meta@test.com").unwrap();
        let entries = store.list(None).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ref_id, token.key());
        assert_eq!(entries[0].data_type, "email");
        assert!(entries[0].created_at > 0);
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = compute_hash(SensitiveDataType::Email, "test@test.com");
        let h2 = compute_hash(SensitiveDataType::Email, "test@test.com");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_for_different_types() {
        let h1 = compute_hash(SensitiveDataType::Email, "test");
        let h2 = compute_hash(SensitiveDataType::Name, "test");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_normalize_no_change_for_email() {
        assert_eq!(normalize(SensitiveDataType::Email, "a@b.com"), "a@b.com");
    }

    #[test]
    fn test_normalize_strips_for_cc() {
        assert_eq!(
            normalize(SensitiveDataType::CreditCard, "4111-1111 1111-1111"),
            "4111111111111111"
        );
    }

    #[test]
    fn test_delete_then_store_same_value() {
        let (_dir, store) = temp_store();

        let t1 = store.store(SensitiveDataType::Email, "reuse@test.com").unwrap();
        store.delete(&t1).unwrap();

        // Storing again should work (no dedup because entry was deleted)
        let t2 = store.store(SensitiveDataType::Email, "reuse@test.com").unwrap();
        // New token generated (different ID)
        assert_ne!(t1.key(), t2.key());
        assert_eq!(store.retrieve(&t2).unwrap(), "reuse@test.com");
    }
}
