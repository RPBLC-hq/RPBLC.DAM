use crate::audit::AuditLog;
use crate::encryption::EnvelopeCrypto;
use crate::schema::apply_schema;
use dam_core::{DamError, DamResult, PiiRef, PiiType};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

/// Metadata about a vault entry (no decrypted values).
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub ref_id: String,
    pub pii_type: PiiType,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub source: Option<String>,
    pub label: Option<String>,
}

/// The encrypted PII vault backed by SQLite.
pub struct VaultStore {
    conn: Mutex<Connection>,
    crypto: EnvelopeCrypto,
}

impl VaultStore {
    /// Open or create a vault at the given path.
    pub fn open(path: &Path, kek: [u8; 32]) -> DamResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path).map_err(|e| DamError::Database(e.to_string()))?;

        // Enable WAL mode for performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| DamError::Database(e.to_string()))?;

        apply_schema(&conn).map_err(|e| DamError::Database(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
            crypto: EnvelopeCrypto::new(kek),
        })
    }

    /// Store a PII value in the vault. Returns the generated reference.
    ///
    /// Performs deduplication: if the exact same value+type already exists, returns the existing ref.
    pub fn store_pii(
        &self,
        pii_type: PiiType,
        plaintext: &str,
        source: Option<&str>,
        label: Option<&str>,
    ) -> DamResult<PiiRef> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;

        // Check for duplicates: decrypt existing entries of same type and compare
        if let Some(existing_ref) = self.find_duplicate(&conn, pii_type, plaintext)? {
            return Ok(existing_ref);
        }

        // Generate a new reference
        let pii_ref = PiiRef::generate(pii_type);
        let encrypted = self.crypto.encrypt(plaintext.as_bytes())?;
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO entries (ref_id, pii_type, ciphertext, dek_enc, iv, created_at, source, label)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                pii_ref.key(),
                pii_type.to_string(),
                encrypted.ciphertext,
                encrypted.dek_encrypted,
                encrypted.iv,
                now,
                source,
                label,
            ],
        )
        .map_err(|e| DamError::Database(e.to_string()))?;

        // Audit the creation
        AuditLog::record(
            &conn,
            &pii_ref.key(),
            "system",
            "create",
            "create",
            true,
            None,
        )?;

        Ok(pii_ref)
    }

    /// Retrieve and decrypt a PII value by reference.
    pub fn retrieve_pii(&self, pii_ref: &PiiRef) -> DamResult<String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;

        let (ciphertext, dek_enc, iv): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT ciphertext, dek_enc, iv FROM entries WHERE ref_id = ?1",
                [pii_ref.key()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DamError::ReferenceNotFound(pii_ref.key()),
                _ => DamError::Database(e.to_string()),
            })?;

        let plaintext = self.crypto.decrypt(&ciphertext, &dek_enc, &iv)?;
        String::from_utf8(plaintext).map_err(|e| DamError::Encryption(e.to_string()))
    }

    /// List vault entries (metadata only, no decryption).
    pub fn list_entries(&self, type_filter: Option<PiiType>) -> DamResult<Vec<VaultEntry>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;

        let mut entries = Vec::new();

        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match type_filter {
            Some(t) => (
                "SELECT ref_id, pii_type, created_at, expires_at, source, label FROM entries WHERE pii_type = ?1 ORDER BY created_at DESC",
                vec![Box::new(t.to_string())],
            ),
            None => (
                "SELECT ref_id, pii_type, created_at, expires_at, source, label FROM entries ORDER BY created_at DESC",
                vec![],
            ),
        };

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| DamError::Database(e.to_string()))?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let pii_type_str: String = row.get(1)?;
                Ok((
                    row.get::<_, String>(0)?,
                    pii_type_str,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|e| DamError::Database(e.to_string()))?;

        for row in rows {
            let (ref_id, pii_type_str, created_at, expires_at, source, label) =
                row.map_err(|e| DamError::Database(e.to_string()))?;
            if let Ok(pii_type) = pii_type_str.parse::<PiiType>() {
                entries.push(VaultEntry {
                    ref_id,
                    pii_type,
                    created_at,
                    expires_at,
                    source,
                    label,
                });
            }
        }

        Ok(entries)
    }

    /// Delete a vault entry by reference.
    pub fn delete_entry(&self, pii_ref: &PiiRef) -> DamResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;

        let deleted = conn
            .execute("DELETE FROM entries WHERE ref_id = ?1", [pii_ref.key()])
            .map_err(|e| DamError::Database(e.to_string()))?;

        if deleted == 0 {
            return Err(DamError::ReferenceNotFound(pii_ref.key()));
        }

        // Also remove consent rules for this ref
        conn.execute("DELETE FROM consent WHERE ref_id = ?1", [pii_ref.key()])
            .map_err(|e| DamError::Database(e.to_string()))?;

        AuditLog::record(
            &conn,
            &pii_ref.key(),
            "system",
            "delete",
            "delete",
            true,
            None,
        )?;

        Ok(())
    }

    /// Get the total number of entries in the vault.
    pub fn entry_count(&self) -> DamResult<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .map_err(|e| DamError::Database(e.to_string()))?;
        Ok(count as usize)
    }

    /// Get entry counts grouped by PII type.
    pub fn entry_counts_by_type(&self) -> DamResult<Vec<(String, usize)>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT pii_type, COUNT(*) FROM entries GROUP BY pii_type ORDER BY COUNT(*) DESC",
            )
            .map_err(|e| DamError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| DamError::Database(e.to_string()))?;

        let mut counts = Vec::new();
        for row in rows {
            let (pii_type, count) = row.map_err(|e| DamError::Database(e.to_string()))?;
            counts.push((pii_type, count as usize));
        }
        Ok(counts)
    }

    /// Access the crypto engine (for resolving).
    pub fn crypto(&self) -> &EnvelopeCrypto {
        &self.crypto
    }

    /// Access the database connection (for consent/audit modules).
    pub fn conn(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Check for a duplicate entry of the same type and value.
    fn find_duplicate(
        &self,
        conn: &Connection,
        pii_type: PiiType,
        plaintext: &str,
    ) -> DamResult<Option<PiiRef>> {
        let mut stmt = conn
            .prepare("SELECT ref_id, ciphertext, dek_enc, iv FROM entries WHERE pii_type = ?1")
            .map_err(|e| DamError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([pii_type.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| DamError::Database(e.to_string()))?;

        for row in rows {
            let (ref_id, ciphertext, dek_enc, iv) =
                row.map_err(|e| DamError::Database(e.to_string()))?;

            if let Ok(decrypted) = self.crypto.decrypt(&ciphertext, &dek_enc, &iv)
                && let Ok(existing_value) = String::from_utf8(decrypted)
                && existing_value == plaintext
            {
                return Ok(Some(PiiRef::from_key(&ref_id)?));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_kek;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn test_vault() -> (VaultStore, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let kek = generate_kek();
        let store = VaultStore::open(&path, kek).unwrap();
        (store, path)
    }

    #[test]
    fn store_and_retrieve() {
        let (store, _path) = test_vault();
        let pii_ref = store
            .store_pii(PiiType::Email, "john@example.com", Some("test"), None)
            .unwrap();

        assert_eq!(pii_ref.pii_type, PiiType::Email);

        let value = store.retrieve_pii(&pii_ref).unwrap();
        assert_eq!(value, "john@example.com");
    }

    #[test]
    fn deduplication() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();
        assert_eq!(ref1.key(), ref2.key());
    }

    #[test]
    fn list_and_delete() {
        let (store, _path) = test_vault();
        store
            .store_pii(PiiType::Email, "a@b.com", None, None)
            .unwrap();
        store
            .store_pii(PiiType::Phone, "555-1234", None, None)
            .unwrap();

        let all = store.list_entries(None).unwrap();
        assert_eq!(all.len(), 2);

        let emails = store.list_entries(Some(PiiType::Email)).unwrap();
        assert_eq!(emails.len(), 1);

        let pii_ref = PiiRef::from_key(&emails[0].ref_id).unwrap();
        store.delete_entry(&pii_ref).unwrap();

        let all = store.list_entries(None).unwrap();
        assert_eq!(all.len(), 1);
    }
}
