use crate::audit::AuditLog;
use crate::encryption::EnvelopeCrypto;
use crate::schema::apply_schema;
use dam_core::{DamError, DamResult, PiiRef, PiiType};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

/// Normalize PII values for consistent deduplication.
/// Strips spaces and dashes. Uppercases types that contain letters.
fn normalize_pii(pii_type: PiiType, value: &str) -> String {
    match pii_type {
        PiiType::CreditCard
        | PiiType::Phone
        | PiiType::Sin
        | PiiType::NhsNumber
        | PiiType::TaxId => value.chars().filter(|c| *c != ' ' && *c != '-').collect(),
        PiiType::Iban
        | PiiType::PostalCode
        | PiiType::NiNumber
        | PiiType::NationalId
        | PiiType::VatNumber
        | PiiType::SwiftBic
        | PiiType::DriversLicense
        | PiiType::InseeNir => value
            .chars()
            .filter(|c| *c != ' ' && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
        _ => value.to_string(),
    }
}

/// Metadata about a vault entry (no decrypted values).
///
/// Returned by [`VaultStore::list_entries`]. The actual PII value is only
/// available via [`VaultStore::retrieve_pii`].
#[derive(Debug, Clone)]
pub struct VaultEntry {
    /// Reference key in `type:hex` form (e.g. `email:a3f71bc9`).
    pub ref_id: String,
    /// Category of PII stored.
    pub pii_type: PiiType,
    /// Unix timestamp when the entry was created.
    pub created_at: i64,
    /// Optional Unix timestamp for automatic expiration.
    pub expires_at: Option<i64>,
    /// Where the PII was detected (e.g. `"http-proxy"`, `"mcp"`).
    pub source: Option<String>,
    /// Optional human-readable label.
    pub label: Option<String>,
}

/// The encrypted PII vault backed by SQLite.
///
/// Thread-safe: the database connection is protected by a [`Mutex`].
/// All values are encrypted with envelope encryption via [`EnvelopeCrypto`].
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
    /// Values are normalized before storage (e.g., credit cards and phones have spaces/dashes removed).
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

        // Normalize the value for consistent deduplication and storage
        let normalized = normalize_pii(pii_type, plaintext);

        // Check for duplicates: decrypt existing entries of same type and compare
        if let Some(existing_ref) = self.find_duplicate(&conn, pii_type, &normalized)? {
            return Ok(existing_ref);
        }

        // Generate a new reference with collision retry
        let encrypted = self.crypto.encrypt(normalized.as_bytes())?;
        let now = chrono::Utc::now().timestamp();

        const MAX_RETRIES: usize = 5;
        let mut pii_ref = PiiRef::generate(pii_type);

        for attempt in 0..MAX_RETRIES {
            match conn.execute(
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
            ) {
                Ok(_) => break,
                Err(rusqlite::Error::SqliteFailure(err, msg))
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    // Only retry on PRIMARY KEY or UNIQUE constraint violations —
                    // regenerating the ref_id can fix those. Other constraint types
                    // (NOT NULL, CHECK, FK) indicate a real bug and should fail immediately.
                    if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                        || err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    {
                        if attempt == MAX_RETRIES - 1 {
                            return Err(DamError::Database(
                                "ref ID collision: max retries exhausted".to_string(),
                            ));
                        }
                        pii_ref = PiiRef::generate(pii_type);
                    } else {
                        return Err(DamError::Database(format!(
                            "constraint violation (code {}): {}",
                            err.extended_code,
                            msg.as_deref().unwrap_or("unknown"),
                        )));
                    }
                }
                Err(e) => return Err(DamError::Database(e.to_string())),
            }
        }

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

    /// Delete all entries and their associated consent rules from the vault.
    pub fn clear_all(&self) -> DamResult<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DamError::Vault(e.to_string()))?;

        let deleted: usize = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .map_err(|e| DamError::Database(e.to_string()))?;

        conn.execute_batch("DELETE FROM consent; DELETE FROM entries;")
            .map_err(|e| DamError::Database(e.to_string()))?;

        AuditLog::record(&conn, "*", "system", "clear", "clear_all", true, None)?;

        Ok(deleted)
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
    fn credit_card_normalization_dedup() {
        let (store, _path) = test_vault();
        // Same card number in different formats should deduplicate
        let ref1 = store
            .store_pii(PiiType::CreditCard, "4111 1111 1111 1111", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::CreditCard, "4111-1111-1111-1111", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::CreditCard, "4111111111111111", None, None)
            .unwrap();

        // All three should return the same reference
        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        // Retrieve should return normalized value
        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "4111111111111111");
    }

    #[test]
    fn phone_normalization_dedup() {
        let (store, _path) = test_vault();
        // Same phone number in different formats should deduplicate
        let ref1 = store
            .store_pii(PiiType::Phone, "555-867-5309", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::Phone, "555 867 5309", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::Phone, "5558675309", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "5558675309");
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

    // --- Edge cases ---

    #[test]
    fn retrieve_nonexistent_ref() {
        let (store, _path) = test_vault();
        let fake_ref = PiiRef::generate(PiiType::Email);
        let result = store.retrieve_pii(&fake_ref);
        assert!(result.is_err());
        match result {
            Err(DamError::ReferenceNotFound(_)) => {}
            other => panic!("expected ReferenceNotFound, got {:?}", other),
        }
    }

    #[test]
    fn delete_nonexistent_ref() {
        let (store, _path) = test_vault();
        let fake_ref = PiiRef::generate(PiiType::Email);
        let result = store.delete_entry(&fake_ref);
        assert!(result.is_err());
        match result {
            Err(DamError::ReferenceNotFound(_)) => {}
            other => panic!("expected ReferenceNotFound, got {:?}", other),
        }
    }

    #[test]
    fn store_empty_value() {
        let (store, _path) = test_vault();
        let pii_ref = store.store_pii(PiiType::Custom, "", None, None).unwrap();
        let value = store.retrieve_pii(&pii_ref).unwrap();
        assert_eq!(value, "");
    }

    #[test]
    fn retrieve_after_delete_fails() {
        let (store, _path) = test_vault();
        let pii_ref = store
            .store_pii(PiiType::Email, "gone@test.com", None, None)
            .unwrap();
        store.delete_entry(&pii_ref).unwrap();

        let result = store.retrieve_pii(&pii_ref);
        assert!(result.is_err());
        match result {
            Err(DamError::ReferenceNotFound(_)) => {}
            other => panic!("expected ReferenceNotFound, got {:?}", other),
        }
    }

    #[test]
    fn dedup_different_types_same_value() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::Custom, "test@test.com", None, None)
            .unwrap();
        // Same value but different type — should NOT deduplicate
        assert_ne!(ref1.key(), ref2.key());
    }

    #[test]
    fn entry_count() {
        let (store, _path) = test_vault();
        assert_eq!(store.entry_count().unwrap(), 0);

        store
            .store_pii(PiiType::Email, "a@b.com", None, None)
            .unwrap();
        assert_eq!(store.entry_count().unwrap(), 1);

        store
            .store_pii(PiiType::Phone, "555-0000", None, None)
            .unwrap();
        assert_eq!(store.entry_count().unwrap(), 2);
    }

    #[test]
    fn list_entries_empty_vault() {
        let (store, _path) = test_vault();
        let entries = store.list_entries(None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn iban_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::Iban, "DE89 3704 0044 0532 0130 00", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::Iban, "de89370400440532013000", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::Iban, "DE89-3704-0044-0532-0130-00", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "DE89370400440532013000");
    }

    #[test]
    fn sin_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::Sin, "130-692-544", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::Sin, "130 692 544", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::Sin, "130692544", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "130692544");
    }

    #[test]
    fn postal_code_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::PostalCode, "K1A 0B1", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::PostalCode, "k1a 0b1", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::PostalCode, "k1a0b1", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "K1A0B1");
    }

    #[test]
    fn ni_number_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::NiNumber, "AB 123 456 C", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::NiNumber, "AB-123-456-C", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::NiNumber, "AB123456C", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "AB123456C");
    }

    #[test]
    fn vat_number_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::VatNumber, "de 123 456 789", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::VatNumber, "DE123456789", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "DE123456789");
    }

    #[test]
    fn swift_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::SwiftBic, "deut de ff", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::SwiftBic, "DEUTDEFF", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "DEUTDEFF");
    }

    #[test]
    fn nhs_normalization_dedup() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::NhsNumber, "943 476 5919", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::NhsNumber, "943-476-5919", None, None)
            .unwrap();
        let ref3 = store
            .store_pii(PiiType::NhsNumber, "9434765919", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());
        assert_eq!(ref2.key(), ref3.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "9434765919");
    }

    #[test]
    fn drivers_license_normalization_uppercase() {
        let (store, _path) = test_vault();
        let ref1 = store
            .store_pii(PiiType::DriversLicense, "morga657054sm9ij", None, None)
            .unwrap();
        let ref2 = store
            .store_pii(PiiType::DriversLicense, "MORGA657054SM9IJ", None, None)
            .unwrap();

        assert_eq!(ref1.key(), ref2.key());

        let value = store.retrieve_pii(&ref1).unwrap();
        assert_eq!(value, "MORGA657054SM9IJ");
    }

    #[test]
    fn non_unique_constraint_violation_fails_immediately() {
        // Verify that non-PK/UNIQUE constraint violations (e.g. NOT NULL)
        // are surfaced as errors rather than silently retried.
        let (store, _path) = test_vault();
        let conn = store.conn.lock().unwrap();

        // Insert directly with NULL in a NOT NULL column to trigger a
        // SQLITE_CONSTRAINT_NOTNULL error (extended code 1299).
        let result = conn.execute(
            "INSERT INTO entries (ref_id, pii_type, ciphertext, dek_enc, iv, created_at)
             VALUES (?1, NULL, ?2, ?3, ?4, ?5)",
            rusqlite::params!["test:0001", b"ct", b"dek", b"iv", 0i64],
        );

        match result {
            Err(rusqlite::Error::SqliteFailure(err, _)) => {
                assert_eq!(err.code, rusqlite::ErrorCode::ConstraintViolation);
                // NOT NULL extended code — must NOT be treated as a collision
                assert_ne!(
                    err.extended_code,
                    rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                );
                assert_ne!(err.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE);
            }
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }
}
