use dam_core::{DamError, DamResult};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// An entry in the audit trail.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub ref_id: String,
    pub accessor: String,
    pub purpose: String,
    pub action: String,
    pub granted: bool,
    pub ts: i64,
    pub detail: Option<String>,
    pub prev_hash: Option<String>,
}

/// Hash-chained audit log for all vault operations.
pub struct AuditLog;

impl AuditLog {
    /// Record an audit entry with hash chaining.
    pub fn record(
        conn: &Connection,
        ref_id: &str,
        accessor: &str,
        purpose: &str,
        action: &str,
        granted: bool,
        detail: Option<&str>,
    ) -> DamResult<()> {
        let now = chrono::Utc::now().timestamp();

        // Get the hash of the previous entry for chain
        let prev_hash: Option<String> = conn
            .query_row(
                "SELECT id, ref_id, accessor, purpose, action, granted, ts, prev_hash
                 FROM audit ORDER BY id DESC LIMIT 1",
                [],
                |row| {
                    let id: i64 = row.get(0)?;
                    let r: String = row.get(1)?;
                    let a: String = row.get(2)?;
                    let p: String = row.get(3)?;
                    let act: String = row.get(4)?;
                    let g: bool = row.get(5)?;
                    let t: i64 = row.get(6)?;
                    let ph: Option<String> = row.get(7)?;
                    Ok(Some(Self::compute_hash(
                        id,
                        &r,
                        &a,
                        &p,
                        &act,
                        g,
                        t,
                        ph.as_deref(),
                    )))
                },
            )
            .unwrap_or(None);

        conn.execute(
            "INSERT INTO audit (ref_id, accessor, purpose, action, granted, ts, detail, prev_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                ref_id, accessor, purpose, action, granted, now, detail, prev_hash
            ],
        )
        .map_err(|e| DamError::Database(e.to_string()))?;

        Ok(())
    }

    /// Record an audit entry using a mutex-wrapped connection.
    pub fn record_locked(
        conn: &Mutex<Connection>,
        ref_id: &str,
        accessor: &str,
        purpose: &str,
        action: &str,
        granted: bool,
        detail: Option<&str>,
    ) -> DamResult<()> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;
        Self::record(&conn, ref_id, accessor, purpose, action, granted, detail)
    }

    /// Query the audit trail, optionally filtered by ref_id.
    pub fn query(
        conn: &Mutex<Connection>,
        ref_filter: Option<&str>,
        limit: usize,
    ) -> DamResult<Vec<AuditEntry>> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;
        let mut entries = Vec::new();

        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match ref_filter {
            Some(ref_id) => (
                "SELECT id, ref_id, accessor, purpose, action, granted, ts, detail, prev_hash
                 FROM audit WHERE ref_id = ?1 ORDER BY id DESC LIMIT ?2",
                vec![
                    Box::new(ref_id.to_string()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(limit as i64),
                ],
            ),
            None => (
                "SELECT id, ref_id, accessor, purpose, action, granted, ts, detail, prev_hash
                 FROM audit ORDER BY id DESC LIMIT ?1",
                vec![Box::new(limit as i64) as Box<dyn rusqlite::types::ToSql>],
            ),
        };

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| DamError::Database(e.to_string()))?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    ref_id: row.get(1)?,
                    accessor: row.get(2)?,
                    purpose: row.get(3)?,
                    action: row.get(4)?,
                    granted: row.get(5)?,
                    ts: row.get(6)?,
                    detail: row.get(7)?,
                    prev_hash: row.get(8)?,
                })
            })
            .map_err(|e| DamError::Database(e.to_string()))?;

        for row in rows {
            entries.push(row.map_err(|e| DamError::Database(e.to_string()))?);
        }

        Ok(entries)
    }

    /// Verify the integrity of the hash chain.
    /// Returns (valid_count, total_count, first_broken_id).
    pub fn verify_chain(conn: &Mutex<Connection>) -> DamResult<(usize, usize, Option<i64>)> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, ref_id, accessor, purpose, action, granted, ts, prev_hash
                 FROM audit ORDER BY id ASC",
            )
            .map_err(|e| DamError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })
            .map_err(|e| DamError::Database(e.to_string()))?;

        let mut total = 0usize;
        let mut valid = 0usize;
        type AuditRow = (
            i64,
            String,
            String,
            String,
            String,
            bool,
            i64,
            Option<String>,
        );
        let mut prev_entry: Option<AuditRow> = None;
        let mut first_broken: Option<i64> = None;

        for row in rows {
            let entry = row.map_err(|e| DamError::Database(e.to_string()))?;
            total += 1;

            match (&prev_entry, &entry.7) {
                (None, None) => {
                    // First entry, no prev_hash expected
                    valid += 1;
                }
                (Some(prev), Some(stored_hash)) => {
                    let expected_hash = Self::compute_hash(
                        prev.0,
                        &prev.1,
                        &prev.2,
                        &prev.3,
                        &prev.4,
                        prev.5,
                        prev.6,
                        prev.7.as_deref(),
                    );
                    if expected_hash == *stored_hash {
                        valid += 1;
                    } else if first_broken.is_none() {
                        first_broken = Some(entry.0);
                    }
                }
                (None, Some(_)) => {
                    // Has prev_hash but is first entry — suspicious but could be a gap
                    if first_broken.is_none() {
                        first_broken = Some(entry.0);
                    }
                }
                (Some(_), None) => {
                    // Missing prev_hash on non-first entry
                    if first_broken.is_none() {
                        first_broken = Some(entry.0);
                    }
                }
            }

            prev_entry = Some(entry);
        }

        Ok((valid, total, first_broken))
    }

    /// Compute SHA-256 hash for an audit entry.
    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        id: i64,
        ref_id: &str,
        accessor: &str,
        purpose: &str,
        action: &str,
        granted: bool,
        ts: i64,
        prev_hash: Option<&str>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.to_le_bytes());
        hasher.update(ref_id.as_bytes());
        hasher.update(accessor.as_bytes());
        hasher.update(purpose.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(if granted { &[1u8] } else { &[0u8] });
        hasher.update(ts.to_le_bytes());
        if let Some(ph) = prev_hash {
            hasher.update(ph.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_kek;
    use crate::store::VaultStore;

    fn test_vault() -> VaultStore {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        VaultStore::open(&path, generate_kek()).unwrap()
    }

    #[test]
    fn record_creates_entry() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();

        let entries = AuditLog::query(conn, None, 100).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ref_id, "email:abc1");
        assert_eq!(entries[0].accessor, "claude");
        assert_eq!(entries[0].purpose, "send");
        assert_eq!(entries[0].action, "resolve");
        assert!(entries[0].granted);
        assert!(entries[0].detail.is_none());
    }

    #[test]
    fn record_with_detail() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(
            conn,
            "email:abc1",
            "claude",
            "send",
            "denied",
            false,
            Some("no consent"),
        )
        .unwrap();

        let entries = AuditLog::query(conn, None, 100).unwrap();
        assert_eq!(entries[0].detail.as_deref(), Some("no consent"));
        assert!(!entries[0].granted);
    }

    #[test]
    fn first_entry_has_no_prev_hash() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();

        let entries = AuditLog::query(conn, None, 100).unwrap();
        assert!(entries[0].prev_hash.is_none());
    }

    #[test]
    fn second_entry_has_prev_hash() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc2", "tool_b", "read", "resolve", true, None)
            .unwrap();

        let entries = AuditLog::query(conn, None, 100).unwrap();
        // query returns DESC order, so entries[0] is the second entry
        assert!(entries[0].prev_hash.is_some());
    }

    #[test]
    fn chain_is_valid_on_intact_log() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc2", "tool_b", "read", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(
            conn,
            "phone:def3",
            "claude",
            "call",
            "denied",
            false,
            Some("no consent"),
        )
        .unwrap();

        let (valid, total, first_broken) = AuditLog::verify_chain(conn).unwrap();
        assert_eq!(total, 3);
        assert_eq!(valid, 3);
        assert!(first_broken.is_none());
    }

    #[test]
    fn chain_detects_tampered_row() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc2", "tool_b", "read", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc3", "tool_c", "list", "resolve", true, None)
            .unwrap();

        // Tamper: flip the granted bit on the first row
        {
            let c = conn.lock().unwrap();
            c.execute("UPDATE audit SET granted = 0 WHERE id = 1", [])
                .unwrap();
        }

        let (valid, total, first_broken) = AuditLog::verify_chain(conn).unwrap();
        assert_eq!(total, 3);
        // First entry is always valid (no prev_hash to check against),
        // but entry 2's prev_hash was computed from the original entry 1 data,
        // which no longer matches.
        assert!(valid < total);
        assert!(first_broken.is_some());
    }

    #[test]
    fn chain_detects_deleted_row() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc2", "tool_b", "read", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc3", "tool_c", "list", "resolve", true, None)
            .unwrap();

        // Delete the middle row — breaks the chain
        {
            let c = conn.lock().unwrap();
            c.execute("DELETE FROM audit WHERE id = 2", []).unwrap();
        }

        let (valid, total, first_broken) = AuditLog::verify_chain(conn).unwrap();
        assert_eq!(total, 2); // only 2 rows remain
        // Entry 3 has prev_hash computed from entry 2 which is gone,
        // so verifying against entry 1 will fail.
        assert!(valid < total);
        assert!(first_broken.is_some());
    }

    #[test]
    fn query_filters_by_ref_id() {
        let vault = test_vault();
        let conn = vault.conn();

        AuditLog::record_locked(conn, "email:abc1", "claude", "send", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "phone:def2", "claude", "call", "resolve", true, None)
            .unwrap();
        AuditLog::record_locked(conn, "email:abc1", "tool_b", "read", "denied", false, None)
            .unwrap();

        let email_entries = AuditLog::query(conn, Some("email:abc1"), 100).unwrap();
        assert_eq!(email_entries.len(), 2);
        assert!(email_entries.iter().all(|e| e.ref_id == "email:abc1"));
    }

    #[test]
    fn query_respects_limit() {
        let vault = test_vault();
        let conn = vault.conn();

        for i in 0..10 {
            AuditLog::record_locked(
                conn,
                &format!("email:abc{i}"),
                "claude",
                "send",
                "resolve",
                true,
                None,
            )
            .unwrap();
        }

        let entries = AuditLog::query(conn, None, 3).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn query_empty_log() {
        let vault = test_vault();
        let conn = vault.conn();

        let entries = AuditLog::query(conn, None, 100).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn verify_chain_empty_log() {
        let vault = test_vault();
        let conn = vault.conn();

        let (valid, total, first_broken) = AuditLog::verify_chain(conn).unwrap();
        assert_eq!(valid, 0);
        assert_eq!(total, 0);
        assert!(first_broken.is_none());
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let h1 = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            true,
            1000,
            None,
        );
        let h2 = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            true,
            1000,
            None,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_hash_changes_with_any_field() {
        let base = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            true,
            1000,
            None,
        );

        // Change each field individually and verify the hash changes
        let changed_id = AuditLog::compute_hash(
            2,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            true,
            1000,
            None,
        );
        let changed_ref = AuditLog::compute_hash(
            1,
            "email:abc2",
            "claude",
            "send",
            "resolve",
            true,
            1000,
            None,
        );
        let changed_accessor = AuditLog::compute_hash(
            1,
            "email:abc1",
            "other",
            "send",
            "resolve",
            true,
            1000,
            None,
        );
        let changed_purpose = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "other",
            "resolve",
            true,
            1000,
            None,
        );
        let changed_action = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "denied",
            true,
            1000,
            None,
        );
        let changed_granted = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            false,
            1000,
            None,
        );
        let changed_ts = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            true,
            9999,
            None,
        );
        let changed_prev = AuditLog::compute_hash(
            1,
            "email:abc1",
            "claude",
            "send",
            "resolve",
            true,
            1000,
            Some("prev"),
        );

        assert_ne!(base, changed_id);
        assert_ne!(base, changed_ref);
        assert_ne!(base, changed_accessor);
        assert_ne!(base, changed_purpose);
        assert_ne!(base, changed_action);
        assert_ne!(base, changed_granted);
        assert_ne!(base, changed_ts);
        assert_ne!(base, changed_prev);
    }
}
