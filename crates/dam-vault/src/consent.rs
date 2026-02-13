use dam_core::{DamError, DamResult};
use rusqlite::Connection;
use std::sync::Mutex;

/// A consent rule record.
#[derive(Debug, Clone)]
pub struct ConsentRule {
    pub ref_id: String,
    pub accessor: String,
    pub purpose: String,
    pub allowed: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Consent management for PII resolution.
pub struct ConsentManager;

impl ConsentManager {
    /// Check whether a specific accessor has consent to resolve a reference for a given purpose.
    ///
    /// Checks in order:
    /// 1. Exact match (ref + accessor + purpose)
    /// 2. Wildcard accessor ("*" + purpose)
    /// 3. Wildcard purpose (accessor + "*")
    /// 4. Full wildcard ("*" + "*")
    ///
    /// Returns false if no matching rule or if the rule is expired.
    pub fn check_consent(
        conn: &Mutex<Connection>,
        ref_id: &str,
        accessor: &str,
        purpose: &str,
    ) -> DamResult<bool> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();

        // Try each specificity level
        let patterns: &[(&str, &str)] = &[
            (accessor, purpose),
            ("*", purpose),
            (accessor, "*"),
            ("*", "*"),
        ];

        for (acc, purp) in patterns {
            let result: Result<(bool, Option<i64>), _> = conn.query_row(
                "SELECT allowed, expires_at FROM consent
                 WHERE ref_id = ?1 AND accessor = ?2 AND purpose = ?3",
                rusqlite::params![ref_id, acc, purp],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Option<i64>>(1)?)),
            );

            match result {
                Ok((allowed, expires_at)) => {
                    // Check expiration
                    if let Some(exp) = expires_at
                        && exp < now
                    {
                        // Expired — clean it up and continue
                        let _ = conn.execute(
                            "DELETE FROM consent WHERE ref_id = ?1 AND accessor = ?2 AND purpose = ?3",
                            rusqlite::params![ref_id, acc, purp],
                        );
                        continue;
                    }
                    return Ok(allowed);
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                Err(e) => return Err(DamError::Database(e.to_string())),
            }
        }

        Ok(false) // No consent rule found = denied
    }

    /// Grant consent for a specific accessor to resolve a reference for a purpose.
    pub fn grant_consent(
        conn: &Mutex<Connection>,
        ref_id: &str,
        accessor: &str,
        purpose: &str,
        expires_at: Option<i64>,
    ) -> DamResult<()> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO consent (ref_id, accessor, purpose, allowed, created_at, expires_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?5)
             ON CONFLICT(ref_id, accessor, purpose) DO UPDATE SET allowed = 1, created_at = ?4, expires_at = ?5",
            rusqlite::params![ref_id, accessor, purpose, now, expires_at],
        )
        .map_err(|e| DamError::Database(e.to_string()))?;

        Ok(())
    }

    /// Revoke consent.
    pub fn revoke_consent(
        conn: &Mutex<Connection>,
        ref_id: &str,
        accessor: &str,
        purpose: &str,
    ) -> DamResult<()> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;

        conn.execute(
            "DELETE FROM consent WHERE ref_id = ?1 AND accessor = ?2 AND purpose = ?3",
            rusqlite::params![ref_id, accessor, purpose],
        )
        .map_err(|e| DamError::Database(e.to_string()))?;

        Ok(())
    }

    /// List all consent rules, optionally filtered by ref_id.
    pub fn list_consent(
        conn: &Mutex<Connection>,
        ref_filter: Option<&str>,
    ) -> DamResult<Vec<ConsentRule>> {
        let conn = conn.lock().map_err(|e| DamError::Vault(e.to_string()))?;
        let mut rules = Vec::new();

        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match ref_filter {
            Some(ref_id) => (
                "SELECT ref_id, accessor, purpose, allowed, created_at, expires_at FROM consent WHERE ref_id = ?1 ORDER BY created_at DESC",
                vec![Box::new(ref_id.to_string())],
            ),
            None => (
                "SELECT ref_id, accessor, purpose, allowed, created_at, expires_at FROM consent ORDER BY created_at DESC",
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
                Ok(ConsentRule {
                    ref_id: row.get(0)?,
                    accessor: row.get(1)?,
                    purpose: row.get(2)?,
                    allowed: row.get(3)?,
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            })
            .map_err(|e| DamError::Database(e.to_string()))?;

        for row in rows {
            rules.push(row.map_err(|e| DamError::Database(e.to_string()))?);
        }

        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_kek;
    use crate::store::VaultStore;
    use dam_core::PiiType;

    fn test_vault() -> VaultStore {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        VaultStore::open(&path, generate_kek()).unwrap()
    }

    #[test]
    fn consent_default_denied() {
        let vault = test_vault();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        let allowed =
            ConsentManager::check_consent(vault.conn(), &pii_ref.key(), "claude", "send_email")
                .unwrap();
        assert!(!allowed);
    }

    #[test]
    fn consent_grant_and_check() {
        let vault = test_vault();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "claude", "send_email", None)
            .unwrap();

        let allowed =
            ConsentManager::check_consent(vault.conn(), &pii_ref.key(), "claude", "send_email")
                .unwrap();
        assert!(allowed);
    }

    #[test]
    fn consent_wildcard() {
        let vault = test_vault();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        // Grant wildcard accessor
        ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "*", "send_email", None)
            .unwrap();

        let allowed =
            ConsentManager::check_consent(vault.conn(), &pii_ref.key(), "any_tool", "send_email")
                .unwrap();
        assert!(allowed);
    }

    #[test]
    fn consent_revoke() {
        let vault = test_vault();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "claude", "send_email", None)
            .unwrap();

        ConsentManager::revoke_consent(vault.conn(), &pii_ref.key(), "claude", "send_email")
            .unwrap();

        let allowed =
            ConsentManager::check_consent(vault.conn(), &pii_ref.key(), "claude", "send_email")
                .unwrap();
        assert!(!allowed);
    }
}
