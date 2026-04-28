use dam_core::{
    PolicyAction, PolicyDecision, Reference, SensitiveType, VaultReadError, VaultReader,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_SCOPE: &str = "global";

#[derive(Debug, thiserror::Error)]
pub enum ConsentError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("system clock is before unix epoch")]
    Clock,

    #[error("invalid vault reference: {0}")]
    InvalidReference(String),

    #[error("vault value not found for {0}")]
    VaultValueNotFound(String),

    #[error("vault read failed")]
    VaultRead,
}

impl From<VaultReadError> for ConsentError {
    fn from(_: VaultReadError) -> Self {
        Self::VaultRead
    }
}

pub type ConsentResult<T> = Result<T, ConsentError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEntry {
    pub id: String,
    pub kind: SensitiveType,
    pub value_fingerprint: String,
    pub vault_key: Option<String>,
    pub scope: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub created_by: String,
    pub reason: Option<String>,
}

impl ConsentEntry {
    pub fn is_active_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }

    pub fn status_at(&self, now: i64) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at <= now {
            "expired"
        } else {
            "active"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantConsent {
    pub kind: SensitiveType,
    pub value: String,
    pub vault_key: Option<String>,
    pub ttl_seconds: u64,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentMatch {
    pub consent_id: String,
    pub kind: SensitiveType,
}

pub struct ConsentStore {
    conn: Mutex<Connection>,
}

impl ConsentStore {
    pub fn open(path: impl AsRef<Path>) -> ConsentResult<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> ConsentResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> ConsentResult<Self> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS consents (
                id TEXT PRIMARY KEY NOT NULL,
                kind TEXT NOT NULL,
                value_fingerprint TEXT NOT NULL,
                vault_key TEXT,
                scope TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                created_by TEXT NOT NULL,
                reason TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_consents_lookup
                ON consents(kind, value_fingerprint, scope, expires_at, revoked_at);
            CREATE INDEX IF NOT EXISTS idx_consents_vault_key
                ON consents(vault_key);
            ",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn grant(&self, grant: &GrantConsent) -> ConsentResult<ConsentEntry> {
        let now = now_unix_secs()?;
        let entry = ConsentEntry {
            id: generate_consent_id(),
            kind: grant.kind,
            value_fingerprint: fingerprint(grant.kind, &grant.value),
            vault_key: grant.vault_key.clone(),
            scope: DEFAULT_SCOPE.to_string(),
            created_at: now,
            expires_at: now + grant.ttl_seconds as i64,
            revoked_at: None,
            created_by: grant.created_by.clone(),
            reason: grant.reason.clone(),
        };

        let conn = self.conn.lock().expect("consent sqlite mutex poisoned");
        conn.execute(
            "
            INSERT INTO consents (
                id, kind, value_fingerprint, vault_key, scope,
                created_at, expires_at, revoked_at, created_by, reason
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ",
            params![
                entry.id,
                entry.kind.tag(),
                entry.value_fingerprint,
                entry.vault_key,
                entry.scope,
                entry.created_at,
                entry.expires_at,
                entry.revoked_at,
                entry.created_by,
                entry.reason,
            ],
        )?;

        Ok(entry)
    }

    pub fn grant_for_reference(
        &self,
        vault_key: &str,
        vault: &(impl VaultReader + ?Sized),
        ttl_seconds: u64,
        created_by: impl Into<String>,
        reason: Option<String>,
    ) -> ConsentResult<ConsentEntry> {
        let reference = Reference::parse_key(vault_key)
            .ok_or_else(|| ConsentError::InvalidReference(vault_key.to_string()))?;
        let Some(value) = vault.read(&reference)? else {
            return Err(ConsentError::VaultValueNotFound(vault_key.to_string()));
        };

        self.grant(&GrantConsent {
            kind: reference.kind,
            value,
            vault_key: Some(reference.key()),
            ttl_seconds,
            created_by: created_by.into(),
            reason,
        })
    }

    pub fn active_for_value(
        &self,
        kind: SensitiveType,
        value: &str,
    ) -> ConsentResult<Option<ConsentEntry>> {
        let now = now_unix_secs()?;
        let value_fingerprint = fingerprint(kind, value);
        let conn = self.conn.lock().expect("consent sqlite mutex poisoned");
        let entry = conn
            .query_row(
                "
                SELECT id, kind, value_fingerprint, vault_key, scope,
                       created_at, expires_at, revoked_at, created_by, reason
                FROM consents
                WHERE kind = ?1
                  AND value_fingerprint = ?2
                  AND scope = ?3
                  AND revoked_at IS NULL
                  AND expires_at > ?4
                ORDER BY expires_at DESC
                LIMIT 1
                ",
                params![kind.tag(), value_fingerprint, DEFAULT_SCOPE, now],
                row_to_entry,
            )
            .optional()?;

        Ok(entry)
    }

    pub fn revoke(&self, id: &str) -> ConsentResult<bool> {
        let now = now_unix_secs()?;
        let conn = self.conn.lock().expect("consent sqlite mutex poisoned");
        let target = conn
            .query_row(
                "
                SELECT kind, value_fingerprint, scope
                FROM consents
                WHERE id = ?1
                ",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;

        let Some((kind, value_fingerprint, scope)) = target else {
            return Ok(false);
        };

        let changed = conn.execute(
            "
            UPDATE consents
            SET revoked_at = ?1
            WHERE kind = ?2
              AND value_fingerprint = ?3
              AND scope = ?4
              AND revoked_at IS NULL
            ",
            params![now, kind, value_fingerprint, scope],
        )?;
        Ok(changed > 0)
    }

    pub fn list(&self) -> ConsentResult<Vec<ConsentEntry>> {
        let conn = self.conn.lock().expect("consent sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "
            SELECT id, kind, value_fingerprint, vault_key, scope,
                   created_at, expires_at, revoked_at, created_by, reason
            FROM consents
            ORDER BY created_at DESC, id ASC
            ",
        )?;

        let entries = stmt
            .query_map([], row_to_entry)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    pub fn count(&self) -> ConsentResult<u64> {
        let conn = self.conn.lock().expect("consent sqlite mutex poisoned");
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM consents", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

pub fn apply_consents_to_decisions(
    decisions: &[PolicyDecision],
    store: Option<&ConsentStore>,
) -> ConsentResult<(Vec<PolicyDecision>, Vec<ConsentMatch>)> {
    let Some(store) = store else {
        return Ok((decisions.to_vec(), Vec::new()));
    };

    let mut matches = Vec::new();
    let mut applied = Vec::with_capacity(decisions.len());
    for decision in decisions {
        if decision.action == PolicyAction::Block {
            applied.push(decision.clone());
            continue;
        }

        if let Some(consent) =
            store.active_for_value(decision.detection.kind, &decision.detection.value)?
        {
            matches.push(ConsentMatch {
                consent_id: consent.id,
                kind: decision.detection.kind,
            });
            applied.push(PolicyDecision::new(
                decision.detection.clone(),
                PolicyAction::Allow,
            ));
        } else {
            applied.push(decision.clone());
        }
    }

    Ok((applied, matches))
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsentEntry> {
    let kind_tag: String = row.get(1)?;
    let kind = SensitiveType::from_tag(&kind_tag).unwrap_or(SensitiveType::Email);
    Ok(ConsentEntry {
        id: row.get(0)?,
        kind,
        value_fingerprint: row.get(2)?,
        vault_key: row.get(3)?,
        scope: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        revoked_at: row.get(7)?,
        created_by: row.get(8)?,
        reason: row.get(9)?,
    })
}

pub fn fingerprint(kind: SensitiveType, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"dam-consent-v1\0");
    hasher.update(kind.tag().as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    bs58::encode(hasher.finalize()).into_string()
}

fn generate_consent_id() -> String {
    let uuid = uuid::Uuid::new_v4();
    format!("consent_{}", bs58::encode(uuid.as_bytes()).into_string())
}

fn now_unix_secs() -> ConsentResult<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConsentError::Clock)?;
    Ok(duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::{VaultRecord, VaultWriter};

    #[test]
    fn grant_and_match_active_value() {
        let store = ConsentStore::open_in_memory().unwrap();
        let entry = store
            .grant(&GrantConsent {
                kind: SensitiveType::Email,
                value: "alice@example.test".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();

        let matched = store
            .active_for_value(SensitiveType::Email, "alice@example.test")
            .unwrap()
            .unwrap();

        assert_eq!(matched.id, entry.id);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn revoked_consent_does_not_match() {
        let store = ConsentStore::open_in_memory().unwrap();
        let entry = store
            .grant(&GrantConsent {
                kind: SensitiveType::Email,
                value: "alice@example.test".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();

        assert!(store.revoke(&entry.id).unwrap());

        assert!(
            store
                .active_for_value(SensitiveType::Email, "alice@example.test")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn revoke_stops_all_active_grants_for_same_exact_value() {
        let store = ConsentStore::open_in_memory().unwrap();
        let first = store
            .grant(&GrantConsent {
                kind: SensitiveType::Email,
                value: "alice@example.test".to_string(),
                vault_key: Some("email:first".to_string()),
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();
        store
            .grant(&GrantConsent {
                kind: SensitiveType::Email,
                value: "alice@example.test".to_string(),
                vault_key: Some("email:second".to_string()),
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();

        assert!(store.revoke(&first.id).unwrap());

        assert!(
            store
                .active_for_value(SensitiveType::Email, "alice@example.test")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .list()
                .unwrap()
                .iter()
                .filter(|entry| entry.revoked_at.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn expired_consent_does_not_match() {
        let store = ConsentStore::open_in_memory().unwrap();
        store
            .grant(&GrantConsent {
                kind: SensitiveType::Email,
                value: "alice@example.test".to_string(),
                vault_key: None,
                ttl_seconds: 0,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();

        assert!(
            store
                .active_for_value(SensitiveType::Email, "alice@example.test")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn grants_from_vault_reference_without_storing_raw_value() {
        let vault = dam_vault::Vault::open_in_memory().unwrap();
        let store = ConsentStore::open_in_memory().unwrap();
        let reference = Reference::generate(SensitiveType::Email);
        vault
            .write(&VaultRecord {
                reference: reference.clone(),
                kind: SensitiveType::Email,
                value: "alice@example.test".to_string(),
            })
            .unwrap();

        let entry = store
            .grant_for_reference(&reference.key(), &vault, 60, "test", None)
            .unwrap();

        assert_eq!(entry.vault_key, Some(reference.key()));
        assert_ne!(entry.value_fingerprint, "alice@example.test");
        assert!(
            store
                .active_for_value(SensitiveType::Email, "alice@example.test")
                .unwrap()
                .is_some()
        );
    }
}
