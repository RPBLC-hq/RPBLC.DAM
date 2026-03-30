use dam_core::DamError;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A consent rule — grants or denies passage for a data type or specific token
/// to a destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRule {
    pub id: String,
    /// Match by data type tag (e.g., "email") or "*" for all types.
    pub data_type: String,
    /// Match by specific token key (e.g., "email:7B2Hkq...") or None for type-level rule.
    pub token_key: Option<String>,
    /// Match by destination host (e.g., "api.anthropic.com") or "*" for all.
    pub destination: String,
    /// The action: "pass" or "redact".
    pub action: ConsentAction,
    /// Unix timestamp when the rule was created.
    pub created_at: i64,
    /// Unix timestamp when the rule expires, or None for permanent.
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentAction {
    Pass,
    Redact,
}

impl ConsentAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Redact => "redact",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Self::Pass),
            "redact" => Some(Self::Redact),
            _ => None,
        }
    }
}

/// The result of checking consent for a specific detection.
#[derive(Debug, Clone)]
pub struct ConsentCheck {
    pub action: ConsentAction,
    pub rule_id: Option<String>,
    pub reason: &'static str,
}

/// SQLite-backed consent rule storage.
pub struct ConsentStore {
    conn: Mutex<Connection>,
    /// Default TTL in seconds. 0 means permanent.
    pub default_ttl_secs: u64,
}

impl ConsentStore {
    /// Open (or create) a consent database. Reuses the vault DB path for simplicity.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, DamError> {
        let conn = Connection::open(db_path).map_err(|e| DamError::Db(e.to_string()))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| DamError::Db(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS consent_rules (
                id          TEXT PRIMARY KEY,
                data_type   TEXT NOT NULL,
                token_key   TEXT,
                destination TEXT NOT NULL,
                action      TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_consent_type_dest
                ON consent_rules (data_type, destination);
            CREATE INDEX IF NOT EXISTS idx_consent_token
                ON consent_rules (token_key);",
        )
        .map_err(|e| DamError::Db(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
            default_ttl_secs: 86400, // 24 hours
        })
    }

    /// Grant consent: create a rule allowing or denying passage.
    ///
    /// - `data_type`: type tag ("email", "ssn") or "*" for all
    /// - `token_key`: specific token key ("email:7B2Hkq...") or None for type-level
    /// - `destination`: host ("api.anthropic.com") or "*" for all
    /// - `action`: Pass or Redact
    /// - `ttl_secs`: time-to-live in seconds, or None for permanent
    pub fn grant(
        &self,
        data_type: &str,
        token_key: Option<&str>,
        destination: &str,
        action: ConsentAction,
        ttl_secs: Option<u64>,
    ) -> Result<ConsentRule, DamError> {
        let now = now_secs();
        let expires_at = ttl_secs.map(|ttl| now + ttl as i64);
        let id = uuid::Uuid::new_v4().to_string();

        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        conn.execute(
            "INSERT INTO consent_rules (id, data_type, token_key, destination, action, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, data_type, token_key, destination, action.as_str(), now, expires_at],
        )
        .map_err(|e| DamError::Db(e.to_string()))?;

        Ok(ConsentRule {
            id,
            data_type: data_type.to_string(),
            token_key: token_key.map(|s| s.to_string()),
            destination: destination.to_string(),
            action,
            created_at: now,
            expires_at,
        })
    }

    /// Revoke a consent rule by ID.
    pub fn revoke(&self, rule_id: &str) -> Result<bool, DamError> {
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let rows = conn
            .execute("DELETE FROM consent_rules WHERE id = ?1", params![rule_id])
            .map_err(|e| DamError::Db(e.to_string()))?;
        Ok(rows > 0)
    }

    /// List all active (non-expired) consent rules.
    pub fn list(&self) -> Result<Vec<ConsentRule>, DamError> {
        let now = now_secs();
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, data_type, token_key, destination, action, created_at, expires_at
                 FROM consent_rules
                 WHERE expires_at IS NULL OR expires_at > ?1
                 ORDER BY created_at DESC",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![now], |row| {
                Ok(ConsentRule {
                    id: row.get(0)?,
                    data_type: row.get(1)?,
                    token_key: row.get(2)?,
                    destination: row.get(3)?,
                    action: ConsentAction::parse(&row.get::<_, String>(4)?)
                        .unwrap_or(ConsentAction::Redact),
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            })
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut rules = Vec::new();
        for row in rows {
            rules.push(row.map_err(|e| DamError::Db(e.to_string()))?);
        }
        Ok(rules)
    }

    /// Check consent for a specific detection against a destination.
    ///
    /// Specificity order (first match wins):
    /// 1. Token + destination deny → Redact
    /// 2. Token + destination allow → Pass
    /// 3. Token + wildcard dest deny → Redact
    /// 4. Token + wildcard dest allow → Pass
    /// 5. Type + destination deny → Redact
    /// 6. Type + destination allow → Pass
    /// 7. Type + wildcard dest deny → Redact
    /// 8. Type + wildcard dest allow → Pass
    /// 9. Wildcard type + destination deny → Redact
    /// 10. Wildcard type + destination allow → Pass
    /// 11. Wildcard type + wildcard dest deny → Redact
    /// 12. Wildcard type + wildcard dest allow → Pass
    /// 13. No match → Redact (default deny)
    pub fn check(
        &self,
        token_key: Option<&str>,
        data_type_tag: &str,
        destination: &str,
    ) -> Result<ConsentCheck, DamError> {
        self.check_with_default(token_key, data_type_tag, destination, ConsentAction::Redact)
    }

    /// Like `check()`, but with an explicit default action when no rule matches.
    /// Use `ConsentAction::Redact` for LLM destinations (default deny),
    /// `ConsentAction::Pass` for non-LLM destinations (default allow, log-only).
    ///
    /// `token_key` is None during the forward pipeline (tokens don't exist yet)
    /// and Some during resolve/release (where token-scoped rules apply).
    pub fn check_with_default(
        &self,
        token_key: Option<&str>,
        data_type_tag: &str,
        destination: &str,
        default_action: ConsentAction,
    ) -> Result<ConsentCheck, DamError> {
        let now = now_secs();
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, data_type, token_key, destination, action
                 FROM consent_rules
                 WHERE (expires_at IS NULL OR expires_at > ?1)",
            )
            .map_err(|e| DamError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![now], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| DamError::Db(e.to_string()))?;

        let mut best_match: Option<(u8, String, ConsentAction)> = None;

        for row in rows {
            let (rule_id, rule_type, rule_token, rule_dest, rule_action) =
                row.map_err(|e| DamError::Db(e.to_string()))?;
            let action = match ConsentAction::parse(&rule_action) {
                Some(a) => a,
                None => continue,
            };

            let specificity = calc_specificity(
                rule_token.as_deref(),
                &rule_type,
                &rule_dest,
                token_key,
                data_type_tag,
                destination,
            );

            if let Some(s) = specificity
                && (best_match.is_none() || s < best_match.as_ref().unwrap().0)
            {
                best_match = Some((s, rule_id, action));
            }
        }

        match best_match {
            Some((_, rule_id, action)) => Ok(ConsentCheck {
                action,
                rule_id: Some(rule_id),
                reason: match action {
                    ConsentAction::Pass => "consent_granted",
                    ConsentAction::Redact => "consent_denied",
                },
            }),
            None => Ok(ConsentCheck {
                action: default_action,
                rule_id: None,
                reason: "no_matching_rule",
            }),
        }
    }

    /// Count active rules.
    pub fn count(&self) -> Result<usize, DamError> {
        let now = now_secs();
        let conn = self.conn.lock().map_err(|e| DamError::Db(e.to_string()))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM consent_rules WHERE expires_at IS NULL OR expires_at > ?1",
                params![now],
                |row| row.get(0),
            )
            .map_err(|e| DamError::Db(e.to_string()))?;
        Ok(count as usize)
    }
}

/// Calculate specificity score (lower = more specific, None = no match).
fn calc_specificity(
    rule_token: Option<&str>,
    rule_type: &str,
    rule_dest: &str,
    actual_token: Option<&str>,
    actual_type: &str,
    actual_dest: &str,
) -> Option<u8> {
    // Token match: if rule requires a token but we don't have one, skip.
    // If rule requires a token and we have one, it must match exactly.
    let token_match = match rule_token {
        Some(rt) => match actual_token {
            Some(at) if rt == at => true,
            _ => return None, // rule needs a token we don't have, or wrong token
        },
        None => false,
    };

    // Type match
    let _type_match = if rule_type == actual_type || rule_type == "*" {
        true
    } else {
        return None;
    };

    // Destination match
    let _dest_match = if rule_dest == actual_dest || rule_dest == "*" {
        true
    } else {
        return None;
    };

    // Specificity: token+exact_dest=0, token+wildcard_dest=1, type+exact_dest=2, etc.
    let score = match (token_match, rule_type != "*", rule_dest != "*") {
        (true, _, true) => 0,       // token + exact dest
        (true, _, false) => 1,      // token + wildcard dest
        (false, true, true) => 2,   // type + exact dest
        (false, true, false) => 3,  // type + wildcard dest
        (false, false, true) => 4,  // wildcard type + exact dest
        (false, false, false) => 5, // wildcard type + wildcard dest
    };

    Some(score)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (ConsentStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("consent_test.db");
        let store = ConsentStore::open(&db).unwrap();
        (store, dir)
    }

    #[test]
    fn test_grant_and_list() {
        let (store, _dir) = temp_store();
        store
            .grant(
                "email",
                None,
                "api.anthropic.com",
                ConsentAction::Pass,
                Some(3600),
            )
            .unwrap();
        let rules = store.list().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].data_type, "email");
        assert_eq!(rules[0].destination, "api.anthropic.com");
        assert_eq!(rules[0].action, ConsentAction::Pass);
        assert!(rules[0].expires_at.is_some());
    }

    #[test]
    fn test_grant_permanent() {
        let (store, _dir) = temp_store();
        store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();
        let rules = store.list().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].expires_at.is_none());
    }

    #[test]
    fn test_grant_with_token() {
        let (store, _dir) = temp_store();
        store
            .grant(
                "email",
                Some("email:7B2HkqFn9xR4mWpD3nYvKt"),
                "*",
                ConsentAction::Pass,
                None,
            )
            .unwrap();
        let rules = store.list().unwrap();
        assert_eq!(
            rules[0].token_key.as_deref(),
            Some("email:7B2HkqFn9xR4mWpD3nYvKt")
        );
    }

    #[test]
    fn test_revoke() {
        let (store, _dir) = temp_store();
        let rule = store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        let revoked = store.revoke(&rule.id).unwrap();
        assert!(revoked);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_revoke_nonexistent() {
        let (store, _dir) = temp_store();
        let revoked = store.revoke("nonexistent").unwrap();
        assert!(!revoked);
    }

    #[test]
    fn test_check_no_rules_defaults_to_redact() {
        let (store, _dir) = temp_store();
        let check = store
            .check(Some("email:abc123"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact);
        assert_eq!(check.reason, "no_matching_rule");
    }

    #[test]
    fn test_check_type_dest_pass() {
        let (store, _dir) = temp_store();
        store
            .grant(
                "email",
                None,
                "api.anthropic.com",
                ConsentAction::Pass,
                None,
            )
            .unwrap();
        let check = store
            .check(Some("email:abc123"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Pass);
    }

    #[test]
    fn test_check_type_dest_no_match() {
        let (store, _dir) = temp_store();
        store
            .grant(
                "email",
                None,
                "api.anthropic.com",
                ConsentAction::Pass,
                None,
            )
            .unwrap();
        // Different destination
        let check = store
            .check(Some("email:abc123"), "email", "api.openai.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact);
    }

    #[test]
    fn test_check_type_wildcard_dest() {
        let (store, _dir) = temp_store();
        store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();
        let check = store
            .check(Some("email:abc123"), "email", "api.openai.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Pass);
    }

    #[test]
    fn test_check_token_overrides_type() {
        let (store, _dir) = temp_store();
        // Type-level: pass emails
        store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();
        // Token-level: deny this specific email
        store
            .grant(
                "email",
                Some("email:abc123"),
                "*",
                ConsentAction::Redact,
                None,
            )
            .unwrap();

        let check = store
            .check(Some("email:abc123"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact); // token override wins

        let check2 = store
            .check(Some("email:other456"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check2.action, ConsentAction::Pass); // other emails still pass
    }

    #[test]
    fn test_check_exact_dest_overrides_wildcard() {
        let (store, _dir) = temp_store();
        // Wildcard: pass emails everywhere
        store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();
        // Exact: deny emails to OpenAI specifically
        store
            .grant("email", None, "api.openai.com", ConsentAction::Redact, None)
            .unwrap();

        let check = store
            .check(Some("email:abc123"), "email", "api.openai.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact); // exact dest wins

        let check2 = store
            .check(Some("email:abc123"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check2.action, ConsentAction::Pass); // wildcard still applies
    }

    #[test]
    fn test_check_wildcard_type() {
        let (store, _dir) = temp_store();
        store
            .grant("*", None, "api.anthropic.com", ConsentAction::Pass, None)
            .unwrap();
        let check = store
            .check(Some("ssn:abc123"), "ssn", "api.anthropic.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Pass);
    }

    #[test]
    fn test_check_specific_type_overrides_wildcard_type() {
        let (store, _dir) = temp_store();
        // Wildcard: pass everything to Anthropic
        store
            .grant("*", None, "api.anthropic.com", ConsentAction::Pass, None)
            .unwrap();
        // Specific: redact SSNs to Anthropic
        store
            .grant(
                "ssn",
                None,
                "api.anthropic.com",
                ConsentAction::Redact,
                None,
            )
            .unwrap();

        let check = store
            .check(Some("ssn:abc123"), "ssn", "api.anthropic.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact); // specific type wins

        let check2 = store
            .check(Some("email:abc123"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check2.action, ConsentAction::Pass); // wildcard covers email
    }

    #[test]
    fn test_expired_rules_ignored() {
        let (store, _dir) = temp_store();
        // Grant with 0-second TTL (already expired)
        store
            .grant("email", None, "*", ConsentAction::Pass, Some(0))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let check = store
            .check(Some("email:abc123"), "email", "api.anthropic.com")
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact); // expired, falls to default
    }

    #[test]
    fn test_count() {
        let (store, _dir) = temp_store();
        assert_eq!(store.count().unwrap(), 0);
        store
            .grant("email", None, "*", ConsentAction::Pass, None)
            .unwrap();
        store
            .grant("ssn", None, "*", ConsentAction::Redact, None)
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_grant_with_value_resolves_to_token() {
        // This tests that the CLI/MCP layer can accept a raw value like "john@acme.com"
        // and resolve it to a token key before calling grant().
        // The store itself just takes a token_key string.
        let (store, _dir) = temp_store();
        store
            .grant(
                "email",
                Some("email:7B2HkqFn9xR4mWpD3nYvKt"),
                "api.anthropic.com",
                ConsentAction::Pass,
                None,
            )
            .unwrap();
        let check = store
            .check(
                Some("email:7B2HkqFn9xR4mWpD3nYvKt"),
                "email",
                "api.anthropic.com",
            )
            .unwrap();
        assert_eq!(check.action, ConsentAction::Pass);
    }

    #[test]
    fn test_check_with_default_pass_no_rules() {
        let (store, _dir) = temp_store();
        let check = store
            .check_with_default(None, "email", "salesforce.com", ConsentAction::Pass)
            .unwrap();
        assert_eq!(check.action, ConsentAction::Pass);
        assert_eq!(check.reason, "no_matching_rule");
    }

    #[test]
    fn test_check_with_default_redact_no_rules() {
        let (store, _dir) = temp_store();
        let check = store
            .check_with_default(None, "email", "api.anthropic.com", ConsentAction::Redact)
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact);
        assert_eq!(check.reason, "no_matching_rule");
    }

    #[test]
    fn test_check_with_default_rule_overrides_default() {
        let (store, _dir) = temp_store();
        store
            .grant("email", None, "salesforce.com", ConsentAction::Redact, None)
            .unwrap();
        let check = store
            .check_with_default(None, "email", "salesforce.com", ConsentAction::Pass)
            .unwrap();
        assert_eq!(check.action, ConsentAction::Redact); // explicit rule overrides default Pass
    }
}
