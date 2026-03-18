use dam_core::{DamError, DamResult, PiiRef};
use dam_vault::{AuditLog, ConsentManager, VaultStore};
use std::sync::Arc;

/// Result of resolving a single PII reference.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// The reference that was resolved.
    pub pii_ref: PiiRef,
    /// Whether consent was granted.
    pub granted: bool,
    /// The decrypted PII value (only present if granted).
    pub value: Option<String>,
    /// Denial reason (only present if denied).
    pub reason: Option<String>,
}

/// Resolves PII references with consent checking and audit logging.
///
/// Every resolution attempt is recorded in the audit trail regardless of outcome.
/// Use [`Resolver::reveal`] for emergency access that bypasses consent.
pub struct Resolver {
    vault: Arc<VaultStore>,
}

impl Resolver {
    /// Create a new resolver backed by the given vault.
    pub fn new(vault: Arc<VaultStore>) -> Self {
        Self { vault }
    }

    /// Resolve a single reference with consent check.
    pub fn resolve(
        &self,
        pii_ref: &PiiRef,
        accessor: &str,
        purpose: &str,
    ) -> DamResult<ResolveResult> {
        let ref_key = pii_ref.key();

        // Check consent
        let allowed =
            ConsentManager::check_consent(self.vault.conn(), &ref_key, accessor, purpose)?;

        if !allowed {
            // Audit the denied access
            AuditLog::record_locked(
                self.vault.conn(),
                &ref_key,
                accessor,
                purpose,
                "denied",
                false,
                Some(&format!(
                    "no consent for {accessor} to access {ref_key} for {purpose}"
                )),
            )?;

            return Err(DamError::ConsentDenied {
                reason: format!(
                    "{} was not resolved — no consent for {accessor} to access for purpose '{purpose}'",
                    pii_ref.display()
                ),
            });
        }

        // Decrypt and return
        let value = self.vault.retrieve_pii(pii_ref)?;

        // Audit the successful resolution
        AuditLog::record_locked(
            self.vault.conn(),
            &ref_key,
            accessor,
            purpose,
            "resolve",
            true,
            None,
        )?;

        Ok(ResolveResult {
            pii_ref: pii_ref.clone(),
            granted: true,
            value: Some(value),
            reason: None,
        })
    }

    /// Resolve multiple references in a text string. Returns the text with
    /// consented references replaced by real values, and denied ones kept as-is.
    pub fn resolve_text(
        &self,
        text: &str,
        accessor: &str,
        purpose: &str,
    ) -> DamResult<ResolveTextResult> {
        let mut results = Vec::new();
        let mut denied = Vec::new();

        let resolved_text = dam_core::reference::replace_refs(text, |pii_ref| {
            match self.resolve(pii_ref, accessor, purpose) {
                Ok(result) => {
                    let value = result.value.clone();
                    results.push(result);
                    value
                }
                Err(DamError::ConsentDenied { reason }) => {
                    denied.push(DeniedRef {
                        pii_ref: pii_ref.clone(),
                        reason: reason.clone(),
                    });
                    None // Keep the reference as-is
                }
                Err(_) => None,
            }
        });

        Ok(ResolveTextResult {
            resolved_text,
            resolved: results,
            denied,
        })
    }

    /// Reveal a PII value without consent check (override/emergency).
    /// This is always audited with the reason.
    pub fn reveal(&self, pii_ref: &PiiRef, reason: &str) -> DamResult<String> {
        let value = self.vault.retrieve_pii(pii_ref)?;

        AuditLog::record_locked(
            self.vault.conn(),
            &pii_ref.key(),
            "dam:reveal",
            "override",
            "reveal",
            true,
            Some(reason),
        )?;

        Ok(value)
    }
}

/// Result of resolving all references in a text string.
#[derive(Debug)]
pub struct ResolveTextResult {
    /// Text with consented references replaced by real values.
    pub resolved_text: String,
    /// Successfully resolved references.
    pub resolved: Vec<ResolveResult>,
    /// References that were denied due to missing consent.
    pub denied: Vec<DeniedRef>,
}

/// A reference that could not be resolved due to missing consent.
#[derive(Debug)]
pub struct DeniedRef {
    /// The reference that was denied.
    pub pii_ref: PiiRef,
    /// Human-readable denial reason.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::PiiType;
    use dam_vault::{ConsentManager, generate_kek};

    fn test_resolver() -> (Resolver, Arc<VaultStore>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
        let resolver = Resolver::new(vault.clone());
        (resolver, vault)
    }

    #[test]
    fn resolve_denied_without_consent() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        let result = resolver.resolve(&pii_ref, "claude", "send_email");
        assert!(result.is_err());
        match result {
            Err(DamError::ConsentDenied { .. }) => {}
            other => panic!("expected ConsentDenied, got {:?}", other),
        }
    }

    #[test]
    fn resolve_granted_with_consent() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "claude", "send_email", None)
            .unwrap();

        let result = resolver.resolve(&pii_ref, "claude", "send_email").unwrap();
        assert!(result.granted);
        assert_eq!(result.value.unwrap(), "test@test.com");
    }

    #[test]
    fn reveal_bypasses_consent() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "secret@test.com", None, None)
            .unwrap();

        // No consent granted, but reveal should work
        let value = resolver.reveal(&pii_ref, "user explicit request").unwrap();
        assert_eq!(value, "secret@test.com");
    }

    // --- Edge cases ---

    #[test]
    fn resolve_nonexistent_ref() {
        let (resolver, _vault) = test_resolver();
        let fake_ref = PiiRef::generate(PiiType::Email);

        // No consent → ConsentDenied before we even hit the vault lookup
        let result = resolver.resolve(&fake_ref, "claude", "send");
        assert!(result.is_err());
    }

    #[test]
    fn reveal_nonexistent_ref() {
        let (resolver, _vault) = test_resolver();
        let fake_ref = PiiRef::generate(PiiType::Email);

        let result = resolver.reveal(&fake_ref, "reason");
        assert!(result.is_err());
        match result {
            Err(DamError::ReferenceNotFound(_)) => {}
            other => panic!("expected ReferenceNotFound, got {:?}", other),
        }
    }

    #[test]
    fn resolve_creates_audit_entry_on_deny() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        // Resolve without consent — should be denied
        let _ = resolver.resolve(&pii_ref, "claude", "send_email");

        // Check that a "denied" audit entry was created
        let entries = dam_vault::AuditLog::query(vault.conn(), Some(&pii_ref.key()), 100).unwrap();
        assert!(entries.iter().any(|e| e.action == "denied" && !e.granted));
    }

    #[test]
    fn resolve_creates_audit_entry_on_grant() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "claude", "send_email", None)
            .unwrap();

        resolver.resolve(&pii_ref, "claude", "send_email").unwrap();

        let entries = dam_vault::AuditLog::query(vault.conn(), Some(&pii_ref.key()), 100).unwrap();
        assert!(entries.iter().any(|e| e.action == "resolve" && e.granted));
    }

    #[test]
    fn reveal_creates_audit_entry() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        resolver.reveal(&pii_ref, "emergency access").unwrap();

        let entries = dam_vault::AuditLog::query(vault.conn(), Some(&pii_ref.key()), 100).unwrap();
        assert!(entries.iter().any(|e| {
            e.action == "reveal"
                && e.accessor == "dam:reveal"
                && e.detail.as_deref() == Some("emergency access")
        }));
    }

    #[test]
    fn resolve_text_no_refs() {
        let (resolver, _vault) = test_resolver();
        let result = resolver
            .resolve_text("plain text with no refs", "claude", "test")
            .unwrap();
        assert_eq!(result.resolved_text, "plain text with no refs");
        assert!(result.resolved.is_empty());
        assert!(result.denied.is_empty());
    }

    #[test]
    fn resolve_text_all_denied() {
        let (resolver, vault) = test_resolver();
        let pii_ref = vault
            .store_pii(PiiType::Email, "test@test.com", None, None)
            .unwrap();

        let text = format!("Contact {}", pii_ref.display());
        let result = resolver.resolve_text(&text, "claude", "send").unwrap();

        // No consent → ref stays as-is
        assert_eq!(result.resolved_text, text);
        assert!(result.resolved.is_empty());
        assert_eq!(result.denied.len(), 1);
    }
}
