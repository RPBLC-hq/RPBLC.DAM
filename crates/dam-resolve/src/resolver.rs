use dam_core::{DamError, DamResult, PiiRef};
use dam_vault::{AuditLog, ConsentManager, VaultStore};
use std::sync::Arc;

/// Result of resolving a single reference.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub pii_ref: PiiRef,
    pub granted: bool,
    pub value: Option<String>,
    pub reason: Option<String>,
}

/// Resolves PII references with consent checking and audit logging.
pub struct Resolver {
    vault: Arc<VaultStore>,
}

impl Resolver {
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

/// Result of resolving references in a text string.
#[derive(Debug)]
pub struct ResolveTextResult {
    pub resolved_text: String,
    pub resolved: Vec<ResolveResult>,
    pub denied: Vec<DeniedRef>,
}

#[derive(Debug)]
pub struct DeniedRef {
    pub pii_ref: PiiRef,
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
}
