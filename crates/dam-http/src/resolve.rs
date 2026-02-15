use dam_core::reference::replace_refs;
use dam_vault::VaultStore;
use std::sync::Arc;

/// Replace all `[type:hex]` references in text with their decrypted vault values.
///
/// This is the outbound resolver — it lets the *user* see real PII values
/// in LLM responses. No consent check is performed because the user is
/// viewing their own data.
///
/// References that cannot be resolved (deleted entries, etc.) are left as-is.
pub fn resolve_text(vault: &Arc<VaultStore>, text: &str) -> String {
    replace_refs(text, |pii_ref| vault.retrieve_pii(pii_ref).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::PiiType;
    use dam_vault::generate_kek;

    fn test_vault() -> Arc<VaultStore> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        Arc::new(VaultStore::open(&path, generate_kek()).unwrap())
    }

    #[test]
    fn resolve_known_ref() {
        let vault = test_vault();
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@example.com", None, None)
            .unwrap();

        let text = format!("Contact {} for details", pii_ref.display());
        let resolved = resolve_text(&vault, &text);
        assert_eq!(resolved, "Contact alice@example.com for details");
    }

    #[test]
    fn resolve_unknown_ref_left_intact() {
        let vault = test_vault();
        let text = "Contact [email:deadbeef] please";
        let resolved = resolve_text(&vault, text);
        assert_eq!(resolved, text);
    }

    #[test]
    fn resolve_multiple_refs() {
        let vault = test_vault();
        let email_ref = vault
            .store_pii(PiiType::Email, "bob@test.com", None, None)
            .unwrap();
        let phone_ref = vault
            .store_pii(PiiType::Phone, "555-1234", None, None)
            .unwrap();

        let text = format!(
            "Email: {}, Phone: {}",
            email_ref.display(),
            phone_ref.display()
        );
        let resolved = resolve_text(&vault, &text);
        // Note: Phone is normalized (dashes removed) for consistent deduplication
        assert_eq!(resolved, "Email: bob@test.com, Phone: 5551234");
    }

    #[test]
    fn resolve_no_refs() {
        let vault = test_vault();
        let text = "Hello, no PII here.";
        let resolved = resolve_text(&vault, text);
        assert_eq!(resolved, text);
    }

    #[test]
    fn resolve_mixed_known_and_unknown() {
        let vault = test_vault();
        let pii_ref = vault.store_pii(PiiType::Name, "Alice", None, None).unwrap();

        let text = format!("Hello {} and [phone:deadbeef]", pii_ref.display());
        let resolved = resolve_text(&vault, &text);
        assert!(resolved.contains("Alice"));
        assert!(resolved.contains("[phone:deadbeef]"));
    }
}
