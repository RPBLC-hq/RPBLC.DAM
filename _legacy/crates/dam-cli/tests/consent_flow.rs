use dam_core::PiiType;
use dam_resolve::Resolver;
use dam_vault::{ConsentManager, VaultStore, generate_kek};
use std::sync::Arc;

fn setup() -> (Arc<VaultStore>, Resolver) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
    let resolver = Resolver::new(vault.clone());
    (vault, resolver)
}

#[test]
fn consent_denied_by_default() {
    let (vault, resolver) = setup();

    let pii_ref = vault
        .store_pii(PiiType::Email, "secret@test.com", None, None)
        .unwrap();

    let result = resolver.resolve(&pii_ref, "claude", "send_email");
    assert!(result.is_err());
}

#[test]
fn consent_grant_then_resolve() {
    let (vault, resolver) = setup();

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
fn wildcard_consent() {
    let (vault, resolver) = setup();

    let pii_ref = vault
        .store_pii(PiiType::Name, "John Smith", None, None)
        .unwrap();

    ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "*", "*", None).unwrap();

    let result = resolver
        .resolve(&pii_ref, "any_tool", "any_purpose")
        .unwrap();
    assert!(result.granted);
    assert_eq!(result.value.unwrap(), "John Smith");
}

#[test]
fn resolve_text_mixed_consent() {
    let (vault, resolver) = setup();

    let email_ref = vault
        .store_pii(PiiType::Email, "user@test.com", None, None)
        .unwrap();
    let phone_ref = vault
        .store_pii(PiiType::Phone, "555-9999", None, None)
        .unwrap();

    ConsentManager::grant_consent(vault.conn(), &email_ref.key(), "claude", "compose", None)
        .unwrap();

    let text = format!("Send to {} at {}", email_ref.display(), phone_ref.display());
    let result = resolver.resolve_text(&text, "claude", "compose").unwrap();

    assert!(result.resolved_text.contains("user@test.com"));
    assert!(result.resolved_text.contains(&phone_ref.display()));
    assert_eq!(result.resolved.len(), 1);
    assert_eq!(result.denied.len(), 1);
}

#[test]
fn reveal_bypasses_consent() {
    let (vault, resolver) = setup();

    let pii_ref = vault
        .store_pii(PiiType::Ssn, "123-45-6789", None, None)
        .unwrap();

    let value = resolver.reveal(&pii_ref, "user requested").unwrap();
    assert_eq!(value, "123-45-6789");
}
