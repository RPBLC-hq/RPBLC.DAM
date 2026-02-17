use dam_core::PiiType;
use dam_detect::DetectionPipeline;
use dam_resolve::Resolver;
use dam_vault::{AuditLog, ConsentManager, VaultStore, generate_kek};
use std::sync::Arc;
use tempfile::tempdir;

fn setup() -> (Arc<VaultStore>, Resolver) {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
    let resolver = Resolver::new(vault.clone());
    (vault, resolver)
}

#[test]
fn consent_does_not_bleed_across_refs() {
    let (vault, resolver) = setup();
    let ref_a = vault
        .store_pii(PiiType::Email, "a@test.com", None, None)
        .unwrap();
    let ref_b = vault
        .store_pii(PiiType::Email, "b@test.com", None, None)
        .unwrap();

    // Grant consent only for ref A
    ConsentManager::grant_consent(vault.conn(), &ref_a.key(), "claude", "send", None).unwrap();

    // Resolve A should succeed
    assert!(resolver.resolve(&ref_a, "claude", "send").is_ok());

    // Resolve B should be denied
    let result = resolver.resolve(&ref_b, "claude", "send");
    assert!(result.is_err());
    match result {
        Err(dam_core::DamError::ConsentDenied { .. }) => {}
        other => panic!("expected ConsentDenied for ref_b, got {:?}", other),
    }
}

#[test]
fn consent_does_not_bleed_across_accessors() {
    let (vault, resolver) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "accessor@test.com", None, None)
        .unwrap();

    // Grant consent for "claude" only
    ConsentManager::grant_consent(vault.conn(), &pii_ref.key(), "claude", "send", None).unwrap();

    // "claude" can resolve
    assert!(resolver.resolve(&pii_ref, "claude", "send").is_ok());

    // "other" cannot
    let result = resolver.resolve(&pii_ref, "other", "send");
    assert!(result.is_err());
    match result {
        Err(dam_core::DamError::ConsentDenied { .. }) => {}
        other => panic!("expected ConsentDenied for 'other', got {:?}", other),
    }
}

#[test]
fn resolve_denied_keeps_ref_format() {
    let (vault, resolver) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "keep-ref@test.com", None, None)
        .unwrap();

    let text = format!("Contact {}", pii_ref.display());
    let result = resolver.resolve_text(&text, "claude", "send").unwrap();

    // Denied ref should remain in [type:id] format
    assert!(
        result.resolved_text.contains(&pii_ref.display()),
        "denied ref should remain as-is in resolved text"
    );
    assert!(!result.resolved_text.contains("keep-ref@test.com"));
}

#[test]
fn wrong_kek_cannot_decrypt() {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let kek1 = generate_kek();

    let vault1 = VaultStore::open(&path, kek1).unwrap();
    let pii_ref = vault1
        .store_pii(PiiType::Email, "secret@test.com", None, None)
        .unwrap();
    drop(vault1);

    // Reopen with a different KEK
    let kek2 = generate_kek();
    let vault2 = VaultStore::open(&path, kek2).unwrap();
    let result = vault2.retrieve_pii(&pii_ref);
    assert!(
        result.is_err(),
        "decryption with wrong KEK should fail, but got: {:?}",
        result
    );
}

#[test]
fn reveal_audited_without_consent_rules() {
    let (vault, resolver) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "reveal-no-consent@test.com", None, None)
        .unwrap();

    // No consent rules exist — reveal should still work and be audited
    let value = resolver.reveal(&pii_ref, "emergency").unwrap();
    assert_eq!(value, "reveal-no-consent@test.com");

    let entries = AuditLog::query(vault.conn(), Some(&pii_ref.key()), 100).unwrap();
    assert!(
        entries.iter().any(|e| e.action == "reveal"),
        "reveal should create an audit entry"
    );
}

#[test]
fn scan_redacted_text_has_no_pii() {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
    let pipeline = DetectionPipeline::basic(vault);

    let raw_email = "visible@example.com";
    let result = pipeline
        .scan(&format!("Contact {raw_email} for info"), None)
        .unwrap();

    assert!(
        !result.redacted_text.contains(raw_email),
        "redacted text should not contain original PII value"
    );
    assert!(result.redacted_text.contains("[email:"));
}

#[test]
fn deleted_ref_reveal_fails() {
    let (vault, resolver) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "delete-reveal@test.com", None, None)
        .unwrap();

    vault.delete_entry(&pii_ref).unwrap();

    let result = resolver.reveal(&pii_ref, "attempt after delete");
    assert!(result.is_err());
    match result {
        Err(dam_core::DamError::ReferenceNotFound(_)) => {}
        other => panic!("expected ReferenceNotFound, got {:?}", other),
    }
}

#[test]
fn delete_also_removes_consent() {
    let (vault, _) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "delete-consent@test.com", None, None)
        .unwrap();
    let key = pii_ref.key();

    // Grant consent
    ConsentManager::grant_consent(vault.conn(), &key, "claude", "send", None).unwrap();
    assert!(ConsentManager::check_consent(vault.conn(), &key, "claude", "send").unwrap());

    // Delete entry (should also remove consent)
    vault.delete_entry(&pii_ref).unwrap();

    // Consent should be gone
    assert!(!ConsentManager::check_consent(vault.conn(), &key, "claude", "send").unwrap());
}
