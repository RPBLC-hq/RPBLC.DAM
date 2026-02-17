use dam_core::PiiType;
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
fn store_creates_audit_entry() {
    let (vault, _) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "audit@test.com", None, None)
        .unwrap();

    let entries = AuditLog::query(vault.conn(), Some(&pii_ref.key()), 100).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.action == "create" && e.accessor == "system"),
        "expected 'create' audit entry, got: {:?}",
        entries.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
}

#[test]
fn delete_creates_audit_entry() {
    let (vault, _) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "delete-audit@test.com", None, None)
        .unwrap();
    let key = pii_ref.key();

    vault.delete_entry(&pii_ref).unwrap();

    let entries = AuditLog::query(vault.conn(), Some(&key), 100).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.action == "delete" && e.accessor == "system"),
        "expected 'delete' audit entry, got: {:?}",
        entries.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
}

#[test]
fn full_lifecycle_audit_trail() {
    let (vault, resolver) = setup();

    // 1. Store
    let pii_ref = vault
        .store_pii(PiiType::Email, "lifecycle@test.com", None, None)
        .unwrap();
    let key = pii_ref.key();

    // 2. Attempt resolve without consent (denied)
    let _ = resolver.resolve(&pii_ref, "claude", "send");

    // 3. Grant consent
    ConsentManager::grant_consent(vault.conn(), &key, "claude", "send", None).unwrap();

    // 4. Resolve with consent (granted)
    resolver.resolve(&pii_ref, "claude", "send").unwrap();

    // 5. Reveal
    resolver.reveal(&pii_ref, "user request").unwrap();

    let entries = AuditLog::query(vault.conn(), Some(&key), 100).unwrap();
    // Entries are returned in DESC order; reverse for chronological
    let actions: Vec<&str> = entries.iter().rev().map(|e| e.action.as_str()).collect();

    assert!(
        actions.contains(&"create"),
        "missing 'create' in {:?}",
        actions
    );
    assert!(
        actions.contains(&"denied"),
        "missing 'denied' in {:?}",
        actions
    );
    assert!(
        actions.contains(&"resolve"),
        "missing 'resolve' in {:?}",
        actions
    );
    assert!(
        actions.contains(&"reveal"),
        "missing 'reveal' in {:?}",
        actions
    );
    assert!(
        actions.len() >= 4,
        "expected at least 4 audit entries, got {}",
        actions.len()
    );
}

#[test]
fn audit_entries_contain_refs_not_values() {
    let (vault, _) = setup();
    let raw_pii = "sensitive@example.com";
    let pii_ref = vault
        .store_pii(PiiType::Email, raw_pii, None, None)
        .unwrap();

    let entries = AuditLog::query(vault.conn(), Some(&pii_ref.key()), 100).unwrap();

    for entry in &entries {
        assert!(
            !entry.ref_id.contains(raw_pii),
            "audit ref_id should not contain raw PII"
        );
        if let Some(detail) = &entry.detail {
            assert!(
                !detail.contains(raw_pii),
                "audit detail should not contain raw PII"
            );
        }
    }
}

#[test]
fn audit_query_filters_by_ref() {
    let (vault, _) = setup();
    let ref1 = vault
        .store_pii(PiiType::Email, "one@test.com", None, None)
        .unwrap();
    let _ref2 = vault
        .store_pii(PiiType::Email, "two@test.com", None, None)
        .unwrap();

    let entries = AuditLog::query(vault.conn(), Some(&ref1.key()), 100).unwrap();
    assert!(
        entries.iter().all(|e| e.ref_id == ref1.key()),
        "filter should only return entries for ref1"
    );
}

#[test]
fn grant_revoke_then_resolve_denied() {
    let (vault, resolver) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "revoke@test.com", None, None)
        .unwrap();
    let key = pii_ref.key();

    // Grant consent and resolve successfully
    ConsentManager::grant_consent(vault.conn(), &key, "claude", "send", None).unwrap();
    let result = resolver.resolve(&pii_ref, "claude", "send");
    assert!(result.is_ok());

    // Revoke consent
    ConsentManager::revoke_consent(vault.conn(), &key, "claude", "send").unwrap();

    // Resolve should now be denied
    let result = resolver.resolve(&pii_ref, "claude", "send");
    assert!(result.is_err());
    match result {
        Err(dam_core::DamError::ConsentDenied { .. }) => {}
        other => panic!("expected ConsentDenied, got {:?}", other),
    }
}
