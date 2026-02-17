use dam_core::PiiType;
use dam_vault::{VaultStore, generate_kek};
use std::sync::Arc;
use tempfile::tempdir;

fn setup() -> (Arc<VaultStore>, [u8; 32], std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let kek = generate_kek();
    let vault = Arc::new(VaultStore::open(&path, kek).unwrap());
    (vault, kek, path)
}

#[test]
fn vault_persist_across_reopen() {
    let (vault, kek, path) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "persist@test.com", None, None)
        .unwrap();

    // Drop the original vault to release the DB connection
    drop(vault);

    // Reopen with the same KEK and path
    let vault2 = VaultStore::open(&path, kek).unwrap();
    let value = vault2.retrieve_pii(&pii_ref).unwrap();
    assert_eq!(value, "persist@test.com");
}

#[test]
fn vault_list_returns_metadata() {
    let (vault, _, _) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "meta@test.com", Some("test-source"), None)
        .unwrap();

    let entries = vault.list_entries(None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ref_id, pii_ref.key());
    assert_eq!(entries[0].pii_type, PiiType::Email);
    // Metadata should not contain the plaintext value
    assert_ne!(entries[0].ref_id, "meta@test.com");
}

#[test]
fn vault_list_type_filter() {
    let (vault, _, _) = setup();
    vault
        .store_pii(PiiType::Email, "a@test.com", None, None)
        .unwrap();
    vault
        .store_pii(PiiType::Email, "b@test.com", None, None)
        .unwrap();
    vault
        .store_pii(PiiType::Phone, "5551234567", None, None)
        .unwrap();

    let emails = vault.list_entries(Some(PiiType::Email)).unwrap();
    assert_eq!(emails.len(), 2);
    assert!(emails.iter().all(|e| e.pii_type == PiiType::Email));

    let phones = vault.list_entries(Some(PiiType::Phone)).unwrap();
    assert_eq!(phones.len(), 1);
}

#[test]
fn vault_show_decrypts_value() {
    let (vault, _, _) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "decryptme@test.com", None, None)
        .unwrap();

    let value = vault.retrieve_pii(&pii_ref).unwrap();
    assert_eq!(value, "decryptme@test.com");
}

#[test]
fn vault_delete_then_retrieve_fails() {
    let (vault, _, _) = setup();
    let pii_ref = vault
        .store_pii(PiiType::Email, "gone@test.com", None, None)
        .unwrap();

    vault.delete_entry(&pii_ref).unwrap();

    let result = vault.retrieve_pii(&pii_ref);
    assert!(result.is_err());
    match result {
        Err(dam_core::DamError::ReferenceNotFound(_)) => {}
        other => panic!("expected ReferenceNotFound, got {:?}", other),
    }
}

#[test]
fn vault_empty_list() {
    let (vault, _, _) = setup();
    let entries = vault.list_entries(None).unwrap();
    assert!(entries.is_empty());
}
