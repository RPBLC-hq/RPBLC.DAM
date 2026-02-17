use dam_core::PiiType;
use dam_detect::DetectionPipeline;
use dam_vault::{VaultStore, generate_kek};
use std::sync::Arc;
use tempfile::tempdir;

fn setup() -> Arc<VaultStore> {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    Arc::new(VaultStore::open(&path, generate_kek()).unwrap())
}

#[test]
fn vault_open_invalid_path() {
    // Try to open vault at a path where the parent is an existing file (not a dir)
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("afile");
    std::fs::write(&file_path, "not a directory").unwrap();

    // Attempt to create vault inside a file (invalid path)
    let bad_path = file_path.join("vault.db");
    let result = VaultStore::open(&bad_path, generate_kek());
    assert!(
        result.is_err(),
        "opening vault with invalid parent should fail"
    );
}

#[test]
fn retrieve_nonexistent_ref() {
    let vault = setup();
    let fake_ref = dam_core::PiiRef::generate(PiiType::Email);

    let result = vault.retrieve_pii(&fake_ref);
    assert!(result.is_err());
    match result {
        Err(dam_core::DamError::ReferenceNotFound(_)) => {}
        other => panic!("expected ReferenceNotFound, got {:?}", other),
    }
}

#[test]
fn vault_empty_counts() {
    let vault = setup();
    assert_eq!(vault.entry_count().unwrap(), 0);
    assert!(vault.entry_counts_by_type().unwrap().is_empty());
}

#[test]
fn scan_pii_at_string_boundaries() {
    let vault = setup();
    let pipeline = DetectionPipeline::basic(vault);

    // PII at the very start
    let result = pipeline.scan("john@start.com is my email", None).unwrap();
    assert!(
        result
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::Email),
        "should detect email at string start"
    );
    assert!(!result.redacted_text.contains("john@start.com"));

    // PII at the very end
    let result = pipeline
        .scan("contact me at end@boundary.com", None)
        .unwrap();
    assert!(
        result
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::Email),
        "should detect email at string end"
    );
    assert!(!result.redacted_text.contains("end@boundary.com"));
}
