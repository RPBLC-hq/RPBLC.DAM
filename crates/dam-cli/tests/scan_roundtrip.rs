use dam_core::PiiType;
use dam_detect::DetectionPipeline;
use dam_vault::{VaultStore, generate_kek};
use std::sync::Arc;

fn setup() -> (Arc<VaultStore>, DetectionPipeline) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
    let pipeline = DetectionPipeline::basic(vault.clone());
    (vault, pipeline)
}

#[test]
fn scan_and_retrieve_email() {
    let (vault, pipeline) = setup();

    let result = pipeline
        .scan("Email me at john@acme.com, SSN 123-45-6789", Some("test"))
        .unwrap();

    assert!(result.detections.len() >= 2);
    assert!(!result.redacted_text.contains("john@acme.com"));
    assert!(!result.redacted_text.contains("123-45-6789"));
    assert!(result.redacted_text.contains("[email:"));
    assert!(result.redacted_text.contains("[ssn:"));

    let email_detection = result
        .detections
        .iter()
        .find(|d| d.pii_type == PiiType::Email)
        .unwrap();

    let value = vault.retrieve_pii(&email_detection.pii_ref).unwrap();
    assert_eq!(value, "john@acme.com");
}

#[test]
fn scan_preserves_non_pii_text() {
    let (_, pipeline) = setup();

    let result = pipeline
        .scan("Hello world, how are you today?", None)
        .unwrap();

    assert!(result.detections.is_empty());
    assert_eq!(result.redacted_text, "Hello world, how are you today?");
}

#[test]
fn scan_dedup_same_value() {
    let (vault, pipeline) = setup();

    let result = pipeline
        .scan("Contact test@example.com or email test@example.com", None)
        .unwrap();

    let refs: Vec<_> = result.detections.iter().map(|d| d.pii_ref.key()).collect();
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0], refs[1]);

    let entries = vault.list_entries(None).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn scan_phone_number() {
    let (_, pipeline) = setup();

    let result = pipeline.scan("Call me at 555-123-4567", None).unwrap();

    assert!(!result.detections.is_empty());
    assert!(result.redacted_text.contains("[phone:"));
    assert!(!result.redacted_text.contains("555-123-4567"));
}
