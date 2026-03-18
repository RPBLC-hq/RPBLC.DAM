use dam_core::{DamConfig, Locale, PiiType};
use dam_detect::DetectionPipeline;
use dam_vault::{VaultStore, generate_kek};
use std::sync::Arc;
use tempfile::tempdir;

fn setup_with_locales(locales: Vec<Locale>) -> DetectionPipeline {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
    let mut config = DamConfig::default();
    config.detection.locales = locales;
    DetectionPipeline::new(&config, vault)
}

#[test]
fn locale_us_detects_ssn() {
    let pipeline = setup_with_locales(vec![Locale::Global, Locale::Us]);
    let result = pipeline.scan("SSN: 078-05-1120", None).unwrap();
    assert!(
        result.detections.iter().any(|d| d.pii_type == PiiType::Ssn),
        "expected SSN detection, got: {:?}",
        result
            .detections
            .iter()
            .map(|d| d.pii_type)
            .collect::<Vec<_>>()
    );
}

#[test]
fn locale_ca_detects_sin() {
    let pipeline = setup_with_locales(vec![Locale::Global, Locale::Ca]);
    let result = pipeline.scan("SIN: 130 692 544", None).unwrap();
    assert!(
        result.detections.iter().any(|d| d.pii_type == PiiType::Sin),
        "expected SIN detection, got: {:?}",
        result
            .detections
            .iter()
            .map(|d| d.pii_type)
            .collect::<Vec<_>>()
    );
}

#[test]
fn locale_uk_detects_nhs() {
    let pipeline = setup_with_locales(vec![Locale::Global, Locale::Uk]);
    let result = pipeline.scan("NHS: 943 476 5919", None).unwrap();
    assert!(
        result
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::NhsNumber),
        "expected NhsNumber detection, got: {:?}",
        result
            .detections
            .iter()
            .map(|d| d.pii_type)
            .collect::<Vec<_>>()
    );
}

#[test]
fn locale_fr_detects_insee() {
    let pipeline = setup_with_locales(vec![Locale::Global, Locale::Fr]);
    let result = pipeline.scan("NIR: 185057800608491", None).unwrap();
    assert!(
        result
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::InseeNir),
        "expected InseeNir detection, got: {:?}",
        result
            .detections
            .iter()
            .map(|d| d.pii_type)
            .collect::<Vec<_>>()
    );
}

#[test]
fn locale_de_detects_steuer_id() {
    let pipeline = setup_with_locales(vec![Locale::Global, Locale::De]);
    let result = pipeline.scan("Steuer-ID: 65929970489", None).unwrap();
    assert!(
        result
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::TaxId),
        "expected TaxId detection, got: {:?}",
        result
            .detections
            .iter()
            .map(|d| d.pii_type)
            .collect::<Vec<_>>()
    );
}

#[test]
fn locale_multi_us_eu() {
    let pipeline = setup_with_locales(vec![Locale::Global, Locale::Us, Locale::Eu]);
    let result = pipeline
        .scan("SSN 078-05-1120, VAT DE123456789", None)
        .unwrap();

    let types: Vec<PiiType> = result.detections.iter().map(|d| d.pii_type).collect();
    assert!(types.contains(&PiiType::Ssn), "expected SSN in {:?}", types);
    assert!(
        types.contains(&PiiType::VatNumber),
        "expected VatNumber in {:?}",
        types
    );
}

#[test]
fn locale_empty_string() {
    let pipeline = setup_with_locales(Locale::defaults());
    let result = pipeline.scan("", None).unwrap();
    assert!(result.detections.is_empty());
    assert_eq!(result.redacted_text, "");
}
