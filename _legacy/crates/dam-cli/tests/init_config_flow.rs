use dam_core::Locale;
use dam_core::PiiType;
use dam_core::config::{DamConfig, Sensitivity};
use dam_detect::DetectionPipeline;
use dam_vault::{VaultStore, generate_kek};
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn config_save_and_load_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let config = DamConfig::default();
    config.save(&path).unwrap();

    let loaded = DamConfig::load(&path).unwrap();
    assert_eq!(loaded.server.http_port, config.server.http_port);
    assert_eq!(loaded.detection.sensitivity, config.detection.sensitivity);
    assert_eq!(loaded.detection.locales, config.detection.locales);
}

#[test]
fn config_default_values() {
    let config = DamConfig::default();
    assert_eq!(config.detection.locales, Locale::defaults());
    assert_eq!(config.detection.sensitivity, Sensitivity::Standard);
    assert_eq!(config.server.http_port, 7828);
}

#[test]
fn config_set_locales_persists() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let mut config = DamConfig::default();
    config.detection.locales = vec![Locale::Global, Locale::Us, Locale::Ca];
    config.save(&path).unwrap();

    let loaded = DamConfig::load(&path).unwrap();
    assert_eq!(
        loaded.detection.locales,
        vec![Locale::Global, Locale::Us, Locale::Ca]
    );
}

#[test]
fn config_set_sensitivity_persists() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let mut config = DamConfig::default();
    config.detection.sensitivity = Sensitivity::Elevated;
    config.save(&path).unwrap();

    let loaded = DamConfig::load(&path).unwrap();
    assert_eq!(loaded.detection.sensitivity, Sensitivity::Elevated);
}

#[test]
fn config_locale_change_affects_detection() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.db");
    let vault = Arc::new(VaultStore::open(&vault_path, generate_kek()).unwrap());

    // Pipeline with Canada locale should detect SIN
    let mut config_ca = DamConfig::default();
    config_ca.detection.locales = vec![Locale::Global, Locale::Ca];
    let pipeline_ca = DetectionPipeline::new(&config_ca, vault.clone());
    let result_ca = pipeline_ca.scan("SIN: 130 692 544", None).unwrap();
    assert!(
        result_ca
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::Sin),
        "Ca locale should detect SIN"
    );

    // Pipeline with US-only locale should NOT detect SIN
    let mut config_us = DamConfig::default();
    config_us.detection.locales = vec![Locale::Global, Locale::Us];
    let pipeline_us = DetectionPipeline::new(&config_us, vault);
    let result_us = pipeline_us.scan("SIN: 130 692 544", None).unwrap();
    assert!(
        !result_us
            .detections
            .iter()
            .any(|d| d.pii_type == PiiType::Sin),
        "Us-only locale should not detect SIN"
    );
}

#[test]
fn config_load_missing_returns_defaults() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nonexistent.toml");

    let config = DamConfig::load(&path).unwrap();
    assert_eq!(config.detection.locales, Locale::defaults());
    assert_eq!(config.detection.sensitivity, Sensitivity::Standard);
    assert_eq!(config.server.http_port, 7828);
}
