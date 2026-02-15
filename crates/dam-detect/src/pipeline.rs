use crate::locales;
use crate::stage_regex::{self, Detection, Pattern};
use crate::stage_rules::RulesEngine;
use dam_core::{DamConfig, DamResult, Locale, PiiRef, PiiType};
use dam_vault::VaultStore;
use std::sync::Arc;

/// Result of scanning text for PII.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// The original text before redaction.
    pub original_text: String,
    /// The text with PII replaced by references.
    pub redacted_text: String,
    /// All PII detections found.
    pub detections: Vec<DetectionResult>,
}

/// A single detection with its vault reference.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub value: String,
    pub pii_type: PiiType,
    pub pii_ref: PiiRef,
    pub confidence: f32,
}

/// The full PII detection pipeline.
pub struct DetectionPipeline {
    rules_engine: RulesEngine,
    vault: Arc<VaultStore>,
    whitelist: Vec<String>,
    excluded_types: Vec<PiiType>,
    patterns: Vec<Pattern>,
}

impl DetectionPipeline {
    /// Create a new pipeline with the given config and vault.
    pub fn new(config: &DamConfig, vault: Arc<VaultStore>) -> Self {
        let rules_engine = RulesEngine::new(&config.detection.custom_rules);
        let patterns = locales::build_patterns(&config.detection.locales);

        Self {
            rules_engine,
            vault,
            whitelist: config.detection.whitelist.clone(),
            excluded_types: config.detection.excluded_types.clone(),
            patterns,
        }
    }

    /// Create a minimal pipeline (no custom rules, no whitelist).
    pub fn basic(vault: Arc<VaultStore>) -> Self {
        let patterns = locales::build_patterns(&Locale::defaults());

        Self {
            rules_engine: RulesEngine::empty(),
            vault,
            whitelist: Vec::new(),
            excluded_types: Vec::new(),
            patterns,
        }
    }

    /// Scan text for PII, store detections in vault, return redacted text.
    pub fn scan(&self, text: &str, source: Option<&str>) -> DamResult<ScanResult> {
        // Stage 1: Regex detection
        let mut detections = stage_regex::detect(text, &self.patterns);

        // Stage 2: User-defined rules
        if !self.rules_engine.is_empty() {
            detections.extend(self.rules_engine.detect(text));
        }

        // Stage 3: NER (Phase 2 stub — no-op)
        // Stage 4: Vault cross-reference (Phase 2 stub — no-op)

        // Filter out whitelisted terms
        detections.retain(|d| !self.is_whitelisted(&d.value));

        // Filter out excluded types
        detections.retain(|d| !self.excluded_types.contains(&d.pii_type));

        // Deduplicate overlapping spans (keep highest confidence)
        detections = deduplicate_spans(detections);

        // Store each detection in vault and build replacement map
        let mut results = Vec::new();
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();

        for detection in &detections {
            let pii_ref =
                self.vault
                    .store_pii(detection.pii_type, &detection.value, source, None)?;

            replacements.push((detection.start, detection.end, pii_ref.display()));

            results.push(DetectionResult {
                value: detection.value.clone(),
                pii_type: detection.pii_type,
                pii_ref,
                confidence: detection.confidence,
            });
        }

        // Build redacted text by replacing spans end-to-start (preserves offsets)
        let mut redacted = text.to_string();
        replacements.sort_by(|a, b| b.0.cmp(&a.0)); // reverse sort by start
        for (start, end, replacement) in &replacements {
            redacted.replace_range(*start..*end, replacement);
        }

        Ok(ScanResult {
            original_text: text.to_string(),
            redacted_text: redacted,
            detections: results,
        })
    }

    fn is_whitelisted(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        self.whitelist.iter().any(|w| w.to_lowercase() == lower)
    }
}

/// Remove overlapping detections, keeping the one with highest confidence.
fn deduplicate_spans(mut detections: Vec<Detection>) -> Vec<Detection> {
    if detections.is_empty() {
        return detections;
    }

    // Sort by start position, then by confidence descending
    detections.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.confidence.total_cmp(&a.confidence))
    });

    let mut result: Vec<Detection> = Vec::new();

    for detection in detections {
        let overlaps = result
            .iter()
            .any(|existing| detection.start < existing.end && detection.end > existing.start);

        if !overlaps {
            result.push(detection);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_vault::generate_kek;

    fn test_pipeline() -> DetectionPipeline {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
        DetectionPipeline::basic(vault)
    }

    #[test]
    fn scan_email_and_ssn() {
        let pipeline = test_pipeline();
        let result = pipeline
            .scan("Email me at john@acme.com, SSN 123-45-6789", None)
            .unwrap();

        assert_eq!(result.detections.len(), 2);
        assert!(result.redacted_text.contains("[email:"));
        assert!(result.redacted_text.contains("[ssn:"));
        assert!(!result.redacted_text.contains("john@acme.com"));
        assert!(!result.redacted_text.contains("123-45-6789"));
    }

    #[test]
    fn scan_no_pii() {
        let pipeline = test_pipeline();
        let result = pipeline.scan("Hello, this is normal text.", None).unwrap();
        assert!(result.detections.is_empty());
        assert_eq!(result.redacted_text, "Hello, this is normal text.");
    }

    #[test]
    fn scan_deduplication() {
        let pipeline = test_pipeline();
        let result = pipeline
            .scan("Contact test@test.com or test@test.com", None)
            .unwrap();
        // Both occurrences detected but map to same vault entry
        assert_eq!(result.detections.len(), 2);
        // But they should reference the same vault entry (dedup)
        assert_eq!(
            result.detections[0].pii_ref.key(),
            result.detections[1].pii_ref.key()
        );
    }
}
