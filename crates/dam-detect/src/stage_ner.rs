// Stage 3: NER-based detection (Phase 2, feature-gated behind "ner")
//
// This module will use the `ort` crate to run a small ONNX NER model
// for detecting PERSON, ORG, GPE, and LOC entities.
//
// Currently a stub that returns no detections.

use crate::stage_regex::Detection;

#[derive(Default)]
pub struct NerDetector;

impl NerDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, _text: &str) -> Vec<Detection> {
        // Phase 2: load ONNX model and run inference
        Vec::new()
    }
}
