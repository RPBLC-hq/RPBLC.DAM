// Stage 4: Vault cross-reference (Phase 2)
//
// Compares text segments against known vault entries for partial matches.
// E.g., if vault has "John Smith", flag "John" in new text.
//
// Currently a stub that returns no detections.

use crate::stage_regex::Detection;

/// Vault cross-reference detector (Phase 2 stub).
///
/// Will compare text segments against known vault entries for partial matches.
/// Currently returns no detections.
#[derive(Default)]
pub struct XrefDetector;

impl XrefDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, _text: &str) -> Vec<Detection> {
        // Phase 2: compare against known vault entries
        Vec::new()
    }
}
