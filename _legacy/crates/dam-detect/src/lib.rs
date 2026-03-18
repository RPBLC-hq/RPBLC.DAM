//! PII detection pipeline: regex patterns, validators, and locale-specific rules.
//!
//! Text flows through a multi-stage pipeline: regex detection with normalization
//! (zero-width stripping, NFKC, URL/Base64 decoding), user-defined rules, and
//! stubs for NER and vault cross-reference. Detected values are validated per type
//! (Luhn for credit cards, Mod97 for IBANs, etc.) and stored in the vault.

pub(crate) mod locales;
pub mod pipeline;
#[cfg(test)]
mod qa_european;
pub mod stage_ner;
pub mod stage_regex;
pub mod stage_rules;
pub mod stage_xref;
pub(crate) mod validators;

pub use pipeline::{DetectionPipeline, DetectionResult, ScanResult};
pub use stage_regex::Detection;
