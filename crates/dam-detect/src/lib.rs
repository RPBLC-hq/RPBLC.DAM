pub(crate) mod locales;
pub mod pipeline;
pub mod stage_ner;
pub mod stage_regex;
pub mod stage_rules;
pub mod stage_xref;
pub(crate) mod validators;

pub use pipeline::{DetectionPipeline, DetectionResult, ScanResult};
pub use stage_regex::Detection;
