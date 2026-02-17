//! Shared types, error handling, configuration, and PII reference format.
//!
//! This is the foundation crate for DAM. It defines the core types used across
//! all other crates: [`PiiRef`] for typed references, [`PiiType`] for PII categories,
//! [`DamConfig`] for configuration, and [`DamError`] for unified error handling.

pub mod config;
pub mod error;
pub mod locale;
pub mod pii_type;
pub mod reference;

pub use config::DamConfig;
pub use error::{DamError, DamResult};
pub use locale::Locale;
pub use pii_type::PiiType;
pub use reference::PiiRef;
