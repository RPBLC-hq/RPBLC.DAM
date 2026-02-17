//! Consent-checked PII resolution for outbound actions.
//!
//! The [`Resolver`] decrypts PII values only when explicit consent has been granted
//! for the requesting accessor and purpose. Every resolution attempt (granted or
//! denied) is recorded in the audit trail. [`DerivedEngine`] (Phase 3 stub) will
//! enable computations on encrypted values without exposing them.

pub mod derived;
pub mod resolver;

pub use derived::{DerivedEngine, DerivedOp, DerivedResult};
pub use resolver::{DeniedRef, ResolveResult, ResolveTextResult, Resolver};
