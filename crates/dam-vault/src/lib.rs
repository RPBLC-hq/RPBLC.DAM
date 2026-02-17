//! Encrypted PII storage with envelope encryption, consent management, and audit logging.
//!
//! The vault stores PII values encrypted with per-entry AES-256-GCM keys (DEKs),
//! wrapped by a master key (KEK) from the OS keychain. Access is governed by
//! [`ConsentManager`] rules and every operation is recorded in a tamper-evident
//! [`AuditLog`] with SHA-256 hash chaining.

pub mod audit;
pub mod consent;
pub mod encryption;
pub mod keychain;
pub mod schema;
pub mod store;

pub use audit::{AuditEntry, AuditLog};
pub use consent::{ConsentManager, ConsentRule};
pub use encryption::{EnvelopeCrypto, generate_kek};
pub use keychain::KeychainManager;
pub use store::{VaultEntry, VaultStore};
