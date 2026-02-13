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
