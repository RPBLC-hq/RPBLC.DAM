use crate::store::VaultStore;
use dam_core::{DamError, SensitiveDataType, Token};

/// Maximum number of token generation retries on ID collision.
const MAX_RETRIES: usize = 5;

/// Mint a token for a sensitive value, storing it in the vault.
///
/// 1. Attempt to store the value (dedup check happens inside `VaultStore::store`).
/// 2. If the store returns an existing token (dedup hit), return it.
/// 3. If a collision occurs on the generated ref_id (extremely unlikely),
///    retry up to `MAX_RETRIES` times.
pub fn mint_token(
    store: &VaultStore,
    data_type: SensitiveDataType,
    plaintext: &str,
) -> Result<Token, DamError> {
    let mut last_err = None;

    for attempt in 0..MAX_RETRIES {
        match store.store(data_type, plaintext) {
            Ok(token) => return Ok(token),
            Err(DamError::Db(ref msg)) if msg.contains("UNIQUE constraint") => {
                // Token ID collision — retry with a new random ID
                tracing::warn!(
                    attempt,
                    data_type = data_type.tag(),
                    "token ID collision, retrying"
                );
                last_err = Some(DamError::Db(msg.clone()));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        DamError::Db(format!("failed to mint token after {MAX_RETRIES} retries"))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::generate_kek;
    use crate::store::VaultStore;

    fn temp_store() -> (tempfile::TempDir, VaultStore) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("mint_test.db");
        let kek = generate_kek();
        let store = VaultStore::open(&db_path, kek).unwrap();
        (dir, store)
    }

    #[test]
    fn test_mint_token_basic() {
        let (_dir, store) = temp_store();

        let token = mint_token(&store, SensitiveDataType::Email, "mint@test.com").unwrap();
        assert_eq!(token.data_type, SensitiveDataType::Email);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_mint_token_dedup() {
        let (_dir, store) = temp_store();

        let t1 = mint_token(&store, SensitiveDataType::Email, "dedup@test.com").unwrap();
        let t2 = mint_token(&store, SensitiveDataType::Email, "dedup@test.com").unwrap();

        assert_eq!(t1.key(), t2.key());
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_mint_token_different_values() {
        let (_dir, store) = temp_store();

        let t1 = mint_token(&store, SensitiveDataType::Email, "a@test.com").unwrap();
        let t2 = mint_token(&store, SensitiveDataType::Email, "b@test.com").unwrap();

        assert_ne!(t1.key(), t2.key());
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_mint_token_retrieve_roundtrip() {
        let (_dir, store) = temp_store();

        let token = mint_token(&store, SensitiveDataType::Phone, "+15551234567").unwrap();
        let value = store.retrieve(&token).unwrap();
        assert_eq!(value, "+15551234567");
    }

    #[test]
    fn test_mint_multiple_types() {
        let (_dir, store) = temp_store();

        let te = mint_token(&store, SensitiveDataType::Email, "x@x.com").unwrap();
        let tp = mint_token(&store, SensitiveDataType::Phone, "+15551234567").unwrap();
        let ts = mint_token(&store, SensitiveDataType::Ssn, "123-45-6789").unwrap();

        assert_eq!(te.data_type, SensitiveDataType::Email);
        assert_eq!(tp.data_type, SensitiveDataType::Phone);
        assert_eq!(ts.data_type, SensitiveDataType::Ssn);
        assert_eq!(store.count().unwrap(), 3);
    }
}
