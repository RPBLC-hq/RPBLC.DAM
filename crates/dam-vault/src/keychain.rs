use dam_core::DamError;
use zeroize::Zeroize;

const SERVICE_NAME: &str = "rpblc-dam";
const ACCOUNT_NAME: &str = "vault-kek";
const KEY_SIZE: usize = 32;

/// Manages the KEK (Key Encryption Key) via OS keychain or passphrase.
pub struct KeychainManager;

impl KeychainManager {
    /// Get or create a KEK from the OS keychain.
    ///
    /// If a key exists, returns it. Otherwise, generates a new random key and stores it.
    pub fn get_or_create_kek() -> Result<[u8; KEY_SIZE], DamError> {
        match Self::get_kek() {
            Ok(kek) => Ok(kek),
            Err(_) => {
                let kek = crate::encryption::generate_kek();
                Self::store_kek(&kek)?;
                Ok(kek)
            }
        }
    }

    /// Get the existing KEK from the OS keychain.
    pub fn get_kek() -> Result<[u8; KEY_SIZE], DamError> {
        let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map_err(|e| DamError::Keychain(e.to_string()))?;

        let secret = entry
            .get_password()
            .map_err(|e| DamError::Keychain(e.to_string()))?;

        let bytes = hex::decode(&secret)
            .map_err(|e| DamError::Keychain(format!("invalid key in keychain: {e}")))?;

        if bytes.len() != KEY_SIZE {
            return Err(DamError::Keychain(format!(
                "key in keychain has wrong length: {}",
                bytes.len()
            )));
        }

        let mut kek = [0u8; KEY_SIZE];
        kek.copy_from_slice(&bytes);
        Ok(kek)
    }

    /// Store a KEK in the OS keychain.
    pub fn store_kek(kek: &[u8; KEY_SIZE]) -> Result<(), DamError> {
        let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map_err(|e| DamError::Keychain(e.to_string()))?;

        let hex_key = hex::encode(kek);
        entry
            .set_password(&hex_key)
            .map_err(|e| DamError::Keychain(e.to_string()))?;

        Ok(())
    }

    /// Delete the KEK from the OS keychain.
    pub fn delete_kek() -> Result<(), DamError> {
        let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map_err(|e| DamError::Keychain(e.to_string()))?;

        entry
            .delete_credential()
            .map_err(|e| DamError::Keychain(e.to_string()))?;

        Ok(())
    }

    /// Derive a KEK from a passphrase using Argon2id.
    pub fn kek_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], DamError> {
        use argon2::Argon2;

        let mut kek = [0u8; KEY_SIZE];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
            .map_err(|e| DamError::Keychain(format!("argon2 error: {e}")))?;

        Ok(kek)
    }

    /// Derive a KEK from an environment variable.
    pub fn kek_from_env(var_name: &str) -> Result<[u8; KEY_SIZE], DamError> {
        let value = std::env::var(var_name)
            .map_err(|_| DamError::Keychain(format!("env var {var_name} not set")))?;

        let mut bytes = hex::decode(&value)
            .map_err(|e| DamError::Keychain(format!("env var {var_name} is not valid hex: {e}")))?;

        if bytes.len() != KEY_SIZE {
            bytes.zeroize();
            return Err(DamError::Keychain(format!(
                "env var {var_name} has wrong length: expected {KEY_SIZE} bytes"
            )));
        }

        let mut kek = [0u8; KEY_SIZE];
        kek.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(kek)
    }
}
