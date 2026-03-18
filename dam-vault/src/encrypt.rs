use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use dam_core::DamError;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// 12-byte nonce for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Combined IV: 12 bytes for data encryption + 12 bytes for KEK wrapping.
const IV_LEN: usize = NONCE_LEN * 2;

/// An encrypted vault entry produced by envelope encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    /// Ciphertext of the original plaintext, encrypted with the DEK.
    pub ciphertext: Vec<u8>,
    /// The DEK encrypted (wrapped) with the KEK.
    pub dek_encrypted: Vec<u8>,
    /// 24 bytes: first 12 = data nonce, last 12 = KEK-wrap nonce.
    pub iv: Vec<u8>,
}

/// AES-256-GCM envelope encryption.
///
/// Each plaintext gets its own random DEK (Data Encryption Key).
/// The DEK encrypts the data, then the KEK (Key Encryption Key) wraps the DEK.
pub struct EnvelopeCrypto {
    kek: [u8; 32],
}

impl EnvelopeCrypto {
    pub fn new(kek: [u8; 32]) -> Self {
        Self { kek }
    }

    /// Encrypt plaintext using envelope encryption.
    ///
    /// 1. Generate a random 32-byte DEK.
    /// 2. Encrypt plaintext with DEK (AES-256-GCM).
    /// 3. Wrap (encrypt) the DEK with the KEK.
    /// 4. Return ciphertext, wrapped DEK, and combined IV.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedEntry, DamError> {
        // Generate random DEK
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);

        // Generate nonces
        let mut data_nonce_bytes = [0u8; NONCE_LEN];
        let mut kek_nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut data_nonce_bytes);
        OsRng.fill_bytes(&mut kek_nonce_bytes);

        let data_nonce = Nonce::from_slice(&data_nonce_bytes);
        let kek_nonce = Nonce::from_slice(&kek_nonce_bytes);

        // Encrypt plaintext with DEK
        let data_cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| DamError::Encryption(format!("DEK cipher init: {e}")))?;
        let ciphertext = data_cipher
            .encrypt(data_nonce, plaintext)
            .map_err(|e| DamError::Encryption(format!("data encrypt: {e}")))?;

        // Wrap DEK with KEK
        let kek_cipher = Aes256Gcm::new_from_slice(&self.kek)
            .map_err(|e| DamError::Encryption(format!("KEK cipher init: {e}")))?;
        let dek_encrypted = kek_cipher
            .encrypt(kek_nonce, dek.as_ref())
            .map_err(|e| DamError::Encryption(format!("DEK wrap: {e}")))?;

        // Zeroize DEK
        let mut dek = dek;
        dek.zeroize();

        // Combine nonces into IV
        let mut iv = Vec::with_capacity(IV_LEN);
        iv.extend_from_slice(&data_nonce_bytes);
        iv.extend_from_slice(&kek_nonce_bytes);

        Ok(EncryptedEntry {
            ciphertext,
            dek_encrypted,
            iv,
        })
    }

    /// Decrypt an encrypted entry.
    ///
    /// 1. Unwrap the DEK using the KEK.
    /// 2. Decrypt the ciphertext using the DEK.
    pub fn decrypt(&self, entry: &EncryptedEntry) -> Result<Vec<u8>, DamError> {
        if entry.iv.len() != IV_LEN {
            return Err(DamError::Encryption(format!(
                "invalid IV length: expected {IV_LEN}, got {}",
                entry.iv.len()
            )));
        }

        let data_nonce = Nonce::from_slice(&entry.iv[..NONCE_LEN]);
        let kek_nonce = Nonce::from_slice(&entry.iv[NONCE_LEN..]);

        // Unwrap DEK
        let kek_cipher = Aes256Gcm::new_from_slice(&self.kek)
            .map_err(|e| DamError::Encryption(format!("KEK cipher init: {e}")))?;
        let mut dek_bytes = kek_cipher
            .decrypt(kek_nonce, entry.dek_encrypted.as_ref())
            .map_err(|e| DamError::Encryption(format!("DEK unwrap: {e}")))?;

        // Decrypt ciphertext
        let data_cipher = Aes256Gcm::new_from_slice(&dek_bytes)
            .map_err(|e| DamError::Encryption(format!("DEK cipher init: {e}")))?;
        let plaintext = data_cipher
            .decrypt(data_nonce, entry.ciphertext.as_ref())
            .map_err(|e| DamError::Encryption(format!("data decrypt: {e}")))?;

        dek_bytes.zeroize();

        Ok(plaintext)
    }
}

/// Generate a random 32-byte KEK.
pub fn generate_kek() -> [u8; 32] {
    let mut kek = [0u8; 32];
    OsRng.fill_bytes(&mut kek);
    kek
}

/// Save a KEK to a file with 0600 permissions.
pub fn save_kek(path: &std::path::Path, kek: &[u8; 32]) -> Result<(), DamError> {
    use std::io::Write;

    // Write data first
    let mut file = std::fs::File::create(path)?;
    file.write_all(kek)?;
    file.sync_all()?;

    // Set permissions to owner-only read/write (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Load a KEK from a file.
pub fn load_kek(path: &std::path::Path) -> Result<[u8; 32], DamError> {
    let data = std::fs::read(path)?;
    if data.len() != 32 {
        return Err(DamError::Encryption(format!(
            "KEK file has invalid length: expected 32, got {}",
            data.len()
        )));
    }
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&data);
    Ok(kek)
}

/// Load a KEK from a file if it exists, otherwise generate and save a new one.
pub fn load_or_generate_kek(path: &std::path::Path) -> Result<[u8; 32], DamError> {
    if path.exists() {
        load_kek(path)
    } else {
        let kek = generate_kek();
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        save_kek(path, &kek)?;
        Ok(kek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);
        let plaintext = b"hello@example.com";

        let entry = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&entry).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);
        let plaintext = b"";

        let entry = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&entry).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);
        let plaintext = vec![0xABu8; 10_000];

        let entry = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&entry).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_iv_length() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let entry = crypto.encrypt(b"test").unwrap();
        assert_eq!(entry.iv.len(), IV_LEN);
    }

    #[test]
    fn test_different_kek_cannot_decrypt() {
        let kek1 = generate_kek();
        let kek2 = generate_kek();
        let crypto1 = EnvelopeCrypto::new(kek1);
        let crypto2 = EnvelopeCrypto::new(kek2);

        let entry = crypto1.encrypt(b"secret").unwrap();
        let result = crypto2.decrypt(&entry);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let mut entry = crypto.encrypt(b"secret").unwrap();
        // Flip a byte
        if let Some(byte) = entry.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = crypto.decrypt(&entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_dek_fails() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let mut entry = crypto.encrypt(b"secret").unwrap();
        if let Some(byte) = entry.dek_encrypted.first_mut() {
            *byte ^= 0xFF;
        }

        let result = crypto.decrypt(&entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_iv_length() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let entry = EncryptedEntry {
            ciphertext: vec![0; 32],
            dek_encrypted: vec![0; 48],
            iv: vec![0; 10], // Wrong length
        };

        let result = crypto.decrypt(&entry);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid IV length"));
    }

    #[test]
    fn test_each_encrypt_produces_unique_output() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);
        let plaintext = b"same data";

        let entry1 = crypto.encrypt(plaintext).unwrap();
        let entry2 = crypto.encrypt(plaintext).unwrap();

        // Different DEKs and nonces mean different ciphertexts
        assert_ne!(entry1.ciphertext, entry2.ciphertext);
        assert_ne!(entry1.dek_encrypted, entry2.dek_encrypted);
        assert_ne!(entry1.iv, entry2.iv);

        // But both decrypt to the same plaintext
        assert_eq!(crypto.decrypt(&entry1).unwrap(), plaintext);
        assert_eq!(crypto.decrypt(&entry2).unwrap(), plaintext);
    }

    #[test]
    fn test_generate_kek_uniqueness() {
        let k1 = generate_kek();
        let k2 = generate_kek();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_save_load_kek_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.kek");
        let kek = generate_kek();

        save_kek(&path, &kek).unwrap();
        let loaded = load_kek(&path).unwrap();

        assert_eq!(kek, loaded);
    }

    #[test]
    fn test_save_kek_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.kek");
        let kek = generate_kek();

        save_kek(&path, &kek).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_load_kek_invalid_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.kek");
        std::fs::write(&path, &[0u8; 16]).unwrap();

        let result = load_kek(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid length"));
    }

    #[test]
    fn test_load_kek_file_not_found() {
        let path = std::path::Path::new("/tmp/nonexistent_dam_test.kek");
        let result = load_kek(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_or_generate_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auto.kek");

        assert!(!path.exists());
        let kek = load_or_generate_kek(&path).unwrap();
        assert!(path.exists());

        // Loading again should return the same KEK
        let kek2 = load_or_generate_kek(&path).unwrap();
        assert_eq!(kek, kek2);
    }

    #[test]
    fn test_load_or_generate_loads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.kek");
        let kek = generate_kek();
        save_kek(&path, &kek).unwrap();

        let loaded = load_or_generate_kek(&path).unwrap();
        assert_eq!(kek, loaded);
    }

    #[test]
    fn test_load_or_generate_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("auto.kek");

        let kek = load_or_generate_kek(&path).unwrap();
        assert!(path.exists());
        assert_eq!(load_kek(&path).unwrap(), kek);
    }

    #[test]
    fn test_encrypt_decrypt_utf8() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);
        let plaintext = "Ren\u{00e9} M\u{00fc}ller, 42 Rue de l'\u{00c9}glise".as_bytes();

        let entry = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&entry).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(
            std::str::from_utf8(&decrypted).unwrap(),
            "Ren\u{00e9} M\u{00fc}ller, 42 Rue de l'\u{00c9}glise"
        );
    }
}
