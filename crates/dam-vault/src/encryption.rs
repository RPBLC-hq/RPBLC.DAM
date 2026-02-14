use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use dam_core::DamError;
use rand::RngCore;
use zeroize::Zeroize;

/// Size of the AES-256 key in bytes.
const KEY_SIZE: usize = 32;
/// Size of the AES-GCM nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Result of encrypting a PII value with envelope encryption.
pub struct EncryptedEntry {
    pub ciphertext: Vec<u8>,
    pub dek_encrypted: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Envelope encryption: each entry gets its own DEK, wrapped by the KEK.
pub struct EnvelopeCrypto {
    kek: [u8; KEY_SIZE],
}

impl EnvelopeCrypto {
    pub fn new(kek: [u8; KEY_SIZE]) -> Self {
        Self { kek }
    }

    /// Encrypt a plaintext PII value.
    ///
    /// 1. Generate random DEK
    /// 2. Encrypt value with DEK (AES-256-GCM)
    /// 3. Encrypt DEK with KEK (AES-256-GCM)
    /// 4. Zeroize DEK from memory
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedEntry, DamError> {
        // Generate random DEK
        let mut dek = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut dek);

        // Generate random IV for the data
        let mut data_iv = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut data_iv);

        // Encrypt the value with DEK
        let data_cipher =
            Aes256Gcm::new_from_slice(&dek).map_err(|e| DamError::Encryption(e.to_string()))?;
        let data_nonce = Nonce::from_slice(&data_iv);
        let ciphertext = data_cipher
            .encrypt(data_nonce, plaintext)
            .map_err(|e| DamError::Encryption(e.to_string()))?;

        // Generate random IV for the DEK wrapping
        let mut kek_iv = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut kek_iv);

        // Wrap DEK with KEK
        let kek_cipher = Aes256Gcm::new_from_slice(&self.kek)
            .map_err(|e| DamError::Encryption(e.to_string()))?;
        let kek_nonce = Nonce::from_slice(&kek_iv);
        let dek_encrypted = kek_cipher
            .encrypt(kek_nonce, dek.as_ref())
            .map_err(|e| DamError::Encryption(e.to_string()))?;

        // Zeroize the DEK
        dek.zeroize();

        // IV = data_iv || kek_iv (24 bytes total)
        let mut iv = Vec::with_capacity(NONCE_SIZE * 2);
        iv.extend_from_slice(&data_iv);
        iv.extend_from_slice(&kek_iv);

        Ok(EncryptedEntry {
            ciphertext,
            dek_encrypted,
            iv,
        })
    }

    /// Decrypt a PII value.
    ///
    /// 1. Unwrap DEK with KEK
    /// 2. Decrypt value with DEK
    /// 3. Zeroize DEK from memory
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        dek_encrypted: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, DamError> {
        if iv.len() != NONCE_SIZE * 2 {
            return Err(DamError::Encryption(format!(
                "invalid IV length: expected {}, got {}",
                NONCE_SIZE * 2,
                iv.len()
            )));
        }

        let data_iv = &iv[..NONCE_SIZE];
        let kek_iv = &iv[NONCE_SIZE..];

        // Unwrap DEK with KEK
        let kek_cipher = Aes256Gcm::new_from_slice(&self.kek)
            .map_err(|e| DamError::Encryption(e.to_string()))?;
        let kek_nonce = Nonce::from_slice(kek_iv);
        let mut dek_bytes = kek_cipher
            .decrypt(kek_nonce, dek_encrypted)
            .map_err(|e| DamError::Encryption(format!("KEK decryption failed: {e}")))?;

        // Decrypt value with DEK
        let data_cipher = Aes256Gcm::new_from_slice(&dek_bytes)
            .map_err(|e| DamError::Encryption(e.to_string()))?;
        let data_nonce = Nonce::from_slice(data_iv);
        let plaintext = data_cipher
            .decrypt(data_nonce, ciphertext)
            .map_err(|e| DamError::Encryption(format!("DEK decryption failed: {e}")))?;

        // Zeroize the DEK
        dek_bytes.zeroize();

        Ok(plaintext)
    }
}

impl Drop for EnvelopeCrypto {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

/// Generate a random 256-bit key suitable for use as a KEK.
pub fn generate_kek() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let plaintext = b"john@example.com";
        let encrypted = crypto.encrypt(plaintext).unwrap();

        let decrypted = crypto
            .decrypt(
                &encrypted.ciphertext,
                &encrypted.dek_encrypted,
                &encrypted.iv,
            )
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_encryptions_produce_different_output() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let plaintext = b"test@test.com";
        let e1 = crypto.encrypt(plaintext).unwrap();
        let e2 = crypto.encrypt(plaintext).unwrap();

        assert_ne!(e1.ciphertext, e2.ciphertext);
        assert_ne!(e1.iv, e2.iv);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek1 = generate_kek();
        let kek2 = generate_kek();
        let crypto1 = EnvelopeCrypto::new(kek1);
        let crypto2 = EnvelopeCrypto::new(kek2);

        let encrypted = crypto1.encrypt(b"secret").unwrap();
        let result = crypto2.decrypt(
            &encrypted.ciphertext,
            &encrypted.dek_encrypted,
            &encrypted.iv,
        );
        assert!(result.is_err());
    }

    // --- Edge cases ---

    #[test]
    fn encrypt_empty_plaintext() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let encrypted = crypto.encrypt(b"").unwrap();
        let decrypted = crypto
            .decrypt(&encrypted.ciphertext, &encrypted.dek_encrypted, &encrypted.iv)
            .unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_payload() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let large = vec![b'x'; 100_000];
        let encrypted = crypto.encrypt(&large).unwrap();
        let decrypted = crypto
            .decrypt(&encrypted.ciphertext, &encrypted.dek_encrypted, &encrypted.iv)
            .unwrap();
        assert_eq!(decrypted, large);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let encrypted = crypto.encrypt(b"sensitive data").unwrap();
        let mut tampered = encrypted.ciphertext.clone();
        tampered[0] ^= 0xff;

        let result = crypto.decrypt(&tampered, &encrypted.dek_encrypted, &encrypted.iv);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_iv_fails() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let encrypted = crypto.encrypt(b"sensitive data").unwrap();
        let mut tampered_iv = encrypted.iv.clone();
        tampered_iv[0] ^= 0xff;

        let result = crypto.decrypt(&encrypted.ciphertext, &encrypted.dek_encrypted, &tampered_iv);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_dek_fails() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let encrypted = crypto.encrypt(b"sensitive data").unwrap();
        let mut tampered_dek = encrypted.dek_encrypted.clone();
        tampered_dek[0] ^= 0xff;

        let result = crypto.decrypt(&encrypted.ciphertext, &tampered_dek, &encrypted.iv);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_iv_length_fails() {
        let kek = generate_kek();
        let crypto = EnvelopeCrypto::new(kek);

        let encrypted = crypto.encrypt(b"test").unwrap();
        let short_iv = vec![0u8; 10]; // should be 24

        let result = crypto.decrypt(&encrypted.ciphertext, &encrypted.dek_encrypted, &short_iv);
        assert!(result.is_err());
    }
}
