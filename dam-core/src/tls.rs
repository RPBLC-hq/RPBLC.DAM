use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::DamError;

/// A generated TLS certificate with its private key.
pub struct InterceptCert {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key_der: PrivateKeyDer<'static>,
}

/// Certificate Authority for TLS interception.
pub struct CertificateAuthority {
    /// Original CA cert DER (for chain inclusion in leaf certs).
    ca_cert_der: CertificateDer<'static>,
    /// CA cert PEM string (for `dam trust` command).
    ca_cert_pem: String,
    /// rcgen Certificate for signing leaf certs.
    rcgen_cert: rcgen::Certificate,
    /// rcgen KeyPair for signing.
    rcgen_key: KeyPair,
}

impl CertificateAuthority {
    /// Load CA from PEM files, or generate if they don't exist.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> Result<Self, DamError> {
        if cert_path.exists() && key_path.exists() {
            Self::load(cert_path, key_path)
        } else {
            Self::generate(cert_path, key_path)
        }
    }

    fn generate(cert_path: &Path, key_path: &Path) -> Result<Self, DamError> {
        let key = KeyPair::generate().map_err(|e| DamError::Tls(format!("key generation: {e}")))?;
        let params = Self::ca_params()?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| DamError::Tls(format!("CA self-sign: {e}")))?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        std::fs::write(cert_path, &cert_pem)
            .map_err(|e| DamError::Tls(format!("write CA cert: {e}")))?;
        std::fs::write(key_path, &key_pem)
            .map_err(|e| DamError::Tls(format!("write CA key: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| DamError::Tls(format!("set key permissions: {e}")))?;
        }

        let cert_der = CertificateDer::from(cert.der().to_vec());

        tracing::info!("Generated CA certificate: {}", cert_path.display());

        Ok(Self {
            ca_cert_der: cert_der,
            ca_cert_pem: cert_pem,
            rcgen_cert: cert,
            rcgen_key: key,
        })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, DamError> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| DamError::Tls(format!("read CA cert: {e}")))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| DamError::Tls(format!("read CA key: {e}")))?;

        // Load original cert DER for chain inclusion
        let ca_cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or_else(|| DamError::Tls("no certificate in PEM file".into()))?
            .map_err(|e| DamError::Tls(format!("parse CA cert: {e}")))?;

        // Load key for signing
        let rcgen_key = KeyPair::from_pem(&key_pem)
            .map_err(|e| DamError::Tls(format!("parse CA key: {e}")))?;

        // Re-create rcgen Certificate for signing leaf certs.
        // The re-created cert may differ in serial/signature, but that's fine —
        // we only use it for signing. Chain inclusion uses the original DER bytes.
        let params = Self::ca_params()?;
        let rcgen_cert = params
            .self_signed(&rcgen_key)
            .map_err(|e| DamError::Tls(format!("re-create CA cert: {e}")))?;

        tracing::info!("Loaded CA certificate: {}", cert_path.display());

        Ok(Self {
            ca_cert_der,
            ca_cert_pem: cert_pem,
            rcgen_cert,
            rcgen_key,
        })
    }

    fn ca_params() -> Result<CertificateParams, DamError> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| DamError::Tls(format!("CA params: {e}")))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "DAM Local CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "DAM");
        Ok(params)
    }

    /// Generate a TLS certificate for the given hostname, signed by this CA.
    pub fn generate_cert(&self, hostname: &str) -> Result<InterceptCert, DamError> {
        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| DamError::Tls(format!("leaf params: {e}")))?;
        params
            .distinguished_name
            .push(DnType::CommonName, hostname);

        let leaf_key =
            KeyPair::generate().map_err(|e| DamError::Tls(format!("leaf key gen: {e}")))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.rcgen_cert, &self.rcgen_key)
            .map_err(|e| DamError::Tls(format!("leaf cert signing: {e}")))?;

        let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
        let chain = vec![leaf_der, self.ca_cert_der.clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        Ok(InterceptCert { cert_chain: chain, key_der })
    }

    /// Get the CA certificate PEM for trust installation.
    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }
}

/// In-memory cache of generated TLS certificates, keyed by hostname.
pub struct CertCache {
    ca: CertificateAuthority,
    cache: DashMap<String, Arc<InterceptCert>>,
}

impl CertCache {
    pub fn new(ca: CertificateAuthority) -> Self {
        Self {
            ca,
            cache: DashMap::new(),
        }
    }

    /// Get or generate a certificate for the given hostname.
    pub fn get_cert(&self, hostname: &str) -> Result<Arc<InterceptCert>, DamError> {
        if let Some(entry) = self.cache.get(hostname) {
            return Ok(entry.clone());
        }
        let cert = self.ca.generate_cert(hostname)?;
        let cert = Arc::new(cert);
        self.cache.insert(hostname.to_string(), cert.clone());
        Ok(cert)
    }

    /// Get the CA certificate PEM.
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.cert_pem()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_load_ca() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca-key.pem");

        // Generate
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));

        // Load
        let ca2 = CertificateAuthority::load_or_generate(&cert_path, &key_path).unwrap();
        assert_eq!(ca.cert_pem(), ca2.cert_pem());
    }

    #[test]
    fn test_generate_leaf_cert() {
        let dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::load_or_generate(
            &dir.path().join("ca.pem"),
            &dir.path().join("ca-key.pem"),
        )
        .unwrap();

        let cert = ca.generate_cert("api.openai.com").unwrap();
        assert_eq!(cert.cert_chain.len(), 2); // leaf + CA
    }

    #[test]
    fn test_cert_cache() {
        let dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::load_or_generate(
            &dir.path().join("ca.pem"),
            &dir.path().join("ca-key.pem"),
        )
        .unwrap();
        let cache = CertCache::new(ca);

        let c1 = cache.get_cert("api.openai.com").unwrap();
        let c2 = cache.get_cert("api.openai.com").unwrap();
        // Same Arc (cached)
        assert!(Arc::ptr_eq(&c1, &c2));

        // Different host = different cert
        let c3 = cache.get_cert("api.anthropic.com").unwrap();
        assert!(!Arc::ptr_eq(&c1, &c3));
    }
}
