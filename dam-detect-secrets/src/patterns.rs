use dam_core::{Detection, SensitiveDataType, Span};
use once_cell::sync::Lazy;
use regex::Regex;

const SOURCE_MODULE: &str = "detect-secrets";

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

static JWT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap()
});

static AWS_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()
});

static GITHUB_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"gh[ps]_[A-Za-z0-9_]{36,}").unwrap()
});

static STRIPE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[sr]k_(live|test)_[A-Za-z0-9]{24,}").unwrap()
});

static OPENAI_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap()
});

static ANTHROPIC_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").unwrap()
});

static PEM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----")
        .unwrap()
});

static CREDENTIAL_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:@]+:[^\s:@]+@[^\s/]+").unwrap()
});

/// Matches common key assignment patterns followed by 32+ hex chars or base64.
static GENERIC_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token|password|secret|token|credentials?)\s*[:=]\s*["']?([A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{32,}={0,2})["']?"#,
    )
    .unwrap()
});

// ---------------------------------------------------------------------------
// Individual detectors
// ---------------------------------------------------------------------------

pub fn detect_jwt(text: &str) -> Vec<Detection> {
    JWT_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::JwtToken,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.95,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_aws_keys(text: &str) -> Vec<Detection> {
    AWS_KEY_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::AwsKey,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.98,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_github_tokens(text: &str) -> Vec<Detection> {
    GITHUB_TOKEN_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::GitHubToken,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.98,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_stripe_keys(text: &str) -> Vec<Detection> {
    STRIPE_KEY_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::StripeKey,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.98,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_openai_keys(text: &str) -> Vec<Detection> {
    // Anthropic keys also start with `sk-`, so exclude them here.
    OPENAI_KEY_RE
        .find_iter(text)
        .filter(|m| !m.as_str().starts_with("sk-ant-"))
        .map(|m| Detection {
            data_type: SensitiveDataType::LlmApiKey,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.9,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_anthropic_keys(text: &str) -> Vec<Detection> {
    ANTHROPIC_KEY_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::LlmApiKey,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.95,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_pem_keys(text: &str) -> Vec<Detection> {
    PEM_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::PrivateKey,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.99,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_credential_urls(text: &str) -> Vec<Detection> {
    CREDENTIAL_URL_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::CredentialUrl,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.95,
            source_module: SOURCE_MODULE.into(),
        })
        .collect()
}

pub fn detect_generic_keys(text: &str) -> Vec<Detection> {
    GENERIC_KEY_RE
        .captures_iter(text)
        .map(|cap| {
            let full = cap.get(0).unwrap();
            let value_group = cap.get(1).unwrap();
            Detection {
                data_type: SensitiveDataType::ApiKey,
                value: value_group.as_str().to_string(),
                span: Span {
                    start: full.start(),
                    end: full.end(),
                },
                confidence: 0.7,
                source_module: SOURCE_MODULE.into(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Aggregate detector
// ---------------------------------------------------------------------------

/// Run all secret-detection patterns against `text` and return every match.
///
/// Callers (typically `SecretsDetectionModule`) should feed the result into
/// `FlowContext.detections`; the flow executor will deduplicate overlapping
/// spans afterward.
pub fn detect_all(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    // Run Anthropic before OpenAI so the OpenAI filter can rely on ordering
    // within `detect_openai_keys` (it already filters `sk-ant-` prefixes).
    out.extend(detect_anthropic_keys(text));
    out.extend(detect_openai_keys(text));
    out.extend(detect_jwt(text));
    out.extend(detect_aws_keys(text));
    out.extend(detect_github_tokens(text));
    out.extend(detect_stripe_keys(text));
    out.extend(detect_pem_keys(text));
    out.extend(detect_credential_urls(text));
    out.extend(detect_generic_keys(text));
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- JWT ------------------------------------------------------------------

    #[test]
    fn test_detect_jwt_valid() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                      eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.\
                      SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let dets = detect_jwt(token);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::JwtToken);
        assert!((dets[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_jwt_embedded() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiIxMjM0NSJ9.abc123def456ghi in header";
        let dets = detect_jwt(text);
        assert_eq!(dets.len(), 1);
        assert!(dets[0].span.start > 0);
    }

    #[test]
    fn test_detect_jwt_false_positive_short_segment() {
        // Segments too short — should not match
        let text = "eyJhbGci.eyJz.abc";
        let dets = detect_jwt(text);
        assert!(dets.is_empty());
    }

    // -- AWS ------------------------------------------------------------------

    #[test]
    fn test_detect_aws_key() {
        let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let dets = detect_aws_keys(text);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::AwsKey);
        assert_eq!(dets[0].value, "AKIAIOSFODNN7EXAMPLE");
        assert!((dets[0].confidence - 0.98).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_aws_key_false_positive_lowercase() {
        let text = "AKIAabcdefghijklmnop";
        let dets = detect_aws_keys(text);
        assert!(dets.is_empty());
    }

    #[test]
    fn test_detect_aws_key_false_positive_short() {
        let text = "AKIA12345678"; // only 8 after prefix
        let dets = detect_aws_keys(text);
        assert!(dets.is_empty());
    }

    // -- GitHub ---------------------------------------------------------------

    #[test]
    fn test_detect_github_pat() {
        let tok = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let dets = detect_github_tokens(tok);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::GitHubToken);
        assert!((dets[0].confidence - 0.98).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_github_secret() {
        let tok = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let dets = detect_github_tokens(tok);
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_detect_github_false_positive_short() {
        let text = "ghp_tooshort";
        let dets = detect_github_tokens(text);
        assert!(dets.is_empty());
    }

    // -- Stripe ---------------------------------------------------------------

    #[test]
    fn test_detect_stripe_live_secret() {
        let key = "sk_live_abcdefghijklmnopqrstuvwx";
        let dets = detect_stripe_keys(key);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::StripeKey);
        assert!((dets[0].confidence - 0.98).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_stripe_test_publishable() {
        let key = "rk_test_abcdefghijklmnopqrstuvwx";
        let dets = detect_stripe_keys(key);
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_detect_stripe_false_positive_unknown_prefix() {
        let text = "xk_live_abcdefghijklmnopqrstuvwx";
        let dets = detect_stripe_keys(text);
        assert!(dets.is_empty());
    }

    // -- OpenAI ---------------------------------------------------------------

    #[test]
    fn test_detect_openai_key() {
        let key = "sk-proj_abc123def456ghi789jkl0";
        let dets = detect_openai_keys(key);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::LlmApiKey);
        assert!((dets[0].confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_openai_does_not_match_anthropic() {
        let key = "sk-ant-api03-AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
        let dets = detect_openai_keys(key);
        assert!(dets.is_empty(), "OpenAI detector must not match Anthropic keys");
    }

    #[test]
    fn test_detect_openai_false_positive_short() {
        let text = "sk-short";
        let dets = detect_openai_keys(text);
        assert!(dets.is_empty());
    }

    // -- Anthropic ------------------------------------------------------------

    #[test]
    fn test_detect_anthropic_key() {
        let key = "sk-ant-api03-AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
        let dets = detect_anthropic_keys(key);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::LlmApiKey);
        assert!((dets[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_anthropic_false_positive_short() {
        let text = "sk-ant-short";
        let dets = detect_anthropic_keys(text);
        assert!(dets.is_empty());
    }

    // -- PEM ------------------------------------------------------------------

    #[test]
    fn test_detect_pem_rsa() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                    MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLA\n\
                    -----END RSA PRIVATE KEY-----";
        let dets = detect_pem_keys(pem);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::PrivateKey);
        assert!((dets[0].confidence - 0.99).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_pem_ec() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
        let dets = detect_pem_keys(pem);
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_detect_pem_false_positive_public() {
        // Public keys should NOT match
        let text = "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----";
        let dets = detect_pem_keys(text);
        assert!(dets.is_empty());
    }

    #[test]
    fn test_detect_pem_embedded_in_json() {
        let json = r#"{"key": "-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----"}"#;
        let dets = detect_pem_keys(json);
        assert_eq!(dets.len(), 1);
    }

    // -- Credential URLs ------------------------------------------------------

    #[test]
    fn test_detect_credential_url_postgres() {
        let url = "postgresql://admin:s3cret@db.example.com:5432/mydb";
        let dets = detect_credential_urls(url);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::CredentialUrl);
        assert!((dets[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_credential_url_https() {
        let url = "https://user:password@api.example.com/v1";
        let dets = detect_credential_urls(url);
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_detect_credential_url_false_positive_no_password() {
        let url = "https://api.example.com/v1";
        let dets = detect_credential_urls(url);
        assert!(dets.is_empty());
    }

    #[test]
    fn test_detect_credential_url_false_positive_no_host() {
        let text = "not://user:pass@";
        let dets = detect_credential_urls(text);
        assert!(dets.is_empty());
    }

    // -- Generic keys ---------------------------------------------------------

    #[test]
    fn test_detect_generic_hex_key() {
        let text = "api_key: \"deadbeefdeadbeefdeadbeefdeadbeef01234567\"";
        let dets = detect_generic_keys(text);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::ApiKey);
        assert_eq!(dets[0].value, "deadbeefdeadbeefdeadbeefdeadbeef01234567");
        assert!((dets[0].confidence - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_generic_base64_key() {
        let text = "secret_key = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';";
        let dets = detect_generic_keys(text);
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_detect_generic_key_with_equals() {
        let text = "AUTH_TOKEN=aabbccddee00112233445566778899aabbccddee";
        let dets = detect_generic_keys(text);
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_detect_generic_key_false_positive_short_value() {
        let text = "api_key: \"tooshort\"";
        let dets = detect_generic_keys(text);
        assert!(dets.is_empty());
    }

    #[test]
    fn test_detect_generic_key_false_positive_no_label() {
        let text = "aabbccddee00112233445566778899aabbccddee";
        let dets = detect_generic_keys(text);
        assert!(dets.is_empty());
    }

    // -- detect_all -----------------------------------------------------------

    #[test]
    fn test_detect_all_empty_input() {
        let dets = detect_all("");
        assert!(dets.is_empty());
    }

    #[test]
    fn test_detect_all_plain_text() {
        let dets = detect_all("Hello, this is a normal sentence with no secrets.");
        assert!(dets.is_empty());
    }

    #[test]
    fn test_detect_all_multiple_types() {
        let text = "key=AKIAIOSFODNN7EXAMPLE and jwt=eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiIxMjM0NSJ9.abc123def456ghi";
        let dets = detect_all(text);
        let types: Vec<_> = dets.iter().map(|d| d.data_type).collect();
        assert!(types.contains(&SensitiveDataType::AwsKey));
        assert!(types.contains(&SensitiveDataType::JwtToken));
    }

    #[test]
    fn test_detect_all_anthropic_not_duplicated_as_openai() {
        let text = "sk-ant-api03-AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
        let dets = detect_all(text);
        // Should have exactly 1 detection (Anthropic), not also an OpenAI one
        let llm_dets: Vec<_> = dets
            .iter()
            .filter(|d| d.data_type == SensitiveDataType::LlmApiKey)
            .collect();
        assert_eq!(llm_dets.len(), 1);
        assert!((llm_dets[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_all_pem_and_url_together() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n\
                    connect to postgresql://admin:pass@db.local";
        let dets = detect_all(text);
        let types: Vec<_> = dets.iter().map(|d| d.data_type).collect();
        assert!(types.contains(&SensitiveDataType::PrivateKey));
        assert!(types.contains(&SensitiveDataType::CredentialUrl));
    }

    #[test]
    fn test_detect_all_source_module_always_set() {
        let text = "AKIAIOSFODNN7EXAMPLE";
        let dets = detect_all(text);
        for d in &dets {
            assert_eq!(d.source_module, "detect-secrets");
        }
    }

    #[test]
    fn test_spans_within_bounds() {
        let text = "prefix AKIAIOSFODNN7EXAMPLE suffix";
        let dets = detect_all(text);
        for d in &dets {
            assert!(d.span.start < d.span.end);
            assert!(d.span.end <= text.len());
            assert_eq!(&text[d.span.start..d.span.end], d.value);
        }
    }
}
