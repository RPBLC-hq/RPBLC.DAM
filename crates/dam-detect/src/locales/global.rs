use crate::stage_regex::Pattern;
use crate::validators::{
    validate_iban, validate_ip, validate_ipv6, validate_luhn_cc, validate_mac_address,
    validate_phone,
};
use dam_core::PiiType;
use regex::Regex;

/// Patterns that apply regardless of locale - not country-specific PII.
pub(crate) fn patterns() -> Vec<Pattern> {
    vec![
        // ── Personal / financial ────────────────────────────────────────────────

        // Email addresses
        Pattern {
            regex: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            pii_type: PiiType::Email,
            confidence: 0.95,
            validator: None,
        },
        // Credit card numbers (common formats, 13-19 digits with optional separators)
        Pattern {
            regex: Regex::new(
                r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b",
            )
            .unwrap(),
            pii_type: PiiType::CreditCard,
            confidence: 0.85,
            validator: Some(validate_luhn_cc),
        },
        // International phone - E.164 with optional separators
        // 7-15 digits total, country code 1-3 digits, separators (space/dash/dot) allowed
        Pattern {
            regex: Regex::new(r"\+[1-9]\d{0,2}(?:[\s\-.]?\d){6,14}\b").unwrap(),
            pii_type: PiiType::Phone,
            confidence: 0.9,
            validator: Some(validate_phone),
        },
        // NANP with parenthesized area code (common CA/US format): +1 (514) 555-0199
        Pattern {
            regex: Regex::new(r"\+?1?[\s\-.]?\(\d{3}\)[\s\-.]?\d{3}[\s\-.]?\d{4}\b").unwrap(),
            pii_type: PiiType::Phone,
            confidence: 0.9,
            validator: Some(validate_phone),
        },
        // IPv4 addresses (public only — private/loopback filtered by validator)
        Pattern {
            regex: Regex::new(
                r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b",
            )
            .unwrap(),
            pii_type: PiiType::IpAddress,
            confidence: 0.8,
            validator: Some(validate_ip),
        },
        // Date of birth patterns (various formats)
        Pattern {
            regex: Regex::new(r"\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b").unwrap(),
            pii_type: PiiType::DateOfBirth,
            confidence: 0.5,
            validator: None,
        },
        // IBAN - 2 letters + 2 digits + 11-30 alphanumeric (case-insensitive)
        Pattern {
            regex: Regex::new(r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
            pii_type: PiiType::Iban,
            confidence: 0.90,
            validator: Some(validate_iban),
        },

        // ── Network identifiers ──────────────────────────────────────────────────

        // IPv6 — fully-expanded 8-group form only (no :: compression)
        // Loopback, link-local, multicast filtered by validator
        Pattern {
            regex: Regex::new(
                r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            )
            .unwrap(),
            pii_type: PiiType::IPv6Address,
            confidence: 0.85,
            validator: Some(validate_ipv6),
        },
        // MAC / hardware address (colon or hyphen separated)
        Pattern {
            regex: Regex::new(r"\b(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b").unwrap(),
            pii_type: PiiType::MacAddress,
            confidence: 0.90,
            validator: Some(validate_mac_address),
        },

        // ── Digital secrets & credentials ───────────────────────────────────────

        // JSON Web Token — header.payload.signature (all three segments base64url-encoded)
        // Headers always begin with eyJ (base64url of `{"`)
        Pattern {
            regex: Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
            pii_type: PiiType::JwtToken,
            confidence: 0.99,
            validator: None,
        },
        // AWS access key ID — AKIA prefix + 16 uppercase alphanumeric chars
        Pattern {
            regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            pii_type: PiiType::AwsKey,
            confidence: 0.99,
            validator: None,
        },
        // AWS ARN — arn:aws:<service>:<region>:<account-id>:<resource>
        // account-id is optional (e.g. S3 ARNs: arn:aws:s3:::bucket/key)
        Pattern {
            regex: Regex::new(
                r"\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{0,12}:[a-zA-Z0-9/\-_:.]+",
            )
            .unwrap(),
            pii_type: PiiType::AwsArn,
            confidence: 0.99,
            validator: None,
        },
        // GitHub tokens — gh followed by token type letter then underscore + 36+ alphanum
        // gho=OAuth, ghp=personal, ghs=server-to-server, ghu=user-to-server, ghr=refresh
        Pattern {
            regex: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(),
            pii_type: PiiType::GitHubToken,
            confidence: 0.99,
            validator: None,
        },
        // Stripe API key — sk_/pk_ (secret/publishable) with live/test environment tag
        Pattern {
            regex: Regex::new(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b").unwrap(),
            pii_type: PiiType::StripeKey,
            confidence: 0.99,
            validator: None,
        },
        // Stripe object IDs — customer (cus_), payment method (pm_), token (tok_),
        // source (src_), subscription (sub_), card (card_) followed by 14+ alphanum
        Pattern {
            regex: Regex::new(r"\b(?:tok|card|pm|src|cus|sub)_[a-zA-Z0-9]{14,}\b").unwrap(),
            pii_type: PiiType::StripeKey,
            confidence: 0.95,
            validator: None,
        },
        // Google API key — AIza prefix + 35 base64url chars (39 chars total)
        Pattern {
            regex: Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.99,
            validator: None,
        },
        // Slack webhook URL — hooks.slack.com/services/<T>/<B>/<token>
        Pattern {
            regex: Regex::new(
                r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+",
            )
            .unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.99,
            validator: None,
        },
        // Slack API token — xox[b=bot, a=app, p=workspace, r=refresh, s=legacy-workspace] prefix
        Pattern {
            regex: Regex::new(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b").unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.99,
            validator: None,
        },
        // SendGrid API key — SG. + 22 chars + . + 43 chars
        Pattern {
            regex: Regex::new(r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b").unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.99,
            validator: None,
        },
        // npm access token — npm_ prefix + 36 alphanum chars
        Pattern {
            regex: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.99,
            validator: None,
        },
        // Mailgun API key — key- prefix + 32 lowercase hex chars
        Pattern {
            regex: Regex::new(r"\bkey-[a-z0-9]{32}\b").unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.97,
            validator: None,
        },
        // Twilio API key SID — SK prefix + 32 lowercase alphanum chars
        Pattern {
            regex: Regex::new(r"\bSK[a-z0-9]{32}\b").unwrap(),
            pii_type: PiiType::ApiKey,
            confidence: 0.97,
            validator: None,
        },

        // ── LLM provider API keys ────────────────────────────────────────────

        // Anthropic API key — sk-ant-api{nn}- + 90+ base64url chars
        Pattern {
            regex: Regex::new(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{90,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.99,
            validator: None,
        },
        // OpenAI project key (2024+) — sk-proj- prefix
        Pattern {
            regex: Regex::new(r"\bsk-proj-[A-Za-z0-9_-]{50,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.99,
            validator: None,
        },
        // OpenAI service-account key — sk-svcacct- prefix
        Pattern {
            regex: Regex::new(r"\bsk-svcacct-[A-Za-z0-9_-]{50,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.99,
            validator: None,
        },
        // OpenAI legacy key — sk- + exactly 48 alphanumeric chars (no dashes/underscores)
        Pattern {
            regex: Regex::new(r"\bsk-[A-Za-z0-9]{48}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.95,
            validator: None,
        },
        // Hugging Face token — hf_ + 34+ alphanumeric chars
        Pattern {
            regex: Regex::new(r"\bhf_[A-Za-z0-9]{34,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.97,
            validator: None,
        },
        // Replicate API token — r8_ + 38+ alphanumeric chars
        Pattern {
            regex: Regex::new(r"\br8_[A-Za-z0-9]{38,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.97,
            validator: None,
        },
        // xAI (Grok) API key — xai- + 48+ alphanumeric chars
        Pattern {
            regex: Regex::new(r"\bxai-[A-Za-z0-9_-]{48,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.97,
            validator: None,
        },
        // Groq API key — gsk_ + 52+ alphanumeric chars
        Pattern {
            regex: Regex::new(r"\bgsk_[A-Za-z0-9]{52,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.97,
            validator: None,
        },
        // Perplexity API key — pplx- + 48+ alphanumeric chars
        Pattern {
            regex: Regex::new(r"\bpplx-[A-Za-z0-9]{48,}\b").unwrap(),
            pii_type: PiiType::LlmApiKey,
            confidence: 0.97,
            validator: None,
        },

        // RSA or EC private key (PEM block)
        Pattern {
            regex: Regex::new(
                r"(?s)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.{50,}?-----END (?:RSA |EC )?PRIVATE KEY-----",
            )
            .unwrap(),
            pii_type: PiiType::PrivateKey,
            confidence: 0.99,
            validator: None,
        },
        // OpenSSH private key (PEM block)
        Pattern {
            regex: Regex::new(
                r"(?s)-----BEGIN OPENSSH PRIVATE KEY-----.{50,}?-----END OPENSSH PRIVATE KEY-----",
            )
            .unwrap(),
            pii_type: PiiType::PrivateKey,
            confidence: 0.99,
            validator: None,
        },
        // Database connection string with embedded credentials
        // Covers postgres, mysql, mongodb, redis, sqlite URI schemes
        Pattern {
            regex: Regex::new(
                r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)://[^\s:@]+:[^\s@]+@\S+",
            )
            .unwrap(),
            pii_type: PiiType::CredentialUrl,
            confidence: 0.98,
            validator: None,
        },
        // Generic URL with embedded user:pass credentials (http/https/ftp)
        Pattern {
            regex: Regex::new(r"https?://[^\s:@/]+:[^\s@/]+@[^\s]+").unwrap(),
            pii_type: PiiType::CredentialUrl,
            confidence: 0.97,
            validator: None,
        },

        // ── Cryptocurrency wallets ───────────────────────────────────────────────

        // Ethereum address — 0x followed by exactly 40 hex chars
        Pattern {
            regex: Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap(),
            pii_type: PiiType::CryptoWallet,
            confidence: 0.97,
            validator: None,
        },
        // Bitcoin bech32 (native SegWit) — bc1 followed by 39-59 lowercase alphanumeric
        Pattern {
            regex: Regex::new(r"\bbc1[a-z0-9]{39,59}\b").unwrap(),
            pii_type: PiiType::CryptoWallet,
            confidence: 0.98,
            validator: None,
        },
        // Bitcoin legacy (P2PKH starts with 1, P2SH starts with 3) + base58 chars
        // Base58 alphabet excludes 0, O, I, l
        Pattern {
            regex: Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b").unwrap(),
            pii_type: PiiType::CryptoWallet,
            confidence: 0.90,
            validator: None,
        },

        // ── Documents ───────────────────────────────────────────────────────────

        // Passport MRZ — TD3 two-line format (44 chars per line)
        // Line 1: document type (P) + subtype + issuer (3) + name field (39)
        // Line 2: doc number (9) + check + nationality (3) + DOB (6) + check +
        //         sex (1) + expiry (6) + check + optional (14) + check + composite check
        Pattern {
            regex: Regex::new(
                r"P[A-Z<][A-Z]{3}[A-Z<]{39}\r?\n[A-Z0-9<]{9}[0-9][A-Z]{3}[0-9]{6}[0-9][MF<][0-9]{6}[0-9][A-Z0-9<]{14}[0-9][0-9]",
            )
            .unwrap(),
            pii_type: PiiType::PassportMrz,
            confidence: 0.99,
            validator: None,
        },

        // ── Logistics ───────────────────────────────────────────────────────────

        // UPS tracking number — 1Z prefix + 16 uppercase alphanumeric chars
        Pattern {
            regex: Regex::new(r"\b1Z[A-Z0-9]{16}\b").unwrap(),
            pii_type: PiiType::UpsTracking,
            confidence: 0.98,
            validator: None,
        },
    ]
}
