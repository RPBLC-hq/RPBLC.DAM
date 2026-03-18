use serde::{Deserialize, Serialize};
use std::fmt;

/// Categories of sensitive data that DAM can detect and mediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveDataType {
    Email,
    Phone,
    Ssn,
    CreditCard,
    Iban,
    IpAddress,
    Name,
    Address,
    JwtToken,
    AwsKey,
    GitHubToken,
    StripeKey,
    ApiKey,
    LlmApiKey,
    PrivateKey,
    CredentialUrl,
    Custom,
}

impl SensitiveDataType {
    /// Short lowercase tag for token format: `email`, `phone`, etc.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::CreditCard => "cc",
            Self::Iban => "iban",
            Self::IpAddress => "ip",
            Self::Name => "name",
            Self::Address => "addr",
            Self::JwtToken => "jwt",
            Self::AwsKey => "aws_key",
            Self::GitHubToken => "gh_token",
            Self::StripeKey => "stripe_key",
            Self::ApiKey => "api_key",
            Self::LlmApiKey => "llm_key",
            Self::PrivateKey => "priv_key",
            Self::CredentialUrl => "cred_url",
            Self::Custom => "custom",
        }
    }

    /// Parse from a tag string (case-insensitive).
    pub fn from_tag(tag: &str) -> Option<Self> {
        let lower = tag.to_ascii_lowercase();
        match lower.as_str() {
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "ssn" => Some(Self::Ssn),
            "cc" | "credit_card" | "creditcard" => Some(Self::CreditCard),
            "iban" => Some(Self::Iban),
            "ip" | "ip_address" | "ipaddress" => Some(Self::IpAddress),
            "name" => Some(Self::Name),
            "addr" | "address" => Some(Self::Address),
            "jwt" | "jwt_token" | "jwttoken" => Some(Self::JwtToken),
            "aws_key" | "awskey" => Some(Self::AwsKey),
            "gh_token" | "ghtoken" | "github_token" => Some(Self::GitHubToken),
            "stripe_key" | "stripekey" => Some(Self::StripeKey),
            "api_key" | "apikey" => Some(Self::ApiKey),
            "llm_key" | "llmkey" | "llm_api_key" => Some(Self::LlmApiKey),
            "priv_key" | "privkey" | "private_key" => Some(Self::PrivateKey),
            "cred_url" | "credurl" | "credential_url" => Some(Self::CredentialUrl),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// All built-in variants (excluding Custom).
    pub fn all() -> &'static [Self] {
        &[
            Self::Email, Self::Phone, Self::Ssn, Self::CreditCard,
            Self::Iban, Self::IpAddress, Self::Name, Self::Address,
            Self::JwtToken, Self::AwsKey, Self::GitHubToken, Self::StripeKey,
            Self::ApiKey, Self::LlmApiKey, Self::PrivateKey, Self::CredentialUrl,
        ]
    }
}

impl fmt::Display for SensitiveDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_roundtrip_all_variants() {
        for &dt in SensitiveDataType::all() {
            let tag = dt.tag();
            let parsed = SensitiveDataType::from_tag(tag)
                .unwrap_or_else(|| panic!("from_tag failed for '{tag}'"));
            assert_eq!(parsed, dt, "roundtrip failed for {tag}");
        }
        // Custom too
        assert_eq!(SensitiveDataType::from_tag("custom"), Some(SensitiveDataType::Custom));
    }

    #[test]
    fn test_from_tag_case_insensitive() {
        assert_eq!(SensitiveDataType::from_tag("EMAIL"), Some(SensitiveDataType::Email));
        assert_eq!(SensitiveDataType::from_tag("Email"), Some(SensitiveDataType::Email));
        assert_eq!(SensitiveDataType::from_tag("email"), Some(SensitiveDataType::Email));
    }

    #[test]
    fn test_from_tag_aliases() {
        assert_eq!(SensitiveDataType::from_tag("cc"), Some(SensitiveDataType::CreditCard));
        assert_eq!(SensitiveDataType::from_tag("credit_card"), Some(SensitiveDataType::CreditCard));
        assert_eq!(SensitiveDataType::from_tag("addr"), Some(SensitiveDataType::Address));
        assert_eq!(SensitiveDataType::from_tag("address"), Some(SensitiveDataType::Address));
        assert_eq!(SensitiveDataType::from_tag("ip"), Some(SensitiveDataType::IpAddress));
    }

    #[test]
    fn test_from_tag_unknown() {
        assert_eq!(SensitiveDataType::from_tag("bogus"), None);
        assert_eq!(SensitiveDataType::from_tag(""), None);
        assert_eq!(SensitiveDataType::from_tag("  "), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", SensitiveDataType::Email), "email");
        assert_eq!(format!("{}", SensitiveDataType::CreditCard), "cc");
    }
}
