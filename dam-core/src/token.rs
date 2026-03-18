use crate::error::{DamError, DamResult};
use crate::types::SensitiveDataType;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Base58 alphabet (excludes 0, O, I, l for visual clarity).
const BASE58_ALPHABET: bs58::Alphabet = *bs58::Alphabet::BITCOIN;

/// Regex matching `[type:base58id]` tokens in text.
/// Base58 IDs are exactly 22 chars (128-bit UUID encoded).
/// Type is lowercase alpha + underscore.
static TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[([a-z_]+):([123456789A-HJ-NP-Za-km-z]{21,22})\]").unwrap()
});

/// A typed reference to a sensitive value stored in the vault.
///
/// Real format: `[type:base58id]` where base58id is a 128-bit UUID (22 chars).
///
/// Examples in docs use short IDs for readability (e.g. `[email:a3f7]`),
/// but generated tokens always use the full 22-char base58 ID.
///
/// ```text
/// [email:7B2HkqFn9xR4mWpD3nYvKt]
/// [phone:9cXJrNpT5wQ8mK2hLbYdRv]
/// [ssn:4fWzR3qN7vJ8mK2hLbYdRv]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    pub data_type: SensitiveDataType,
    /// Base58-encoded 128-bit UUID (22 chars).
    pub id: String,
}

impl Token {
    /// Generate a new token with a random 128-bit UUID encoded as base58 (22 chars).
    pub fn generate(data_type: SensitiveDataType) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let id = bs58::encode(uuid.as_bytes())
            .with_alphabet(&BASE58_ALPHABET)
            .into_string();
        Self { data_type, id }
    }

    /// The key form: `email:7B2HkqFn9xR4mWpD3nYvKt`
    pub fn key(&self) -> String {
        format!("{}:{}", self.data_type.tag(), self.id)
    }

    /// The bracketed display form: `[email:7B2HkqFn9xR4mWpD3nYvKt]`
    pub fn display(&self) -> String {
        format!("[{}]", self.key())
    }

    /// Parse from key form `email:7B2HkqFn9xR4mWpD3nYvKt`.
    pub fn from_key(key: &str) -> DamResult<Self> {
        let (tag, id) = key
            .split_once(':')
            .ok_or_else(|| DamError::InvalidToken(key.to_string()))?;
        let data_type = SensitiveDataType::from_tag(tag)
            .ok_or_else(|| DamError::InvalidToken(format!("unknown type: {tag}")))?;
        if !is_valid_base58_id(id) {
            return Err(DamError::InvalidToken(format!("bad id: {id}")));
        }
        Ok(Self {
            data_type,
            id: id.to_string(),
        })
    }

    /// Extract all tokens from text, returning (token, match_start, match_end).
    pub fn extract_all(text: &str) -> Vec<(Token, usize, usize)> {
        TOKEN_RE
            .captures_iter(text)
            .filter_map(|cap| {
                let m = cap.get(0)?;
                let tag = cap.get(1)?.as_str();
                let id = cap.get(2)?.as_str();
                let data_type = SensitiveDataType::from_tag(tag)?;
                Some((
                    Token {
                        data_type,
                        id: id.to_string(),
                    },
                    m.start(),
                    m.end(),
                ))
            })
            .collect()
    }

    /// Replace all tokens in text using a resolver function.
    /// If the resolver returns None, the token is left as-is.
    pub fn replace_all<F>(text: &str, mut resolver: F) -> String
    where
        F: FnMut(&Token) -> Option<String>,
    {
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for (token, start, end) in Self::extract_all(text) {
            result.push_str(&text[last_end..start]);
            if let Some(replacement) = resolver(&token) {
                result.push_str(&replacement);
            } else {
                result.push_str(&text[start..end]);
            }
            last_end = end;
        }
        result.push_str(&text[last_end..]);
        result
    }
}

/// Check that a string is a valid base58 ID (21-22 chars, valid alphabet, decodes to 16 bytes).
fn is_valid_base58_id(id: &str) -> bool {
    (id.len() == 21 || id.len() == 22)
        && bs58::decode(id).with_alphabet(&BASE58_ALPHABET).into_vec()
            .map(|bytes| bytes.len() == 16)
            .unwrap_or(false)
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.key())
    }
}

impl FromStr for Token {
    type Err = DamError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = s.strip_prefix('[').unwrap_or(s);
        let inner = inner.strip_suffix(']').unwrap_or(inner);
        Self::from_key(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let t = Token::generate(SensitiveDataType::Email);
        assert_eq!(t.data_type, SensitiveDataType::Email);
        assert_eq!(t.id.len(), 22);
        // All chars should be valid base58
        assert!(is_valid_base58_id(&t.id));
    }

    #[test]
    fn test_generate_unique() {
        let a = Token::generate(SensitiveDataType::Email);
        let b = Token::generate(SensitiveDataType::Email);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn test_key_and_display() {
        let t = Token {
            data_type: SensitiveDataType::Email,
            id: "7B2HkqFn9xR4mWpD3nYvKt".into(),
        };
        assert_eq!(t.key(), "email:7B2HkqFn9xR4mWpD3nYvKt");
        assert_eq!(t.display(), "[email:7B2HkqFn9xR4mWpD3nYvKt]");
        assert_eq!(t.to_string(), "[email:7B2HkqFn9xR4mWpD3nYvKt]");
    }

    #[test]
    fn test_from_key_valid() {
        let t = Token::from_key("email:7B2HkqFn9xR4mWpD3nYvKt").unwrap();
        assert_eq!(t.data_type, SensitiveDataType::Email);
        assert_eq!(t.id, "7B2HkqFn9xR4mWpD3nYvKt");
    }

    #[test]
    fn test_from_key_invalid_no_colon() {
        assert!(Token::from_key("email7B2HkqFn9xR4mWpD3nYvKt").is_err());
    }

    #[test]
    fn test_from_key_invalid_unknown_type() {
        assert!(Token::from_key("bogus:7B2HkqFn9xR4mWpD3nYvKt").is_err());
    }

    #[test]
    fn test_from_key_invalid_short_id() {
        assert!(Token::from_key("email:abc").is_err());
    }

    #[test]
    fn test_from_key_invalid_wrong_length() {
        assert!(Token::from_key("email:7B2Hkq").is_err()); // too short
    }

    #[test]
    fn test_from_key_invalid_bad_chars() {
        // 'O' and '0' are not in base58 alphabet
        assert!(Token::from_key("email:OOOOOOOOOOOOOOOOOOOOOO").is_err());
    }

    #[test]
    fn test_from_str_with_brackets() {
        let t: Token = "[email:7B2HkqFn9xR4mWpD3nYvKt]".parse().unwrap();
        assert_eq!(t.data_type, SensitiveDataType::Email);
    }

    #[test]
    fn test_from_str_without_brackets() {
        let t: Token = "email:7B2HkqFn9xR4mWpD3nYvKt".parse().unwrap();
        assert_eq!(t.data_type, SensitiveDataType::Email);
    }

    #[test]
    fn test_extract_all_multiple() {
        let text = "Hello [email:7B2HkqFn9xR4mWpD3nYvKt] and [phone:9cXJrNpT5wQ8mK2hLbYdRv]!";
        let results = Token::extract_all(text);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0.data_type, SensitiveDataType::Email);
        assert_eq!(results[1].0.data_type, SensitiveDataType::Phone);
    }

    #[test]
    fn test_extract_all_none() {
        let results = Token::extract_all("no tokens here");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_rejects_wrong_length() {
        // 8-char hex ID should NOT match (old format)
        let results = Token::extract_all("[email:a3f71bc9]");
        assert_eq!(results.len(), 0);
        // 20 chars — too short
        let results = Token::extract_all("[email:7B2HkqFn9xR4mWpD3nY]");
        assert_eq!(results.len(), 0);
        // 23 chars — too long
        let results = Token::extract_all("[email:7B2HkqFn9xR4mWpD3nYvKtX]");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_replace_all_resolves() {
        let id = "7B2HkqFn9xR4mWpD3nYvKt";
        let text = format!("Hello [email:{id}]!");
        let result = Token::replace_all(&text, |t| {
            if t.id == id {
                Some("john@example.com".into())
            } else {
                None
            }
        });
        assert_eq!(result, "Hello john@example.com!");
    }

    #[test]
    fn test_replace_all_unresolved_stays() {
        let text = "Hello [email:7B2HkqFn9xR4mWpD3nYvKt]!";
        let result = Token::replace_all(text, |_| None);
        assert_eq!(result, text);
    }

    #[test]
    fn test_replace_all_no_tokens() {
        let text = "plain text";
        let result = Token::replace_all(text, |_| Some("X".into()));
        assert_eq!(result, "plain text");
    }

    #[test]
    fn test_bracket_in_normal_text_not_extracted() {
        let results = Token::extract_all("array[0] and obj[key]");
        assert!(results.is_empty());
    }

    #[test]
    fn test_roundtrip_generate_parse() {
        let original = Token::generate(SensitiveDataType::CreditCard);
        let display = original.display();
        let parsed: Token = display.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_base58_id_decodes_to_16_bytes() {
        let t = Token::generate(SensitiveDataType::Email);
        let bytes = bs58::decode(&t.id)
            .with_alphabet(&BASE58_ALPHABET)
            .into_vec()
            .unwrap();
        assert_eq!(bytes.len(), 16); // 128-bit UUID
    }
}
