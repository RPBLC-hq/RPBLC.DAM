use crate::error::{DamError, DamResult};
use crate::pii_type::PiiType;
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A typed reference to a PII value stored in the vault.
///
/// Format: `[type:hex]` e.g. `[email:a3f71bc9]` (8 hex chars locally, 4-16 accepted)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PiiRef {
    pub pii_type: PiiType,
    pub id: String,
}

impl PiiRef {
    /// Generate a new reference with a random 8-character hex ID.
    pub fn generate(pii_type: PiiType) -> Self {
        let mut rng = rand::thread_rng();
        let id: u32 = rng.r#gen();
        Self {
            pii_type,
            id: format!("{id:08x}"),
        }
    }

    /// The short key used in the vault: `email:a3f71bc9`
    pub fn key(&self) -> String {
        format!("{}:{}", self.pii_type.tag(), self.id)
    }

    /// The bracketed display form: `[email:a3f71bc9]`
    pub fn display(&self) -> String {
        format!("[{}]", self.key())
    }

    /// Parse from the key form `email:a3f71bc9`.
    pub fn from_key(key: &str) -> DamResult<Self> {
        let (tag, id) = key
            .split_once(':')
            .ok_or_else(|| DamError::InvalidReference(key.to_string()))?;
        let pii_type = PiiType::from_tag(tag)
            .ok_or_else(|| DamError::InvalidReference(format!("unknown type tag: {tag}")))?;
        Ok(Self {
            pii_type,
            id: id.to_string(),
        })
    }
}

impl fmt::Display for PiiRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.key())
    }
}

impl FromStr for PiiRef {
    type Err = DamError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept both `[email:a3f71bc9]` and `email:a3f71bc9`
        let inner = s
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(s);
        Self::from_key(inner)
    }
}

/// Regex that matches `[type:hex]` references in text.
/// Accepts 4-16 hex chars to support locally-generated IDs (8 chars)
/// and future remote-generated IDs of varying length.
static REF_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[([a-z_]+):([a-f0-9]{4,16})\]").expect("ref pattern should compile"));

/// Extract all PII references from a string.
pub fn extract_refs(text: &str) -> Vec<PiiRef> {
    REF_PATTERN
        .captures_iter(text)
        .filter_map(|cap| {
            let tag = cap.get(1)?.as_str();
            let id = cap.get(2)?.as_str();
            let pii_type = PiiType::from_tag(tag)?;
            Some(PiiRef {
                pii_type,
                id: id.to_string(),
            })
        })
        .collect()
}

/// Replace all PII references in text using a resolver function.
/// The function receives a `PiiRef` and returns the replacement string.
pub fn replace_refs(text: &str, mut resolver: impl FnMut(&PiiRef) -> Option<String>) -> String {
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for caps in REF_PATTERN.captures_iter(text) {
        let full_match = caps.get(0).unwrap();
        result.push_str(&text[last_end..full_match.start()]);

        let tag = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let id = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        if let Some(pii_type) = PiiType::from_tag(tag) {
            let pii_ref = PiiRef {
                pii_type,
                id: id.to_string(),
            };
            if let Some(resolved) = resolver(&pii_ref) {
                result.push_str(&resolved);
            } else {
                result.push_str(full_match.as_str());
            }
        } else {
            result.push_str(full_match.as_str());
        }

        last_end = full_match.end();
    }

    result.push_str(&text[last_end..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_parse() {
        let r = PiiRef::generate(PiiType::Email);
        assert_eq!(r.pii_type, PiiType::Email);
        assert_eq!(r.id.len(), 8);

        let parsed: PiiRef = r.display().parse().unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn extract_multiple_refs() {
        let text = "Contact [name:c7a1] at [email:f2b3] or [phone:d3e4]";
        let refs = extract_refs(text);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].pii_type, PiiType::Name);
        assert_eq!(refs[1].pii_type, PiiType::Email);
        assert_eq!(refs[2].pii_type, PiiType::Phone);
    }

    #[test]
    fn replace_refs_works() {
        let text = "Hello [name:abcd], your email is [email:1234]";
        let result = replace_refs(text, |r| match r.key().as_str() {
            "name:abcd" => Some("John".to_string()),
            "email:1234" => Some("john@example.com".to_string()),
            _ => None,
        });
        assert_eq!(result, "Hello John, your email is john@example.com");
    }

    #[test]
    fn from_key() {
        let r = PiiRef::from_key("ssn:beef").unwrap();
        assert_eq!(r.pii_type, PiiType::Ssn);
        assert_eq!(r.id, "beef");
    }
}
