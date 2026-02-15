use crate::error::DamError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Geographic locale for PII detection patterns.
///
/// Each locale contributes its own set of regex patterns to the detection pipeline.
/// `Global` patterns apply regardless of locale selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    Global,
    Us,
    Ca,
    Eu,
    Uk,
    Fr,
    De,
    Jp,
    Kr,
    In,
    Cn,
}

impl Locale {
    /// All defined locales.
    pub fn all() -> &'static [Locale] {
        &[
            Locale::Global,
            Locale::Us,
            Locale::Ca,
            Locale::Eu,
            Locale::Uk,
            Locale::Fr,
            Locale::De,
            Locale::Jp,
            Locale::Kr,
            Locale::In,
            Locale::Cn,
        ]
    }

    /// Default locale set (all locales enabled).
    pub fn defaults() -> Vec<Locale> {
        Self::all().to_vec()
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Locale::Global => "global",
            Locale::Us => "us",
            Locale::Ca => "ca",
            Locale::Eu => "eu",
            Locale::Uk => "uk",
            Locale::Fr => "fr",
            Locale::De => "de",
            Locale::Jp => "jp",
            Locale::Kr => "kr",
            Locale::In => "in",
            Locale::Cn => "cn",
        };
        write!(f, "{s}")
    }
}

impl FromStr for Locale {
    type Err = DamError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "global" => Ok(Locale::Global),
            "us" => Ok(Locale::Us),
            "ca" => Ok(Locale::Ca),
            "eu" => Ok(Locale::Eu),
            "uk" => Ok(Locale::Uk),
            "fr" => Ok(Locale::Fr),
            "de" => Ok(Locale::De),
            "jp" => Ok(Locale::Jp),
            "kr" => Ok(Locale::Kr),
            "in" => Ok(Locale::In),
            "cn" => Ok(Locale::Cn),
            _ => Err(DamError::Config(format!("unknown locale: {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_parse() {
        for locale in Locale::all() {
            let s = locale.to_string();
            let parsed: Locale = s.parse().unwrap();
            assert_eq!(*locale, parsed);
        }
    }

    #[test]
    fn case_insensitive_parse() {
        assert_eq!("US".parse::<Locale>().unwrap(), Locale::Us);
        assert_eq!("Global".parse::<Locale>().unwrap(), Locale::Global);
        assert_eq!("JP".parse::<Locale>().unwrap(), Locale::Jp);
        assert_eq!("cN".parse::<Locale>().unwrap(), Locale::Cn);
    }

    #[test]
    fn unknown_locale_error() {
        let err = "xx".parse::<Locale>().unwrap_err();
        assert!(matches!(err, DamError::Config(_)));
        assert!(err.to_string().contains("unknown locale"));
    }

    #[test]
    fn defaults_equals_all() {
        let defaults = Locale::defaults();
        let all = Locale::all();
        assert_eq!(defaults.len(), all.len());
        for (d, a) in defaults.iter().zip(all.iter()) {
            assert_eq!(d, a);
        }
    }

    #[test]
    fn serde_round_trip() {
        let locale = Locale::Us;
        let json = serde_json::to_string(&locale).unwrap();
        assert_eq!(json, "\"us\"");
        let parsed: Locale = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Locale::Us);
    }
}
