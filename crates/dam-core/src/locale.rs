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
        ]
    }

    /// Default locale set (all locales enabled).
    pub fn defaults() -> Vec<Locale> {
        Self::all().to_vec()
    }

    /// Human-readable label for display in UI prompts.
    pub fn label(&self) -> &'static str {
        match self {
            Locale::Global => "Global (email, credit card, IP, IBAN)",
            Locale::Us => "United States (SSN, US phone)",
            Locale::Ca => "Canada (SIN, postal code)",
            Locale::Eu => "EU (VAT, SWIFT/BIC)",
            Locale::Uk => "United Kingdom (NI, NHS, DVLA)",
            Locale::Fr => "France (INSEE/NIR)",
            Locale::De => "Germany (ID card, tax ID)",
        }
    }

    /// All locales that can be toggled during `dam init`.
    /// Global is excluded because it's always active.
    pub fn selectable() -> &'static [Locale] {
        &[
            Locale::Us,
            Locale::Ca,
            Locale::Eu,
            Locale::Uk,
            Locale::Fr,
            Locale::De,
        ]
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
        assert_eq!("EU".parse::<Locale>().unwrap(), Locale::Eu);
        assert_eq!("De".parse::<Locale>().unwrap(), Locale::De);
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

    #[test]
    fn label_returns_description() {
        assert_eq!(Locale::Us.label(), "United States (SSN, US phone)");
        assert_eq!(
            Locale::Global.label(),
            "Global (email, credit card, IP, IBAN)"
        );
        assert_eq!(Locale::Uk.label(), "United Kingdom (NI, NHS, DVLA)");
    }

    #[test]
    fn selectable_excludes_global() {
        let selectable = Locale::selectable();
        assert!(!selectable.contains(&Locale::Global));
        assert_eq!(selectable.len(), 6);
        assert!(selectable.contains(&Locale::Us));
        assert!(selectable.contains(&Locale::Ca));
        assert!(selectable.contains(&Locale::Eu));
        assert!(selectable.contains(&Locale::Uk));
        assert!(selectable.contains(&Locale::Fr));
        assert!(selectable.contains(&Locale::De));
    }
}
