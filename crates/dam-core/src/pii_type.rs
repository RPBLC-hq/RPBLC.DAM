use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// All recognized categories of personally identifiable information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    Email,
    Phone,
    Ssn,
    CreditCard,
    IpAddress,
    DateOfBirth,
    Iban,
    Sin,
    PostalCode,
    Name,
    Address,
    Organization,
    Location,
    Custom,
}

impl fmt::Display for PiiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::CreditCard => "credit_card",
            Self::IpAddress => "ip",
            Self::DateOfBirth => "dob",
            Self::Iban => "iban",
            Self::Sin => "sin",
            Self::PostalCode => "postal_code",
            Self::Name => "name",
            Self::Address => "address",
            Self::Organization => "org",
            Self::Location => "location",
            Self::Custom => "custom",
        };
        write!(f, "{s}")
    }
}

impl FromStr for PiiType {
    type Err = crate::error::DamError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "email" => Ok(Self::Email),
            "phone" => Ok(Self::Phone),
            "ssn" => Ok(Self::Ssn),
            "credit_card" | "creditcard" | "cc" => Ok(Self::CreditCard),
            "ip" | "ip_address" | "ipaddress" => Ok(Self::IpAddress),
            "dob" | "date_of_birth" | "dateofbirth" => Ok(Self::DateOfBirth),
            "iban" => Ok(Self::Iban),
            "sin" | "social_insurance_number" => Ok(Self::Sin),
            "postal" | "postal_code" | "postalcode" | "zip" => Ok(Self::PostalCode),
            "name" => Ok(Self::Name),
            "address" | "addr" => Ok(Self::Address),
            "org" | "organization" => Ok(Self::Organization),
            "location" | "loc" => Ok(Self::Location),
            "custom" => Ok(Self::Custom),
            _ => Err(crate::error::DamError::InvalidPiiType(s.to_string())),
        }
    }
}

impl PiiType {
    /// Short tag used in reference strings like `[email:a3f71bc9]`.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::CreditCard => "cc",
            Self::IpAddress => "ip",
            Self::DateOfBirth => "dob",
            Self::Iban => "iban",
            Self::Sin => "sin",
            Self::PostalCode => "postal",
            Self::Name => "name",
            Self::Address => "addr",
            Self::Organization => "org",
            Self::Location => "loc",
            Self::Custom => "custom",
        }
    }

    /// Parse a tag back into a PiiType.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "ssn" => Some(Self::Ssn),
            "cc" => Some(Self::CreditCard),
            "ip" => Some(Self::IpAddress),
            "dob" => Some(Self::DateOfBirth),
            "iban" => Some(Self::Iban),
            "sin" => Some(Self::Sin),
            "postal" => Some(Self::PostalCode),
            "name" => Some(Self::Name),
            "addr" => Some(Self::Address),
            "org" => Some(Self::Organization),
            "loc" => Some(Self::Location),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// All built-in PII types.
    pub fn all() -> &'static [PiiType] {
        &[
            Self::Email,
            Self::Phone,
            Self::Ssn,
            Self::CreditCard,
            Self::IpAddress,
            Self::DateOfBirth,
            Self::Iban,
            Self::Sin,
            Self::PostalCode,
            Self::Name,
            Self::Address,
            Self::Organization,
            Self::Location,
            Self::Custom,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_tag() {
        for pii_type in PiiType::all() {
            let tag = pii_type.tag();
            let parsed = PiiType::from_tag(tag).expect("should parse tag");
            assert_eq!(*pii_type, parsed);
        }
    }

    #[test]
    fn from_str_aliases() {
        assert_eq!("cc".parse::<PiiType>().unwrap(), PiiType::CreditCard);
        assert_eq!("addr".parse::<PiiType>().unwrap(), PiiType::Address);
        assert_eq!("IP".parse::<PiiType>().unwrap(), PiiType::IpAddress);
    }

    // --- Edge cases ---

    #[test]
    fn from_str_unknown_returns_err() {
        assert!("garbage".parse::<PiiType>().is_err());
    }

    #[test]
    fn from_str_empty_returns_err() {
        assert!("".parse::<PiiType>().is_err());
    }

    #[test]
    fn from_tag_unknown_returns_none() {
        assert!(PiiType::from_tag("unknown").is_none());
        assert!(PiiType::from_tag("").is_none());
    }

    #[test]
    fn from_tag_is_case_sensitive() {
        // from_tag uses exact match, uppercase should fail
        assert!(PiiType::from_tag("Email").is_none());
        assert!(PiiType::from_tag("SSN").is_none());
    }

    #[test]
    fn from_str_is_case_insensitive() {
        // from_str lowercases first, so these should work
        assert_eq!("EMAIL".parse::<PiiType>().unwrap(), PiiType::Email);
        assert_eq!("Ssn".parse::<PiiType>().unwrap(), PiiType::Ssn);
    }
}
