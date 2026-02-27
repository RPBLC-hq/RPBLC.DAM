use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// All recognized categories of personally identifiable information.
///
/// Each variant has a short [`tag()`](PiiType::tag) used in reference strings
/// (e.g. `[email:a3f71bc9]`) and a longer [`Display`] form for human output.
/// Use [`FromStr`] for case-insensitive parsing with aliases (e.g. "cc" → `CreditCard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    /// Email address (tag: `email`). Global locale.
    Email,
    /// Phone number (tag: `phone`). Global + US locale.
    Phone,
    /// US Social Security Number (tag: `ssn`). US locale.
    Ssn,
    /// Credit card number, Luhn-validated (tag: `cc`). Global locale.
    CreditCard,
    /// IPv4 address, public IPs only (tag: `ip`). Global locale.
    IpAddress,
    /// Date of birth (tag: `dob`). Global locale.
    DateOfBirth,
    /// International Bank Account Number, Mod97-validated (tag: `iban`). Global locale.
    Iban,
    /// Canadian Social Insurance Number, Luhn-validated (tag: `sin`). Canada locale.
    Sin,
    /// Canadian postal code (tag: `postal`). Canada locale.
    PostalCode,
    /// UK National Insurance number (tag: `ni`). UK locale.
    NiNumber,
    /// UK NHS number, Mod11-validated (tag: `nhs`). UK locale.
    NhsNumber,
    /// UK driving licence, DVLA format (tag: `dl`). UK locale.
    DriversLicense,
    /// French INSEE/NIR (tag: `nir`). France locale.
    InseeNir,
    /// National identity card number (tag: `natid`). Germany locale.
    NationalId,
    /// Tax identification number (tag: `taxid`). Germany locale.
    TaxId,
    /// EU VAT number (tag: `vat`). EU locale.
    VatNumber,
    /// SWIFT/BIC code (tag: `swift`). EU locale.
    SwiftBic,
    /// Person name (tag: `name`). Phase 2 NER.
    Name,
    /// Physical address (tag: `addr`). Phase 2 NER.
    Address,
    /// Organization name (tag: `org`). Phase 2 NER.
    Organization,
    /// Geographic location (tag: `loc`). Phase 2 NER.
    Location,
    // --- Digital secrets & credentials ---
    /// JSON Web Token — three base64url segments (tag: `jwt`).
    JwtToken,
    /// AWS access key ID — AKIA-prefixed 20-char credential (tag: `aws_key`).
    AwsKey,
    /// AWS resource identifier — arn:aws:... format (tag: `aws_arn`).
    AwsArn,
    /// GitHub personal access or OAuth token — gh[pousr]_-prefixed (tag: `gh_token`).
    GitHubToken,
    /// Stripe API key or object ID — sk_/pk_/cus_/tok_/pm_/src_/sub_/card_-prefixed (tag: `stripe_key`).
    StripeKey,
    /// Generic third-party API key — Google (AIza), Slack (xox), SendGrid (SG.), npm (npm_), Mailgun (key-), Twilio (SK) (tag: `api_key`).
    ApiKey,
    /// LLM provider API key — Anthropic (sk-ant-), OpenAI (sk-/sk-proj-/sk-svcacct-), Hugging Face (hf_), Replicate (r8_), xAI (xai-), Groq (gsk_), Perplexity (pplx-) (tag: `llm_key`).
    LlmApiKey,
    /// PEM-encoded private key — RSA, EC, or OpenSSH (tag: `priv_key`).
    PrivateKey,
    /// URL with embedded credentials, e.g. `postgres://user:pass@host/db` (tag: `cred_url`).
    CredentialUrl,
    // --- Financial ---
    /// UK bank sort code + account number pair (tag: `bank_acct`).
    BankAccount,
    // --- Crypto ---
    /// Cryptocurrency wallet address — Bitcoin (legacy/bech32) or Ethereum (tag: `wallet`).
    CryptoWallet,
    // --- Network ---
    /// MAC / hardware address (tag: `mac`).
    MacAddress,
    /// IPv6 address — fully-expanded 8-group form (tag: `ipv6`).
    IPv6Address,
    // --- Documents ---
    /// Passport Machine Readable Zone — TD3 two-line format (tag: `mrz`).
    PassportMrz,
    // --- Logistics ---
    /// UPS shipment tracking number — 1Z-prefixed 18-char format (tag: `ups`).
    UpsTracking,
    // --- Vehicle ---
    /// Vehicle Identification Number, ISO 3779 check digit (tag: `vin`). Global locale.
    Vin,
    // --- National IDs (regional) ---
    /// Singapore NRIC/FIN — citizen and foreign resident identity (tag: `nric`). Singapore locale.
    Nric,
    /// Spanish NIF — Número de Identificación Fiscal (tag: `nif`). Spain locale.
    Nif,
    /// Spanish NIE — Número de Identidad de Extranjero (tag: `nie`). Spain locale.
    Nie,
    /// Italian Codice Fiscale — 16-character tax code with checksum (tag: `cf`). Italy locale.
    CodiceFiscale,
    /// Brazilian CPF — Cadastro de Pessoas Físicas, double mod-11 check (tag: `cpf`). Brazil locale.
    Cpf,
    /// Mexican CURP — Clave Única de Registro de Población, 18-char identity code (tag: `curp`). Mexico locale.
    Curp,
    /// UAE Emirates ID — 15-digit national identity card, Luhn-validated (tag: `eid`). UAE locale.
    EmiratesId,
    // --- Government / Professional ---
    /// DEA registration number — Drug Enforcement Administration (tag: `dea`). US locale.
    DeaNumber,
    /// User-defined PII type from custom rules (tag: `custom`).
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
            Self::NiNumber => "ni_number",
            Self::NhsNumber => "nhs_number",
            Self::DriversLicense => "drivers_license",
            Self::InseeNir => "insee_nir",
            Self::NationalId => "national_id",
            Self::TaxId => "tax_id",
            Self::VatNumber => "vat_number",
            Self::SwiftBic => "swift_bic",
            Self::Name => "name",
            Self::Address => "address",
            Self::Organization => "org",
            Self::Location => "location",
            Self::JwtToken => "jwt_token",
            Self::AwsKey => "aws_key",
            Self::AwsArn => "aws_arn",
            Self::GitHubToken => "github_token",
            Self::StripeKey => "stripe_key",
            Self::ApiKey => "api_key",
            Self::LlmApiKey => "llm_api_key",
            Self::PrivateKey => "private_key",
            Self::CredentialUrl => "credential_url",
            Self::BankAccount => "bank_account",
            Self::CryptoWallet => "crypto_wallet",
            Self::MacAddress => "mac_address",
            Self::IPv6Address => "ipv6_address",
            Self::PassportMrz => "passport_mrz",
            Self::UpsTracking => "ups_tracking",
            Self::Vin => "vin",
            Self::Nric => "nric",
            Self::Nif => "nif",
            Self::Nie => "nie",
            Self::CodiceFiscale => "codice_fiscale",
            Self::Cpf => "cpf",
            Self::Curp => "curp",
            Self::EmiratesId => "emirates_id",
            Self::DeaNumber => "dea_number",
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
            "ni" | "ni_number" | "ninumber" => Ok(Self::NiNumber),
            "nhs" | "nhs_number" | "nhsnumber" => Ok(Self::NhsNumber),
            "dl" | "drivers_license" | "driverslicense" => Ok(Self::DriversLicense),
            "nir" | "insee_nir" | "inseenir" => Ok(Self::InseeNir),
            "natid" | "national_id" | "nationalid" => Ok(Self::NationalId),
            "taxid" | "tax_id" => Ok(Self::TaxId),
            "vat" | "vat_number" | "vatnumber" => Ok(Self::VatNumber),
            "swift" | "swift_bic" | "swiftbic" | "bic" => Ok(Self::SwiftBic),
            "name" => Ok(Self::Name),
            "address" | "addr" => Ok(Self::Address),
            "org" | "organization" => Ok(Self::Organization),
            "location" | "loc" => Ok(Self::Location),
            "jwt" | "jwt_token" | "jwttoken" => Ok(Self::JwtToken),
            "aws_key" | "awskey" => Ok(Self::AwsKey),
            "aws_arn" | "awsarn" => Ok(Self::AwsArn),
            "gh_token" | "ghtoken" | "github_token" => Ok(Self::GitHubToken),
            "stripe_key" | "stripekey" => Ok(Self::StripeKey),
            "api_key" | "apikey" => Ok(Self::ApiKey),
            "llm_key" | "llm_api_key" | "llmapikey" => Ok(Self::LlmApiKey),
            "priv_key" | "privkey" | "private_key" => Ok(Self::PrivateKey),
            "cred_url" | "credurl" | "credential_url" => Ok(Self::CredentialUrl),
            "bank_acct" | "bank_account" | "bankaccount" => Ok(Self::BankAccount),
            "wallet" | "crypto_wallet" => Ok(Self::CryptoWallet),
            "mac" | "mac_address" | "macaddress" => Ok(Self::MacAddress),
            "ipv6" | "ipv6_address" => Ok(Self::IPv6Address),
            "mrz" | "passport_mrz" => Ok(Self::PassportMrz),
            "ups" | "ups_tracking" => Ok(Self::UpsTracking),
            "vin" => Ok(Self::Vin),
            "nric" => Ok(Self::Nric),
            "nif" => Ok(Self::Nif),
            "nie" => Ok(Self::Nie),
            "cf" | "codice_fiscale" | "codicefiscale" => Ok(Self::CodiceFiscale),
            "cpf" => Ok(Self::Cpf),
            "curp" => Ok(Self::Curp),
            "eid" | "emirates_id" | "emiratesid" => Ok(Self::EmiratesId),
            "dea" | "dea_number" | "deanumber" => Ok(Self::DeaNumber),
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
            Self::NiNumber => "ni",
            Self::NhsNumber => "nhs",
            Self::DriversLicense => "dl",
            Self::InseeNir => "nir",
            Self::NationalId => "natid",
            Self::TaxId => "taxid",
            Self::VatNumber => "vat",
            Self::SwiftBic => "swift",
            Self::Name => "name",
            Self::Address => "addr",
            Self::Organization => "org",
            Self::Location => "loc",
            Self::JwtToken => "jwt",
            Self::AwsKey => "aws_key",
            Self::AwsArn => "aws_arn",
            Self::GitHubToken => "gh_token",
            Self::StripeKey => "stripe_key",
            Self::ApiKey => "api_key",
            Self::LlmApiKey => "llm_key",
            Self::PrivateKey => "priv_key",
            Self::CredentialUrl => "cred_url",
            Self::BankAccount => "bank_acct",
            Self::CryptoWallet => "wallet",
            Self::MacAddress => "mac",
            Self::IPv6Address => "ipv6",
            Self::PassportMrz => "mrz",
            Self::UpsTracking => "ups",
            Self::Vin => "vin",
            Self::Nric => "nric",
            Self::Nif => "nif",
            Self::Nie => "nie",
            Self::CodiceFiscale => "cf",
            Self::Cpf => "cpf",
            Self::Curp => "curp",
            Self::EmiratesId => "eid",
            Self::DeaNumber => "dea",
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
            "ni" => Some(Self::NiNumber),
            "nhs" => Some(Self::NhsNumber),
            "dl" => Some(Self::DriversLicense),
            "nir" => Some(Self::InseeNir),
            "natid" => Some(Self::NationalId),
            "taxid" => Some(Self::TaxId),
            "vat" => Some(Self::VatNumber),
            "swift" => Some(Self::SwiftBic),
            "name" => Some(Self::Name),
            "addr" => Some(Self::Address),
            "org" => Some(Self::Organization),
            "loc" => Some(Self::Location),
            "jwt" => Some(Self::JwtToken),
            "aws_key" => Some(Self::AwsKey),
            "aws_arn" => Some(Self::AwsArn),
            "gh_token" => Some(Self::GitHubToken),
            "stripe_key" => Some(Self::StripeKey),
            "api_key" => Some(Self::ApiKey),
            "llm_key" => Some(Self::LlmApiKey),
            "priv_key" => Some(Self::PrivateKey),
            "cred_url" => Some(Self::CredentialUrl),
            "bank_acct" => Some(Self::BankAccount),
            "wallet" => Some(Self::CryptoWallet),
            "mac" => Some(Self::MacAddress),
            "ipv6" => Some(Self::IPv6Address),
            "mrz" => Some(Self::PassportMrz),
            "ups" => Some(Self::UpsTracking),
            "vin" => Some(Self::Vin),
            "nric" => Some(Self::Nric),
            "nif" => Some(Self::Nif),
            "nie" => Some(Self::Nie),
            "cf" => Some(Self::CodiceFiscale),
            "cpf" => Some(Self::Cpf),
            "curp" => Some(Self::Curp),
            "eid" => Some(Self::EmiratesId),
            "dea" => Some(Self::DeaNumber),
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
            Self::NiNumber,
            Self::NhsNumber,
            Self::DriversLicense,
            Self::InseeNir,
            Self::NationalId,
            Self::TaxId,
            Self::VatNumber,
            Self::SwiftBic,
            Self::Name,
            Self::Address,
            Self::Organization,
            Self::Location,
            Self::JwtToken,
            Self::AwsKey,
            Self::AwsArn,
            Self::GitHubToken,
            Self::StripeKey,
            Self::ApiKey,
            Self::LlmApiKey,
            Self::PrivateKey,
            Self::CredentialUrl,
            Self::BankAccount,
            Self::CryptoWallet,
            Self::MacAddress,
            Self::IPv6Address,
            Self::PassportMrz,
            Self::UpsTracking,
            Self::Vin,
            Self::Nric,
            Self::Nif,
            Self::Nie,
            Self::CodiceFiscale,
            Self::Cpf,
            Self::Curp,
            Self::EmiratesId,
            Self::DeaNumber,
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
