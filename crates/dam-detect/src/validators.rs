//! Shared PII validators used by locale pattern modules.

/// Luhn algorithm — generic implementation accepting any digit count >= 2.
pub(crate) fn validate_luhn(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 2 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Luhn check for credit cards — requires 13-19 digits.
pub(crate) fn validate_luhn_cc(value: &str) -> bool {
    let digit_count = value.chars().filter(|c| c.is_ascii_digit()).count();
    (13..=19).contains(&digit_count) && validate_luhn(value)
}

/// Luhn check for Canadian SIN — requires exactly 9 digits, first digit not 0 or 8.
pub(crate) fn validate_luhn_sin(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 9 {
        return false;
    }

    // First digit cannot be 0 or 8
    if digits[0] == 0 || digits[0] == 8 {
        return false;
    }

    validate_luhn(value)
}

/// Validate SSN: exclude known invalid ranges (000, 666, 900-999 for area).
pub(crate) fn validate_ssn(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits[..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..].parse().unwrap_or(0);

    // Invalid area numbers
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    // Group and serial can't be all zeros
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Validate that an IP is not a common non-PII address (localhost, broadcast, etc.).
pub(crate) fn validate_ip(value: &str) -> bool {
    let parts: Vec<u8> = value.split('.').filter_map(|p| p.parse().ok()).collect();

    if parts.len() != 4 {
        return false;
    }

    // Exclude common non-PII IPs
    match (parts[0], parts[1], parts[2], parts[3]) {
        (127, _, _, _) => false,       // loopback
        (0, 0, 0, 0) => false,         // unspecified
        (255, 255, 255, 255) => false, // broadcast
        (10, _, _, _) => false,        // private class A
        (172, 16..=31, _, _) => false, // private class B
        (192, 168, _, _) => false,     // private class C
        (169, 254, _, _) => false,     // link-local
        _ => true,
    }
}

/// MOD 97-10 check (ISO 7064) used by IBAN validation.
/// Expects an alphanumeric string. Rearranges first 4 chars to end,
/// converts letters A=10..Z=35, computes iterative mod 97.
pub(crate) fn validate_mod97(value: &str) -> bool {
    if value.len() < 5 || !value.is_ascii() {
        return false;
    }

    // Rearrange: move first 4 chars to end
    let rearranged = format!("{}{}", &value[4..], &value[..4]);

    // Convert to numeric string: A=10, B=11, ..., Z=35
    let mut numeric = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_uppercase() {
            let val = (c as u32) - ('A' as u32) + 10;
            numeric.push_str(&val.to_string());
        } else {
            return false;
        }
    }

    // Iterative mod 97 to avoid big-integer arithmetic
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let s = std::str::from_utf8(chunk).unwrap_or("0");
        let combined = format!("{remainder}{s}");
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }

    remainder == 1
}

/// IBAN country-specific length table (ISO 13616).
fn iban_length(country: &str) -> Option<usize> {
    match country {
        "AL" => Some(28),
        "AD" => Some(24),
        "AT" => Some(20),
        "AZ" => Some(28),
        "BH" => Some(22),
        "BY" => Some(28),
        "BE" => Some(16),
        "BA" => Some(20),
        "BR" => Some(29),
        "BG" => Some(22),
        "CR" => Some(22),
        "HR" => Some(21),
        "CY" => Some(28),
        "CZ" => Some(24),
        "DK" => Some(18),
        "DO" => Some(28),
        "TL" => Some(23),
        "EG" => Some(29),
        "SV" => Some(28),
        "EE" => Some(20),
        "FO" => Some(18),
        "FI" => Some(18),
        "FR" => Some(27),
        "GE" => Some(22),
        "DE" => Some(22),
        "GI" => Some(23),
        "GR" => Some(27),
        "GL" => Some(18),
        "GT" => Some(28),
        "HU" => Some(28),
        "IS" => Some(26),
        "IQ" => Some(23),
        "IE" => Some(22),
        "IL" => Some(23),
        "IT" => Some(27),
        "JO" => Some(30),
        "KZ" => Some(20),
        "XK" => Some(20),
        "KW" => Some(30),
        "LV" => Some(21),
        "LB" => Some(28),
        "LI" => Some(21),
        "LT" => Some(20),
        "LU" => Some(20),
        "MK" => Some(19),
        "MT" => Some(31),
        "MR" => Some(27),
        "MU" => Some(30),
        "MC" => Some(27),
        "MD" => Some(24),
        "ME" => Some(22),
        "NL" => Some(18),
        "NO" => Some(15),
        "PK" => Some(24),
        "PS" => Some(29),
        "PL" => Some(28),
        "PT" => Some(25),
        "QA" => Some(29),
        "RO" => Some(24),
        "LC" => Some(32),
        "SM" => Some(27),
        "ST" => Some(25),
        "SA" => Some(24),
        "RS" => Some(22),
        "SC" => Some(31),
        "SK" => Some(24),
        "SI" => Some(19),
        "ES" => Some(24),
        "SE" => Some(24),
        "CH" => Some(21),
        "TN" => Some(24),
        "TR" => Some(26),
        "UA" => Some(29),
        "AE" => Some(23),
        "GB" => Some(22),
        "VG" => Some(24),
        _ => None,
    }
}

/// Validate an IBAN: format check + country-specific length + MOD 97.
pub(crate) fn validate_iban(value: &str) -> bool {
    let upper = value.to_uppercase();
    let clean: String = upper
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    // Non-ASCII input cannot be a valid IBAN; reject early to make byte slicing safe.
    if !clean.is_ascii() {
        return false;
    }

    // Minimum IBAN length is 15 (Norway), max is 34
    if clean.len() < 15 || clean.len() > 34 {
        return false;
    }

    // First 2 chars must be letters (country code)
    let country: &str = &clean[..2];
    if !country.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Chars 3-4 must be digits (check digits)
    if !clean[2..4].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Rest must be alphanumeric
    if !clean[4..].chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    // Country-specific length check
    if let Some(expected_len) = iban_length(country)
        && clean.len() != expected_len
    {
        return false;
    }

    validate_mod97(&clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Luhn (generic) ---

    #[test]
    fn luhn_valid() {
        assert!(validate_luhn("79927398713")); // Wikipedia example
        assert!(validate_luhn("0000000000")); // All zeros, 10 digits
    }

    #[test]
    fn luhn_invalid() {
        assert!(!validate_luhn("79927398710"));
        assert!(!validate_luhn("1234567890"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!validate_luhn("1"));
        assert!(!validate_luhn(""));
    }

    #[test]
    fn luhn_strips_non_digits() {
        assert!(validate_luhn("7992-7398-713"));
        assert!(validate_luhn("7992 7398 713"));
    }

    // --- Luhn CC ---

    #[test]
    fn luhn_cc_valid_visa() {
        assert!(validate_luhn_cc("4111111111111111"));
        assert!(validate_luhn_cc("4111 1111 1111 1111"));
    }

    #[test]
    fn luhn_cc_valid_mastercard() {
        assert!(validate_luhn_cc("5500000000000004"));
    }

    #[test]
    fn luhn_cc_valid_amex() {
        assert!(validate_luhn_cc("378282246310005"));
    }

    #[test]
    fn luhn_cc_too_short() {
        // 12 digits — below CC range
        assert!(!validate_luhn_cc("123456789012"));
    }

    #[test]
    fn luhn_cc_too_long() {
        // 20 digits — above CC range
        assert!(!validate_luhn_cc("12345678901234567890"));
    }

    #[test]
    fn luhn_cc_fails_luhn() {
        assert!(!validate_luhn_cc("4111111111111112"));
    }

    // --- Luhn SIN ---

    #[test]
    fn luhn_sin_valid() {
        // 130 692 544 passes Luhn and starts with 1
        assert!(validate_luhn_sin("130692544"));
        assert!(validate_luhn_sin("130-692-544"));
        assert!(validate_luhn_sin("130 692 544"));
    }

    #[test]
    fn luhn_sin_starts_with_zero_rejected() {
        // 046 454 286 passes Luhn but starts with 0 — invalid
        assert!(!validate_luhn_sin("046454286"));
    }

    #[test]
    fn luhn_sin_starts_with_eight_rejected() {
        // Starts with 8 — reserved, should be rejected
        assert!(!validate_luhn_sin("800000002"));
    }

    #[test]
    fn luhn_sin_wrong_length() {
        assert!(!validate_luhn_sin("12345678")); // 8 digits
        assert!(!validate_luhn_sin("1234567890")); // 10 digits
    }

    #[test]
    fn luhn_sin_fails_luhn() {
        // 123-456-780 — 9 digits, starts with 1, but likely fails Luhn
        assert!(!validate_luhn_sin("123456780"));
    }

    #[test]
    fn luhn_sin_valid_starting_with_various_digits() {
        // 130 692 544 passes Luhn and starts with 1
        assert!(validate_luhn_sin("130692544"));
    }

    // --- SSN ---

    #[test]
    fn ssn_valid() {
        assert!(validate_ssn("123-45-6789"));
        assert!(validate_ssn("123 45 6789"));
        assert!(validate_ssn("123456789"));
    }

    #[test]
    fn ssn_invalid_area_zero() {
        assert!(!validate_ssn("000-12-3456"));
    }

    #[test]
    fn ssn_invalid_area_666() {
        assert!(!validate_ssn("666-12-3456"));
    }

    #[test]
    fn ssn_invalid_area_900_plus() {
        assert!(!validate_ssn("900-12-3456"));
        assert!(!validate_ssn("999-88-7777"));
    }

    #[test]
    fn ssn_invalid_zero_group() {
        assert!(!validate_ssn("123-00-6789"));
    }

    #[test]
    fn ssn_invalid_zero_serial() {
        assert!(!validate_ssn("123-45-0000"));
    }

    #[test]
    fn ssn_wrong_length() {
        assert!(!validate_ssn("12345678"));
        assert!(!validate_ssn("1234567890"));
    }

    // --- IP ---

    #[test]
    fn ip_valid_public() {
        assert!(validate_ip("8.8.8.8"));
        assert!(validate_ip("203.0.113.1"));
        assert!(validate_ip("1.1.1.1"));
    }

    #[test]
    fn ip_reject_loopback() {
        assert!(!validate_ip("127.0.0.1"));
        assert!(!validate_ip("127.255.255.255"));
    }

    #[test]
    fn ip_reject_private() {
        assert!(!validate_ip("10.0.0.1"));
        assert!(!validate_ip("172.16.0.1"));
        assert!(!validate_ip("172.31.255.255"));
        assert!(!validate_ip("192.168.1.1"));
    }

    #[test]
    fn ip_reject_link_local() {
        assert!(!validate_ip("169.254.1.1"));
        assert!(!validate_ip("169.254.169.254"));
    }

    #[test]
    fn ip_reject_broadcast() {
        assert!(!validate_ip("255.255.255.255"));
    }

    #[test]
    fn ip_reject_unspecified() {
        assert!(!validate_ip("0.0.0.0"));
    }

    #[test]
    fn ip_wrong_format() {
        assert!(!validate_ip("not.an.ip"));
        assert!(!validate_ip("1.2.3"));
        assert!(!validate_ip(""));
    }

    // --- MOD 97 ---

    #[test]
    fn mod97_valid_de_iban() {
        assert!(validate_mod97("DE89370400440532013000"));
    }

    #[test]
    fn mod97_valid_gb_iban() {
        assert!(validate_mod97("GB29NWBK60161331926819"));
    }

    #[test]
    fn mod97_valid_fr_iban() {
        assert!(validate_mod97("FR7630006000011234567890189"));
    }

    #[test]
    fn mod97_invalid_check_digits() {
        assert!(!validate_mod97("DE00370400440532013000"));
    }

    #[test]
    fn mod97_too_short() {
        assert!(!validate_mod97("DE89"));
        assert!(!validate_mod97(""));
    }

    #[test]
    fn mod97_lowercase_rejected() {
        // Our mod97 only accepts uppercase
        assert!(!validate_mod97("de89370400440532013000"));
    }

    // --- IBAN ---

    #[test]
    fn iban_valid_german() {
        assert!(validate_iban("DE89370400440532013000"));
        assert!(validate_iban("DE89 3704 0044 0532 0130 00")); // with spaces
    }

    #[test]
    fn iban_valid_british() {
        assert!(validate_iban("GB29NWBK60161331926819"));
    }

    #[test]
    fn iban_valid_french() {
        assert!(validate_iban("FR7630006000011234567890189"));
    }

    #[test]
    fn iban_valid_norwegian() {
        assert!(validate_iban("NO9386011117947")); // 15 chars, shortest IBAN
    }

    #[test]
    fn iban_valid_case_insensitive() {
        assert!(validate_iban("de89370400440532013000"));
    }

    #[test]
    fn iban_invalid_check_digits() {
        assert!(!validate_iban("DE00370400440532013000"));
    }

    #[test]
    fn iban_invalid_country_length() {
        // DE should be 22 chars, this is 23
        assert!(!validate_iban("DE893704004405320130001"));
    }

    #[test]
    fn iban_too_short() {
        assert!(!validate_iban("DE89370400"));
    }

    #[test]
    fn iban_too_long() {
        assert!(!validate_iban("DE8937040044053201300000000000000000000"));
    }

    #[test]
    fn iban_invalid_format() {
        assert!(!validate_iban("1234567890123456")); // no country code
        assert!(!validate_iban("")); // empty
    }
}
