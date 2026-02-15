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

/// UK National Insurance number prefix validation.
/// Excludes: BG, GB, NK, KN, TN, NT, ZZ, and prefixes starting with D, F, I, Q, U, V.
pub(crate) fn validate_ni_prefix(value: &str) -> bool {
    let clean: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if clean.len() != 9 {
        return false;
    }
    let upper = clean.to_uppercase();
    let prefix = &upper[..2];

    // Invalid prefixes
    !matches!(prefix, "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ")
        && !matches!(upper.as_bytes()[0], b'D' | b'F' | b'I' | b'Q' | b'U' | b'V')
}

/// UK NHS number: MOD 11 weighted check digit.
/// Weights: 10, 9, 8, 7, 6, 5, 4, 3, 2. Check digit = 11 - (sum mod 11).
/// If check digit is 10, the number is invalid. If 11, check digit is 0.
pub(crate) fn validate_nhs_mod11(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 10 {
        return false;
    }

    let weights = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits
        .iter()
        .take(9)
        .zip(weights.iter())
        .map(|(d, w)| d * w)
        .sum();

    let remainder = sum % 11;
    let check = 11 - remainder;

    // Check digit of 10 means the number is invalid
    if check == 10 {
        return false;
    }

    let expected = if check == 11 { 0 } else { check };
    digits[9] == expected
}

/// UK DVLA driving licence validation (16 alphanumeric chars).
/// Surname(5), decade(1), month(2, female +50), day(2), year(1), initials(2), check(3).
pub(crate) fn validate_dvla_license(value: &str) -> bool {
    let clean: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    if clean.len() != 16 {
        return false;
    }

    let upper = clean.to_uppercase();
    let bytes = upper.as_bytes();

    // First 5 chars: surname portion (letters or '9' for padding)
    if !bytes[..5]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b == b'9')
    {
        return false;
    }

    // Chars 6-11 (index 5-10): date portion — all digits
    if !bytes[5..11].iter().all(|&b| b.is_ascii_digit()) {
        return false;
    }

    // Month check (index 6-7): 01-12 or 51-62 (female)
    let month: u32 = std::str::from_utf8(&bytes[6..8])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !((1..=12).contains(&month) || (51..=62).contains(&month)) {
        return false;
    }

    // Day check (index 8-9): 01-31
    let day: u32 = std::str::from_utf8(&bytes[8..10])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !(1..=31).contains(&day) {
        return false;
    }

    true
}

/// French NIR (numéro de sécurité sociale) key validation.
/// 15 digits: 13-digit base + 2-digit key. Key = 97 - (base mod 97).
/// Special handling for Corsica: 2A → 19, 2B → 18 in the département field (positions 5-6).
pub(crate) fn validate_nir_key(value: &str) -> bool {
    let digits: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    if digits.len() != 15 {
        return false;
    }

    // Handle Corsica départements: positions 5-6 (0-indexed) may be 2A or 2B
    let upper = digits.to_uppercase();
    let base_str = &upper[..13];
    let key_str = &upper[13..15];

    let key: u64 = match key_str.parse() {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Replace 2A/2B in département field for numeric computation
    let base_numeric = if base_str.len() >= 7 && &base_str[5..7] == "2A" {
        format!("{}19{}", &base_str[..5], &base_str[7..])
    } else if base_str.len() >= 7 && &base_str[5..7] == "2B" {
        format!("{}18{}", &base_str[..5], &base_str[7..])
    } else {
        base_str.to_string()
    };

    let base: u64 = match base_numeric.parse() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let expected_key = 97 - (base % 97);
    key == expected_key
}

/// German Steuer-ID (tax identification number) validation.
/// 11 digits. First digit is not 0. The first 10 digits must have exactly one digit
/// appearing twice (or three times) and the rest appearing once. Check digit is position 11.
/// Uses the iterative product-sum check digit algorithm.
pub(crate) fn validate_steuer_id(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 11 {
        return false;
    }

    // First digit must not be 0
    if digits[0] == 0 {
        return false;
    }

    // Digit frequency check on first 10 digits:
    // Exactly one digit must appear 2 or 3 times, rest exactly once (or not at all)
    let mut freq = [0u32; 10];
    for &d in &digits[..10] {
        freq[d as usize] += 1;
    }
    let doubles = freq.iter().filter(|&&f| f == 2).count();
    let triples = freq.iter().filter(|&&f| f == 3).count();
    let valid_freq = (doubles == 1 && triples == 0) || (doubles == 0 && triples == 1);
    if !valid_freq {
        return false;
    }

    // Iterative check digit algorithm
    let mut product = 10u32;
    for &d in &digits[..10] {
        let mut sum = (d + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }

    let check = 11 - product;
    let expected = if check == 10 { 0 } else { check };
    digits[10] == expected
}

/// ICAO 9303 check digit for German Personalausweis.
/// Weights cycle 7-3-1. Digits map to themselves, letters A=10..Z=35, '<'=0.
pub(crate) fn validate_icao_check(value: &str) -> bool {
    let clean: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    if clean.len() != 10 {
        return false;
    }

    let upper = clean.to_uppercase();
    let bytes = upper.as_bytes();
    let weights = [7, 3, 1, 7, 3, 1, 7, 3, 1];

    // First char must be a letter from the valid set
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }

    let mut sum: u32 = 0;
    for (i, &b) in bytes[..9].iter().enumerate() {
        let val = if b.is_ascii_digit() {
            (b - b'0') as u32
        } else if b.is_ascii_uppercase() {
            (b - b'A') as u32 + 10
        } else {
            return false;
        };
        sum += val * weights[i];
    }

    let expected_check = sum % 10;
    let last = bytes[9];
    if !last.is_ascii_digit() {
        return false;
    }
    let actual_check = (last - b'0') as u32;

    actual_check == expected_check
}

/// EU VAT number format validation.
/// Checks country prefix (2 letters) + country-specific length and basic format.
pub(crate) fn validate_eu_vat(value: &str) -> bool {
    let clean: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    if clean.len() < 4 {
        return false;
    }

    let upper = clean.to_uppercase();
    if !upper.is_ascii() {
        return false;
    }

    let country = &upper[..2];
    let body = &upper[2..];

    // Country-specific length validation (total length including prefix)
    match country {
        "AT" => body.len() == 9 && body.starts_with('U'),
        "BE" => body.len() == 10 && body.chars().all(|c| c.is_ascii_digit()),
        "BG" => (body.len() == 9 || body.len() == 10) && body.chars().all(|c| c.is_ascii_digit()),
        "CY" => body.len() == 9 && body[..8].chars().all(|c| c.is_ascii_digit()),
        "CZ" => {
            (body.len() == 8 || body.len() == 9 || body.len() == 10)
                && body.chars().all(|c| c.is_ascii_digit())
        }
        "DE" => body.len() == 9 && body.chars().all(|c| c.is_ascii_digit()),
        "DK" => body.len() == 8 && body.chars().all(|c| c.is_ascii_digit()),
        "EE" => body.len() == 9 && body.chars().all(|c| c.is_ascii_digit()),
        "EL" => body.len() == 9 && body.chars().all(|c| c.is_ascii_digit()),
        "ES" => body.len() == 9,
        "FI" => body.len() == 8 && body.chars().all(|c| c.is_ascii_digit()),
        "FR" => body.len() == 11,
        "HR" => body.len() == 11 && body.chars().all(|c| c.is_ascii_digit()),
        "HU" => body.len() == 8 && body.chars().all(|c| c.is_ascii_digit()),
        "IE" => body.len() == 7 || body.len() == 8 || body.len() == 9,
        "IT" => body.len() == 11 && body.chars().all(|c| c.is_ascii_digit()),
        "LT" => (body.len() == 9 || body.len() == 12) && body.chars().all(|c| c.is_ascii_digit()),
        "LU" => body.len() == 8 && body.chars().all(|c| c.is_ascii_digit()),
        "LV" => body.len() == 11 && body.chars().all(|c| c.is_ascii_digit()),
        "MT" => body.len() == 8 && body.chars().all(|c| c.is_ascii_digit()),
        "NL" => body.len() == 12,
        "PL" => body.len() == 10 && body.chars().all(|c| c.is_ascii_digit()),
        "PT" => body.len() == 9 && body.chars().all(|c| c.is_ascii_digit()),
        "RO" => (2..=10).contains(&body.len()) && body.chars().all(|c| c.is_ascii_digit()),
        "SE" => body.len() == 12 && body.chars().all(|c| c.is_ascii_digit()),
        "SI" => body.len() == 8 && body.chars().all(|c| c.is_ascii_digit()),
        "SK" => body.len() == 10 && body.chars().all(|c| c.is_ascii_digit()),
        _ => false, // Unknown EU country prefix
    }
}

/// SWIFT/BIC code validation.
/// 8 or 11 characters: 4 bank code (letters) + 2 country code (letters, ISO 3166-1)
/// + 2 location code (alphanumeric) + optional 3 branch code (alphanumeric).
pub(crate) fn validate_swift_bic(value: &str) -> bool {
    let clean: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    if clean.len() != 8 && clean.len() != 11 {
        return false;
    }

    let upper = clean.to_uppercase();
    let bytes = upper.as_bytes();

    // First 4 chars: bank code (letters only)
    if !bytes[..4].iter().all(|b| b.is_ascii_uppercase()) {
        return false;
    }

    // Chars 5-6: country code (letters, must be valid ISO 3166-1 alpha-2)
    let country = std::str::from_utf8(&bytes[4..6]).unwrap_or("");
    if !is_valid_iso3166(country) {
        return false;
    }

    // Chars 7-8: location code (alphanumeric)
    if !bytes[6..8].iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }

    // If 11 chars, chars 9-11: branch code (alphanumeric)
    if clean.len() == 11 && !bytes[8..11].iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }

    true
}

/// Check if a 2-letter code is a valid ISO 3166-1 alpha-2 country code.
/// Covers all current sovereign states and commonly used codes.
fn is_valid_iso3166(code: &str) -> bool {
    matches!(
        code,
        "AD" | "AE"
            | "AF"
            | "AG"
            | "AI"
            | "AL"
            | "AM"
            | "AO"
            | "AQ"
            | "AR"
            | "AS"
            | "AT"
            | "AU"
            | "AW"
            | "AX"
            | "AZ"
            | "BA"
            | "BB"
            | "BD"
            | "BE"
            | "BF"
            | "BG"
            | "BH"
            | "BI"
            | "BJ"
            | "BL"
            | "BM"
            | "BN"
            | "BO"
            | "BQ"
            | "BR"
            | "BS"
            | "BT"
            | "BV"
            | "BW"
            | "BY"
            | "BZ"
            | "CA"
            | "CC"
            | "CD"
            | "CF"
            | "CG"
            | "CH"
            | "CI"
            | "CK"
            | "CL"
            | "CM"
            | "CN"
            | "CO"
            | "CR"
            | "CU"
            | "CV"
            | "CW"
            | "CX"
            | "CY"
            | "CZ"
            | "DE"
            | "DJ"
            | "DK"
            | "DM"
            | "DO"
            | "DZ"
            | "EC"
            | "EE"
            | "EG"
            | "EH"
            | "ER"
            | "ES"
            | "ET"
            | "FI"
            | "FJ"
            | "FK"
            | "FM"
            | "FO"
            | "FR"
            | "GA"
            | "GB"
            | "GD"
            | "GE"
            | "GF"
            | "GG"
            | "GH"
            | "GI"
            | "GL"
            | "GM"
            | "GN"
            | "GP"
            | "GQ"
            | "GR"
            | "GS"
            | "GT"
            | "GU"
            | "GW"
            | "GY"
            | "HK"
            | "HM"
            | "HN"
            | "HR"
            | "HT"
            | "HU"
            | "ID"
            | "IE"
            | "IL"
            | "IM"
            | "IN"
            | "IO"
            | "IQ"
            | "IR"
            | "IS"
            | "IT"
            | "JE"
            | "JM"
            | "JO"
            | "JP"
            | "KE"
            | "KG"
            | "KH"
            | "KI"
            | "KM"
            | "KN"
            | "KP"
            | "KR"
            | "KW"
            | "KY"
            | "KZ"
            | "LA"
            | "LB"
            | "LC"
            | "LI"
            | "LK"
            | "LR"
            | "LS"
            | "LT"
            | "LU"
            | "LV"
            | "LY"
            | "MA"
            | "MC"
            | "MD"
            | "ME"
            | "MF"
            | "MG"
            | "MH"
            | "MK"
            | "ML"
            | "MM"
            | "MN"
            | "MO"
            | "MP"
            | "MQ"
            | "MR"
            | "MS"
            | "MT"
            | "MU"
            | "MV"
            | "MW"
            | "MX"
            | "MY"
            | "MZ"
            | "NA"
            | "NC"
            | "NE"
            | "NF"
            | "NG"
            | "NI"
            | "NL"
            | "NO"
            | "NP"
            | "NR"
            | "NU"
            | "NZ"
            | "OM"
            | "PA"
            | "PE"
            | "PF"
            | "PG"
            | "PH"
            | "PK"
            | "PL"
            | "PM"
            | "PN"
            | "PR"
            | "PS"
            | "PT"
            | "PW"
            | "PY"
            | "QA"
            | "RE"
            | "RO"
            | "RS"
            | "RU"
            | "RW"
            | "SA"
            | "SB"
            | "SC"
            | "SD"
            | "SE"
            | "SG"
            | "SH"
            | "SI"
            | "SJ"
            | "SK"
            | "SL"
            | "SM"
            | "SN"
            | "SO"
            | "SR"
            | "SS"
            | "ST"
            | "SV"
            | "SX"
            | "SY"
            | "SZ"
            | "TC"
            | "TD"
            | "TF"
            | "TG"
            | "TH"
            | "TJ"
            | "TK"
            | "TL"
            | "TM"
            | "TN"
            | "TO"
            | "TR"
            | "TT"
            | "TV"
            | "TW"
            | "TZ"
            | "UA"
            | "UG"
            | "UM"
            | "US"
            | "UY"
            | "UZ"
            | "VA"
            | "VC"
            | "VE"
            | "VG"
            | "VI"
            | "VN"
            | "VU"
            | "WF"
            | "WS"
            | "XK"
            | "YE"
            | "YT"
            | "ZA"
            | "ZM"
            | "ZW"
    )
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

    // --- NI Number ---

    #[test]
    fn ni_valid() {
        assert!(validate_ni_prefix("AB123456C"));
        assert!(validate_ni_prefix("CE123456D"));
    }

    #[test]
    fn ni_reject_invalid_prefixes() {
        assert!(!validate_ni_prefix("BG123456A")); // BG excluded
        assert!(!validate_ni_prefix("GB123456A")); // GB excluded
        assert!(!validate_ni_prefix("NK123456A")); // NK excluded
        assert!(!validate_ni_prefix("KN123456A")); // KN excluded
        assert!(!validate_ni_prefix("TN123456A")); // TN excluded
        assert!(!validate_ni_prefix("NT123456A")); // NT excluded
        assert!(!validate_ni_prefix("ZZ123456A")); // ZZ excluded
    }

    #[test]
    fn ni_reject_invalid_first_letter() {
        assert!(!validate_ni_prefix("DA123456A")); // D not allowed
        assert!(!validate_ni_prefix("FA123456A")); // F not allowed
        assert!(!validate_ni_prefix("IA123456A")); // I not allowed
        assert!(!validate_ni_prefix("QA123456A")); // Q not allowed
        assert!(!validate_ni_prefix("UA123456A")); // U not allowed
        assert!(!validate_ni_prefix("VA123456A")); // V not allowed
    }

    #[test]
    fn ni_wrong_length() {
        assert!(!validate_ni_prefix("AB12345C")); // 8 chars
        assert!(!validate_ni_prefix("AB1234567C")); // 10 chars
    }

    // --- NHS Number ---

    #[test]
    fn nhs_valid() {
        // 943 476 5919: weights 10*9 + 9*4 + 8*3 + 7*4 + 6*7 + 5*6 + 4*5 + 3*9 + 2*1 = 90+36+24+28+42+30+20+27+2 = 299
        // 299 % 11 = 2, check = 11-2 = 9 ✓
        assert!(validate_nhs_mod11("9434765919"));
    }

    #[test]
    fn nhs_valid_with_spaces() {
        assert!(validate_nhs_mod11("943 476 5919"));
    }

    #[test]
    fn nhs_invalid_check_digit() {
        assert!(!validate_nhs_mod11("9434765910"));
    }

    #[test]
    fn nhs_wrong_length() {
        assert!(!validate_nhs_mod11("943476591")); // 9 digits
        assert!(!validate_nhs_mod11("94347659190")); // 11 digits
    }

    // --- DVLA Licence ---

    #[test]
    fn dvla_valid() {
        // MORGA657054SM9IJ — surname MORGA, decade 6, month 57 (female July), day 05, year 4, initials SM, check 9IJ
        assert!(validate_dvla_license("MORGA657054SM9IJ"));
    }

    #[test]
    fn dvla_valid_male() {
        // SMITH701010JJ9AA — surname SMITH, decade 7, month 01, day 01, year 0, initials JJ, check 9AA
        assert!(validate_dvla_license("SMITH701010JJ9AA"));
    }

    #[test]
    fn dvla_reject_invalid_month() {
        // Month 13 is invalid for both male and female
        assert!(!validate_dvla_license("SMITH713010JJ9AA"));
    }

    #[test]
    fn dvla_reject_invalid_day() {
        // Day 00 is invalid
        assert!(!validate_dvla_license("SMITH701000JJ9AA"));
        // Day 32 is invalid
        assert!(!validate_dvla_license("SMITH701320JJ9AA"));
    }

    #[test]
    fn dvla_wrong_length() {
        assert!(!validate_dvla_license("SMITH70101"));
        assert!(!validate_dvla_license("SMITH701010JJ9AAXX"));
    }

    // --- NIR (French) ---

    #[test]
    fn nir_valid_male() {
        // 1 85 05 78 006 084 91 — male born May 1985 in dept 78
        // base=1850578006084, 1850578006084 mod 97 = 6, key = 97-6 = 91 ✓
        assert!(validate_nir_key("185057800608491"));
    }

    #[test]
    fn nir_valid_corsica_2a() {
        // Corsica 2A département: replace 2A with 19 for calculation
        // 2 93 07 2A 000 100 XX — need to compute the correct key
        // base with 2A→19: 2930719000100, mod 97 = ?
        // 2930719000100 % 97 = 2930719000100 / 97 = 30213597939 * 97 = 2930718999983, remainder = 117
        // Hmm, let me compute properly: 2930719000100 mod 97
        // Let's just test with a value we can verify
        let base_str = "293072A000100";
        let base_numeric: u64 = "2930719000100".parse().unwrap();
        let key = 97 - (base_numeric % 97);
        let nir = format!("{base_str}{key:02}");
        assert!(validate_nir_key(&nir));
    }

    #[test]
    fn nir_invalid_key() {
        assert!(!validate_nir_key("185057800608400")); // key should be 91, not 00
    }

    #[test]
    fn nir_wrong_length() {
        assert!(!validate_nir_key("18505780060843")); // 14 digits
        assert!(!validate_nir_key("1850578006084366")); // 16 digits
    }

    // --- Steuer-ID ---

    #[test]
    fn steuer_id_valid() {
        // 65929970489 is a commonly cited test Steuer-ID
        // Let's verify: first digit 6 (not 0) ✓
        // digits: 6,5,9,2,9,9,7,0,4,8,9
        // freq: 0→1, 2→1, 4→1, 5→1, 6→1, 7→1, 8→1, 9→3 — one triple ✓
        assert!(validate_steuer_id("65929970489"));
    }

    #[test]
    fn steuer_id_reject_starts_with_zero() {
        assert!(!validate_steuer_id("05929970489"));
    }

    #[test]
    fn steuer_id_reject_wrong_frequency() {
        // All same digits — fails frequency check (one digit appears 10 times)
        assert!(!validate_steuer_id("11111111111"));
    }

    #[test]
    fn steuer_id_wrong_length() {
        assert!(!validate_steuer_id("6592997048")); // 10 digits
        assert!(!validate_steuer_id("659299704899")); // 12 digits
    }

    // --- ICAO Check (Personalausweis) ---

    #[test]
    fn icao_valid() {
        // T22000129 + check digit
        // T=29, 2=2, 2=2, 0=0, 0=0, 0=0, 1=1, 2=2, 9=9
        // weights: 7,3,1,7,3,1,7,3,1
        // 29*7=203, 2*3=6, 2*1=2, 0*7=0, 0*3=0, 0*1=0, 1*7=7, 2*3=6, 9*1=9
        // sum=233, 233%10=3
        assert!(validate_icao_check("T220001293"));
    }

    #[test]
    fn icao_invalid_check() {
        assert!(!validate_icao_check("T220001290")); // wrong check digit
    }

    #[test]
    fn icao_wrong_length() {
        assert!(!validate_icao_check("T2200012"));
        assert!(!validate_icao_check("T22000129300"));
    }

    // --- EU VAT ---

    #[test]
    fn eu_vat_valid_de() {
        assert!(validate_eu_vat("DE123456789")); // DE + 9 digits
    }

    #[test]
    fn eu_vat_valid_at() {
        assert!(validate_eu_vat("ATU12345678")); // AT + U + 8 digits
    }

    #[test]
    fn eu_vat_valid_fr() {
        assert!(validate_eu_vat("FR12345678901")); // FR + 11 chars
    }

    #[test]
    fn eu_vat_reject_wrong_length() {
        assert!(!validate_eu_vat("DE12345678")); // DE needs 9 digits, got 8
        assert!(!validate_eu_vat("DE1234567890")); // DE needs 9 digits, got 10
    }

    #[test]
    fn eu_vat_reject_unknown_country() {
        assert!(!validate_eu_vat("XX123456789")); // XX not a valid EU country
    }

    #[test]
    fn eu_vat_reject_too_short() {
        assert!(!validate_eu_vat("DE"));
        assert!(!validate_eu_vat(""));
    }

    // --- SWIFT/BIC ---

    #[test]
    fn swift_valid_8_char() {
        assert!(validate_swift_bic("DEUTDEFF")); // Deutsche Bank Frankfurt
    }

    #[test]
    fn swift_valid_11_char() {
        assert!(validate_swift_bic("DEUTDEFF500")); // Deutsche Bank with branch
    }

    #[test]
    fn swift_valid_various() {
        assert!(validate_swift_bic("BNPAFRPP")); // BNP Paribas
        assert!(validate_swift_bic("CHASUS33")); // JPMorgan Chase
        assert!(validate_swift_bic("NWBKGB2L")); // NatWest
    }

    #[test]
    fn swift_reject_invalid_country() {
        assert!(!validate_swift_bic("DEUTXXFF")); // XX not valid ISO country
    }

    #[test]
    fn swift_reject_wrong_length() {
        assert!(!validate_swift_bic("DEUTDE")); // 6 chars
        assert!(!validate_swift_bic("DEUTDEFF50")); // 10 chars
    }

    #[test]
    fn swift_reject_digits_in_bank_code() {
        assert!(!validate_swift_bic("D3UTDEFF")); // digit in first 4
    }

    #[test]
    fn swift_lowercase_normalized() {
        assert!(validate_swift_bic("deutdeff")); // validator uppercases
    }

    #[test]
    fn swift_reject_common_words() {
        // Random 8-letter uppercase strings where positions 5-6 aren't a valid country
        assert!(!validate_swift_bic("TESTXXAB")); // XX not valid
        assert!(!validate_swift_bic("ABCDQQRS")); // QQ not valid
    }

    #[test]
    fn swift_empty() {
        assert!(!validate_swift_bic(""));
    }

    // --- NHS MOD 11 edge cases ---

    #[test]
    fn nhs_reject_check_digit_ten() {
        // When check digit computes to 10, the number is invalid.
        // We need: sum mod 11 = 1, so check = 11-1 = 10 → invalid.
        // 100 000 001 X: weights 10,9,8,7,6,5,4,3,2
        // 10*1+9*0+8*0+7*0+6*0+5*0+4*0+3*0+2*1 = 12
        // 12 mod 11 = 1, check = 10 → invalid ✓
        // So "1000000010" should be invalid regardless of last digit
        assert!(!validate_nhs_mod11("1000000010"));
        assert!(!validate_nhs_mod11("1000000011"));
        assert!(!validate_nhs_mod11("1000000019"));
    }

    #[test]
    fn nhs_check_digit_zero() {
        // When sum mod 11 = 0, check = 11, expected digit = 0
        // Need sum divisible by 11.
        // 0000000000: weights sum = 0, 0 mod 11 = 0, check = 11, expected = 0 ✓
        assert!(validate_nhs_mod11("0000000000"));
    }

    #[test]
    fn nhs_with_dashes() {
        assert!(validate_nhs_mod11("943-476-5919"));
    }

    #[test]
    fn nhs_empty() {
        assert!(!validate_nhs_mod11(""));
    }

    // --- DVLA edge cases ---

    #[test]
    fn dvla_reject_month_in_gap() {
        // Month 49 is not valid male (>12) or female (must be 51-62)
        assert!(!validate_dvla_license("SMITH749010JJ9AA"));
        // Month 50 also in gap
        assert!(!validate_dvla_license("SMITH750010JJ9AA"));
    }

    #[test]
    fn dvla_female_month_boundaries() {
        // Month 51 = female January (lowest valid female month)
        assert!(validate_dvla_license("SMITH751010JJ9AA"));
        // Month 62 = female December (highest valid female month)
        assert!(validate_dvla_license("SMITH762010JJ9AA"));
        // Month 63 = invalid
        assert!(!validate_dvla_license("SMITH763010JJ9AA"));
    }

    #[test]
    fn dvla_surname_with_9_padding() {
        // Short surname padded with 9s: "JONES" → "JONES", "LEE" → "LEE99"
        assert!(validate_dvla_license("LEE99701010JJ9AA"));
    }

    #[test]
    fn dvla_empty() {
        assert!(!validate_dvla_license(""));
    }

    // --- NI edge cases ---

    #[test]
    fn ni_lowercase_normalized() {
        // Validator uppercases input
        assert!(validate_ni_prefix("ab123456c"));
    }

    #[test]
    fn ni_empty() {
        assert!(!validate_ni_prefix(""));
    }

    // --- NIR edge cases ---

    #[test]
    fn nir_reject_non_corsica_letters() {
        // 2C in département field should fail — not 2A or 2B
        assert!(!validate_nir_key("293072C00010020"));
    }

    #[test]
    fn nir_empty() {
        assert!(!validate_nir_key(""));
    }

    // --- Steuer-ID edge cases ---

    #[test]
    fn steuer_id_reject_all_unique_digits() {
        // 10 different digits: 1234567890 + check — no doubles or triples
        // freq: each digit appears exactly once → doubles=0, triples=0 → invalid
        assert!(!validate_steuer_id("12345678901"));
    }

    #[test]
    fn steuer_id_reject_two_pairs() {
        // Two different digits each appearing twice → doubles=2 → invalid
        // 1123456789 + check: 1 appears 2x, all others once
        // Wait, that's only one double. Let me do: 1122345678 + check
        // 1→2, 2→2, 3→1, 4→1, 5→1, 6→1, 7→1, 8→1 → doubles=2 → invalid
        assert!(!validate_steuer_id("11223456789"));
    }

    #[test]
    fn steuer_id_valid_with_one_double() {
        // 86095742719: digits 8,6,0,9,5,7,4,2,7,1
        // freq: 7→2, rest→1 → doubles=1 ✓
        // Need to verify check digit too... let me compute:
        // product starts at 10
        // d=8: sum=(8+10)%10=8, product=(8*2)%11=5
        // d=6: sum=(6+5)%10=1, product=(1*2)%11=2
        // d=0: sum=(0+2)%10=2, product=(2*2)%11=4
        // d=9: sum=(9+4)%10=3, product=(3*2)%11=6
        // d=5: sum=(5+6)%10=1, product=(1*2)%11=2
        // d=7: sum=(7+2)%10=9, product=(9*2)%11=7
        // d=4: sum=(4+7)%10=1, product=(1*2)%11=2
        // d=2: sum=(2+2)%10=4, product=(4*2)%11=8
        // d=7: sum=(7+8)%10=5, product=(5*2)%11=10
        // d=1: sum=(1+10)%10=1, product=(1*2)%11=2
        // check=11-2=9
        assert!(validate_steuer_id("86095742719"));
    }

    #[test]
    fn steuer_id_empty() {
        assert!(!validate_steuer_id(""));
    }

    // --- ICAO edge cases ---

    #[test]
    fn icao_all_letters() {
        // C + CFGHJKLM + check
        // C=12, F=15, G=16, H=17, J=19, K=20, L=21, M=22
        // weights: 7,3,1,7,3,1,7,3,1
        // 12*7=84, 15*3=45, 16*1=16, 17*7=119, 19*3=57, 20*1=20, 21*7=147, 22*3=66, ?
        // Wait, need 9 body chars. Let's use CCFGHJKLM:
        // C=12,C=12,F=15,G=16,H=17,J=19,K=20,L=21,M=22
        // 12*7=84, 12*3=36, 15*1=15, 16*7=112, 17*3=51, 19*1=19, 20*7=140, 21*3=63, 22*1=22
        // sum = 84+36+15+112+51+19+140+63+22 = 542
        // 542 % 10 = 2
        assert!(validate_icao_check("CCFGHJKLM2"));
    }

    #[test]
    fn icao_reject_non_alpha_first() {
        // First char must be a letter
        assert!(!validate_icao_check("1220001293"));
    }

    #[test]
    fn icao_empty() {
        assert!(!validate_icao_check(""));
    }

    // --- EU VAT edge cases ---

    #[test]
    fn eu_vat_at_missing_u_prefix() {
        // AT requires body to start with 'U'
        assert!(!validate_eu_vat("AT123456789"));
    }

    #[test]
    fn eu_vat_lowercase_normalized() {
        assert!(validate_eu_vat("de123456789"));
    }

    #[test]
    fn eu_vat_empty() {
        assert!(!validate_eu_vat(""));
    }
}
