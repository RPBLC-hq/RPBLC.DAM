/// Luhn checksum validation for credit card numbers.
///
/// Expects a string of digits (no spaces or dashes). Returns `true` if valid.
pub fn luhn(digits: &str) -> bool {
    let bytes: Vec<u8> = digits
        .bytes()
        .filter_map(|b| {
            if b.is_ascii_digit() {
                Some(b - b'0')
            } else {
                None
            }
        })
        .collect();

    if bytes.len() < 2 {
        return false;
    }

    let mut sum: u32 = 0;
    let parity = bytes.len() % 2;

    for (i, &d) in bytes.iter().enumerate() {
        let mut n = d as u32;
        if i % 2 == parity {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
    }

    sum.is_multiple_of(10)
}

/// Mod-97 validation for IBAN numbers (ISO 7064).
///
/// Expects the full IBAN string (country code + check digits + BBAN).
/// Returns `true` if the remainder after rearranging and converting to digits is 1.
pub fn mod97(iban: &str) -> bool {
    // Remove spaces and uppercase
    let clean: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if clean.len() < 5 {
        return false;
    }

    // Move the first 4 chars to the end
    let rearranged = format!("{}{}", &clean[4..], &clean[..4]);

    // Convert letters to two-digit numbers (A=10, B=11, ..., Z=35)
    let mut numeric = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_alphabetic() {
            let val = (c as u32) - ('A' as u32) + 10;
            numeric.push_str(&val.to_string());
        } else {
            return false;
        }
    }

    // Compute mod 97 on the large number using iterative remainder
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let s = std::str::from_utf8(chunk).unwrap_or("0");
        let combined = format!("{remainder}{s}");
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }

    remainder == 1
}

/// Validate a US Social Security Number area code.
///
/// Rules:
/// - Area (first 3 digits) must not be 000, 666, or 900-999.
/// - Group (middle 2 digits) must not be 00.
/// - Serial (last 4 digits) must not be 0000.
///
/// Expects a string of exactly 9 digits (no dashes).
pub fn ssn_area(digits: &str) -> bool {
    let clean: Vec<u8> = digits.bytes().filter(|b| b.is_ascii_digit()).collect();

    if clean.len() != 9 {
        return false;
    }

    let area = parse_digits(&clean[0..3]);
    let group = parse_digits(&clean[3..5]);
    let serial = parse_digits(&clean[5..9]);

    // Reject invalid area codes
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Reject zero group
    if group == 0 {
        return false;
    }

    // Reject zero serial
    if serial == 0 {
        return false;
    }

    true
}

/// Parse a slice of ASCII digit bytes into a u32.
fn parse_digits(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc * 10 + (b - b'0') as u32)
}

/// Validate phone number length (digit count between 7 and 15 inclusive, per E.164).
///
/// Expects a string of digits only (strip non-digits before calling).
pub fn phone_length(digits: &str) -> bool {
    let count = digits.chars().filter(|c| c.is_ascii_digit()).count();
    (7..=15).contains(&count)
}

/// Check whether an IPv4 address is in a private or loopback range.
///
/// Returns `true` if the address IS private/loopback (i.e., should be rejected
/// as non-PII since private IPs don't identify individuals on the internet).
///
/// Private ranges:
/// - 10.0.0.0/8
/// - 172.16.0.0/12 (172.16.x.x through 172.31.x.x)
/// - 192.168.0.0/16
/// - 127.0.0.0/8 (loopback)
pub fn ip_is_private(ip: &str) -> bool {
    let octets: Vec<u8> = ip.split('.').filter_map(|s| s.parse::<u8>().ok()).collect();

    if octets.len() != 4 {
        return false; // not a valid IPv4 — caller should handle
    }

    let (a, b) = (octets[0], octets[1]);

    matches!((a, b), (10, _) | (172, 16..=31) | (192, 168) | (127, _))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Luhn ──────────────────────────────────────────────────────────

    #[test]
    fn luhn_valid_visa() {
        assert!(luhn("4111111111111111"));
    }

    #[test]
    fn luhn_valid_mastercard() {
        assert!(luhn("5500000000000004"));
    }

    #[test]
    fn luhn_valid_amex() {
        assert!(luhn("378282246310005"));
    }

    #[test]
    fn luhn_invalid_off_by_one() {
        assert!(!luhn("4111111111111112"));
    }

    #[test]
    fn luhn_all_zeros() {
        // "0000000000000000" — Luhn sum = 0, 0 % 10 == 0, technically valid
        assert!(luhn("0000000000000000"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn("1"));
        assert!(!luhn(""));
    }

    #[test]
    fn luhn_non_digit_filtered() {
        // spaces/dashes filtered out, digits still pass
        assert!(luhn("4111 1111 1111 1111"));
    }

    // ── Mod97 (IBAN) ─────────────────────────────────────────────────

    #[test]
    fn mod97_valid_gb() {
        assert!(mod97("GB29 NWBK 6016 1331 9268 19"));
    }

    #[test]
    fn mod97_valid_de() {
        assert!(mod97("DE89370400440532013000"));
    }

    #[test]
    fn mod97_valid_fr() {
        assert!(mod97("FR7630006000011234567890189"));
    }

    #[test]
    fn mod97_invalid_check_digits() {
        assert!(!mod97("GB00 NWBK 6016 1331 9268 19"));
    }

    #[test]
    fn mod97_too_short() {
        assert!(!mod97("GB29"));
    }

    #[test]
    fn mod97_invalid_chars() {
        assert!(!mod97("GB29!WBK60161331926819"));
    }

    // ── SSN area validation ──────────────────────────────────────────

    #[test]
    fn ssn_valid() {
        assert!(ssn_area("123456789"));
    }

    #[test]
    fn ssn_reject_area_000() {
        assert!(!ssn_area("000456789"));
    }

    #[test]
    fn ssn_reject_area_666() {
        assert!(!ssn_area("666456789"));
    }

    #[test]
    fn ssn_reject_area_900() {
        assert!(!ssn_area("900456789"));
    }

    #[test]
    fn ssn_reject_area_999() {
        assert!(!ssn_area("999456789"));
    }

    #[test]
    fn ssn_reject_zero_group() {
        assert!(!ssn_area("123006789"));
    }

    #[test]
    fn ssn_reject_zero_serial() {
        assert!(!ssn_area("123450000"));
    }

    #[test]
    fn ssn_wrong_length() {
        assert!(!ssn_area("12345678")); // 8 digits
        assert!(!ssn_area("1234567890")); // 10 digits
    }

    #[test]
    fn ssn_boundary_area_001() {
        assert!(ssn_area("001011111"));
    }

    #[test]
    fn ssn_boundary_area_665() {
        assert!(ssn_area("665011111"));
    }

    #[test]
    fn ssn_boundary_area_667() {
        assert!(ssn_area("667011111"));
    }

    #[test]
    fn ssn_boundary_area_899() {
        assert!(ssn_area("899011111"));
    }

    // ── Phone length ─────────────────────────────────────────────────

    #[test]
    fn phone_valid_7() {
        assert!(phone_length("1234567"));
    }

    #[test]
    fn phone_valid_15() {
        assert!(phone_length("123456789012345"));
    }

    #[test]
    fn phone_valid_10() {
        assert!(phone_length("2025551234"));
    }

    #[test]
    fn phone_too_short() {
        assert!(!phone_length("123456"));
    }

    #[test]
    fn phone_too_long() {
        assert!(!phone_length("1234567890123456"));
    }

    #[test]
    fn phone_empty() {
        assert!(!phone_length(""));
    }

    // ── IP private range ─────────────────────────────────────────────

    #[test]
    fn ip_private_10() {
        assert!(ip_is_private("10.0.0.1"));
        assert!(ip_is_private("10.255.255.255"));
    }

    #[test]
    fn ip_private_172() {
        assert!(ip_is_private("172.16.0.1"));
        assert!(ip_is_private("172.31.255.255"));
        // 172.15 and 172.32 are NOT private
        assert!(!ip_is_private("172.15.0.1"));
        assert!(!ip_is_private("172.32.0.1"));
    }

    #[test]
    fn ip_private_192_168() {
        assert!(ip_is_private("192.168.0.1"));
        assert!(ip_is_private("192.168.255.255"));
    }

    #[test]
    fn ip_loopback() {
        assert!(ip_is_private("127.0.0.1"));
        assert!(ip_is_private("127.255.255.255"));
    }

    #[test]
    fn ip_public() {
        assert!(!ip_is_private("8.8.8.8"));
        assert!(!ip_is_private("1.1.1.1"));
        assert!(!ip_is_private("203.0.113.1"));
    }

    #[test]
    fn ip_invalid_format() {
        assert!(!ip_is_private("not.an.ip.address"));
        assert!(!ip_is_private(""));
        assert!(!ip_is_private("999.999.999.999")); // octets > 255 fail u8 parse
    }
}
