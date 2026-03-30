use dam_core::{Detection, SensitiveDataType, Span};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::validators;

const SOURCE_MODULE: &str = "detect-pii";

// ── Compiled regex patterns ──────────────────────────────────────────

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap());

/// E.164 international phone: +<country code><number>, 7-15 digits total.
static PHONE_E164_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\+[1-9]\d{6,14}").unwrap());

/// NANP phone: (XXX) XXX-XXXX or XXX-XXX-XXXX or XXX.XXX.XXXX
static PHONE_NANP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:\(\d{3}\)\s?|\d{3}[\-.])\d{3}[\-.]\d{4}").unwrap());

/// SSN with dashes: XXX-XX-XXXX
static SSN_DASHED_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

/// SSN without dashes: 9 consecutive digits (word-bounded).
static SSN_BARE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{9}\b").unwrap());

/// Credit card: formatted (with separators) or bare 13-16 digits.
/// Formatted: XXXX-XXXX-XXXX-XXXX (Visa/MC) or XXXX-XXXXXX-XXXXX (Amex).
/// Bare: 13-16 contiguous digits. Does NOT match 17+ digit sequences (avoids timestamps).
static CREDIT_CARD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b|\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b|\b\d{13,16}\b",
    )
    .unwrap()
});

/// IBAN: 2 letter country code, 2 check digits, 4-30 alphanumeric BBAN chars.
static IBAN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?[A-Z0-9]{4}){1,7}(?:\s?[A-Z0-9]{1,4})?\b")
        .unwrap()
});

/// IPv4 address: four dot-separated octets.
static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b").unwrap()
});

// ── Per-type detection functions ─────────────────────────────────────

pub fn detect_emails(text: &str) -> Vec<Detection> {
    EMAIL_RE
        .find_iter(text)
        .map(|m| Detection {
            data_type: SensitiveDataType::Email,
            value: m.as_str().to_string(),
            span: Span {
                start: m.start(),
                end: m.end(),
            },
            confidence: 0.95,
            source_module: SOURCE_MODULE.into(),
            verdict: dam_core::Verdict::Pending,
        })
        .collect()
}

pub fn detect_phones(text: &str) -> Vec<Detection> {
    let mut detections = Vec::new();

    for m in PHONE_E164_RE.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if validators::phone_length(&digits) {
            detections.push(Detection {
                data_type: SensitiveDataType::Phone,
                value: m.as_str().to_string(),
                span: Span {
                    start: m.start(),
                    end: m.end(),
                },
                confidence: 0.90,
                source_module: SOURCE_MODULE.into(),
                verdict: dam_core::Verdict::Pending,
            });
        }
    }

    for m in PHONE_NANP_RE.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if validators::phone_length(&digits) {
            // Only add if not already covered by an E.164 detection at the same span.
            let already = detections
                .iter()
                .any(|d| d.span.start <= m.start() && d.span.end >= m.end());
            if !already {
                detections.push(Detection {
                    data_type: SensitiveDataType::Phone,
                    value: m.as_str().to_string(),
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                    },
                    confidence: 0.85,
                    source_module: SOURCE_MODULE.into(),
                    verdict: dam_core::Verdict::Pending,
                });
            }
        }
    }

    detections
}

pub fn detect_ssns(text: &str) -> Vec<Detection> {
    let mut detections = Vec::new();

    for m in SSN_DASHED_RE.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if validators::ssn_area(&digits) {
            detections.push(Detection {
                data_type: SensitiveDataType::Ssn,
                value: m.as_str().to_string(),
                span: Span {
                    start: m.start(),
                    end: m.end(),
                },
                confidence: 0.95,
                source_module: SOURCE_MODULE.into(),
                verdict: dam_core::Verdict::Pending,
            });
        }
    }

    for m in SSN_BARE_RE.find_iter(text) {
        let digits = m.as_str();
        // Skip if this span is already covered by a dashed SSN detection.
        let already = detections
            .iter()
            .any(|d| d.span.start <= m.start() && d.span.end >= m.end());
        if !already && validators::ssn_area(digits) {
            detections.push(Detection {
                data_type: SensitiveDataType::Ssn,
                value: m.as_str().to_string(),
                span: Span {
                    start: m.start(),
                    end: m.end(),
                },
                confidence: 0.70, // lower confidence for bare 9-digit sequences
                source_module: SOURCE_MODULE.into(),
                verdict: dam_core::Verdict::Pending,
            });
        }
    }

    detections
}

pub fn detect_credit_cards(text: &str) -> Vec<Detection> {
    CREDIT_CARD_RE
        .find_iter(text)
        .filter_map(|m| {
            let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 13 && digits.len() <= 19 && validators::luhn(&digits) {
                Some(Detection {
                    data_type: SensitiveDataType::CreditCard,
                    value: m.as_str().to_string(),
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                    },
                    confidence: 0.95,
                    source_module: SOURCE_MODULE.into(),
                    verdict: dam_core::Verdict::Pending,
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_ibans(text: &str) -> Vec<Detection> {
    IBAN_RE
        .find_iter(text)
        .filter_map(|m| {
            if validators::mod97(m.as_str()) {
                Some(Detection {
                    data_type: SensitiveDataType::Iban,
                    value: m.as_str().to_string(),
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                    },
                    confidence: 0.95,
                    source_module: SOURCE_MODULE.into(),
                    verdict: dam_core::Verdict::Pending,
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_ip_addresses(text: &str) -> Vec<Detection> {
    IPV4_RE
        .find_iter(text)
        .filter_map(|m| {
            if !validators::ip_is_private(m.as_str()) {
                Some(Detection {
                    data_type: SensitiveDataType::IpAddress,
                    value: m.as_str().to_string(),
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                    },
                    confidence: 0.90,
                    source_module: SOURCE_MODULE.into(),
                    verdict: dam_core::Verdict::Pending,
                })
            } else {
                None
            }
        })
        .collect()
}

// ── Aggregated detection ─────────────────────────────────────────────

/// Run all PII detection patterns against `text` and return combined results.
pub fn detect_all(text: &str) -> Vec<Detection> {
    let mut detections = Vec::new();
    detections.extend(detect_emails(text));
    detections.extend(detect_phones(text));
    detections.extend(detect_ssns(text));
    detections.extend(detect_credit_cards(text));
    detections.extend(detect_ibans(text));
    detections.extend(detect_ip_addresses(text));
    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Email ─────────────────────────────────────────────────────────

    #[test]
    fn detect_simple_email() {
        let dets = detect_emails("contact user@example.com for info");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "user@example.com");
        assert_eq!(dets[0].data_type, SensitiveDataType::Email);
        assert_eq!(dets[0].span.start, 8);
        assert_eq!(dets[0].span.end, 24);
    }

    #[test]
    fn detect_email_with_plus() {
        let dets = detect_emails("test+tag@example.co.uk");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "test+tag@example.co.uk");
    }

    #[test]
    fn detect_multiple_emails() {
        let dets = detect_emails("a@b.com and c@d.org");
        assert_eq!(dets.len(), 2);
    }

    #[test]
    fn detect_no_email() {
        let dets = detect_emails("no emails here");
        assert!(dets.is_empty());
    }

    // ── Phone ─────────────────────────────────────────────────────────

    #[test]
    fn detect_e164_phone() {
        let dets = detect_phones("call +14155551234 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "+14155551234");
        assert_eq!(dets[0].data_type, SensitiveDataType::Phone);
    }

    #[test]
    fn detect_nanp_phone_parens() {
        let dets = detect_phones("call (415) 555-1234 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "(415) 555-1234");
    }

    #[test]
    fn detect_nanp_phone_dashes() {
        let dets = detect_phones("call 415-555-1234 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "415-555-1234");
    }

    #[test]
    fn detect_nanp_phone_dots() {
        let dets = detect_phones("call 415.555.1234 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "415.555.1234");
    }

    #[test]
    fn detect_no_phone() {
        let dets = detect_phones("no phone here");
        assert!(dets.is_empty());
    }

    // ── SSN ───────────────────────────────────────────────────────────

    #[test]
    fn detect_ssn_dashed() {
        let dets = detect_ssns("ssn is 123-45-6789");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "123-45-6789");
        assert_eq!(dets[0].data_type, SensitiveDataType::Ssn);
        assert_eq!(dets[0].confidence, 0.95);
    }

    #[test]
    fn detect_ssn_bare() {
        let dets = detect_ssns("ssn is 123456789 ok");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "123456789");
        assert_eq!(dets[0].confidence, 0.70);
    }

    #[test]
    fn reject_ssn_area_000() {
        let dets = detect_ssns("000-12-3456");
        assert!(dets.is_empty());
    }

    #[test]
    fn reject_ssn_area_666() {
        let dets = detect_ssns("666-12-3456");
        assert!(dets.is_empty());
    }

    #[test]
    fn reject_ssn_area_900() {
        let dets = detect_ssns("900-12-3456");
        assert!(dets.is_empty());
    }

    #[test]
    fn reject_ssn_zero_group() {
        let dets = detect_ssns("123-00-4567");
        assert!(dets.is_empty());
    }

    // ── Credit Card ───────────────────────────────────────────────────

    #[test]
    fn detect_visa() {
        let dets = detect_credit_cards("card 4111111111111111 here");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "4111111111111111");
        assert_eq!(dets[0].data_type, SensitiveDataType::CreditCard);
    }

    #[test]
    fn detect_visa_with_spaces() {
        let dets = detect_credit_cards("card 4111 1111 1111 1111 here");
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn detect_visa_with_dashes() {
        let dets = detect_credit_cards("card 4111-1111-1111-1111 here");
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn reject_invalid_luhn() {
        let dets = detect_credit_cards("card 4111111111111112 here");
        assert!(dets.is_empty());
    }

    // ── IBAN ──────────────────────────────────────────────────────────

    #[test]
    fn detect_iban_gb() {
        let dets = detect_ibans("iban GB29NWBK60161331926819 ok");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].data_type, SensitiveDataType::Iban);
    }

    #[test]
    fn detect_iban_de() {
        let dets = detect_ibans("pay to DE89370400440532013000");
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn reject_invalid_iban_check() {
        let dets = detect_ibans("iban GB00NWBK60161331926819 ok");
        assert!(dets.is_empty());
    }

    // ── IP Address ────────────────────────────────────────────────────

    #[test]
    fn detect_public_ip() {
        let dets = detect_ip_addresses("from 203.0.113.42 request");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].value, "203.0.113.42");
        assert_eq!(dets[0].data_type, SensitiveDataType::IpAddress);
    }

    #[test]
    fn reject_private_10() {
        let dets = detect_ip_addresses("server at 10.0.0.1");
        assert!(dets.is_empty());
    }

    #[test]
    fn reject_private_172() {
        let dets = detect_ip_addresses("server at 172.16.0.1");
        assert!(dets.is_empty());
    }

    #[test]
    fn reject_private_192() {
        let dets = detect_ip_addresses("server at 192.168.1.1");
        assert!(dets.is_empty());
    }

    #[test]
    fn reject_loopback() {
        let dets = detect_ip_addresses("localhost 127.0.0.1");
        assert!(dets.is_empty());
    }

    #[test]
    fn detect_multiple_ips() {
        let dets = detect_ip_addresses("8.8.8.8 and 1.1.1.1");
        assert_eq!(dets.len(), 2);
    }

    // ── detect_all ────────────────────────────────────────────────────

    #[test]
    fn detect_all_mixed() {
        let text = "Email user@test.com, phone +14155551234, SSN 123-45-6789, \
                    card 4111111111111111, IP 8.8.8.8";
        let dets = detect_all(text);
        let types: Vec<_> = dets.iter().map(|d| d.data_type).collect();
        assert!(types.contains(&SensitiveDataType::Email));
        assert!(types.contains(&SensitiveDataType::Phone));
        assert!(types.contains(&SensitiveDataType::Ssn));
        assert!(types.contains(&SensitiveDataType::CreditCard));
        assert!(types.contains(&SensitiveDataType::IpAddress));
    }

    #[test]
    fn detect_all_empty() {
        let dets = detect_all("nothing sensitive here");
        assert!(dets.is_empty());
    }

    #[test]
    fn detect_all_source_module() {
        let dets = detect_all("user@example.com");
        assert_eq!(dets[0].source_module, "detect-pii");
    }
}
