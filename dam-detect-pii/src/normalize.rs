use unicode_normalization::UnicodeNormalization;

/// Zero-width and invisible characters to strip.
const STRIP_CHARS: &[char] = &[
    '\u{200B}', // zero-width space
    '\u{200C}', // zero-width non-joiner
    '\u{200D}', // zero-width joiner
    '\u{FEFF}', // byte order mark / zero-width no-break space
    '\u{00AD}', // soft hyphen
];

/// Unicode dash code points replaced with ASCII hyphen-minus (U+002D).
const DASH_CHARS: &[char] = &[
    '\u{2010}', // hyphen
    '\u{2011}', // non-breaking hyphen
    '\u{2012}', // figure dash
    '\u{2013}', // en dash
    '\u{2014}', // em dash
    '\u{2015}', // horizontal bar
    '\u{FE58}', // small em dash
    '\u{FE63}', // small hyphen-minus
    '\u{FF0D}', // fullwidth hyphen-minus
];

/// Normalize text for PII detection:
/// 1. Strip zero-width / invisible characters.
/// 2. Apply NFKC unicode normalization.
/// 3. Replace unicode dashes with ASCII hyphen.
/// 4. URL-decode `%XX` sequences.
pub fn normalize(input: &str) -> String {
    let stripped = strip_zero_width(input);
    let nfkc: String = stripped.nfkc().collect();
    let dashes = replace_dashes(&nfkc);
    url_decode(&dashes)
}

/// Remove zero-width and invisible characters.
fn strip_zero_width(input: &str) -> String {
    input.chars().filter(|c| !STRIP_CHARS.contains(c)).collect()
}

/// Replace various unicode dash characters with ASCII hyphen-minus.
fn replace_dashes(input: &str) -> String {
    input
        .chars()
        .map(|c| if DASH_CHARS.contains(&c) { '-' } else { c })
        .collect()
}

/// Decode percent-encoded `%XX` sequences. Invalid sequences are left as-is.
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'%'
            && i + 2 < len
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Convert an ASCII hex digit to its numeric value.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_zero_width ──────────────────────────────────────────────

    #[test]
    fn strip_zero_width_space() {
        assert_eq!(strip_zero_width("a\u{200B}b"), "ab");
    }

    #[test]
    fn strip_zero_width_non_joiner() {
        assert_eq!(strip_zero_width("a\u{200C}b"), "ab");
    }

    #[test]
    fn strip_zero_width_joiner() {
        assert_eq!(strip_zero_width("a\u{200D}b"), "ab");
    }

    #[test]
    fn strip_bom() {
        assert_eq!(strip_zero_width("\u{FEFF}hello"), "hello");
    }

    #[test]
    fn strip_soft_hyphen() {
        assert_eq!(strip_zero_width("hel\u{00AD}lo"), "hello");
    }

    #[test]
    fn strip_multiple_invisible() {
        let input = "\u{FEFF}\u{200B}a\u{200C}\u{200D}b\u{00AD}c";
        assert_eq!(strip_zero_width(input), "abc");
    }

    #[test]
    fn strip_no_invisible() {
        assert_eq!(strip_zero_width("hello world"), "hello world");
    }

    // ── NFKC normalization ────────────────────────────────────────────

    #[test]
    fn nfkc_fullwidth_digits() {
        // Fullwidth digits -> ASCII digits under NFKC
        let input = "\u{FF11}\u{FF12}\u{FF13}"; // １２３
        let result = normalize(input);
        assert_eq!(result, "123");
    }

    #[test]
    fn nfkc_ligature() {
        // ﬁ (U+FB01) -> fi under NFKC
        let input = "\u{FB01}le";
        let result = normalize(input);
        assert_eq!(result, "file");
    }

    // ── replace_dashes ────────────────────────────────────────────────

    #[test]
    fn replace_en_dash() {
        assert_eq!(replace_dashes("a\u{2013}b"), "a-b");
    }

    #[test]
    fn replace_em_dash() {
        assert_eq!(replace_dashes("a\u{2014}b"), "a-b");
    }

    #[test]
    fn replace_fullwidth_hyphen() {
        assert_eq!(replace_dashes("a\u{FF0D}b"), "a-b");
    }

    #[test]
    fn replace_figure_dash() {
        assert_eq!(replace_dashes("123\u{2012}456"), "123-456");
    }

    #[test]
    fn replace_multiple_dashes() {
        let input = "\u{2010}\u{2011}\u{2013}\u{2014}";
        assert_eq!(replace_dashes(input), "----");
    }

    #[test]
    fn ascii_hyphen_preserved() {
        assert_eq!(replace_dashes("a-b"), "a-b");
    }

    // ── url_decode ────────────────────────────────────────────────────

    #[test]
    fn decode_at_sign() {
        assert_eq!(url_decode("user%40example.com"), "user@example.com");
    }

    #[test]
    fn decode_space() {
        assert_eq!(url_decode("hello%20world"), "hello world");
    }

    #[test]
    fn decode_multiple() {
        assert_eq!(url_decode("%48%65%6C%6C%6F"), "Hello");
    }

    #[test]
    fn decode_mixed_case_hex() {
        assert_eq!(url_decode("%4a%4A"), "JJ");
    }

    #[test]
    fn decode_invalid_hex_left_alone() {
        assert_eq!(url_decode("%GG"), "%GG");
    }

    #[test]
    fn decode_truncated_percent_left_alone() {
        assert_eq!(url_decode("abc%2"), "abc%2");
    }

    #[test]
    fn decode_trailing_percent() {
        assert_eq!(url_decode("abc%"), "abc%");
    }

    #[test]
    fn decode_no_encoding() {
        assert_eq!(url_decode("hello"), "hello");
    }

    // ── full normalize pipeline ───────────────────────────────────────

    #[test]
    fn normalize_combined() {
        // Zero-width + unicode dash + percent-encoded @
        let input = "\u{200B}user\u{2013}name%40example.com";
        assert_eq!(normalize(input), "user-name@example.com");
    }

    #[test]
    fn normalize_empty() {
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn normalize_plain_ascii() {
        assert_eq!(normalize("hello world"), "hello world");
    }

    #[test]
    fn normalize_ssn_with_en_dashes() {
        assert_eq!(normalize("123\u{2013}45\u{2013}6789"), "123-45-6789");
    }
}
