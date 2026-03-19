//! JSON-aware content extraction for LLM API request bodies.
//!
//! Scans raw JSON bytes to find byte ranges of message content strings that should
//! be inspected for PII. Returns ranges of the raw string content between quotes,
//! so PII detection can run directly on body slices with correct byte offsets.
//!
//! Scanned: `messages[*].content` (string or array of `{type: "text", text: "..."}`)
//! Skipped: system/developer role messages, top-level keys (system, tools, model, etc.)

/// Extract byte ranges of scannable content strings from an LLM API request body.
///
/// Returns `Some(ranges)` if the body is a JSON object with a `messages` array.
/// Each range is `(start, end)` — byte offsets of the string content between quotes.
/// Returns `None` if parsing fails or the body doesn't look like an LLM API request,
/// signaling the caller to fall back to full-body scanning.
pub fn scannable_ranges(body: &str) -> Option<Vec<(usize, usize)>> {
    let mut s = Scanner::new(body.as_bytes());
    s.find_message_content_ranges()
}

struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.bytes.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, ch: u8) -> Option<()> {
        self.skip_ws();
        if self.peek()? == ch {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    // ── JSON primitives ───────────────────────────────────────────

    /// Read a JSON string. Returns byte range of content between the quotes.
    fn read_string_range(&mut self) -> Option<(usize, usize)> {
        self.skip_ws();
        if self.peek()? != b'"' {
            return None;
        }
        self.pos += 1; // opening quote
        let start = self.pos;
        loop {
            match self.advance()? {
                b'"' => return Some((start, self.pos - 1)),
                b'\\' => {
                    self.advance()?; // skip escaped char
                }
                _ => {}
            }
        }
    }

    /// Read a JSON string key/value. Returns the raw content (unescaped keys are fine).
    fn read_string_value(&mut self) -> Option<String> {
        let (start, end) = self.read_string_range()?;
        Some(String::from_utf8_lossy(&self.bytes[start..end]).to_string())
    }

    /// Skip any JSON value without recording it.
    fn skip_value(&mut self) -> Option<()> {
        self.skip_ws();
        match self.peek()? {
            b'"' => {
                self.read_string_range()?;
                Some(())
            }
            b'{' => self.skip_object(),
            b'[' => self.skip_array(),
            b't' | b'f' | b'n' => self.skip_keyword(),
            b'-' | b'0'..=b'9' => self.skip_number(),
            _ => None,
        }
    }

    fn skip_object(&mut self) -> Option<()> {
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Some(());
        }
        loop {
            self.read_string_range()?; // key
            self.expect(b':')?;
            self.skip_value()?;
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    fn skip_array(&mut self) -> Option<()> {
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Some(());
        }
        loop {
            self.skip_value()?;
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    fn skip_keyword(&mut self) -> Option<()> {
        while let Some(b) = self.peek() {
            if b.is_ascii_alphabetic() {
                self.pos += 1;
            } else {
                break;
            }
        }
        Some(())
    }

    fn skip_number(&mut self) -> Option<()> {
        while let Some(b) = self.peek() {
            if matches!(b, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                self.pos += 1;
            } else {
                break;
            }
        }
        Some(())
    }

    // ── Message-aware scanning ────────────────────────────────────

    /// Walk the top-level object to find `messages` or `input` and extract content ranges.
    /// Handles both Chat Completions API (`messages`) and Responses API (`input`).
    fn find_message_content_ranges(&mut self) -> Option<Vec<(usize, usize)>> {
        self.skip_ws();
        self.expect(b'{')?;

        let mut ranges = Vec::new();
        let mut found = false;

        self.skip_ws();
        if self.peek()? == b'}' {
            return None;
        }

        loop {
            self.skip_ws();
            let key = self.read_string_value()?;
            self.expect(b':')?;

            if key == "messages" || key == "input" {
                self.skip_ws();
                match self.peek()? {
                    b'[' => {
                        self.scan_messages_array(&mut ranges)?;
                        found = true;
                    }
                    b'"' => {
                        // String input (Responses API simple form)
                        let range = self.read_string_range()?;
                        ranges.push(range);
                        found = true;
                    }
                    _ => {
                        // null or other — skip
                        self.skip_value()?;
                    }
                }
            } else {
                self.skip_value()?;
            }

            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => break,
                _ => return None,
            }
        }

        if found {
            Some(ranges)
        } else {
            None
        }
    }

    fn scan_messages_array(&mut self, ranges: &mut Vec<(usize, usize)>) -> Option<()> {
        self.skip_ws();
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Some(());
        }
        loop {
            self.scan_message_object(ranges)?;
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    /// Scan one message object. Collects content ranges only if role is not system/developer.
    fn scan_message_object(&mut self, ranges: &mut Vec<(usize, usize)>) -> Option<()> {
        self.skip_ws();
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Some(());
        }

        let mut is_system = false;
        let mut content_ranges: Vec<(usize, usize)> = Vec::new();

        loop {
            self.skip_ws();
            let key = self.read_string_value()?;
            self.expect(b':')?;

            if key == "role" {
                self.skip_ws();
                if self.peek() == Some(b'"') {
                    let role = self.read_string_value()?;
                    if role == "system" || role == "developer" {
                        is_system = true;
                    }
                } else {
                    self.skip_value()?;
                }
            } else if key == "content" {
                self.skip_ws();
                match self.peek()? {
                    b'"' => {
                        let range = self.read_string_range()?;
                        content_ranges.push(range);
                    }
                    b'[' => {
                        self.scan_content_blocks(&mut content_ranges)?;
                    }
                    _ => {
                        // null, number, etc.
                        self.skip_value()?;
                    }
                }
            } else {
                self.skip_value()?;
            }

            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }

        if !is_system {
            ranges.extend(content_ranges);
        }

        Some(())
    }

    /// Scan an array of content blocks, collecting `text` field ranges.
    fn scan_content_blocks(&mut self, ranges: &mut Vec<(usize, usize)>) -> Option<()> {
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Some(());
        }
        loop {
            self.scan_content_block(ranges)?;
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    /// Scan one content block object, recording the `text` field range if present.
    fn scan_content_block(&mut self, ranges: &mut Vec<(usize, usize)>) -> Option<()> {
        self.skip_ws();
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Some(());
        }
        loop {
            self.skip_ws();
            let key = self.read_string_value()?;
            self.expect(b':')?;

            if key == "text" {
                self.skip_ws();
                if self.peek() == Some(b'"') {
                    let range = self.read_string_range()?;
                    ranges.push(range);
                } else {
                    self.skip_value()?;
                }
            } else {
                self.skip_value()?;
            }

            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic structure ───────────────────────────────────────────

    #[test]
    fn simple_user_message() {
        let body = r#"{"messages":[{"role":"user","content":"my email is alice@test.com"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        let (s, e) = ranges[0];
        assert_eq!(&body[s..e], "my email is alice@test.com");
    }

    #[test]
    fn system_message_skipped() {
        let body = r#"{"messages":[{"role":"system","content":"you have email admin@sys.com"},{"role":"user","content":"hello"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        let (s, e) = ranges[0];
        assert_eq!(&body[s..e], "hello");
    }

    #[test]
    fn developer_message_skipped() {
        let body = r#"{"messages":[{"role":"developer","content":"dev@example.com"},{"role":"user","content":"hi"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "hi");
    }

    #[test]
    fn assistant_message_scanned() {
        let body = r#"{"messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "a");
        assert_eq!(&body[ranges[1].0..ranges[1].1], "b");
    }

    #[test]
    fn tool_message_scanned() {
        let body = r#"{"messages":[{"role":"tool","content":"output data","tool_call_id":"x"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "output data");
    }

    // ── Content block arrays ──────────────────────────────────────

    #[test]
    fn content_blocks_text() {
        let body = r#"{"messages":[{"role":"user","content":[{"type":"text","text":"email: a@b.com"}]}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "email: a@b.com");
    }

    #[test]
    fn content_blocks_mixed() {
        let body = r#"{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x.com/img.png"}},{"type":"text","text":"describe this"}]}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "describe this");
    }

    #[test]
    fn multiple_text_blocks() {
        let body = r#"{"messages":[{"role":"user","content":[{"type":"text","text":"first"},{"type":"text","text":"second"}]}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "first");
        assert_eq!(&body[ranges[1].0..ranges[1].1], "second");
    }

    // ── Null / missing content ────────────────────────────────────

    #[test]
    fn null_content() {
        let body = r#"{"messages":[{"role":"assistant","content":null,"tool_calls":[]}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn empty_messages() {
        let body = r#"{"model":"gpt-4","messages":[]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert!(ranges.is_empty());
    }

    // ── Role after content (key order independence) ───────────────

    #[test]
    fn role_after_content() {
        let body = r#"{"messages":[{"content":"secret@email.com","role":"system"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        // System message — content should be excluded even though role came after content
        assert!(ranges.is_empty());
    }

    #[test]
    fn role_after_content_user() {
        let body = r#"{"messages":[{"content":"user@email.com","role":"user"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "user@email.com");
    }

    // ── JSON escapes ──────────────────────────────────────────────

    #[test]
    fn escaped_quotes_in_content() {
        let body = r#"{"messages":[{"role":"user","content":"he said \"hello\" to bob@x.com"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        let slice = &body[ranges[0].0..ranges[0].1];
        assert!(slice.contains("bob@x.com"));
    }

    #[test]
    fn escaped_newline_in_content() {
        let body = r#"{"messages":[{"role":"user","content":"line1\nline2 bob@x.com"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        let slice = &body[ranges[0].0..ranges[0].1];
        assert!(slice.contains("bob@x.com"));
    }

    // ── Non-LLM bodies ───────────────────────────────────────────

    #[test]
    fn no_messages_key() {
        let body = r#"{"model":"gpt-4","prompt":"hello"}"#;
        assert!(scannable_ranges(body).is_none());
    }

    #[test]
    fn not_json() {
        assert!(scannable_ranges("not json at all").is_none());
    }

    #[test]
    fn empty_object() {
        assert!(scannable_ranges("{}").is_none());
    }

    // ── Top-level keys before messages ────────────────────────────

    #[test]
    fn messages_not_first_key() {
        let body = r#"{"model":"gpt-4","temperature":0.7,"messages":[{"role":"user","content":"hi"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "hi");
    }

    // ── Whitespace tolerance ──────────────────────────────────────

    #[test]
    fn pretty_printed_json() {
        let body = r#"{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "my ssn is 123-45-6789"
    }
  ]
}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "my ssn is 123-45-6789");
    }

    // ── Full realistic request ────────────────────────────────────

    #[test]
    fn realistic_openai_request() {
        let body = r#"{"model":"gpt-4","messages":[{"role":"system","content":"You are a helpful assistant. Contact support@example.com for help."},{"role":"user","content":"My phone is +14155551234"},{"role":"assistant","content":"I noted your phone number."},{"role":"user","content":"Also my email is alice@test.com"}],"temperature":0.7,"tools":[{"type":"function","function":{"name":"send_email","parameters":{"type":"object","properties":{"to":{"type":"string","description":"Email like user@example.com"}}}}}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        // Should get: user msg 1, assistant msg, user msg 2 — NOT system msg
        assert_eq!(ranges.len(), 3);
        assert_eq!(
            &body[ranges[0].0..ranges[0].1],
            "My phone is +14155551234"
        );
        assert_eq!(
            &body[ranges[1].0..ranges[1].1],
            "I noted your phone number."
        );
        assert_eq!(
            &body[ranges[2].0..ranges[2].1],
            "Also my email is alice@test.com"
        );
    }

    #[test]
    fn realistic_anthropic_request() {
        let body = r#"{"model":"claude-3-5-sonnet-20241022","system":"You help with emails. Example: admin@corp.com","messages":[{"role":"user","content":"forward to alice@personal.com"},{"role":"assistant","content":"Done."}],"max_tokens":1024}"#;
        let ranges = scannable_ranges(body).unwrap();
        // system is top-level key (not in messages), so not scanned
        // user + assistant messages scanned
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            &body[ranges[0].0..ranges[0].1],
            "forward to alice@personal.com"
        );
        assert_eq!(&body[ranges[1].0..ranges[1].1], "Done.");
    }

    // ── Responses API (input key) ─────────────────────────────────

    #[test]
    fn responses_api_input_array() {
        let body = r#"{"model":"gpt-4.1","input":[{"role":"user","content":"my email is bob@test.com"}],"instructions":"You are helpful. Contact admin@sys.com."}"#;
        let ranges = scannable_ranges(body).unwrap();
        // instructions is top-level (like system), NOT scanned
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            &body[ranges[0].0..ranges[0].1],
            "my email is bob@test.com"
        );
    }

    #[test]
    fn responses_api_input_string() {
        let body = r#"{"model":"gpt-4.1","input":"call me at +14155551234"}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            &body[ranges[0].0..ranges[0].1],
            "call me at +14155551234"
        );
    }

    #[test]
    fn responses_api_system_in_input_skipped() {
        let body = r#"{"model":"gpt-4.1","input":[{"role":"system","content":"admin@sys.com"},{"role":"user","content":"hi"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "hi");
    }

    #[test]
    fn responses_api_developer_in_input_skipped() {
        let body = r#"{"model":"gpt-4.1","input":[{"role":"developer","content":"dev@x.com"},{"role":"user","content":"hello"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "hello");
    }

    #[test]
    fn responses_api_instructions_not_scanned() {
        let body = r#"{"instructions":"Contact support@example.com for help","model":"gpt-4.1","input":[{"role":"user","content":"test"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        // Only user content, not instructions
        assert_eq!(ranges.len(), 1);
        assert_eq!(&body[ranges[0].0..ranges[0].1], "test");
    }

    #[test]
    fn responses_api_with_tools() {
        let body = r#"{"model":"gpt-4.1","input":[{"role":"user","content":"echo banana@apple.com"}],"tools":[{"type":"function","function":{"name":"shell","parameters":{}}}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            &body[ranges[0].0..ranges[0].1],
            "echo banana@apple.com"
        );
    }

    #[test]
    fn responses_api_conversation_history() {
        let body = r#"{"model":"gpt-4.1","input":[{"role":"user","content":"my email is alice@test.com"},{"role":"assistant","content":"Got it, alice@test.com."},{"role":"user","content":"now send it"}]}"#;
        let ranges = scannable_ranges(body).unwrap();
        assert_eq!(ranges.len(), 3);
        assert_eq!(
            &body[ranges[0].0..ranges[0].1],
            "my email is alice@test.com"
        );
        assert_eq!(
            &body[ranges[1].0..ranges[1].1],
            "Got it, alice@test.com."
        );
        assert_eq!(&body[ranges[2].0..ranges[2].1], "now send it");
    }
}
