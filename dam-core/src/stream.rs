use bytes::BytesMut;

/// Buffers raw SSE bytes and yields complete events (delimited by `\n\n`).
pub struct SseBuffer {
    buf: BytesMut,
    scan_from: usize,
}

impl SseBuffer {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            scan_from: 0,
        }
    }

    /// Feed raw bytes into the buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to extract the next complete SSE event.
    /// Returns the event bytes (including the trailing `\n\n`) or None.
    pub fn next_event(&mut self) -> Option<Vec<u8>> {
        let buf = &self.buf[self.scan_from..];

        // Look for \n\n or \r\n\r\n
        let pos = find_event_boundary(buf);

        if let Some((end_offset, boundary_len)) = pos {
            let abs_end = self.scan_from + end_offset + boundary_len;
            let event = self.buf[..abs_end].to_vec();
            let _ = self.buf.split_to(abs_end);
            self.scan_from = 0;
            Some(event)
        } else {
            // No complete event yet. Next time, start scanning near the end
            // to avoid O(n²) rescanning. Keep 3 bytes overlap for boundary detection.
            self.scan_from = self.buf.len().saturating_sub(3);
            None
        }
    }
}

fn find_event_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some((i, 2));
        }
        if i + 3 < buf.len()
            && buf[i] == b'\r' && buf[i + 1] == b'\n'
            && buf[i + 2] == b'\r' && buf[i + 3] == b'\n'
        {
            return Some((i, 4));
        }
    }
    None
}

/// Handles token references (`[type:hex]`) that may be split across streaming chunks.
///
/// Call `push()` with each text chunk — it returns text safe to emit.
/// Call `finish()` at content block end to flush remaining buffer.
pub struct StreamingTokenizer<F> {
    replacer: F,
    buffer: String,
}

impl<F> StreamingTokenizer<F>
where
    F: FnMut(&str) -> String,
{
    pub fn new(replacer: F) -> Self {
        Self {
            replacer,
            buffer: String::new(),
        }
    }

    /// Append a text chunk. Returns text safe to emit now.
    pub fn push(&mut self, chunk: &str) -> String {
        self.buffer.push_str(chunk);

        let hold_from = self.find_partial_token_start();

        if let Some(pos) = hold_from {
            let emittable = self.buffer[..pos].to_string();
            let held = self.buffer[pos..].to_string();
            self.buffer = held;
            (self.replacer)(&emittable)
        } else {
            let emittable = std::mem::take(&mut self.buffer);
            (self.replacer)(&emittable)
        }
    }

    /// Flush remaining buffer (called at content block end).
    pub fn finish(&mut self) -> String {
        let remaining = std::mem::take(&mut self.buffer);
        if remaining.is_empty() {
            return String::new();
        }
        (self.replacer)(&remaining)
    }

    /// Find a potential partial token `[...` at the end of buffer.
    fn find_partial_token_start(&self) -> Option<usize> {
        // Longest token: `[credential_url:xxxxxxxxxxxxxxxxxxxx]` = 39 chars
        // (15 type chars + colon + 22 base58 chars + brackets)
        let window = 45;
        let start = self.buffer.len().saturating_sub(window);
        let tail = &self.buffer[start..];

        if let Some(rel_pos) = tail.rfind('[') {
            let abs_pos = start + rel_pos;
            let after = &self.buffer[abs_pos..];
            if after.contains(']') {
                None // Complete token, no need to hold
            } else {
                Some(abs_pos)
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SseBuffer tests ----

    #[test]
    fn test_sse_single_event() {
        let mut buf = SseBuffer::new();
        buf.feed(b"event: message\ndata: {}\n\n");
        let event = buf.next_event().unwrap();
        assert_eq!(event, b"event: message\ndata: {}\n\n");
        assert!(buf.next_event().is_none());
    }

    #[test]
    fn test_sse_split_event() {
        let mut buf = SseBuffer::new();
        buf.feed(b"event: message\n");
        assert!(buf.next_event().is_none());
        buf.feed(b"data: {}\n\n");
        let event = buf.next_event().unwrap();
        assert_eq!(event, b"event: message\ndata: {}\n\n");
    }

    #[test]
    fn test_sse_multiple_events() {
        let mut buf = SseBuffer::new();
        buf.feed(b"event: a\ndata: 1\n\nevent: b\ndata: 2\n\n");
        let e1 = buf.next_event().unwrap();
        assert!(e1.starts_with(b"event: a"));
        let e2 = buf.next_event().unwrap();
        assert!(e2.starts_with(b"event: b"));
        assert!(buf.next_event().is_none());
    }

    #[test]
    fn test_sse_crlf_terminator() {
        let mut buf = SseBuffer::new();
        buf.feed(b"event: x\r\ndata: y\r\n\r\n");
        let event = buf.next_event().unwrap();
        assert!(!event.is_empty());
    }

    #[test]
    fn test_sse_empty_feed() {
        let mut buf = SseBuffer::new();
        buf.feed(b"");
        assert!(buf.next_event().is_none());
    }

    #[test]
    fn test_sse_keepalive() {
        let mut buf = SseBuffer::new();
        buf.feed(b":keepalive\n\n");
        let event = buf.next_event().unwrap();
        assert_eq!(event, b":keepalive\n\n");
    }

    // ---- StreamingTokenizer tests ----

    fn identity_replacer(s: &str) -> String {
        s.to_string()
    }

    // Test base58 token: [email:7B2HkqFn9xR4mWpD3nYvKt]
    fn mock_replacer(s: &str) -> String {
        s.replace("[email:7B2HkqFn9xR4mWpD3nYvKt]", "john@example.com")
    }

    #[test]
    fn test_tokenizer_single_chunk_complete() {
        let mut t = StreamingTokenizer::new(mock_replacer);
        let out = t.push("Hello [email:7B2HkqFn9xR4mWpD3nYvKt] world");
        assert_eq!(out, "Hello john@example.com world");
    }

    #[test]
    fn test_tokenizer_split_across_two() {
        let mut t = StreamingTokenizer::new(mock_replacer);
        let out1 = t.push("Hello [email:7B2HkqFn9x");
        assert_eq!(out1, "Hello "); // held the partial
        let out2 = t.push("R4mWpD3nYvKt] world");
        assert_eq!(out2, "john@example.com world");
    }

    #[test]
    fn test_tokenizer_split_across_three() {
        let mut t = StreamingTokenizer::new(mock_replacer);
        let o1 = t.push("Hello [email");
        assert_eq!(o1, "Hello ");
        let o2 = t.push(":7B2HkqFn9x");
        assert_eq!(o2, "");
        let o3 = t.push("R4mWpD3nYvKt] world");
        assert_eq!(o3, "john@example.com world");
    }

    #[test]
    fn test_tokenizer_plain_text() {
        let mut t = StreamingTokenizer::new(identity_replacer);
        let out = t.push("no tokens here");
        assert_eq!(out, "no tokens here");
    }

    #[test]
    fn test_tokenizer_finish_flushes() {
        let mut t = StreamingTokenizer::new(identity_replacer);
        let out = t.push("partial [email:abc");
        assert_eq!(out, "partial ");
        let flushed = t.finish();
        assert_eq!(flushed, "[email:abc"); // flushed as-is (incomplete)
    }

    #[test]
    fn test_tokenizer_bracket_in_normal_text() {
        let mut t = StreamingTokenizer::new(identity_replacer);
        // `array[0]` should not be held forever (not a token pattern)
        let out = t.push("array[0] done");
        assert_eq!(out, "array[0] done");
    }

    #[test]
    fn test_tokenizer_multiple_tokens_one_chunk() {
        let replacer = |s: &str| {
            s.replace("[email:7B2HkqFn9xR4mWpD3nYvKt]", "a@b.com")
                .replace("[phone:9cXJrNpT5wQ8mK2hLbYdRv]", "555-1234")
        };
        let mut t = StreamingTokenizer::new(replacer);
        let out = t.push("A [email:7B2HkqFn9xR4mWpD3nYvKt] B [phone:9cXJrNpT5wQ8mK2hLbYdRv] C");
        assert_eq!(out, "A a@b.com B 555-1234 C");
    }

    #[test]
    fn test_tokenizer_empty_chunks() {
        let mut t = StreamingTokenizer::new(identity_replacer);
        let out = t.push("");
        assert_eq!(out, "");
    }

    #[test]
    fn test_tokenizer_large_chunk() {
        let mut t = StreamingTokenizer::new(identity_replacer);
        let big = "x".repeat(2_000_000);
        let out = t.push(&big);
        assert_eq!(out.len(), 2_000_000);
    }
}
