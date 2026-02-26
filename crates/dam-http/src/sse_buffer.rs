use bytes::BytesMut;

/// Reusable SSE byte buffer that splits raw bytes into complete events.
///
/// An SSE event is terminated by `\n\n` (or `\r\n\r\n`). This struct buffers
/// incoming bytes and yields complete events one at a time.
pub(crate) struct SseBuffer {
    pub(crate) raw_buf: BytesMut,
    scan_from: usize,
}

impl SseBuffer {
    pub(crate) fn new() -> Self {
        Self {
            raw_buf: BytesMut::new(),
            scan_from: 0,
        }
    }

    /// Feed raw bytes from the upstream response.
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        self.raw_buf.extend_from_slice(chunk);
    }

    /// Extract the next complete SSE event (terminated by `\n\n`).
    pub(crate) fn next_event(&mut self) -> Option<Vec<u8>> {
        let buf = &self.raw_buf[..];
        let start = self.scan_from.min(buf.len());

        for i in start..buf.len().saturating_sub(1) {
            if buf[i] == b'\n' && buf[i + 1] == b'\n' {
                let event = self.raw_buf.split_to(i + 2).to_vec();
                self.scan_from = 0;
                return Some(event);
            }
        }

        for i in start.saturating_sub(2)..buf.len().saturating_sub(3) {
            if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n'
            {
                let event = self.raw_buf.split_to(i + 4).to_vec();
                self.scan_from = 0;
                return Some(event);
            }
        }

        self.scan_from = buf.len().saturating_sub(3);
        None
    }
}
