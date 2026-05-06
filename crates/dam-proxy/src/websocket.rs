use axum::http::{HeaderMap, HeaderName, Method, header};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const MAX_WEBSOCKET_FRAME_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const OPCODE_CONTINUATION: u8 = 0x0;
pub(crate) const OPCODE_TEXT: u8 = 0x1;
pub(crate) const OPCODE_BINARY: u8 = 0x2;
pub(crate) const OPCODE_CLOSE: u8 = 0x8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebSocketFrame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl WebSocketFrame {
    pub(crate) fn close(code: u16, reason: &str) -> Self {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        Self {
            fin: true,
            opcode: OPCODE_CLOSE,
            payload,
        }
    }

    pub(crate) fn is_unfragmented_text(&self) -> bool {
        self.fin && self.opcode == OPCODE_TEXT
    }

    pub(crate) fn is_fragmented_text_or_continuation(&self) -> bool {
        (!self.fin && self.opcode == OPCODE_TEXT) || self.opcode == OPCODE_CONTINUATION
    }

    pub(crate) fn is_binary(&self) -> bool {
        self.opcode == OPCODE_BINARY
    }
}

pub(crate) fn is_upgrade_request(method: &Method, headers: &HeaderMap) -> bool {
    method == Method::GET
        && header_token_contains(headers, header::CONNECTION, "upgrade")
        && header_token_contains(headers, header::UPGRADE, "websocket")
        && headers.contains_key("sec-websocket-key")
}

pub(crate) fn request_header_should_skip(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authorization"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "content-length"
            | "sec-websocket-extensions"
    )
}

pub(crate) fn response_is_switching_protocols(raw: &[u8]) -> Result<bool, String> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| "WebSocket upstream response headers are not utf-8".to_string())?;
    let Some(status_line) = text.split("\r\n").next() else {
        return Ok(false);
    };
    Ok(status_line.starts_with("HTTP/1.1 101 ") || status_line == "HTTP/1.1 101")
}

pub(crate) fn filter_response_header_bytes(raw: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| "WebSocket upstream response headers are not utf-8".to_string())?;
    let mut output = Vec::new();
    let mut saw_connection = false;
    let mut saw_upgrade = false;
    for line in text.trim_end_matches("\r\n\r\n").split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            if name == "sec-websocket-extensions"
                || name == "content-length"
                || name == "transfer-encoding"
            {
                continue;
            }
            saw_connection |= name == "connection";
            saw_upgrade |= name == "upgrade";
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if !saw_connection {
        output.extend_from_slice(b"connection: Upgrade\r\n");
    }
    if !saw_upgrade {
        output.extend_from_slice(b"upgrade: websocket\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(output)
}

pub(crate) async fn read_frame<R>(reader: &mut R) -> Result<Option<WebSocketFrame>, String>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0_u8; 2];
    let mut read = reader
        .read(&mut head[..1])
        .await
        .map_err(|error| format!("failed to read WebSocket frame: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    while read < 2 {
        let next = reader
            .read(&mut head[read..])
            .await
            .map_err(|error| format!("failed to read WebSocket frame: {error}"))?;
        if next == 0 {
            return Err("WebSocket frame ended before the header completed".to_string());
        }
        read += next;
    }

    let fin = head[0] & 0x80 != 0;
    let rsv = head[0] & 0x70;
    if rsv != 0 {
        return Err("compressed or extension WebSocket frames are not supported".to_string());
    }
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut payload_len = u64::from(head[1] & 0x7f);
    if payload_len == 126 {
        let mut extended = [0_u8; 2];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|error| format!("failed to read WebSocket frame length: {error}"))?;
        payload_len = u64::from(u16::from_be_bytes(extended));
    } else if payload_len == 127 {
        let mut extended = [0_u8; 8];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|error| format!("failed to read WebSocket frame length: {error}"))?;
        payload_len = u64::from_be_bytes(extended);
    }
    if payload_len > MAX_WEBSOCKET_FRAME_BYTES as u64 {
        return Err("WebSocket frame exceeds the supported size".to_string());
    }

    let mut mask = [0_u8; 4];
    if masked {
        reader
            .read_exact(&mut mask)
            .await
            .map_err(|error| format!("failed to read WebSocket frame mask: {error}"))?;
    }
    let mut payload = vec![0_u8; payload_len as usize];
    if !payload.is_empty() {
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|error| format!("failed to read WebSocket frame payload: {error}"))?;
    }
    if masked {
        apply_mask(&mut payload, mask);
    }

    Ok(Some(WebSocketFrame {
        fin,
        opcode,
        payload,
    }))
}

pub(crate) async fn write_masked_frame<W>(
    writer: &mut W,
    frame: &WebSocketFrame,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let mask = masking_key();
    let mut payload = frame.payload.clone();
    apply_mask(&mut payload, mask);
    write_frame_parts(writer, frame.fin, frame.opcode, Some(mask), &payload).await
}

pub(crate) async fn write_unmasked_frame<W>(
    writer: &mut W,
    frame: &WebSocketFrame,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    write_frame_parts(writer, frame.fin, frame.opcode, None, &frame.payload).await
}

async fn write_frame_parts<W>(
    writer: &mut W,
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload: &[u8],
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_WEBSOCKET_FRAME_BYTES {
        return Err("WebSocket frame exceeds the supported size".to_string());
    }
    let mut header = Vec::with_capacity(14);
    header.push(if fin { 0x80 | opcode } else { opcode });
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    if payload.len() < 126 {
        header.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if let Some(mask) = mask {
        header.extend_from_slice(&mask);
    }
    writer
        .write_all(&header)
        .await
        .map_err(|error| format!("failed to write WebSocket frame header: {error}"))?;
    writer
        .write_all(payload)
        .await
        .map_err(|error| format!("failed to write WebSocket frame payload: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| format!("failed to flush WebSocket frame: {error}"))
}

fn header_token_contains(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

fn masking_key() -> [u8; 4] {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn masked_frame_round_trips_to_unmasked_payload() {
        let mut raw = vec![0x81, 0x85, 1, 2, 3, 4];
        let mut payload = b"hello".to_vec();
        apply_mask(&mut payload, [1, 2, 3, 4]);
        raw.extend_from_slice(&payload);

        let frame = read_frame(&mut raw.as_slice()).await.unwrap().unwrap();

        assert!(frame.is_unfragmented_text());
        assert_eq!(frame.payload, b"hello");
    }

    #[tokio::test]
    async fn unmasked_close_frame_uses_server_to_client_framing() {
        let mut output = Vec::new();
        write_unmasked_frame(&mut output, &WebSocketFrame::close(1008, "blocked"))
            .await
            .unwrap();

        assert_eq!(output[0], 0x80 | OPCODE_CLOSE);
        assert_eq!(output[1] & 0x80, 0);
        assert_eq!(&output[2..4], &1008_u16.to_be_bytes());
        assert!(output.ends_with(b"blocked"));
    }

    #[test]
    fn upgrade_detection_accepts_standard_websocket_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "keep-alive, Upgrade".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("sec-websocket-key", "test".parse().unwrap());

        assert!(is_upgrade_request(&Method::GET, &headers));
    }

    #[test]
    fn response_filter_removes_extension_negotiation() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-extensions: permessage-deflate\r\n\r\n";
        let filtered = filter_response_header_bytes(raw).unwrap();
        let text = String::from_utf8(filtered).unwrap();

        assert!(!text.contains("sec-websocket-extensions"));
        assert!(text.ends_with("\r\n\r\n"));
    }
}
