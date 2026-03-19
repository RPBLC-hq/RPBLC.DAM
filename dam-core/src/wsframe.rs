//! Minimal WebSocket frame parser, serializer, and fragment assembler (RFC 6455).
//!
//! No external crate — just raw byte parsing. Used by the inspected WebSocket relay
//! to read/write frames while running the DAM pipeline on text frame payloads.

/// Maximum assembled message size (16 MiB) to prevent OOM.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Unknown(u8),
}

impl Opcode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            other => Self::Unknown(other),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
            Self::Unknown(b) => b,
        }
    }

    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

/// Try to parse one complete frame from `buf`. Returns `(frame, bytes_consumed)` or `None`.
/// Payload is returned unmasked.
pub fn parse_frame(buf: &[u8]) -> Option<(Frame, usize)> {
    if buf.len() < 2 {
        return None;
    }

    let fin = buf[0] & 0x80 != 0;
    let opcode = Opcode::from_byte(buf[0] & 0x0F);
    let masked = buf[1] & 0x80 != 0;
    let len_byte = (buf[1] & 0x7F) as usize;

    let (payload_len, header_end) = if len_byte <= 125 {
        (len_byte, 2)
    } else if len_byte == 126 {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        (len, 4)
    } else {
        // len_byte == 127
        if buf.len() < 10 {
            return None;
        }
        let len = u64::from_be_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]) as usize;
        if len > MAX_MESSAGE_SIZE {
            return None; // reject oversized frames
        }
        (len, 10)
    };

    let mask_len = if masked { 4 } else { 0 };
    let total = header_end + mask_len + payload_len;
    if buf.len() < total {
        return None;
    }

    let mask_key = if masked {
        [
            buf[header_end],
            buf[header_end + 1],
            buf[header_end + 2],
            buf[header_end + 3],
        ]
    } else {
        [0; 4]
    };

    let payload_start = header_end + mask_len;
    let mut payload = buf[payload_start..payload_start + payload_len].to_vec();

    if masked {
        unmask(&mut payload, mask_key);
    }

    Some((Frame { fin, opcode, payload }, total))
}

/// Serialize a frame to wire format. If `mask` is true, generates a random mask key.
pub fn serialize_frame(frame: &Frame, mask: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + frame.payload.len());

    // Byte 0: FIN + opcode
    let b0 = if frame.fin { 0x80 } else { 0x00 } | frame.opcode.to_byte();
    buf.push(b0);

    // Byte 1: MASK + length
    let mask_bit: u8 = if mask { 0x80 } else { 0x00 };
    let len = frame.payload.len();
    if len <= 125 {
        buf.push(mask_bit | len as u8);
    } else if len <= 65535 {
        buf.push(mask_bit | 126);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(mask_bit | 127);
        buf.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if mask {
        let key = rand_mask_key();
        buf.extend_from_slice(&key);
        let mut payload = frame.payload.clone();
        unmask(&mut payload, key);
        buf.extend_from_slice(&payload);
    } else {
        buf.extend_from_slice(&frame.payload);
    }

    buf
}

fn unmask(payload: &mut [u8], key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

fn rand_mask_key() -> [u8; 4] {
    // Simple PRNG from thread-local state. Good enough for mask keys.
    let mut key = [0u8; 4];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    key[0] = seed as u8;
    key[1] = (seed >> 8) as u8;
    key[2] = (seed >> 16) as u8;
    key[3] = (seed >> 24) as u8;
    key
}

/// Reassembles fragmented WebSocket messages.
/// Control frames (ping/pong/close) are returned immediately regardless of fragment state.
pub struct FrameAssembler {
    fragments: Vec<u8>,
    started_opcode: Option<Opcode>,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self {
            fragments: Vec::new(),
            started_opcode: None,
        }
    }

    /// Feed a frame. Returns the complete message (payload + original opcode) when done,
    /// or None if still accumulating fragments.
    /// Control frames are returned immediately.
    pub fn feed(&mut self, frame: Frame) -> Option<(Vec<u8>, Opcode)> {
        // Control frames: never fragmented, pass through immediately
        if frame.opcode.is_control() {
            return Some((frame.payload, frame.opcode));
        }

        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                // Start of a new message
                self.started_opcode = Some(frame.opcode);
                self.fragments.clear();
                self.fragments.extend_from_slice(&frame.payload);
            }
            Opcode::Continuation => {
                // Continue existing message
                self.fragments.extend_from_slice(&frame.payload);
            }
            _ => return None,
        }

        // Enforce size limit
        if self.fragments.len() > MAX_MESSAGE_SIZE {
            self.fragments.clear();
            self.started_opcode = None;
            return None;
        }

        if frame.fin {
            let opcode = self.started_opcode.take().unwrap_or(Opcode::Text);
            let payload = std::mem::take(&mut self.fragments);
            Some((payload, opcode))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unmasked_text() {
        let mut buf = vec![0x81, 0x05]; // FIN + Text, len=5
        buf.extend_from_slice(b"hello");
        let (frame, consumed) = parse_frame(&buf).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload, b"hello");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn parse_masked_text() {
        let mask: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
        let mut payload = b"Hello".to_vec();
        unmask(&mut payload, mask); // mask it

        let mut buf = vec![0x81, 0x85]; // FIN + Text, MASK, len=5
        buf.extend_from_slice(&mask);
        buf.extend_from_slice(&payload);

        let (frame, consumed) = parse_frame(&buf).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload, b"Hello"); // unmasked
        assert_eq!(consumed, 11); // 2 + 4 + 5
    }

    #[test]
    fn parse_binary() {
        let mut buf = vec![0x82, 0x03]; // FIN + Binary, len=3
        buf.extend_from_slice(&[1, 2, 3]);
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload, &[1, 2, 3]);
    }

    #[test]
    fn parse_close() {
        let buf = vec![0x88, 0x02, 0x03, 0xE8]; // Close, len=2, status 1000
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.payload, &[0x03, 0xE8]);
    }

    #[test]
    fn parse_ping_pong() {
        let ping = vec![0x89, 0x00]; // Ping, len=0
        let (frame, _) = parse_frame(&ping).unwrap();
        assert_eq!(frame.opcode, Opcode::Ping);

        let pong = vec![0x8A, 0x04, 0x74, 0x65, 0x73, 0x74]; // Pong, "test"
        let (frame, _) = parse_frame(&pong).unwrap();
        assert_eq!(frame.opcode, Opcode::Pong);
        assert_eq!(frame.payload, b"test");
    }

    #[test]
    fn parse_extended_16bit() {
        let payload = vec![0x41; 300]; // 300 bytes of 'A'
        let mut buf = vec![0x81, 0x7E]; // FIN + Text, len=126 (extended)
        buf.extend_from_slice(&(300u16).to_be_bytes());
        buf.extend_from_slice(&payload);
        let (frame, consumed) = parse_frame(&buf).unwrap();
        assert_eq!(frame.payload.len(), 300);
        assert_eq!(consumed, 2 + 2 + 300);
    }

    #[test]
    fn parse_incomplete_returns_none() {
        assert!(parse_frame(&[]).is_none());
        assert!(parse_frame(&[0x81]).is_none());
        assert!(parse_frame(&[0x81, 0x05, 0x01]).is_none()); // need 5 bytes, only 1
    }

    #[test]
    fn roundtrip_unmasked() {
        let frame = Frame {
            fin: true,
            opcode: Opcode::Text,
            payload: b"hello world".to_vec(),
        };
        let wire = serialize_frame(&frame, false);
        let (parsed, consumed) = parse_frame(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert!(parsed.fin);
        assert_eq!(parsed.opcode, Opcode::Text);
        assert_eq!(parsed.payload, b"hello world");
    }

    #[test]
    fn roundtrip_masked() {
        let frame = Frame {
            fin: true,
            opcode: Opcode::Text,
            payload: b"test data".to_vec(),
        };
        let wire = serialize_frame(&frame, true);
        // Masked wire should be 2 + 4 + 9 = 15 bytes
        assert_eq!(wire.len(), 15);
        assert_eq!(wire[1] & 0x80, 0x80); // mask bit set
        let (parsed, _) = parse_frame(&wire).unwrap();
        assert_eq!(parsed.payload, b"test data"); // unmasked
    }

    #[test]
    fn assembler_single_frame() {
        let mut asm = FrameAssembler::new();
        let frame = Frame {
            fin: true,
            opcode: Opcode::Text,
            payload: b"complete".to_vec(),
        };
        let result = asm.feed(frame).unwrap();
        assert_eq!(result.0, b"complete");
        assert_eq!(result.1, Opcode::Text);
    }

    #[test]
    fn assembler_fragmented() {
        let mut asm = FrameAssembler::new();

        // Fragment 1: Text, FIN=false
        assert!(asm
            .feed(Frame {
                fin: false,
                opcode: Opcode::Text,
                payload: b"hel".to_vec(),
            })
            .is_none());

        // Fragment 2: Continuation, FIN=false
        assert!(asm
            .feed(Frame {
                fin: false,
                opcode: Opcode::Continuation,
                payload: b"lo ".to_vec(),
            })
            .is_none());

        // Fragment 3: Continuation, FIN=true
        let (payload, opcode) = asm
            .feed(Frame {
                fin: true,
                opcode: Opcode::Continuation,
                payload: b"world".to_vec(),
            })
            .unwrap();
        assert_eq!(payload, b"hello world");
        assert_eq!(opcode, Opcode::Text);
    }

    #[test]
    fn assembler_control_interleaved() {
        let mut asm = FrameAssembler::new();

        // Start fragmented text
        assert!(asm
            .feed(Frame {
                fin: false,
                opcode: Opcode::Text,
                payload: b"part1".to_vec(),
            })
            .is_none());

        // Ping in the middle — returned immediately
        let (payload, opcode) = asm
            .feed(Frame {
                fin: true,
                opcode: Opcode::Ping,
                payload: vec![],
            })
            .unwrap();
        assert_eq!(opcode, Opcode::Ping);
        assert!(payload.is_empty());

        // Continue fragmented text
        let (payload, opcode) = asm
            .feed(Frame {
                fin: true,
                opcode: Opcode::Continuation,
                payload: b"part2".to_vec(),
            })
            .unwrap();
        assert_eq!(payload, b"part1part2");
        assert_eq!(opcode, Opcode::Text);
    }
}
