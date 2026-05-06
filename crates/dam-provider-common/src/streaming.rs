use axum::body::Bytes;
use futures_util::{Stream, StreamExt, stream};
use std::{io, pin::Pin};

use crate::sse::rewrite_event_stream_text;

const STREAM_TRANSFORM_TAIL_BYTES: usize = 64;
const EVENT_STREAM_TAIL_EVENTS: usize = 4;

pub type ProviderByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

struct TransformState<S, F> {
    stream: Pin<Box<S>>,
    transform: F,
    pending: Vec<u8>,
    finished: bool,
}

struct EventStreamTransformState<S, F> {
    stream: Pin<Box<S>>,
    transform: F,
    pending: Vec<u8>,
    finished: bool,
}

pub fn transform_streaming_body<S, F>(stream: S, transform: F) -> ProviderByteStream
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
    F: Fn(Bytes) -> Bytes + Clone + Send + Sync + 'static,
{
    let state = TransformState {
        stream: Box::pin(stream),
        transform,
        pending: Vec::new(),
        finished: false,
    };

    Box::pin(stream::unfold(state, |mut state| async move {
        loop {
            if state.finished {
                return None;
            }

            match state.stream.as_mut().next().await {
                Some(Ok(chunk)) => {
                    state.pending.extend_from_slice(&chunk);
                    if let Some(output) = state.emit_ready() {
                        return Some((Ok(output), state));
                    }
                }
                Some(Err(error)) => return Some((Err(error), state)),
                None => {
                    state.finished = true;
                    if let Some(output) = state.emit_finish() {
                        return Some((Ok(output), state));
                    }
                    return None;
                }
            }
        }
    }))
}

pub fn transform_event_stream_text_body<S, F>(stream: S, transform: F) -> ProviderByteStream
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
    F: Fn(Bytes) -> Bytes + Clone + Send + Sync + 'static,
{
    let state = EventStreamTransformState {
        stream: Box::pin(stream),
        transform,
        pending: Vec::new(),
        finished: false,
    };

    Box::pin(stream::unfold(state, |mut state| async move {
        loop {
            if state.finished {
                return None;
            }

            match state.stream.as_mut().next().await {
                Some(Ok(chunk)) => {
                    state.pending.extend_from_slice(&chunk);
                    if let Some(output) = state.emit_ready() {
                        return Some((Ok(output), state));
                    }
                }
                Some(Err(error)) => return Some((Err(error), state)),
                None => {
                    state.finished = true;
                    if let Some(output) = state.emit_finish() {
                        return Some((Ok(output), state));
                    }
                    return None;
                }
            }
        }
    }))
}

impl<S, F> TransformState<S, F>
where
    F: Fn(Bytes) -> Bytes,
{
    fn emit_ready(&mut self) -> Option<Bytes> {
        if self.pending.len() <= STREAM_TRANSFORM_TAIL_BYTES {
            return None;
        }

        let target_len = self.pending.len() - STREAM_TRANSFORM_TAIL_BYTES;
        let (emit_len, should_transform) = match valid_utf8_prefix_len(&self.pending, target_len) {
            Some(emit_len) => (emit_len, true),
            None => (target_len, false),
        };
        if emit_len == 0 {
            return None;
        }

        let output = self.pending.drain(..emit_len).collect::<Vec<_>>();
        if should_transform {
            Some((self.transform)(Bytes::from(output)))
        } else {
            Some(Bytes::from(output))
        }
    }

    fn emit_finish(&mut self) -> Option<Bytes> {
        if self.pending.is_empty() {
            return None;
        }

        let output = std::mem::take(&mut self.pending);
        Some((self.transform)(Bytes::from(output)))
    }
}

impl<S, F> EventStreamTransformState<S, F>
where
    F: Fn(Bytes) -> Bytes,
{
    fn emit_ready(&mut self) -> Option<Bytes> {
        let complete_len = complete_event_stream_prefix_len(&self.pending)?;
        let complete = Bytes::copy_from_slice(&self.pending[..complete_len]);
        let transformed = rewrite_event_stream_text(complete, &self.transform);
        let mut events = split_complete_event_stream_events(transformed.as_ref());
        if events.len() <= EVENT_STREAM_TAIL_EVENTS {
            return None;
        }

        let emit_count = events.len() - EVENT_STREAM_TAIL_EVENTS;
        let retained = events.split_off(emit_count);
        let output = events.concat();
        let incomplete = self.pending.split_off(complete_len);
        self.pending = retained.concat();
        self.pending.extend_from_slice(&incomplete);
        Some(Bytes::from(output))
    }

    fn emit_finish(&mut self) -> Option<Bytes> {
        if self.pending.is_empty() {
            return None;
        }

        let output = std::mem::take(&mut self.pending);
        Some(rewrite_event_stream_text(
            Bytes::from(output),
            &self.transform,
        ))
    }
}

fn complete_event_stream_prefix_len(bytes: &[u8]) -> Option<usize> {
    let mut last = None;
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\n' && bytes[index + 1] == b'\n' {
            last = Some(index + 2);
            index += 2;
            continue;
        }
        if index + 3 < bytes.len()
            && bytes[index] == b'\r'
            && bytes[index + 1] == b'\n'
            && bytes[index + 2] == b'\r'
            && bytes[index + 3] == b'\n'
        {
            last = Some(index + 4);
            index += 4;
            continue;
        }
        index += 1;
    }
    last
}

fn split_complete_event_stream_events(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut events = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\n' && bytes[index + 1] == b'\n' {
            events.push(bytes[start..index + 2].to_vec());
            start = index + 2;
            index += 2;
            continue;
        }
        index += 1;
    }
    if start < bytes.len() {
        events.push(bytes[start..].to_vec());
    }
    events
}

fn valid_utf8_prefix_len(bytes: &[u8], target_len: usize) -> Option<usize> {
    let mut len = target_len.min(bytes.len());
    for _ in 0..=4 {
        if std::str::from_utf8(&bytes[..len]).is_ok() {
            return Some(len);
        }
        len = len.checked_sub(1)?;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::TryStreamExt;

    async fn collect_text(stream: ProviderByteStream) -> String {
        let chunks = stream.try_collect::<Vec<_>>().await.unwrap();
        let bytes = chunks.into_iter().flatten().collect::<Vec<_>>();
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn transforms_reference_split_across_chunks() {
        let reference = "[email:1111111111111111111111]";
        let first = format!("event: delta\ndata: prefix {reference}");
        let split = first.len() - 8;
        let chunks = stream::iter([
            Ok(Bytes::from(first[..split].to_string())),
            Ok(Bytes::from(format!("{} suffix\n\n", &first[split..]))),
        ]);

        let body = collect_text(transform_streaming_body(chunks, move |chunk| {
            let text = String::from_utf8(chunk.to_vec()).unwrap();
            Bytes::from(text.replace(reference, "alice@example.com"))
        }))
        .await;

        assert!(body.contains("alice@example.com"));
        assert!(!body.contains("[email:"));
    }

    #[tokio::test]
    async fn flushes_short_final_chunks() {
        let chunks = stream::iter([Ok(Bytes::from_static(b"short body"))]);

        let body = collect_text(transform_streaming_body(chunks, |chunk| {
            let text = String::from_utf8(chunk.to_vec()).unwrap();
            Bytes::from(text.replace("short", "resolved"))
        }))
        .await;

        assert_eq!(body, "resolved body");
    }

    #[tokio::test]
    async fn emits_invalid_long_prefix_without_transforming() {
        let chunks = stream::iter([
            Ok(Bytes::from(vec![0xff; STREAM_TRANSFORM_TAIL_BYTES + 8])),
            Ok(Bytes::from_static(b"done")),
        ]);

        let output = transform_streaming_body(chunks, |_| Bytes::from_static(b"transformed"))
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        assert!(output.starts_with(&[0xff; 8]));
        assert!(output.ends_with(b"transformed"));
    }

    #[tokio::test]
    async fn resolves_reference_split_across_sse_text_delta_events() {
        let chunks = stream::iter([
            Ok(Bytes::from_static(
                br#"event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"[email:abc"}}

"#,
            )),
            Ok(Bytes::from_static(
                br#"event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"123]"}}

"#,
            )),
        ]);

        let body = collect_text(transform_event_stream_text_body(chunks, |chunk| {
            let text = String::from_utf8(chunk.to_vec()).unwrap();
            Bytes::from(text.replace("[email:abc123]", "banana@example.test"))
        }))
        .await;

        assert!(body.contains("banana@example.test"));
        assert!(!body.contains("[email:abc123]"));
        assert!(body.contains(r#""text":"""#));
        assert!(body.contains("event: content_block_delta"));
    }

    #[tokio::test]
    async fn event_stream_transform_emits_before_end_of_stream() {
        let events = (0..8)
            .map(|index| {
                Ok(Bytes::from(format!(
                    "event: delta\ndata: {{\"text\":\"chunk-{index}\"}}\n\n"
                )))
            })
            .collect::<Vec<_>>();

        let chunks = transform_event_stream_text_body(stream::iter(events), |chunk| chunk)
            .try_collect::<Vec<_>>()
            .await
            .unwrap();

        assert!(chunks.len() > 1);
        assert!(
            String::from_utf8(chunks.concat())
                .unwrap()
                .contains("chunk-0")
        );
    }

    #[tokio::test]
    async fn event_stream_transform_handles_crlf_event_boundaries() {
        let chunks = stream::iter([
            Ok(Bytes::from_static(
                b"event: delta\r\ndata: {\"text\":\"[email:abc\"}\r\n\r\n",
            )),
            Ok(Bytes::from_static(
                b"event: delta\r\ndata: {\"text\":\"123]\"}\r\n\r\n",
            )),
            Ok(Bytes::from_static(
                b"event: delta\r\ndata: {\"text\":\"done\"}\r\n\r\n",
            )),
            Ok(Bytes::from_static(
                b"event: delta\r\ndata: {\"text\":\"tail\"}\r\n\r\n",
            )),
            Ok(Bytes::from_static(
                b"event: delta\r\ndata: {\"text\":\"finish\"}\r\n\r\n",
            )),
        ]);

        let body = collect_text(transform_event_stream_text_body(chunks, |chunk| {
            let text = String::from_utf8(chunk.to_vec()).unwrap();
            Bytes::from(text.replace("[email:abc123]", "banana@example.test"))
        }))
        .await;

        assert!(body.contains("banana@example.test"));
        assert!(!body.contains("[email:abc123]"));
    }
}
