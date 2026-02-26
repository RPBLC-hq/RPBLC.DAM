pub(crate) use crate::anthropic_handler::{AnthropicSseState, handle_messages};
pub(crate) use crate::openai_handler::{OpenAiSseState, handle_chat_completions};
pub(crate) use crate::responses_handler::{
    ResponsesSseState, handle_codex_responses, handle_responses,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sse_buffer::SseBuffer;
    use crate::upstream::MAX_UPSTREAM_URL_LEN;
    use crate::upstream::extract_upstream_override;
    use axum::http::HeaderMap;
    use std::collections::HashSet;
    use std::sync::Arc;

    use dam_core::PiiType;
    use dam_vault::generate_kek;

    fn test_vault_with_entry() -> (Arc<dam_vault::VaultStore>, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(dam_vault::VaultStore::open(&path, generate_kek()).unwrap());
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@example.com", None, None)
            .unwrap();
        (vault, pii_ref.key())
    }

    #[test]
    fn sse_buffer_splits_events() {
        let mut buf = SseBuffer::new();
        buf.feed(b"event: ping\ndata: {}\n\nevent: message_start\ndata: {}\n\n");

        let ev1 = buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev1).contains("ping"));

        let ev2 = buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev2).contains("message_start"));

        assert!(buf.next_event().is_none());
    }

    #[test]
    fn sse_state_splits_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault, Arc::new(HashSet::new()));

        state.buf.feed(b"event: ping\ndata: {}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n");

        let ev1 = state.buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev1).contains("ping"));

        let ev2 = state.buf.next_event().unwrap();
        assert!(String::from_utf8_lossy(&ev2).contains("message_start"));

        assert!(state.buf.next_event().is_none());
    }

    #[test]
    fn sse_state_passthrough_non_text_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault, Arc::new(HashSet::new()));

        let ping = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
        state.buf.feed(ping);

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        assert_eq!(output, ping.to_vec());
    }

    #[test]
    fn sse_state_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = AnthropicSseState::new(vault, allowlist_for(&ref_key));

        let data = format!(
            r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"Hello [{}] world"}}}}"#,
            ref_key
        );
        let event = format!("event: content_block_delta\ndata: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("alice@example.com"));
        assert!(!output_str.contains(&format!("[{ref_key}]")));
    }

    #[test]
    fn openai_sse_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault, allowlist_for(&ref_key));

        let data = format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"Hello [{ref_key}] world"}},"finish_reason":null}}]}}"#,
        );
        let event = format!("data: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);
        assert_eq!(outputs.len(), 1);

        let output_str = String::from_utf8(outputs[0].clone()).unwrap();
        assert!(output_str.contains("alice@example.com"), "should resolve ref: {output_str}");
        assert!(!output_str.contains(&format!("[{ref_key}]")));
    }

    #[test]
    fn openai_sse_passthrough_non_content_chunk() {
        let (vault, _) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault, Arc::new(HashSet::new()));
        let data = r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#;
        let event = format!("data: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);
        assert_eq!(outputs.len(), 1);

        let output_str = String::from_utf8(outputs[0].clone()).unwrap();
        assert!(output_str.contains("assistant"));
    }

    #[test]
    fn openai_sse_done_termination() {
        let (vault, _) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault, Arc::new(HashSet::new()));

        let event = "data: [DONE]\n\n";
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev);
        let last = String::from_utf8(outputs.last().unwrap().clone()).unwrap();
        assert!(last.contains("[DONE]"));
    }

    #[test]
    fn responses_sse_resolves_text_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, allowlist_for(&ref_key));

        let data = format!(r#"{{"delta":"Hello [{ref_key}] world","output_index":0,"content_index":0}}"#,);
        let event = format!("event: response.output_text.delta\ndata: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("alice@example.com"), "should resolve ref: {output_str}");
        assert!(!output_str.contains(&format!("[{ref_key}]")));
        assert!(output_str.starts_with("event: response.output_text.delta\n"));
    }

    #[test]
    fn responses_sse_passthrough_non_text_events() {
        let (vault, _) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, Arc::new(HashSet::new()));

        let event =
            b"event: response.created\ndata: {\"type\":\"response\",\"id\":\"resp_abc\"}\n\n";
        state.buf.feed(event);

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        assert_eq!(output, event.to_vec());
    }

    #[test]
    fn responses_sse_flush_on_text_done() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, Arc::new(HashSet::new()));

        let partial = format!("[{}", &ref_key[..ref_key.len() / 2]);
        let data1 = format!(r#"{{"delta":"{partial}","output_index":0,"content_index":0}}"#,);
        let event1 = format!("event: response.output_text.delta\ndata: {data1}\n\n");
        state.buf.feed(event1.as_bytes());
        let ev1 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev1);

        let rest = &ref_key[ref_key.len() / 2..];
        let data2 = format!(r#"{{"delta":"{rest}]","output_index":0,"content_index":0}}"#,);
        let event2 = format!("event: response.output_text.delta\ndata: {data2}\n\n");
        state.buf.feed(event2.as_bytes());
        let ev2 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev2);

        let done_data = r#"{"output_index":0,"content_index":0,"text":"full text"}"#;
        let done_event = format!("event: response.output_text.done\ndata: {done_data}\n\n");
        state.buf.feed(done_event.as_bytes());
        let ev3 = state.buf.next_event().unwrap();
        let output = state.process_event(&ev3);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("response.output_text.done"));
        assert!(state.resolvers.is_empty(), "resolver should be removed after done");
    }

    #[test]
    fn responses_sse_flush_on_completed() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, Arc::new(HashSet::new()));

        let partial = format!("[{}", &ref_key[..ref_key.len() / 2]);
        let data1 = format!(r#"{{"delta":"{partial}","output_index":0,"content_index":0}}"#,);
        let event1 = format!("event: response.output_text.delta\ndata: {data1}\n\n");
        state.buf.feed(event1.as_bytes());
        let ev1 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev1);

        let completed_event = b"event: response.completed\ndata: {\"type\":\"response\"}\n\n";
        state.buf.feed(completed_event);
        let ev2 = state.buf.next_event().unwrap();
        let output = state.process_event(&ev2);
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("response.completed"));
        assert!(state.resolvers.is_empty(), "all resolvers should be flushed on completed");
    }

    #[test]
    fn responses_sse_function_call_delta() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = ResponsesSseState::new(vault, allowlist_for(&ref_key));

        let data = format!(r#"{{"delta":"[{ref_key}]","output_index":0,"content_index":0}}"#,);
        let event = format!("event: response.function_call_arguments.delta\ndata: {data}\n\n");
        state.buf.feed(event.as_bytes());

        let ev = state.buf.next_event().unwrap();
        let output = state.process_event(&ev);
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("alice@example.com"),
            "should resolve ref in function call args: {output_str}"
        );
        assert!(output_str.starts_with("event: response.function_call_arguments.delta\n"));
    }

    fn allowlist_for(ref_key: &str) -> Arc<HashSet<String>> {
        let mut set = HashSet::new();
        set.insert(ref_key.to_string());
        Arc::new(set)
    }

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            axum::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::header::HeaderValue::from_str(value).unwrap(),
        );
        map
    }

    #[test]
    fn upstream_override_absent() {
        let headers = HeaderMap::new();
        assert!(extract_upstream_override(&headers).unwrap().is_none());
    }

    #[test]
    fn upstream_override_https() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn upstream_override_http_localhost() {
        let headers = headers_with("x-dam-upstream", "http://localhost:8080");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn upstream_override_strips_trailing_slash() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai/");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn upstream_override_trims_whitespace() {
        let headers = headers_with("x-dam-upstream", "  https://api.x.ai  ");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn upstream_override_empty_string() {
        let headers = headers_with("x-dam-upstream", "");
        assert!(extract_upstream_override(&headers).unwrap().is_none());
    }

    #[test]
    fn upstream_override_whitespace_only() {
        let headers = headers_with("x-dam-upstream", "   ");
        assert!(extract_upstream_override(&headers).unwrap().is_none());
    }

    #[test]
    fn upstream_override_rejects_ftp() {
        let headers = headers_with("x-dam-upstream", "ftp://evil.com");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_no_scheme() {
        let headers = headers_with("x-dam-upstream", "not a url");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_credentials() {
        let headers = headers_with("x-dam-upstream", "https://user:pass@api.x.ai");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_query_string() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai?key=val");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_fragment() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai#frag");
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_rejects_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(MAX_UPSTREAM_URL_LEN));
        let headers = headers_with("x-dam-upstream", &long_url);
        assert!(extract_upstream_override(&headers).is_err());
    }

    #[test]
    fn upstream_override_allows_path_prefix() {
        let headers = headers_with("x-dam-upstream", "https://gateway.corp.com/openai-proxy");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://gateway.corp.com/openai-proxy")
        );
    }

    #[test]
    fn upstream_override_allows_local_ip() {
        let headers = headers_with("x-dam-upstream", "http://127.0.0.1:11434");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("http://127.0.0.1:11434")
        );
    }

    #[test]
    fn upstream_override_strips_multiple_trailing_slashes() {
        let headers = headers_with("x-dam-upstream", "https://api.x.ai///");
        assert_eq!(
            extract_upstream_override(&headers).unwrap().as_deref(),
            Some("https://api.x.ai")
        );
    }

    #[test]
    fn openai_sse_flush_on_stop() {
        let (vault, ref_key) = test_vault_with_entry();
        let mut state = OpenAiSseState::new(vault, allowlist_for(&ref_key));

        let partial = format!("[{}", &ref_key[..ref_key.len() / 2]);
        let data1 = format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"{partial}"}},"finish_reason":null}}]}}"#,
        );
        let event1 = format!("data: {data1}\n\n");
        state.buf.feed(event1.as_bytes());
        let ev1 = state.buf.next_event().unwrap();
        let _ = state.process_event(&ev1);

        let rest = &ref_key[ref_key.len() / 2..];
        let data2 = format!(
            r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"{rest}]"}},"finish_reason":"stop"}}]}}"#,
        );
        let event2 = format!("data: {data2}\n\n");
        state.buf.feed(event2.as_bytes());
        let ev2 = state.buf.next_event().unwrap();
        let outputs = state.process_event(&ev2);

        let combined: String = outputs
            .iter()
            .map(|o| String::from_utf8_lossy(o).to_string())
            .collect();
        assert!(
            combined.contains("alice@example.com"),
            "should resolve ref across chunks: {combined}"
        );
    }
}
