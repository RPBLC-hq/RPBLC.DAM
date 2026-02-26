//! HTTP proxy for transparent PII interception on Anthropic API requests.
//!
//! Intercepts `POST /v1/messages`, scans user messages for PII, replaces
//! detected values with vault references, and resolves references in responses.
//! Supports both streaming (SSE) and non-streaming modes with chunk-boundary-safe
//! reference resolution via [`StreamingResolver`](streaming::StreamingResolver).

pub mod anthropic;
pub mod error;
pub mod anthropic_handler;
pub mod health;
pub mod headers;
pub mod openai;
pub mod openai_handler;
pub mod proxy;
pub mod resolve;
pub mod responses;
pub mod responses_handler;
pub mod router;
pub mod routes;
pub mod server;
pub mod sse_buffer;
pub mod streaming;
pub mod upstream;
pub mod upstream_error;
