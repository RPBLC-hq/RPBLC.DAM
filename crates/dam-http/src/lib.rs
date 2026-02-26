//! HTTP proxy for transparent PII interception on Anthropic API requests.
//!
//! Intercepts `POST /v1/messages`, scans user messages for PII, replaces
//! detected values with vault references, and resolves references in responses.
//! Supports both streaming (SSE) and non-streaming modes with chunk-boundary-safe
//! reference resolution via [`StreamingResolver`](streaming::StreamingResolver).

pub mod anthropic;
pub mod error;
pub mod openai;
pub mod proxy;
pub mod resolve;
pub mod responses;
pub mod routes;
pub mod server;
pub mod streaming;
pub mod upstream;
