//! MCP server exposing DAM vault tools to AI agents over stdio transport.
//!
//! Provides 7 tools (`dam_scan`, `dam_resolve`, `dam_consent`, `dam_vault_search`,
//! `dam_status`, `dam_reveal`, `dam_compare`) via the Model Context Protocol.
//! The server injects instructions guiding the LLM to always scan input and
//! work with typed references instead of raw PII values.

pub mod server;

pub use server::DamMcpServer;
