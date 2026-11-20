//! The doc backend in Rust.
//!
//! It serves the same HTTP API and WebSocket protocol as the Bun server in
//! `src/server`, on the same database, and is tested by the same suite
//! (`src/api-tests`). Modules keep the names of the TypeScript files they
//! port, so the two can be read side by side.

pub mod common;
pub mod content;
pub mod jsutil;
