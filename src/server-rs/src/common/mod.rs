//! Ports of the parts of `src/common` the server uses.

pub mod editor;

/// Where the diagram renderer is loaded from; the app's script policy allows exactly this path.
pub const MERMAID_BASE: &str = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/";
