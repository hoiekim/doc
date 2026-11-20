//! Port of `src/common/editor/sanitize.ts`.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::jsutil::{is_js_whitespace, js_trim};

fn scheme_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^([a-z][a-z0-9+.-]*):").expect("scheme pattern"))
}

fn allowed_scheme_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(https?|mailto|tel):").expect("allowed scheme pattern"))
}

fn data_image_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^data:image/(png|jpe?g|gif|webp|avif|svg\+xml);").expect("data image pattern"))
}

/// A URL that is safe to put in `href`/`src`: relative, fragment, http(s),
/// mailto or tel, and `data:image/` when `allow_data_image`. Anything else
/// (javascript:, data:text/html, vbscript:, ...) becomes `""`, and so does a
/// value that is not a string.
pub fn clean_url(value: Option<&Value>, allow_data_image: bool) -> String {
    match value.and_then(Value::as_str) {
        Some(s) => clean_url_str(s, allow_data_image),
        None => String::new(),
    }
}

/// `clean_url` for a value known to be a string.
pub fn clean_url_str(value: &str, allow_data_image: bool) -> String {
    let s = js_trim(value);
    if s.is_empty() {
        return String::new();
    }
    // Browsers ignore control characters and whitespace inside the scheme.
    let compact: String = s.chars().filter(|c| !(is_js_whitespace(*c) || (*c as u32) <= 0x1f || *c == '\u{7f}')).collect();
    if !scheme_re().is_match(&compact) {
        return s.to_string();
    }
    if allowed_scheme_re().is_match(&compact) {
        return s.to_string();
    }
    if allow_data_image && data_image_re().is_match(&compact) {
        return s.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cleans_urls() {
        assert_eq!(clean_url_str(" https://example.com/a b ", false), "https://example.com/a b");
        assert_eq!(clean_url_str("/relative/path", false), "/relative/path");
        assert_eq!(clean_url_str("#anchor", false), "#anchor");
        assert_eq!(clean_url_str("MAILTO:a@b.c", false), "MAILTO:a@b.c");
        assert_eq!(clean_url_str("javascript:alert(1)", false), "");
        assert_eq!(clean_url_str("java\tscript:alert(1)", false), "");
        assert_eq!(clean_url_str("data:image/png;base64,AAAA", false), "");
        assert_eq!(clean_url_str("data:image/png;base64,AAAA", true), "data:image/png;base64,AAAA");
        assert_eq!(clean_url_str("data:text/html,<script>", true), "");
        assert_eq!(clean_url_str("1:2", false), "1:2");
        assert_eq!(clean_url(Some(&json!(5)), false), "");
        assert_eq!(clean_url(None, false), "");
    }
}
