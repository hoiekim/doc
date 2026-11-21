//! Port of `src/server/lib/search.ts`.

/// Escapes the characters `LIKE` gives meaning to, so a value matches literally.
pub fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '\\' || ch == '%' || ch == '_' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}
