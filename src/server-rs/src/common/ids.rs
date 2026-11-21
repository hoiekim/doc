//! Port of `src/common/ids.ts`.

use base64::Engine;
use rand::RngCore;

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn random_string(alphabet: &[u8], length: usize) -> String {
    // Rejection sampling keeps every character uniformly distributed.
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(length);
    let mut bytes = vec![0u8; length * 2];
    while out.len() < length {
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        for &byte in &bytes {
            if byte as usize >= limit {
                continue;
            }
            out.push(alphabet[byte as usize % alphabet.len()] as char);
            if out.len() == length {
                break;
            }
        }
    }
    out
}

/// Public page identifier used in URLs: 10 base-62 characters.
pub fn slug_id() -> String {
    random_string(BASE62, 10)
}

/// Public share key: 10 characters of `[0-9a-z]`.
pub fn share_key() -> String {
    random_string(BASE36, 10)
}

/// Secret token (sessions, password resets, invitations): 32 random bytes, base64url.
pub fn token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Short id for records scoped to one parent (base properties, choices): a prefix plus 9 of `[0-9a-z]`.
pub fn short_id(prefix: &str) -> String {
    format!("{prefix}{}", random_string(BASE36, 9))
}

/// Random v4 UUID.
pub fn uuid() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

/// `8-4-4-4-12` hexadecimal digits, in either case.
pub fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// 1 to 32 characters of `[0-9A-Za-z]`.
pub fn is_slug_id(value: &str) -> bool {
    (1..=32).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_their_shapes() {
        assert!(is_slug_id(&slug_id()) && slug_id().len() == 10);
        assert!(share_key().len() == 10 && share_key().bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()));
        assert_eq!(token().len(), 43);
        assert!(short_id("p").starts_with('p') && short_id("p").len() == 10);
        assert!(is_uuid(&uuid()));
        assert!(is_uuid("0123ABCD-89ef-4567-89ab-0123456789AB"));
        assert!(!is_uuid("0123abcd-89ef-4567-89ab-0123456789a"));
        assert!(!is_uuid("0123abcd089ef-4567-89ab-0123456789ab"));
        assert!(!is_slug_id("") && !is_slug_id("a-b") && is_slug_id("aZ09"));
    }
}
