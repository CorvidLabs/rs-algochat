//! PSK exchange URI generation and parsing.
//!
//! Format: `algochat-psk://v1?addr=<address>&psk=<base64url>&label=<label>`
//!
//! Used for out-of-band exchange of pre-shared keys between peers.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::types::{AlgoChatError, Result};

/// A parsed PSK exchange URI containing all fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PSKExchangeURI {
    /// The Algorand address of the peer.
    pub address: String,
    /// The pre-shared key (32 bytes).
    pub psk: Vec<u8>,
    /// Optional human-readable label for the conversation.
    pub label: Option<String>,
}

impl PSKExchangeURI {
    /// Creates a new PSK exchange URI.
    ///
    /// # Arguments
    /// * `address` - The Algorand address
    /// * `psk` - The pre-shared key bytes (32 bytes)
    /// * `label` - Optional label
    pub fn new(address: impl Into<String>, psk: Vec<u8>, label: Option<String>) -> Self {
        Self {
            address: address.into(),
            psk,
            label,
        }
    }

    /// Encodes the URI to a string.
    ///
    /// # Returns
    /// The URI string in the format `algochat-psk://v1?addr=...&psk=...&label=...`
    pub fn encode(&self) -> String {
        let psk_encoded = URL_SAFE_NO_PAD.encode(&self.psk);
        let mut uri = format!(
            "algochat-psk://v1?addr={}&psk={}",
            self.address, psk_encoded
        );
        if let Some(ref label) = self.label {
            uri.push_str(&format!("&label={}", url_encode(label)));
        }
        uri
    }

    /// Parses a PSK exchange URI string.
    ///
    /// # Arguments
    /// * `uri` - The URI string to parse
    ///
    /// # Returns
    /// A PSKExchangeURI if parsing succeeds
    pub fn parse(uri: &str) -> Result<Self> {
        let prefix = "algochat-psk://v1?";
        if !uri.starts_with(prefix) {
            return Err(AlgoChatError::InvalidEnvelope(
                "Invalid PSK URI scheme or version".to_string(),
            ));
        }

        let query = &uri[prefix.len()..];
        let params: std::collections::HashMap<&str, &str> = query
            .split('&')
            .filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                Some((parts.next()?, parts.next()?))
            })
            .collect();

        let address = params
            .get("addr")
            .ok_or_else(|| AlgoChatError::InvalidEnvelope("Missing 'addr' parameter".to_string()))?
            .to_string();

        let psk_encoded = params
            .get("psk")
            .ok_or_else(|| AlgoChatError::InvalidEnvelope("Missing 'psk' parameter".to_string()))?;

        let psk = URL_SAFE_NO_PAD
            .decode(psk_encoded)
            .map_err(|e| AlgoChatError::InvalidEnvelope(format!("Invalid base64url PSK: {}", e)))?;

        let label = params.get("label").map(|l| url_decode(l)).transpose()?;

        Ok(Self {
            address,
            psk,
            label,
        })
    }
}

/// Simple URL encoding for label values.
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

/// Simple URL decoding for label values.
fn url_decode(s: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            let byte = u8::from_str_radix(&hex, 16)
                .map_err(|_| AlgoChatError::InvalidEnvelope("Invalid percent-encoding".to_string()))?;
            bytes.push(byte);
        } else if c == '+' {
            bytes.push(b' ');
        } else {
            bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| AlgoChatError::InvalidEnvelope("Invalid UTF-8 in URL-decoded value".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let psk = vec![0xAA; 32];
        let uri = PSKExchangeURI::new(
            "ALGO_ADDRESS_HERE",
            psk.clone(),
            Some("Test Label".to_string()),
        );

        let encoded = uri.encode();
        assert!(encoded.starts_with("algochat-psk://v1?"));

        let decoded = PSKExchangeURI::parse(&encoded).unwrap();
        assert_eq!(decoded.address, "ALGO_ADDRESS_HERE");
        assert_eq!(decoded.psk, psk);
        assert_eq!(decoded.label, Some("Test Label".to_string()));
    }

    #[test]
    fn test_encode_without_label() {
        let psk = vec![0xBB; 32];
        let uri = PSKExchangeURI::new("ADDR123", psk.clone(), None);

        let encoded = uri.encode();
        assert!(!encoded.contains("&label="));

        let decoded = PSKExchangeURI::parse(&encoded).unwrap();
        assert_eq!(decoded.address, "ADDR123");
        assert_eq!(decoded.psk, psk);
        assert_eq!(decoded.label, None);
    }

    #[test]
    fn test_base64url_encoding() {
        let psk = vec![0xFF; 32];
        let uri = PSKExchangeURI::new("ADDR", psk, None);
        let encoded = uri.encode();

        let psk_part = encoded.split("psk=").nth(1).unwrap();
        assert!(!psk_part.contains('+'));
        assert!(!psk_part.contains('/'));
        assert!(!psk_part.contains('='));
    }

    #[test]
    fn test_parse_invalid_scheme() {
        let result = PSKExchangeURI::parse("https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_addr() {
        let result = PSKExchangeURI::parse("algochat-psk://v1?psk=AAAA");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_psk() {
        let result = PSKExchangeURI::parse("algochat-psk://v1?addr=ADDR");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_encoding_special_chars() {
        let uri = PSKExchangeURI::new("ADDR", vec![0x00; 32], Some("Hello World!".to_string()));

        let encoded = uri.encode();
        assert!(encoded.contains("Hello%20World%21"));

        let decoded = PSKExchangeURI::parse(&encoded).unwrap();
        assert_eq!(decoded.label, Some("Hello World!".to_string()));
    }

    #[test]
    fn test_url_encode_decode_two_byte_utf8() {
        // "café" contains é which is U+00E9 = 2-byte UTF-8 sequence [0xC3, 0xA9]
        let label = "café";
        let encoded = url_encode(label);
        assert!(encoded.contains("caf%C3%A9"), "encoded was: {}", encoded);
        let decoded = url_decode(&encoded).unwrap();
        assert_eq!(decoded, label);
    }

    #[test]
    fn test_url_encode_decode_three_byte_utf8() {
        // "こんにちは" — each character is a 3-byte UTF-8 sequence
        let label = "こんにちは";
        let encoded = url_encode(label);
        let decoded = url_decode(&encoded).unwrap();
        assert_eq!(decoded, label);
    }

    #[test]
    fn test_url_encode_decode_four_byte_utf8() {
        // Emoji — 4-byte UTF-8 sequence
        let label = "🔑 key";
        let encoded = url_encode(label);
        let decoded = url_decode(&encoded).unwrap();
        assert_eq!(decoded, label);
    }

    #[test]
    fn test_roundtrip_non_ascii_label() {
        let psk = vec![0xCC; 32];
        let uri = PSKExchangeURI::new("ADDR", psk.clone(), Some("café 🔑".to_string()));

        let encoded = uri.encode();
        let decoded = PSKExchangeURI::parse(&encoded).unwrap();
        assert_eq!(decoded.label, Some("café 🔑".to_string()));
        assert_eq!(decoded.psk, psk);
    }

    #[test]
    fn test_url_decode_invalid_utf8() {
        // 0xFF is not valid UTF-8 on its own
        let result = url_decode("%FF");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_decode_invalid_hex() {
        let result = url_decode("%ZZ");
        assert!(result.is_err());
    }
}
