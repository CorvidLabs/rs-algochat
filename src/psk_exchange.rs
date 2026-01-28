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
        let mut uri = format!("algochat-psk://v1?addr={}&psk={}", self.address, psk_encoded);
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

        let label = params.get("label").map(|l| url_decode(l));

        Ok(Self {
            address,
            psk,
            label,
        })
    }
}

/// Simple URL encoding for label values.
fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "%20".to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

/// Simple URL decoding for label values.
fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
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
        let uri = PSKExchangeURI::new(
            "ADDR",
            vec![0x00; 32],
            Some("Hello World!".to_string()),
        );

        let encoded = uri.encode();
        assert!(encoded.contains("Hello%20World%21"));

        let decoded = PSKExchangeURI::parse(&encoded).unwrap();
        assert_eq!(decoded.label, Some("Hello World!".to_string()));
    }
}
