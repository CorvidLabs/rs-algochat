//! Encryption and decryption for AlgoChat messages.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::envelope::ChatEnvelope;
use crate::keys::{generate_ephemeral_keypair, x25519_ecdh};
use crate::types::{
    AlgoChatError, DecryptedContent, Result, ENCRYPTION_INFO_PREFIX, MAX_PAYLOAD_SIZE, NONCE_SIZE,
    PROTOCOL_ID, PROTOCOL_VERSION, SENDER_KEY_INFO_PREFIX,
};

/// Encrypt a message for a recipient.
///
/// # Arguments
/// * `plaintext` - Message to encrypt
/// * `sender_private_key` - Sender's X25519 private key
/// * `sender_public_key` - Sender's X25519 public key
/// * `recipient_public_key` - Recipient's X25519 public key
///
/// # Returns
/// ChatEnvelope containing the encrypted message
pub fn encrypt_message(
    plaintext: &str,
    _sender_private_key: &StaticSecret,
    sender_public_key: &PublicKey,
    recipient_public_key: &PublicKey,
) -> Result<ChatEnvelope> {
    let message_bytes = plaintext.as_bytes();

    if message_bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(AlgoChatError::MessageTooLarge(message_bytes.len()));
    }

    // Generate ephemeral key pair for this message
    let (ephemeral_private, ephemeral_public) = generate_ephemeral_keypair();

    // Derive symmetric key for message encryption
    let sender_pub_bytes = sender_public_key.as_bytes();
    let recipient_pub_bytes = recipient_public_key.as_bytes();
    let ephemeral_pub_bytes = ephemeral_public.as_bytes();

    let shared_secret = x25519_ecdh(&ephemeral_private, recipient_public_key);

    // Build info: prefix + sender pubkey + recipient pubkey
    let mut info = Vec::with_capacity(ENCRYPTION_INFO_PREFIX.len() + 64);
    info.extend_from_slice(ENCRYPTION_INFO_PREFIX);
    info.extend_from_slice(sender_pub_bytes);
    info.extend_from_slice(recipient_pub_bytes);

    let hkdf = Hkdf::<Sha256>::new(Some(ephemeral_pub_bytes), &shared_secret);
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(&info, &mut symmetric_key)
        .map_err(|e| AlgoChatError::EncryptionError(format!("HKDF expand failed: {}", e)))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt message
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| AlgoChatError::EncryptionError(format!("Cipher init failed: {}", e)))?;
    let ciphertext = cipher
        .encrypt(nonce, message_bytes)
        .map_err(|e| AlgoChatError::EncryptionError(format!("Encryption failed: {}", e)))?;

    // Encrypt the symmetric key for sender (bidirectional decryption)
    let sender_shared_secret = x25519_ecdh(&ephemeral_private, sender_public_key);

    let mut sender_info = Vec::with_capacity(SENDER_KEY_INFO_PREFIX.len() + 32);
    sender_info.extend_from_slice(SENDER_KEY_INFO_PREFIX);
    sender_info.extend_from_slice(sender_pub_bytes);

    let sender_hkdf = Hkdf::<Sha256>::new(Some(ephemeral_pub_bytes), &sender_shared_secret);
    let mut sender_encryption_key = [0u8; 32];
    sender_hkdf
        .expand(&sender_info, &mut sender_encryption_key)
        .map_err(|e| AlgoChatError::EncryptionError(format!("Sender HKDF failed: {}", e)))?;

    let sender_cipher = ChaCha20Poly1305::new_from_slice(&sender_encryption_key)
        .map_err(|e| AlgoChatError::EncryptionError(format!("Sender cipher init failed: {}", e)))?;
    let encrypted_sender_key = sender_cipher
        .encrypt(nonce, symmetric_key.as_slice())
        .map_err(|e| {
            AlgoChatError::EncryptionError(format!("Sender key encryption failed: {}", e))
        })?;

    Ok(ChatEnvelope {
        version: PROTOCOL_VERSION,
        protocol_id: PROTOCOL_ID,
        sender_public_key: *sender_pub_bytes,
        ephemeral_public_key: *ephemeral_pub_bytes,
        nonce: nonce_bytes,
        encrypted_sender_key,
        ciphertext,
    })
}

/// Decrypt a message from an envelope.
///
/// # Arguments
/// * `envelope` - The encrypted envelope
/// * `my_private_key` - Our X25519 private key
/// * `my_public_key` - Our X25519 public key
///
/// # Returns
/// DecryptedContent if successful, None if it's a key-publish message
pub fn decrypt_message(
    envelope: &ChatEnvelope,
    my_private_key: &StaticSecret,
    my_public_key: &PublicKey,
) -> Result<Option<DecryptedContent>> {
    let my_pub_bytes = my_public_key.as_bytes();
    let we_are_sender = my_pub_bytes == &envelope.sender_public_key;

    let plaintext = if we_are_sender {
        decrypt_as_sender(envelope, my_private_key, my_pub_bytes)?
    } else {
        decrypt_as_recipient(envelope, my_private_key, my_pub_bytes)?
    };

    // Check for key-publish payload
    if is_key_publish_payload(&plaintext) {
        return Ok(None);
    }

    Ok(Some(parse_message_payload(&plaintext)?))
}

fn decrypt_as_recipient(
    envelope: &ChatEnvelope,
    recipient_private_key: &StaticSecret,
    recipient_pub_bytes: &[u8; 32],
) -> Result<Vec<u8>> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral_public_key);

    let shared_secret = x25519_ecdh(recipient_private_key, &ephemeral_public);

    // Build info: prefix + sender pubkey + recipient pubkey
    let mut info = Vec::with_capacity(ENCRYPTION_INFO_PREFIX.len() + 64);
    info.extend_from_slice(ENCRYPTION_INFO_PREFIX);
    info.extend_from_slice(&envelope.sender_public_key);
    info.extend_from_slice(recipient_pub_bytes);

    let hkdf = Hkdf::<Sha256>::new(Some(&envelope.ephemeral_public_key), &shared_secret);
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(&info, &mut symmetric_key)
        .map_err(|e| AlgoChatError::DecryptionError(format!("HKDF expand failed: {}", e)))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| AlgoChatError::DecryptionError(format!("Cipher init failed: {}", e)))?;
    let nonce = Nonce::from_slice(&envelope.nonce);

    cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|e| AlgoChatError::DecryptionError(format!("Decryption failed: {}", e)))
}

fn decrypt_as_sender(
    envelope: &ChatEnvelope,
    sender_private_key: &StaticSecret,
    sender_pub_bytes: &[u8; 32],
) -> Result<Vec<u8>> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral_public_key);

    // First, recover the symmetric key
    let shared_secret = x25519_ecdh(sender_private_key, &ephemeral_public);

    let mut sender_info = Vec::with_capacity(SENDER_KEY_INFO_PREFIX.len() + 32);
    sender_info.extend_from_slice(SENDER_KEY_INFO_PREFIX);
    sender_info.extend_from_slice(sender_pub_bytes);

    let sender_hkdf = Hkdf::<Sha256>::new(Some(&envelope.ephemeral_public_key), &shared_secret);
    let mut sender_decryption_key = [0u8; 32];
    sender_hkdf
        .expand(&sender_info, &mut sender_decryption_key)
        .map_err(|e| AlgoChatError::DecryptionError(format!("Sender HKDF failed: {}", e)))?;

    let sender_cipher = ChaCha20Poly1305::new_from_slice(&sender_decryption_key)
        .map_err(|e| AlgoChatError::DecryptionError(format!("Sender cipher init failed: {}", e)))?;
    let nonce = Nonce::from_slice(&envelope.nonce);

    let symmetric_key = sender_cipher
        .decrypt(nonce, envelope.encrypted_sender_key.as_slice())
        .map_err(|e| {
            AlgoChatError::DecryptionError(format!("Sender key decryption failed: {}", e))
        })?;

    // Now decrypt the message
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key).map_err(|e| {
        AlgoChatError::DecryptionError(format!("Message cipher init failed: {}", e))
    })?;

    cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|e| AlgoChatError::DecryptionError(format!("Message decryption failed: {}", e)))
}

fn is_key_publish_payload(data: &[u8]) -> bool {
    if data.is_empty() || data[0] != b'{' {
        return false;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            return json.get("type").and_then(|v| v.as_str()) == Some("key-publish");
        }
    }
    false
}

fn parse_message_payload(data: &[u8]) -> Result<DecryptedContent> {
    let text = std::str::from_utf8(data)
        .map_err(|e| AlgoChatError::DecryptionError(format!("Invalid UTF-8: {}", e)))?;

    // Try to parse as JSON (for structured messages with reply context)
    if text.starts_with('{') {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(msg_text) = json.get("text").and_then(|v| v.as_str()) {
                let reply_to = json.get("replyTo");
                return Ok(DecryptedContent {
                    text: msg_text.to_string(),
                    reply_to_id: reply_to
                        .and_then(|r| r.get("txid"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    reply_to_preview: reply_to
                        .and_then(|r| r.get("preview"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                });
            }
        }
    }

    Ok(DecryptedContent::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derive_keys_from_seed;
    use std::collections::HashMap;

    const ALICE_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const BOB_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn alice_keys() -> (StaticSecret, PublicKey) {
        let seed = hex::decode(ALICE_SEED_HEX).unwrap();
        derive_keys_from_seed(&seed).unwrap()
    }

    fn bob_keys() -> (StaticSecret, PublicKey) {
        let seed = hex::decode(BOB_SEED_HEX).unwrap();
        derive_keys_from_seed(&seed).unwrap()
    }

    fn test_messages() -> HashMap<&'static str, &'static str> {
        let mut messages = HashMap::new();
        messages.insert("empty", "");
        messages.insert("single_char", "X");
        messages.insert("whitespace", "   \t\n   ");
        messages.insert("numbers", "1234567890");
        messages.insert("punctuation", "!@#$%^&*()_+-=[]{}\\|;':\",./<>?");
        messages.insert("newlines", "Line 1\nLine 2\nLine 3");
        messages.insert("emoji_simple", "Hello 👋 World 🌍");
        messages.insert("emoji_zwj", "Family: 👨‍👩‍👧‍👦");
        messages.insert("chinese", "你好世界 - Hello World");
        messages.insert("arabic", "مرحبا بالعالم");
        messages.insert("japanese", "こんにちは世界 カタカナ 漢字");
        messages.insert("korean", "안녕하세요 세계");
        messages.insert("accents", "Café résumé naïve");
        messages.insert("cyrillic", "Привет мир");
        messages.insert("json", r#"{"key": "value", "num": 42}"#);
        messages.insert("html", r#"<div class="test">Content</div>"#);
        messages.insert("url", "https://example.com/path?q=test&lang=en");
        messages.insert("code", r#"func hello() { print("Hi") }"#);
        messages
    }

    fn long_text() -> String {
        "The quick brown fox jumps over the lazy dog. ".repeat(11)
    }

    fn max_payload() -> String {
        "A".repeat(882)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();

        let message = "Hello from Rust!";

        let envelope =
            encrypt_message(message, &alice_private, &alice_public, &bob_public).unwrap();

        let decrypted = decrypt_message(&envelope, &bob_private, &bob_public)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted.text, message);
    }

    #[test]
    fn test_sender_can_decrypt() {
        let (alice_private, alice_public) = alice_keys();
        let (_, bob_public) = bob_keys();

        let message = "I sent this!";

        let envelope =
            encrypt_message(message, &alice_private, &alice_public, &bob_public).unwrap();

        let decrypted = decrypt_message(&envelope, &alice_private, &alice_public)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted.text, message);
    }

    #[test]
    fn test_message_too_large() {
        let (alice_private, alice_public) = alice_keys();
        let (_, bob_public) = bob_keys();

        let message = "A".repeat(MAX_PAYLOAD_SIZE + 1);

        let result = encrypt_message(&message, &alice_private, &alice_public, &bob_public);
        assert!(matches!(result, Err(AlgoChatError::MessageTooLarge(_))));
    }

    #[test]
    fn test_all_message_types() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();

        let messages = test_messages();
        let mut passed = 0;
        let mut failed = 0;

        for (key, expected) in &messages {
            let envelope =
                match encrypt_message(expected, &alice_private, &alice_public, &bob_public) {
                    Ok(env) => env,
                    Err(e) => {
                        println!("✗ {} - encryption failed: {:?}", key, e);
                        failed += 1;
                        continue;
                    }
                };

            match decrypt_message(&envelope, &bob_private, &bob_public) {
                Ok(Some(decrypted)) if decrypted.text == *expected => {
                    println!("✓ {}", key);
                    passed += 1;
                }
                Ok(Some(decrypted)) => {
                    println!("✗ {} - mismatch: {:?} vs {:?}", key, decrypted.text, expected);
                    failed += 1;
                }
                Ok(None) => {
                    println!("✗ {} - returned None", key);
                    failed += 1;
                }
                Err(e) => {
                    println!("✗ {} - decryption failed: {:?}", key, e);
                    failed += 1;
                }
            }
        }

        println!("Message types: {}/{} passed", passed, passed + failed);
        assert_eq!(failed, 0, "Some message types failed");
    }

    #[test]
    fn test_long_text_message() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();

        let message = long_text();

        let envelope =
            encrypt_message(&message, &alice_private, &alice_public, &bob_public).unwrap();

        let decrypted = decrypt_message(&envelope, &bob_private, &bob_public)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted.text, message);
    }

    #[test]
    fn test_max_payload_message() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();

        let message = max_payload();

        let envelope =
            encrypt_message(&message, &alice_private, &alice_public, &bob_public).unwrap();

        let decrypted = decrypt_message(&envelope, &bob_private, &bob_public)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted.text, message);
    }

    #[test]
    fn test_bidirectional_all_messages() {
        let (alice_private, alice_public) = alice_keys();
        let (_, bob_public) = bob_keys();

        let messages = test_messages();

        for (key, expected) in &messages {
            let envelope =
                encrypt_message(expected, &alice_private, &alice_public, &bob_public).unwrap();

            // Sender (Alice) can decrypt their own message
            let decrypted = decrypt_message(&envelope, &alice_private, &alice_public)
                .unwrap()
                .unwrap();

            assert_eq!(
                decrypted.text, *expected,
                "Bidirectional decryption failed for {}",
                key
            );
        }
    }
}
