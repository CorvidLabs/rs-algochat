//! PSK encryption and decryption for AlgoChat messages.
//!
//! Combines ECDH key agreement with a pre-shared key ratchet for
//! dual-layer security. Both the ECDH shared secret and the PSK
//! must be correct to derive the message encryption key.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::{generate_ephemeral_keypair, x25519_ecdh};
use crate::psk_ratchet::{derive_hybrid_symmetric_key, derive_psk_at_counter, derive_sender_key};
use crate::psk_types::{PSKEnvelope, PSK_MAX_PAYLOAD_SIZE};
use crate::types::{AlgoChatError, Result, NONCE_SIZE};

/// Encrypts a message using the PSK protocol.
///
/// # Arguments
/// * `plaintext` - Message to encrypt
/// * `sender_private_key` - Sender's X25519 private key
/// * `sender_public_key` - Sender's X25519 public key
/// * `recipient_public_key` - Recipient's X25519 public key
/// * `initial_psk` - The initial pre-shared key (32 bytes)
/// * `ratchet_counter` - The current ratchet counter
///
/// # Returns
/// A PSKEnvelope containing the encrypted message
pub fn encrypt_psk_message(
    plaintext: &str,
    sender_private_key: &StaticSecret,
    sender_public_key: &PublicKey,
    recipient_public_key: &PublicKey,
    initial_psk: &[u8],
    ratchet_counter: u32,
) -> Result<PSKEnvelope> {
    let message_bytes = plaintext.as_bytes();

    if message_bytes.len() > PSK_MAX_PAYLOAD_SIZE {
        return Err(AlgoChatError::MessageTooLarge(message_bytes.len()));
    }

    // Derive the current PSK from the ratchet
    let current_psk = derive_psk_at_counter(initial_psk, ratchet_counter)?;

    // Generate ephemeral key pair
    let (ephemeral_private, ephemeral_public) = generate_ephemeral_keypair();

    let sender_pub_bytes = sender_public_key.as_bytes();
    let recipient_pub_bytes = recipient_public_key.as_bytes();
    let ephemeral_pub_bytes = ephemeral_public.as_bytes();

    // ECDH with recipient
    let shared_secret = x25519_ecdh(&ephemeral_private, recipient_public_key);

    // Derive hybrid symmetric key (ECDH + PSK)
    let symmetric_key = derive_hybrid_symmetric_key(
        &shared_secret,
        &current_psk,
        ephemeral_pub_bytes,
        sender_pub_bytes,
        recipient_pub_bytes,
    )?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt message
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| AlgoChatError::EncryptionError(format!("PSK cipher init failed: {}", e)))?;
    let ciphertext = cipher
        .encrypt(nonce, message_bytes)
        .map_err(|e| AlgoChatError::EncryptionError(format!("PSK encryption failed: {}", e)))?;

    // Encrypt the symmetric key for sender (bidirectional decryption)
    let sender_shared_secret = x25519_ecdh(&ephemeral_private, sender_public_key);
    let sender_encryption_key = derive_sender_key(
        &sender_shared_secret,
        &current_psk,
        ephemeral_pub_bytes,
        sender_pub_bytes,
    )?;

    let sender_cipher = ChaCha20Poly1305::new_from_slice(&sender_encryption_key).map_err(|e| {
        AlgoChatError::EncryptionError(format!("PSK sender cipher init failed: {}", e))
    })?;
    let encrypted_sender_key = sender_cipher
        .encrypt(nonce, symmetric_key.as_slice())
        .map_err(|e| {
            AlgoChatError::EncryptionError(format!("PSK sender key encryption failed: {}", e))
        })?;

    Ok(PSKEnvelope {
        ratchet_counter,
        sender_public_key: *sender_pub_bytes,
        ephemeral_public_key: *ephemeral_pub_bytes,
        nonce: nonce_bytes,
        encrypted_sender_key,
        ciphertext,
    })
}

/// Decrypts a PSK message envelope.
///
/// Automatically detects whether we are the sender or recipient and
/// uses the appropriate decryption path.
///
/// # Arguments
/// * `envelope` - The PSK envelope to decrypt
/// * `my_private_key` - Our X25519 private key
/// * `my_public_key` - Our X25519 public key
/// * `initial_psk` - The initial pre-shared key (32 bytes)
///
/// # Returns
/// The decrypted message text
pub fn decrypt_psk_message(
    envelope: &PSKEnvelope,
    my_private_key: &StaticSecret,
    my_public_key: &PublicKey,
    initial_psk: &[u8],
) -> Result<String> {
    let my_pub_bytes = my_public_key.as_bytes();
    let we_are_sender = my_pub_bytes == &envelope.sender_public_key;

    // Derive the current PSK from the ratchet counter in the envelope
    let current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)?;

    let plaintext = if we_are_sender {
        decrypt_psk_as_sender(envelope, my_private_key, my_pub_bytes, &current_psk)?
    } else {
        decrypt_psk_as_recipient(envelope, my_private_key, my_pub_bytes, &current_psk)?
    };

    let text = std::str::from_utf8(&plaintext)
        .map_err(|e| AlgoChatError::DecryptionError(format!("Invalid UTF-8: {}", e)))?;

    Ok(text.to_string())
}

/// Decrypts a PSK message as the recipient.
fn decrypt_psk_as_recipient(
    envelope: &PSKEnvelope,
    recipient_private_key: &StaticSecret,
    recipient_pub_bytes: &[u8; 32],
    current_psk: &[u8],
) -> Result<Vec<u8>> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral_public_key);

    // ECDH with ephemeral key
    let shared_secret = x25519_ecdh(recipient_private_key, &ephemeral_public);

    // Derive hybrid symmetric key
    let symmetric_key = derive_hybrid_symmetric_key(
        &shared_secret,
        current_psk,
        &envelope.ephemeral_public_key,
        &envelope.sender_public_key,
        recipient_pub_bytes,
    )?;

    // Decrypt message
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
        .map_err(|e| AlgoChatError::DecryptionError(format!("PSK cipher init failed: {}", e)))?;
    let nonce = Nonce::from_slice(&envelope.nonce);

    cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|e| AlgoChatError::DecryptionError(format!("PSK decryption failed: {}", e)))
}

/// Decrypts a PSK message as the sender (bidirectional decryption).
fn decrypt_psk_as_sender(
    envelope: &PSKEnvelope,
    sender_private_key: &StaticSecret,
    sender_pub_bytes: &[u8; 32],
    current_psk: &[u8],
) -> Result<Vec<u8>> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral_public_key);

    // ECDH with sender's own key to recover sender key
    let shared_secret = x25519_ecdh(sender_private_key, &ephemeral_public);

    let sender_decryption_key = derive_sender_key(
        &shared_secret,
        current_psk,
        &envelope.ephemeral_public_key,
        sender_pub_bytes,
    )?;

    // Decrypt the symmetric key
    let sender_cipher = ChaCha20Poly1305::new_from_slice(&sender_decryption_key).map_err(|e| {
        AlgoChatError::DecryptionError(format!("PSK sender cipher init failed: {}", e))
    })?;
    let nonce = Nonce::from_slice(&envelope.nonce);

    let symmetric_key = sender_cipher
        .decrypt(nonce, envelope.encrypted_sender_key.as_slice())
        .map_err(|e| {
            AlgoChatError::DecryptionError(format!("PSK sender key decryption failed: {}", e))
        })?;

    // Decrypt the message
    let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key).map_err(|e| {
        AlgoChatError::DecryptionError(format!("PSK message cipher init failed: {}", e))
    })?;

    cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|e| {
            AlgoChatError::DecryptionError(format!("PSK message decryption failed: {}", e))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derive_keys_from_seed;

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

    fn test_psk() -> Vec<u8> {
        vec![0xAA; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();
        let psk = test_psk();

        let message = "Hello PSK from Rust!";

        let envelope =
            encrypt_psk_message(message, &alice_private, &alice_public, &bob_public, &psk, 0)
                .unwrap();

        let decrypted = decrypt_psk_message(&envelope, &bob_private, &bob_public, &psk).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_sender_self_decrypt() {
        let (alice_private, alice_public) = alice_keys();
        let (_, bob_public) = bob_keys();
        let psk = test_psk();

        let message = "I sent this PSK message!";

        let envelope =
            encrypt_psk_message(message, &alice_private, &alice_public, &bob_public, &psk, 0)
                .unwrap();

        let decrypted =
            decrypt_psk_message(&envelope, &alice_private, &alice_public, &psk).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_different_counters() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();
        let psk = test_psk();

        for counter in [0u32, 1, 50, 99, 100, 101, 200, 1000] {
            let message = format!("Message at counter {}", counter);

            let envelope = encrypt_psk_message(
                &message,
                &alice_private,
                &alice_public,
                &bob_public,
                &psk,
                counter,
            )
            .unwrap();

            assert_eq!(envelope.ratchet_counter, counter);

            let decrypted =
                decrypt_psk_message(&envelope, &bob_private, &bob_public, &psk).unwrap();
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_wrong_psk_fails() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();
        let psk = test_psk();
        let wrong_psk = vec![0xBB; 32];

        let message = "Secret message";

        let envelope =
            encrypt_psk_message(message, &alice_private, &alice_public, &bob_public, &psk, 0)
                .unwrap();

        let result = decrypt_psk_message(&envelope, &bob_private, &bob_public, &wrong_psk);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_large() {
        let (alice_private, alice_public) = alice_keys();
        let (_, bob_public) = bob_keys();
        let psk = test_psk();

        let message = "A".repeat(PSK_MAX_PAYLOAD_SIZE + 1);

        let result = encrypt_psk_message(
            &message,
            &alice_private,
            &alice_public,
            &bob_public,
            &psk,
            0,
        );
        assert!(matches!(result, Err(AlgoChatError::MessageTooLarge(_))));
    }

    #[test]
    fn test_max_payload() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();
        let psk = test_psk();

        let message = "A".repeat(PSK_MAX_PAYLOAD_SIZE);

        let envelope = encrypt_psk_message(
            &message,
            &alice_private,
            &alice_public,
            &bob_public,
            &psk,
            0,
        )
        .unwrap();

        let decrypted = decrypt_psk_message(&envelope, &bob_private, &bob_public, &psk).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_empty_message() {
        let (alice_private, alice_public) = alice_keys();
        let (bob_private, bob_public) = bob_keys();
        let psk = test_psk();

        let message = "";

        let envelope =
            encrypt_psk_message(message, &alice_private, &alice_public, &bob_public, &psk, 0)
                .unwrap();

        let decrypted = decrypt_psk_message(&envelope, &bob_private, &bob_public, &psk).unwrap();
        assert_eq!(decrypted, message);
    }
}
