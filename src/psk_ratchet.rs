//! Two-level ratchet for PSK (Pre-Shared Key) derivation.
//!
//! The ratchet uses a session/position hierarchy:
//! - **Session PSK**: Derived from the initial PSK + session index
//! - **Position PSK**: Derived from the session PSK + position within session
//!
//! This provides forward secrecy: compromising one position key does not
//! reveal past or future keys.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::psk_types::PSK_SESSION_SIZE;
use crate::types::{AlgoChatError, Result};

/// Salt used for session-level PSK derivation.
const SESSION_SALT: &[u8] = b"AlgoChat-PSK-Session";

/// Salt used for position-level PSK derivation.
const POSITION_SALT: &[u8] = b"AlgoChat-PSK-Position";

/// Info prefix for hybrid symmetric key derivation.
const HYBRID_KEY_INFO_PREFIX: &[u8] = b"AlgoChatV1-PSK";

/// Info prefix for sender key derivation.
const SENDER_KEY_INFO_PREFIX: &[u8] = b"AlgoChatV1-PSK-SenderKey";

/// Derives a session PSK from the initial PSK and session index.
///
/// # Arguments
/// * `initial_psk` - The initial pre-shared key (32 bytes)
/// * `session_index` - The session index (counter / PSK_SESSION_SIZE)
///
/// # Returns
/// A 32-byte session PSK
pub fn derive_session_psk(initial_psk: &[u8], session_index: u32) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(SESSION_SALT), initial_psk);
    let mut session_psk = [0u8; 32];
    hkdf.expand(&session_index.to_be_bytes(), &mut session_psk)
        .map_err(|e| {
            AlgoChatError::KeyDerivationFailed(format!("Session PSK derivation failed: {}", e))
        })?;
    Ok(session_psk)
}

/// Derives a position PSK from a session PSK and position within the session.
///
/// # Arguments
/// * `session_psk` - The session PSK (32 bytes)
/// * `position` - The position within the session (counter % PSK_SESSION_SIZE)
///
/// # Returns
/// A 32-byte position PSK
pub fn derive_position_psk(session_psk: &[u8], position: u32) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(POSITION_SALT), session_psk);
    let mut position_psk = [0u8; 32];
    hkdf.expand(&position.to_be_bytes(), &mut position_psk)
        .map_err(|e| {
            AlgoChatError::KeyDerivationFailed(format!("Position PSK derivation failed: {}", e))
        })?;
    Ok(position_psk)
}

/// Derives the PSK at a given ratchet counter value.
///
/// This combines session and position derivation:
/// - session_index = counter / PSK_SESSION_SIZE
/// - position = counter % PSK_SESSION_SIZE
///
/// # Arguments
/// * `initial_psk` - The initial pre-shared key (32 bytes)
/// * `counter` - The ratchet counter
///
/// # Returns
/// A 32-byte PSK for this counter value
pub fn derive_psk_at_counter(initial_psk: &[u8], counter: u32) -> Result<[u8; 32]> {
    let session_index = counter / PSK_SESSION_SIZE;
    let position = counter % PSK_SESSION_SIZE;

    let session_psk = derive_session_psk(initial_psk, session_index)?;
    derive_position_psk(&session_psk, position)
}

/// Derives a hybrid symmetric key combining ECDH shared secret and PSK.
///
/// This provides dual-layer security: both the ECDH key agreement and the
/// pre-shared key must be correct to derive the encryption key.
///
/// # Arguments
/// * `shared_secret` - The ECDH shared secret (32 bytes)
/// * `current_psk` - The current ratcheted PSK (32 bytes)
/// * `ephemeral_public_key` - The ephemeral public key (used as salt, 32 bytes)
/// * `sender_public_key` - The sender's public key (32 bytes)
/// * `recipient_public_key` - The recipient's public key (32 bytes)
///
/// # Returns
/// A 32-byte symmetric key for message encryption
pub fn derive_hybrid_symmetric_key(
    shared_secret: &[u8],
    current_psk: &[u8],
    ephemeral_public_key: &[u8],
    sender_public_key: &[u8],
    recipient_public_key: &[u8],
) -> Result<[u8; 32]> {
    // IKM = shared_secret || current_psk
    let mut ikm = Vec::with_capacity(shared_secret.len() + current_psk.len());
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(current_psk);

    // info = prefix || sender_public_key || recipient_public_key
    let mut info = Vec::with_capacity(HYBRID_KEY_INFO_PREFIX.len() + 64);
    info.extend_from_slice(HYBRID_KEY_INFO_PREFIX);
    info.extend_from_slice(sender_public_key);
    info.extend_from_slice(recipient_public_key);

    // salt = ephemeral_public_key
    let hkdf = Hkdf::<Sha256>::new(Some(ephemeral_public_key), &ikm);
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(&info, &mut symmetric_key).map_err(|e| {
        AlgoChatError::KeyDerivationFailed(format!("Hybrid key derivation failed: {}", e))
    })?;

    Ok(symmetric_key)
}

/// Derives a sender key for bidirectional decryption with PSK.
///
/// This key is used to encrypt the symmetric key so the sender can
/// also decrypt their own messages.
///
/// # Arguments
/// * `sender_shared_secret` - ECDH shared secret with sender's static key (32 bytes)
/// * `current_psk` - The current ratcheted PSK (32 bytes)
/// * `ephemeral_public_key` - The ephemeral public key (used as salt, 32 bytes)
/// * `sender_public_key` - The sender's public key (32 bytes)
///
/// # Returns
/// A 32-byte sender key for encrypting the symmetric key
pub fn derive_sender_key(
    sender_shared_secret: &[u8],
    current_psk: &[u8],
    ephemeral_public_key: &[u8],
    sender_public_key: &[u8],
) -> Result<[u8; 32]> {
    // IKM = sender_shared_secret || current_psk
    let mut ikm = Vec::with_capacity(sender_shared_secret.len() + current_psk.len());
    ikm.extend_from_slice(sender_shared_secret);
    ikm.extend_from_slice(current_psk);

    // info = prefix || sender_public_key
    let mut info = Vec::with_capacity(SENDER_KEY_INFO_PREFIX.len() + 32);
    info.extend_from_slice(SENDER_KEY_INFO_PREFIX);
    info.extend_from_slice(sender_public_key);

    // salt = ephemeral_public_key
    let hkdf = Hkdf::<Sha256>::new(Some(ephemeral_public_key), &ikm);
    let mut sender_key = [0u8; 32];
    hkdf.expand(&info, &mut sender_key).map_err(|e| {
        AlgoChatError::KeyDerivationFailed(format!("Sender key derivation failed: {}", e))
    })?;

    Ok(sender_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn test_session_psk_vectors() {
        let psk = test_psk();

        let session0 = derive_session_psk(&psk, 0).unwrap();
        assert_eq!(
            hex::encode(session0),
            "a031707ea9e9e50bd8ea4eb9a2bd368465ea1aff14caab293d38954b4717e888"
        );

        let session1 = derive_session_psk(&psk, 1).unwrap();
        assert_eq!(
            hex::encode(session1),
            "994cffbb4f84fa5410d44574bb9fa7408a8c2f1ed2b3a00f5168fc74c71f7cea"
        );
    }

    #[test]
    fn test_counter_psk_vectors() {
        let psk = test_psk();

        let counter0 = derive_psk_at_counter(&psk, 0).unwrap();
        assert_eq!(
            hex::encode(counter0),
            "2918fd486b9bd024d712f6234b813c0f4167237d60c2c1fca37326b20497c165"
        );

        let counter99 = derive_psk_at_counter(&psk, 99).unwrap();
        assert_eq!(
            hex::encode(counter99),
            "5b48a50a25261f6b63fe9c867b46be46de4d747c3477db6290045ba519a4d38b"
        );

        let counter100 = derive_psk_at_counter(&psk, 100).unwrap();
        assert_eq!(
            hex::encode(counter100),
            "7a15d3add6a28858e6a1f1ea0d22bdb29b7e129a1330c4908d9b46a460992694"
        );
    }

    #[test]
    fn test_session_boundary() {
        let psk = test_psk();
        let psk99 = derive_psk_at_counter(&psk, 99).unwrap();
        let psk100 = derive_psk_at_counter(&psk, 100).unwrap();
        assert_ne!(psk99, psk100);

        let psk0 = derive_psk_at_counter(&psk, 0).unwrap();
        let psk1 = derive_psk_at_counter(&psk, 1).unwrap();
        assert_ne!(psk0, psk1);
    }

    #[test]
    fn test_deterministic_derivation() {
        let psk = test_psk();
        let result1 = derive_psk_at_counter(&psk, 42).unwrap();
        let result2 = derive_psk_at_counter(&psk, 42).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hybrid_key_derivation() {
        let shared_secret = [0x11u8; 32];
        let current_psk = [0x22u8; 32];
        let ephemeral = [0x33u8; 32];
        let sender = [0x44u8; 32];
        let recipient = [0x55u8; 32];

        let key = derive_hybrid_symmetric_key(
            &shared_secret,
            &current_psk,
            &ephemeral,
            &sender,
            &recipient,
        )
        .unwrap();

        let key2 = derive_hybrid_symmetric_key(
            &shared_secret,
            &current_psk,
            &ephemeral,
            &sender,
            &recipient,
        )
        .unwrap();
        assert_eq!(key, key2);

        let different_psk = [0x99u8; 32];
        let key3 = derive_hybrid_symmetric_key(
            &shared_secret,
            &different_psk,
            &ephemeral,
            &sender,
            &recipient,
        )
        .unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_sender_key_derivation() {
        let shared_secret = [0x11u8; 32];
        let current_psk = [0x22u8; 32];
        let ephemeral = [0x33u8; 32];
        let sender = [0x44u8; 32];

        let key = derive_sender_key(&shared_secret, &current_psk, &ephemeral, &sender).unwrap();
        let key2 = derive_sender_key(&shared_secret, &current_psk, &ephemeral, &sender).unwrap();
        assert_eq!(key, key2);

        let different_psk = [0x99u8; 32];
        let key3 = derive_sender_key(&shared_secret, &different_psk, &ephemeral, &sender).unwrap();
        assert_ne!(key, key3);
    }

    /// Protocol spec Test Case 4.2: PSK Symmetric Key Derivation
    #[test]
    fn test_spec_vector_4_2_psk_symmetric_key_derivation() {
        use crate::keys::derive_keys_from_seed;

        let sender_seed = [0x01u8; 32];
        let recipient_seed = [0x02u8; 32];
        let ephemeral_seed = [0x03u8; 32];
        let initial_psk = [0xAAu8; 32];

        let (sender_private, sender_public) = derive_keys_from_seed(&sender_seed).unwrap();
        let (recipient_private, recipient_public) = derive_keys_from_seed(&recipient_seed).unwrap();
        let (ephemeral_private, ephemeral_public) = derive_keys_from_seed(&ephemeral_seed).unwrap();

        // Verify public keys match spec
        assert_eq!(
            hex::encode(sender_public.as_bytes()),
            "cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86c"
        );
        assert_eq!(
            hex::encode(recipient_public.as_bytes()),
            "5d5da7177c24372f08fbd5f2acaf1a94296a9fd1d747e03a370ab162ed484d09"
        );
        assert_eq!(
            hex::encode(ephemeral_public.as_bytes()),
            "a56fa4362f0646d8818192d769727ca9dca7fc60730b69b632fc7bb370757f53"
        );

        // Derive current PSK at counter 0
        let current_psk = derive_psk_at_counter(&initial_psk, 0).unwrap();
        assert_eq!(
            hex::encode(current_psk),
            "2918fd486b9bd024d712f6234b813c0f4167237d60c2c1fca37326b20497c165"
        );

        // ECDH: ephemeral -> recipient
        let shared_secret = crate::keys::x25519_ecdh(&ephemeral_private, &recipient_public);
        assert_eq!(
            hex::encode(shared_secret),
            "3d4a443a1a0cafb7bb0eee148334f307e862ba9b5d517b475c903f8245ff1750"
        );

        // Hybrid symmetric key
        let psk_symmetric_key = derive_hybrid_symmetric_key(
            &shared_secret,
            &current_psk,
            ephemeral_public.as_bytes(),
            sender_public.as_bytes(),
            recipient_public.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(psk_symmetric_key),
            "cf082d0fbd4d380a5278cc29b3d584ede66f29776f86cbc8c065a9c5705de9d1"
        );

        // ECDH: ephemeral -> sender
        let sender_shared_secret = crate::keys::x25519_ecdh(&ephemeral_private, &sender_public);
        assert_eq!(
            hex::encode(sender_shared_secret),
            "86a66e48b0821f96ec63514f37ab235c2805bdb4b1b2fce695ff8a75c287eb16"
        );

        // Sender encryption key
        let psk_sender_key = derive_sender_key(
            &sender_shared_secret,
            &current_psk,
            ephemeral_public.as_bytes(),
            sender_public.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(psk_sender_key),
            "ca575ea2874b1f074930026f7a2729cc1543f593bc185712e65be4eab6660a59"
        );

        // Also verify recipient can derive the same shared secret
        let recipient_shared = crate::keys::x25519_ecdh(&recipient_private, &ephemeral_public);
        assert_eq!(shared_secret, recipient_shared);

        // And sender can derive the same sender shared secret
        let sender_shared = crate::keys::x25519_ecdh(&sender_private, &ephemeral_public);
        assert_eq!(sender_shared_secret, sender_shared);
    }
}
