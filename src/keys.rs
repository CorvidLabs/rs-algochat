//! Key derivation and management for AlgoChat.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::types::{AlgoChatError, Result, KEY_DERIVATION_INFO, KEY_DERIVATION_SALT};

/// Derive X25519 key pair from a 32-byte seed using HKDF-SHA256.
///
/// # Arguments
/// * `seed` - 32-byte seed (e.g., from Algorand account secret key)
///
/// # Returns
/// Tuple of (private_key, public_key)
pub fn derive_keys_from_seed(seed: &[u8]) -> Result<(StaticSecret, PublicKey)> {
    if seed.len() != 32 {
        return Err(AlgoChatError::InvalidSeedLength(seed.len()));
    }

    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), seed);
    let mut derived_key = [0u8; 32];
    hkdf.expand(KEY_DERIVATION_INFO, &mut derived_key)
        .expect("32 bytes is a valid length for HKDF-SHA256");

    let private_key = StaticSecret::from(derived_key);
    let public_key = PublicKey::from(&private_key);

    Ok((private_key, public_key))
}

/// Generate a random ephemeral X25519 key pair for message encryption.
///
/// # Returns
/// Tuple of (private_key, public_key)
pub fn generate_ephemeral_keypair() -> (StaticSecret, PublicKey) {
    let private_key = StaticSecret::random_from_rng(rand::thread_rng());
    let public_key = PublicKey::from(&private_key);
    (private_key, public_key)
}

/// Perform X25519 ECDH key exchange.
///
/// # Arguments
/// * `private_key` - Our private key
/// * `public_key` - Their public key
///
/// # Returns
/// 32-byte shared secret
pub fn x25519_ecdh(private_key: &StaticSecret, public_key: &PublicKey) -> [u8; 32] {
    private_key.diffie_hellman(public_key).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const ALICE_PUBLIC_KEY_HEX: &str =
        "a04407c78ff19a0bbd578588d6100bca4ed7f89acfc600666dbab1d36061c064";
    const BOB_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const BOB_PUBLIC_KEY_HEX: &str =
        "b43231dc85ba0781ad3df9b8f8458a5e6f4c1030d0526ace9540300e0398ae03";

    #[test]
    fn test_derive_alice_keys() {
        let seed = hex::decode(ALICE_SEED_HEX).unwrap();
        let (_, public_key) = derive_keys_from_seed(&seed).unwrap();
        assert_eq!(hex::encode(public_key.as_bytes()), ALICE_PUBLIC_KEY_HEX);
    }

    #[test]
    fn test_derive_bob_keys() {
        let seed = hex::decode(BOB_SEED_HEX).unwrap();
        let (_, public_key) = derive_keys_from_seed(&seed).unwrap();
        assert_eq!(hex::encode(public_key.as_bytes()), BOB_PUBLIC_KEY_HEX);
    }

    #[test]
    fn test_invalid_seed_length() {
        let result = derive_keys_from_seed(b"too short");
        assert!(matches!(result, Err(AlgoChatError::InvalidSeedLength(9))));
    }

    #[test]
    fn test_deterministic_derivation() {
        let seed = hex::decode(ALICE_SEED_HEX).unwrap();
        let (_, public1) = derive_keys_from_seed(&seed).unwrap();
        let (_, public2) = derive_keys_from_seed(&seed).unwrap();
        assert_eq!(public1.as_bytes(), public2.as_bytes());
    }
}
