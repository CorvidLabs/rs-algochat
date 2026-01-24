//! Signature verification for AlgoChat encryption keys.
//!
//! This module provides functions to sign encryption public keys with an
//! Algorand account's Ed25519 key, and verify those signatures. This prevents
//! key substitution attacks by proving key ownership.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::types::{AlgoChatError, Result, SIGNATURE_SIZE};

/// Size of an Ed25519 signature (64 bytes).
pub const ED25519_SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

/// Signs an encryption public key with an Ed25519 signing key.
///
/// This creates a cryptographic proof that the encryption key belongs to
/// the holder of the Ed25519 private key (Algorand account).
///
/// # Arguments
/// * `encryption_public_key` - The X25519 public key to sign (32 bytes)
/// * `signing_key` - The Ed25519 signing key (from Algorand account)
///
/// # Returns
/// The Ed25519 signature (64 bytes)
pub fn sign_encryption_key(
    encryption_public_key: &[u8],
    signing_key: &SigningKey,
) -> Result<[u8; 64]> {
    if encryption_public_key.len() != 32 {
        return Err(AlgoChatError::InvalidPublicKey(format!(
            "Encryption public key must be 32 bytes, got {}",
            encryption_public_key.len()
        )));
    }

    let signature = signing_key.sign(encryption_public_key);
    Ok(signature.to_bytes())
}

/// Verifies that an encryption public key was signed by an Ed25519 key.
///
/// This checks that the signature over the X25519 encryption key was
/// created by the Ed25519 private key corresponding to the given public key.
///
/// # Arguments
/// * `encryption_public_key` - The X25519 public key (32 bytes)
/// * `verifying_key` - The Ed25519 public key (from Algorand address)
/// * `signature` - The Ed25519 signature to verify (64 bytes)
///
/// # Returns
/// `true` if the signature is valid
pub fn verify_encryption_key(
    encryption_public_key: &[u8],
    verifying_key: &VerifyingKey,
    signature: &[u8],
) -> Result<bool> {
    if encryption_public_key.len() != 32 {
        return Err(AlgoChatError::InvalidPublicKey(format!(
            "Encryption public key must be 32 bytes, got {}",
            encryption_public_key.len()
        )));
    }

    if signature.len() != SIGNATURE_SIZE {
        return Err(AlgoChatError::InvalidSignature(format!(
            "Signature must be {} bytes, got {}",
            SIGNATURE_SIZE,
            signature.len()
        )));
    }

    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| AlgoChatError::InvalidSignature("Invalid signature bytes".into()))?;

    let signature = Signature::from_bytes(&signature_bytes);

    Ok(verifying_key.verify(encryption_public_key, &signature).is_ok())
}

/// Verifies an encryption key using raw Ed25519 public key bytes.
///
/// # Arguments
/// * `encryption_public_key` - The X25519 public key (32 bytes)
/// * `ed25519_public_key` - The Ed25519 public key bytes (32 bytes, e.g., Algorand address bytes)
/// * `signature` - The Ed25519 signature (64 bytes)
///
/// # Returns
/// `true` if the signature is valid
pub fn verify_encryption_key_bytes(
    encryption_public_key: &[u8],
    ed25519_public_key: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if ed25519_public_key.len() != 32 {
        return Err(AlgoChatError::InvalidPublicKey(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            ed25519_public_key.len()
        )));
    }

    let key_bytes: [u8; 32] = ed25519_public_key
        .try_into()
        .map_err(|_| AlgoChatError::InvalidPublicKey("Invalid public key bytes".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AlgoChatError::InvalidPublicKey(format!("Invalid Ed25519 public key: {}", e)))?;

    verify_encryption_key(encryption_public_key, &verifying_key, signature)
}

/// Generates a human-readable fingerprint for an encryption public key.
///
/// The fingerprint is a truncated SHA-256 hash formatted for easy comparison.
///
/// # Arguments
/// * `public_key` - The encryption public key (32 bytes)
///
/// # Returns
/// A fingerprint string like "A7B3 C9D1 E5F2 8A4B"
pub fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();

    hash.iter()
        .take(8)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.join(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Fake X25519 public key (32 bytes)
        let encryption_key = [42u8; 32];

        let signature = sign_encryption_key(&encryption_key, &signing_key).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = verify_encryption_key(&encryption_key, &verifying_key, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();

        let encryption_key = [42u8; 32];
        let signature = sign_encryption_key(&encryption_key, &signing_key).unwrap();

        let valid = verify_encryption_key(&encryption_key, &wrong_key, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let encryption_key = [42u8; 32];
        let wrong_key = [99u8; 32];

        let signature = sign_encryption_key(&encryption_key, &signing_key).unwrap();

        let valid = verify_encryption_key(&wrong_key, &verifying_key, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_fingerprint() {
        let key = [0u8; 32];
        let fp = fingerprint(&key);
        // Should be 4 groups of 4 hex chars separated by spaces
        assert_eq!(fp.len(), 19); // "XXXX XXXX XXXX XXXX"
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }

    #[test]
    fn test_invalid_key_length() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let result = sign_encryption_key(&[0u8; 16], &signing_key);
        assert!(matches!(result, Err(AlgoChatError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_invalid_signature_length() {
        let verifying_key = SigningKey::generate(&mut OsRng).verifying_key();
        let result = verify_encryption_key(&[0u8; 32], &verifying_key, &[0u8; 32]);
        assert!(matches!(result, Err(AlgoChatError::InvalidSignature(_))));
    }
}
