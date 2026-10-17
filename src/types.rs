//! Type definitions and protocol constants for AlgoChat.

use thiserror::Error;

/// Protocol version byte.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Protocol version byte for v2 (AEAD header binding).
///
/// v2 envelopes are wire-identical to v1 except the leading version byte is
/// `0x02` and both AEAD operations bind the header metadata prefix as
/// Associated Data (AAD). See proposal 0001. v1 envelopes remain fully valid.
pub const PROTOCOL_VERSION_V2: u8 = 0x02;

/// Protocol ID byte.
pub const PROTOCOL_ID: u8 = 0x01;

/// Length of the standard v2 AAD: the metadata prefix of the header.
///
/// `version(1) + protocol_id(1) + sender_public_key(32) + ephemeral_public_key(32) + nonce(12)`
pub const STANDARD_V2_AAD_LEN: usize = 78;

/// Length of the PSK v2 AAD: the metadata prefix of the PSK header.
///
/// `version(1) + protocol_id(1) + ratchet_counter(4) + sender_public_key(32)`
/// `+ ephemeral_public_key(32) + nonce(12)`
pub const PSK_V2_AAD_LEN: usize = 82;

/// Size of the envelope header in bytes.
pub const HEADER_SIZE: usize = 126;

/// Size of the authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of the encrypted sender key (32-byte key + 16-byte tag).
pub const ENCRYPTED_SENDER_KEY_SIZE: usize = 48;

/// Algorand note ceiling in bytes. A 4097-byte note is rejected.
pub const MAX_NOTE_SIZE: usize = 4096;

/// Note bytes included in one minimum fee before the surcharge starts.
const NOTE_FEE_INCLUDED_BYTES: usize = 1024;

/// Maximum standard plaintext size in bytes.
///
/// The header stays 126 bytes and the Poly1305 tag stays 16, so this is 3954.
pub const MAX_PAYLOAD_SIZE: usize = MAX_NOTE_SIZE - HEADER_SIZE - TAG_SIZE;

/// Size of the nonce in bytes.
pub const NONCE_SIZE: usize = 12;

/// Size of a public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Key derivation salt.
pub const KEY_DERIVATION_SALT: &[u8] = b"AlgoChat-v1-encryption";

/// Key derivation info.
pub const KEY_DERIVATION_INFO: &[u8] = b"x25519-key";

/// Encryption info prefix for message encryption.
pub const ENCRYPTION_INFO_PREFIX: &[u8] = b"AlgoChatV1";

/// Sender key info prefix for bidirectional decryption.
pub const SENDER_KEY_INFO_PREFIX: &[u8] = b"AlgoChatV1-SenderKey";

/// Decrypted message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedContent {
    /// The message text.
    pub text: String,
    /// Transaction ID this message replies to, if any.
    pub reply_to_id: Option<String>,
    /// Preview of the replied message, if any.
    pub reply_to_preview: Option<String>,
}

impl DecryptedContent {
    /// Create a new DecryptedContent with just text.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            reply_to_id: None,
            reply_to_preview: None,
        }
    }
}

/// Errors that can occur during AlgoChat operations.
#[derive(Error, Debug)]
pub enum AlgoChatError {
    // Encryption Errors
    /// Invalid seed length.
    #[error("Invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// Message too large.
    #[error("Message too large: {0} bytes (max {MAX_PAYLOAD_SIZE})")]
    MessageTooLarge(usize),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption failed.
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Failed to encode message as UTF-8.
    #[error("Encoding failed: {0}")]
    EncodingError(String),

    /// Failed to generate secure random bytes.
    #[error("Random generation failed")]
    RandomGenerationFailed,

    /// Invalid public key format.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Could not derive encryption keys.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Signature verification failed.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    // Envelope Errors
    /// Invalid envelope data.
    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// Unknown protocol version.
    #[error("Unknown protocol version: {0}")]
    UnknownVersion(u8),

    /// Unknown protocol ID.
    #[error("Unknown protocol ID: {0}")]
    UnknownProtocolId(u8),

    // Network Errors
    /// Indexer is not configured.
    #[error("Indexer not configured")]
    IndexerNotConfigured,

    /// Could not find public key for address.
    #[error("Public key not found for address: {0}")]
    PublicKeyNotFound(String),

    /// Invalid recipient address.
    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    // Transaction Errors
    /// Transaction failed.
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    /// Note exceeds the Algorand note ceiling.
    #[error("Note is {0} bytes (max {MAX_NOTE_SIZE})")]
    NoteTooLarge(usize),

    /// Insufficient balance.
    #[error("Insufficient balance: need {required} microAlgos, have {available}")]
    InsufficientBalance { required: u64, available: u64 },

    // Storage Errors
    /// Key not found in storage.
    #[error("Key not found for address: {0}")]
    KeyNotFound(String),

    /// Storage operation failed.
    #[error("Storage failed: {0}")]
    StorageFailed(String),

    // Queue Errors
    /// Message not found in queue.
    #[error("Message not found: {0}")]
    MessageNotFound(String),
}

pub type Result<T> = std::result::Result<T, AlgoChatError>;

/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Minimum payment amount in microAlgos (0.001 ALGO).
pub const MINIMUM_PAYMENT: u64 = 1000;

/// Returns the microAlgo fee for a payment that carries a note.
///
/// The first 1024 bytes cost one minimum fee. Each byte past 1024 adds one
/// ten-thousandth of `min_fee`, rounded up once. This crate has no Falcon
/// signer, so the scheme component is one minimum fee and the note surcharge
/// is added on top.
///
/// # Errors
///
/// Returns [`AlgoChatError::NoteTooLarge`] when `note_size` exceeds
/// [`MAX_NOTE_SIZE`]. Returns [`AlgoChatError::TransactionFailed`] when the
/// computed fee does not fit in a `u64`.
pub fn payment_fee(note_size: usize, min_fee: u64) -> Result<u64> {
    if note_size > MAX_NOTE_SIZE {
        return Err(AlgoChatError::NoteTooLarge(note_size));
    }

    // Bound by MAX_NOTE_SIZE above, so this widening cast cannot truncate.
    // (over * min_fee + 9999) / 10000 rounds the per-byte surcharge up once.
    let over = note_size.saturating_sub(NOTE_FEE_INCLUDED_BYTES) as u128;
    let surcharge = (over * u128::from(min_fee)).div_ceil(10_000);
    let fee = u128::from(min_fee) + surcharge;
    u64::try_from(fee).map_err(|_| {
        AlgoChatError::TransactionFailed("Payment fee does not fit in u64".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_fees_at_min_fee_1000() {
        assert_eq!(payment_fee(1024, 1000).unwrap(), 1000);
        assert_eq!(payment_fee(2000, 1000).unwrap(), 1098);
        assert_eq!(payment_fee(4096, 1000).unwrap(), 1308);
    }

    #[test]
    fn test_payment_fee_rejects_note_past_ceiling() {
        assert!(matches!(
            payment_fee(MAX_NOTE_SIZE + 1, 1000),
            Err(AlgoChatError::NoteTooLarge(_))
        ));
    }
}
