//! Type definitions and protocol constants for AlgoChat.

use thiserror::Error;

/// Protocol version byte.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Protocol ID byte.
pub const PROTOCOL_ID: u8 = 0x01;

/// Size of the envelope header in bytes.
pub const HEADER_SIZE: usize = 126;

/// Size of the authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of the encrypted sender key (32-byte key + 16-byte tag).
pub const ENCRYPTED_SENDER_KEY_SIZE: usize = 48;

/// Maximum payload size in bytes.
pub const MAX_PAYLOAD_SIZE: usize = 882;

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
    /// Invalid seed length.
    #[error("Invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// Message too large.
    #[error("Message too large: {0} bytes (max {MAX_PAYLOAD_SIZE})")]
    MessageTooLarge(usize),

    /// Invalid envelope data.
    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption failed.
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Unknown protocol version.
    #[error("Unknown protocol version: {0}")]
    UnknownVersion(u8),

    /// Unknown protocol ID.
    #[error("Unknown protocol ID: {0}")]
    UnknownProtocolId(u8),
}

pub type Result<T> = std::result::Result<T, AlgoChatError>;
