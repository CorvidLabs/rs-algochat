//! Type definitions and constants for the PSK (Pre-Shared Key) protocol v1.1.
//!
//! The PSK protocol extends AlgoChat with a shared secret ratchet,
//! providing forward secrecy and additional authentication beyond ECDH.

/// PSK protocol version byte.
pub const PSK_VERSION: u8 = 0x01;

/// PSK protocol ID byte (0x02 distinguishes from standard 0x01).
pub const PSK_PROTOCOL_ID: u8 = 0x02;

/// Size of the PSK envelope header in bytes.
///
/// Layout: version(1) + protocolId(1) + ratchetCounter(4) + senderPublicKey(32)
///       + ephemeralPublicKey(32) + nonce(12) + encryptedSenderKey(48) = 130
pub const PSK_HEADER_SIZE: usize = 130;

/// Size of the authentication tag in bytes.
pub const PSK_TAG_SIZE: usize = 16;

/// Size of the encrypted sender key (32-byte key + 16-byte tag).
pub const PSK_ENCRYPTED_SENDER_KEY_SIZE: usize = 48;

/// Maximum payload size in bytes for PSK messages.
pub const PSK_MAX_PAYLOAD_SIZE: usize = 878;

/// Number of positions in a single session before rotating.
pub const PSK_SESSION_SIZE: u32 = 100;

/// Counter window for replay protection.
pub const PSK_COUNTER_WINDOW: u32 = 200;

/// PSK message envelope containing all fields for a PSK-encrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PSKEnvelope {
    /// Ratchet counter value used to derive the PSK for this message.
    pub ratchet_counter: u32,
    /// Sender's X25519 public key (32 bytes).
    pub sender_public_key: [u8; 32],
    /// Ephemeral X25519 public key (32 bytes).
    pub ephemeral_public_key: [u8; 32],
    /// Nonce for encryption (12 bytes).
    pub nonce: [u8; 12],
    /// Encrypted symmetric key for sender decryption (48 bytes).
    pub encrypted_sender_key: Vec<u8>,
    /// Encrypted message ciphertext (variable length).
    pub ciphertext: Vec<u8>,
}
