//! Type definitions and constants for the PSK (Pre-Shared Key) protocol v1.1.
//!
//! The PSK protocol extends AlgoChat with a shared secret ratchet,
//! providing forward secrecy and additional authentication beyond ECDH.

/// PSK protocol version byte.
pub const PSK_VERSION: u8 = 0x01;

/// PSK protocol version byte for v2 (AEAD header binding).
///
/// Wire-identical to PSK v1 except the leading version byte is `0x02` and both
/// AEAD operations bind the PSK header metadata prefix as Associated Data.
/// See proposal 0001.
pub const PSK_VERSION_V2: u8 = 0x02;

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
    /// Protocol version byte (`0x01` = v1 no AAD, `0x02` = v2 header AAD).
    pub version: u8,
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

impl PSKEnvelope {
    /// Build the v2 AEAD Associated Data (the PSK header metadata prefix).
    ///
    /// This is `bytes[0..82)` of the encoded header:
    /// `version ‖ protocol_id ‖ ratchet_counter(be) ‖ sender_public_key`
    /// `‖ ephemeral_public_key ‖ nonce`. Both AEAD operations of a v2 PSK
    /// envelope authenticate this same AAD.
    pub fn v2_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(crate::types::PSK_V2_AAD_LEN);
        aad.push(self.version);
        aad.push(PSK_PROTOCOL_ID);
        aad.extend_from_slice(&self.ratchet_counter.to_be_bytes());
        aad.extend_from_slice(&self.sender_public_key);
        aad.extend_from_slice(&self.ephemeral_public_key);
        aad.extend_from_slice(&self.nonce);
        aad
    }
}
