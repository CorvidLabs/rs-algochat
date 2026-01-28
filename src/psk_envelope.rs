//! Envelope encoding and decoding for the PSK protocol.
//!
//! Wire format (130-byte header + variable ciphertext):
//! - \[0\]:      version (0x01)
//! - \[1\]:      protocolId (0x02)
//! - \[2..6\]:   ratchetCounter (4 bytes, big-endian u32)
//! - \[6..38\]:  senderPublicKey (32 bytes)
//! - \[38..70\]: ephemeralPublicKey (32 bytes)
//! - \[70..82\]: nonce (12 bytes)
//! - \[82..130\]: encryptedSenderKey (48 bytes)
//! - \[130..\]: ciphertext + 16-byte authentication tag

use crate::psk_types::{
    PSKEnvelope, PSK_ENCRYPTED_SENDER_KEY_SIZE, PSK_HEADER_SIZE, PSK_PROTOCOL_ID, PSK_VERSION,
};
use crate::types::{AlgoChatError, Result, NONCE_SIZE, PUBLIC_KEY_SIZE};

/// Encodes a PSK envelope to bytes.
///
/// # Arguments
/// * `envelope` - The PSK envelope to encode
///
/// # Returns
/// A byte vector containing the encoded envelope
pub fn encode_psk_envelope(envelope: &PSKEnvelope) -> Vec<u8> {
    let mut data = Vec::with_capacity(PSK_HEADER_SIZE + envelope.ciphertext.len());
    data.push(PSK_VERSION);
    data.push(PSK_PROTOCOL_ID);
    data.extend_from_slice(&envelope.ratchet_counter.to_be_bytes());
    data.extend_from_slice(&envelope.sender_public_key);
    data.extend_from_slice(&envelope.ephemeral_public_key);
    data.extend_from_slice(&envelope.nonce);
    data.extend_from_slice(&envelope.encrypted_sender_key);
    data.extend_from_slice(&envelope.ciphertext);
    data
}

/// Decodes bytes into a PSK envelope.
///
/// # Arguments
/// * `data` - The raw bytes to decode
///
/// # Returns
/// A PSKEnvelope if the data is valid
pub fn decode_psk_envelope(data: &[u8]) -> Result<PSKEnvelope> {
    if data.len() < PSK_HEADER_SIZE {
        return Err(AlgoChatError::InvalidEnvelope(format!(
            "PSK data too short: {} bytes (minimum {})",
            data.len(),
            PSK_HEADER_SIZE
        )));
    }

    let version = data[0];
    let protocol_id = data[1];

    if version != PSK_VERSION {
        return Err(AlgoChatError::UnknownVersion(version));
    }

    if protocol_id != PSK_PROTOCOL_ID {
        return Err(AlgoChatError::UnknownProtocolId(protocol_id));
    }

    let mut offset = 2;

    // Ratchet counter (4 bytes, big-endian)
    let ratchet_counter = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    let mut sender_public_key = [0u8; 32];
    sender_public_key.copy_from_slice(&data[offset..offset + PUBLIC_KEY_SIZE]);
    offset += PUBLIC_KEY_SIZE;

    let mut ephemeral_public_key = [0u8; 32];
    ephemeral_public_key.copy_from_slice(&data[offset..offset + PUBLIC_KEY_SIZE]);
    offset += PUBLIC_KEY_SIZE;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[offset..offset + NONCE_SIZE]);
    offset += NONCE_SIZE;

    let encrypted_sender_key = data[offset..offset + PSK_ENCRYPTED_SENDER_KEY_SIZE].to_vec();
    offset += PSK_ENCRYPTED_SENDER_KEY_SIZE;

    let ciphertext = data[offset..].to_vec();

    Ok(PSKEnvelope {
        ratchet_counter,
        sender_public_key,
        ephemeral_public_key,
        nonce,
        encrypted_sender_key,
        ciphertext,
    })
}

/// Checks if data looks like a valid PSK message.
///
/// # Arguments
/// * `data` - The raw bytes to check
///
/// # Returns
/// `true` if the data has the correct version and protocol ID for PSK
pub fn is_psk_message(data: &[u8]) -> bool {
    if data.len() < PSK_HEADER_SIZE {
        return false;
    }
    data[0] == PSK_VERSION && data[1] == PSK_PROTOCOL_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let envelope = PSKEnvelope {
            ratchet_counter: 42,
            sender_public_key: [1u8; 32],
            ephemeral_public_key: [2u8; 32],
            nonce: [3u8; 12],
            encrypted_sender_key: vec![4u8; 48],
            ciphertext: vec![5u8; 64],
        };

        let encoded = encode_psk_envelope(&envelope);
        assert_eq!(encoded.len(), PSK_HEADER_SIZE + 64);

        let decoded = decode_psk_envelope(&encoded).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn test_ratchet_counter_encoding() {
        let envelope = PSKEnvelope {
            ratchet_counter: 0x01020304,
            sender_public_key: [0u8; 32],
            ephemeral_public_key: [0u8; 32],
            nonce: [0u8; 12],
            encrypted_sender_key: vec![0u8; 48],
            ciphertext: vec![0u8; 16],
        };

        let encoded = encode_psk_envelope(&envelope);
        assert_eq!(encoded[2], 0x01);
        assert_eq!(encoded[3], 0x02);
        assert_eq!(encoded[4], 0x03);
        assert_eq!(encoded[5], 0x04);

        let decoded = decode_psk_envelope(&encoded).unwrap();
        assert_eq!(decoded.ratchet_counter, 0x01020304);
    }

    #[test]
    fn test_is_psk_message() {
        let mut valid = vec![PSK_VERSION, PSK_PROTOCOL_ID];
        valid.extend(vec![0u8; PSK_HEADER_SIZE - 2]);
        assert!(is_psk_message(&valid));

        let mut standard = vec![0x01, 0x01];
        standard.extend(vec![0u8; PSK_HEADER_SIZE - 2]);
        assert!(!is_psk_message(&standard));

        assert!(!is_psk_message(&[PSK_VERSION, PSK_PROTOCOL_ID]));
        assert!(!is_psk_message(&[]));
    }

    #[test]
    fn test_decode_too_short() {
        let result = decode_psk_envelope(&[PSK_VERSION, PSK_PROTOCOL_ID]);
        assert!(matches!(result, Err(AlgoChatError::InvalidEnvelope(_))));
    }

    #[test]
    fn test_decode_wrong_version() {
        let mut data = vec![0u8; PSK_HEADER_SIZE + 16];
        data[0] = 0x02;
        data[1] = PSK_PROTOCOL_ID;
        let result = decode_psk_envelope(&data);
        assert!(matches!(result, Err(AlgoChatError::UnknownVersion(0x02))));
    }

    #[test]
    fn test_decode_wrong_protocol_id() {
        let mut data = vec![0u8; PSK_HEADER_SIZE + 16];
        data[0] = PSK_VERSION;
        data[1] = 0x01;
        let result = decode_psk_envelope(&data);
        assert!(matches!(
            result,
            Err(AlgoChatError::UnknownProtocolId(0x01))
        ));
    }

    #[test]
    fn test_zero_counter() {
        let envelope = PSKEnvelope {
            ratchet_counter: 0,
            sender_public_key: [0u8; 32],
            ephemeral_public_key: [0u8; 32],
            nonce: [0u8; 12],
            encrypted_sender_key: vec![0u8; 48],
            ciphertext: vec![0u8; 16],
        };
        let encoded = encode_psk_envelope(&envelope);
        let decoded = decode_psk_envelope(&encoded).unwrap();
        assert_eq!(decoded.ratchet_counter, 0);
    }

    #[test]
    fn test_max_counter() {
        let envelope = PSKEnvelope {
            ratchet_counter: u32::MAX,
            sender_public_key: [0u8; 32],
            ephemeral_public_key: [0u8; 32],
            nonce: [0u8; 12],
            encrypted_sender_key: vec![0u8; 48],
            ciphertext: vec![0u8; 16],
        };
        let encoded = encode_psk_envelope(&envelope);
        let decoded = decode_psk_envelope(&encoded).unwrap();
        assert_eq!(decoded.ratchet_counter, u32::MAX);
    }
}
