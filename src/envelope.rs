//! Envelope encoding and decoding for AlgoChat protocol.

use crate::types::{
    AlgoChatError, Result, ENCRYPTED_SENDER_KEY_SIZE, HEADER_SIZE, NONCE_SIZE, PROTOCOL_ID,
    PROTOCOL_VERSION, PROTOCOL_VERSION_V2, PUBLIC_KEY_SIZE, STANDARD_V2_AAD_LEN,
};

/// AlgoChat message envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatEnvelope {
    /// Protocol version.
    pub version: u8,
    /// Protocol ID.
    pub protocol_id: u8,
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

impl ChatEnvelope {
    /// Encode the envelope to bytes.
    ///
    /// Format (126-byte header + ciphertext):
    /// - [0]      version (0x01)
    /// - [1]      protocolId (0x01)
    /// - [2-33]   senderPublicKey (32 bytes)
    /// - [34-65]  ephemeralPublicKey (32 bytes)
    /// - [66-77]  nonce (12 bytes)
    /// - [78-125] encryptedSenderKey (48 bytes)
    /// - [126+]   ciphertext (variable)
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len());
        data.push(self.version);
        data.push(self.protocol_id);
        data.extend_from_slice(&self.sender_public_key);
        data.extend_from_slice(&self.ephemeral_public_key);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.encrypted_sender_key);
        data.extend_from_slice(&self.ciphertext);
        data
    }

    /// Build the v2 AEAD Associated Data (the header metadata prefix).
    ///
    /// This is `bytes[0..78)` of the encoded header:
    /// `version ‖ protocol_id ‖ sender_public_key ‖ ephemeral_public_key ‖ nonce`.
    /// Both AEAD operations of a v2 envelope authenticate this same AAD.
    pub fn v2_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(STANDARD_V2_AAD_LEN);
        aad.push(self.version);
        aad.push(self.protocol_id);
        aad.extend_from_slice(&self.sender_public_key);
        aad.extend_from_slice(&self.ephemeral_public_key);
        aad.extend_from_slice(&self.nonce);
        aad
    }

    /// Decode bytes into an envelope.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(AlgoChatError::InvalidEnvelope(format!(
                "Data too short: {} bytes (minimum {})",
                data.len(),
                HEADER_SIZE
            )));
        }

        let version = data[0];
        let protocol_id = data[1];

        if version != PROTOCOL_VERSION && version != PROTOCOL_VERSION_V2 {
            return Err(AlgoChatError::UnknownVersion(version));
        }

        if protocol_id != PROTOCOL_ID {
            return Err(AlgoChatError::UnknownProtocolId(protocol_id));
        }

        let mut offset = 2;

        let mut sender_public_key = [0u8; 32];
        sender_public_key.copy_from_slice(&data[offset..offset + PUBLIC_KEY_SIZE]);
        offset += PUBLIC_KEY_SIZE;

        let mut ephemeral_public_key = [0u8; 32];
        ephemeral_public_key.copy_from_slice(&data[offset..offset + PUBLIC_KEY_SIZE]);
        offset += PUBLIC_KEY_SIZE;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        let encrypted_sender_key = data[offset..offset + ENCRYPTED_SENDER_KEY_SIZE].to_vec();
        offset += ENCRYPTED_SENDER_KEY_SIZE;

        let ciphertext = data[offset..].to_vec();

        Ok(Self {
            version,
            protocol_id,
            sender_public_key,
            ephemeral_public_key,
            nonce,
            encrypted_sender_key,
            ciphertext,
        })
    }
}

/// Check if data looks like a valid AlgoChat envelope.
///
/// Accepts both protocol version `0x01` (v1, no AAD) and `0x02` (v2, header AAD).
pub fn is_chat_message(data: &[u8]) -> bool {
    if data.len() < HEADER_SIZE {
        return false;
    }
    (data[0] == PROTOCOL_VERSION || data[0] == PROTOCOL_VERSION_V2) && data[1] == PROTOCOL_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let envelope = ChatEnvelope {
            version: PROTOCOL_VERSION,
            protocol_id: PROTOCOL_ID,
            sender_public_key: [1u8; 32],
            ephemeral_public_key: [2u8; 32],
            nonce: [3u8; 12],
            encrypted_sender_key: vec![4u8; 48],
            ciphertext: vec![5u8; 32],
        };

        let encoded = envelope.encode();
        assert_eq!(encoded.len(), HEADER_SIZE + 32);

        let decoded = ChatEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn test_is_chat_message() {
        let valid = vec![PROTOCOL_VERSION, PROTOCOL_ID];
        let mut padded = valid.clone();
        padded.extend(vec![0u8; HEADER_SIZE - 2]);

        assert!(is_chat_message(&padded));
        assert!(!is_chat_message(&[0x00, 0x01]));
        assert!(!is_chat_message(&[0x01, 0x00]));
        assert!(!is_chat_message(&[]));
    }

    #[test]
    fn test_decode_too_short() {
        let result = ChatEnvelope::decode(&[0x01, 0x01]);
        assert!(matches!(result, Err(AlgoChatError::InvalidEnvelope(_))));
    }

    #[test]
    fn test_decode_wrong_version() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0] = 0x03;
        data[1] = PROTOCOL_ID;
        let result = ChatEnvelope::decode(&data);
        assert!(matches!(result, Err(AlgoChatError::UnknownVersion(0x03))));
    }

    #[test]
    fn test_decode_v2_version_accepted() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0] = PROTOCOL_VERSION_V2;
        data[1] = PROTOCOL_ID;
        let decoded = ChatEnvelope::decode(&data).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION_V2);
    }

    #[test]
    fn test_is_chat_message_accepts_v2() {
        let mut data = vec![PROTOCOL_VERSION_V2, PROTOCOL_ID];
        data.extend(vec![0u8; HEADER_SIZE - 2]);
        assert!(is_chat_message(&data));
    }

    #[test]
    fn test_v2_aad_layout() {
        let envelope = ChatEnvelope {
            version: PROTOCOL_VERSION_V2,
            protocol_id: PROTOCOL_ID,
            sender_public_key: [1u8; 32],
            ephemeral_public_key: [2u8; 32],
            nonce: [3u8; 12],
            encrypted_sender_key: vec![4u8; 48],
            ciphertext: vec![5u8; 32],
        };
        let aad = envelope.v2_aad();
        assert_eq!(aad.len(), 78);
        // The AAD must equal the first 78 bytes of the encoded envelope.
        assert_eq!(&aad[..], &envelope.encode()[..78]);
    }
}
