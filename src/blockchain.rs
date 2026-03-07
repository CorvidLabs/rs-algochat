//! Blockchain interfaces for Algorand integration.
//!
//! This module provides traits for interacting with Algorand nodes (algod)
//! and indexers. Implementations can use any Algorand SDK.

use crate::models::DiscoveredKey;
use crate::types::Result;

/// Configuration for Algorand node connections.
#[derive(Debug, Clone)]
pub struct AlgorandConfig {
    /// Algod node URL.
    pub algod_url: String,
    /// Algod API token.
    pub algod_token: String,
    /// Indexer URL (optional).
    pub indexer_url: Option<String>,
    /// Indexer API token (optional).
    pub indexer_token: Option<String>,
}

impl AlgorandConfig {
    /// Creates a new configuration for connecting to Algorand nodes.
    pub fn new(algod_url: &str, algod_token: &str) -> Self {
        Self {
            algod_url: algod_url.to_string(),
            algod_token: algod_token.to_string(),
            indexer_url: None,
            indexer_token: None,
        }
    }

    /// Sets the indexer configuration.
    pub fn with_indexer(mut self, url: &str, token: &str) -> Self {
        self.indexer_url = Some(url.to_string());
        self.indexer_token = Some(token.to_string());
        self
    }

    /// Creates configuration for LocalNet (Algokit sandbox).
    pub fn localnet() -> Self {
        Self {
            algod_url: "http://localhost:4001".to_string(),
            algod_token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            indexer_url: Some("http://localhost:8980".to_string()),
            indexer_token: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        }
    }

    /// Creates configuration for TestNet (via Nodely).
    pub fn testnet() -> Self {
        Self {
            algod_url: "https://testnet-api.4160.nodely.dev".to_string(),
            algod_token: String::new(),
            indexer_url: Some("https://testnet-idx.4160.nodely.dev".to_string()),
            indexer_token: Some(String::new()),
        }
    }

    /// Creates configuration for MainNet (via Nodely).
    pub fn mainnet() -> Self {
        Self {
            algod_url: "https://mainnet-api.4160.nodely.dev".to_string(),
            algod_token: String::new(),
            indexer_url: Some("https://mainnet-idx.4160.nodely.dev".to_string()),
            indexer_token: Some(String::new()),
        }
    }
}

/// Transaction information returned after submission.
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    /// Transaction ID.
    pub txid: String,
    /// Round in which the transaction was confirmed (if confirmed).
    pub confirmed_round: Option<u64>,
}

/// A note field transaction from the blockchain.
#[derive(Debug, Clone)]
pub struct NoteTransaction {
    /// Transaction ID.
    pub txid: String,
    /// Sender address.
    pub sender: String,
    /// Receiver address.
    pub receiver: String,
    /// Note field contents.
    pub note: Vec<u8>,
    /// Round in which the transaction was confirmed.
    pub confirmed_round: u64,
    /// Timestamp of the block (Unix time).
    pub round_time: u64,
}

/// Trait for interacting with an Algorand node (algod).
#[async_trait::async_trait]
pub trait AlgodClient: Send + Sync {
    /// Get the current network parameters.
    async fn get_suggested_params(&self) -> Result<SuggestedParams>;

    /// Get account information.
    async fn get_account_info(&self, address: &str) -> Result<AccountInfo>;

    /// Submit a signed transaction.
    async fn submit_transaction(&self, signed_txn: &[u8]) -> Result<String>;

    /// Wait for a transaction to be confirmed.
    async fn wait_for_confirmation(&self, txid: &str, rounds: u32) -> Result<TransactionInfo>;

    /// Get the current round.
    async fn get_current_round(&self) -> Result<u64>;
}

/// Suggested transaction parameters.
#[derive(Debug, Clone)]
pub struct SuggestedParams {
    /// Fee per byte in microAlgos.
    pub fee: u64,
    /// Minimum fee in microAlgos.
    pub min_fee: u64,
    /// First valid round.
    pub first_valid: u64,
    /// Last valid round.
    pub last_valid: u64,
    /// Genesis ID.
    pub genesis_id: String,
    /// Genesis hash.
    pub genesis_hash: [u8; 32],
}

/// Account information.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// Account address.
    pub address: String,
    /// Account balance in microAlgos.
    pub amount: u64,
    /// Minimum balance required.
    pub min_balance: u64,
}

/// Trait for interacting with an Algorand indexer.
#[async_trait::async_trait]
pub trait IndexerClient: Send + Sync {
    /// Search for transactions with notes sent to/from an address.
    async fn search_transactions(
        &self,
        address: &str,
        after_round: Option<u64>,
        limit: Option<u32>,
    ) -> Result<Vec<NoteTransaction>>;

    /// Search for transactions between two addresses.
    async fn search_transactions_between(
        &self,
        address1: &str,
        address2: &str,
        after_round: Option<u64>,
        limit: Option<u32>,
    ) -> Result<Vec<NoteTransaction>>;

    /// Get a specific transaction by ID.
    async fn get_transaction(&self, txid: &str) -> Result<NoteTransaction>;

    /// Wait for a transaction to be indexed.
    async fn wait_for_indexer(&self, txid: &str, timeout_secs: u32) -> Result<NoteTransaction>;
}

/// Discovers the encryption public key for an Algorand address.
///
/// This searches the indexer for key announcement transactions from the address.
/// The key is considered verified if it was signed by the address's Ed25519 key.
pub async fn discover_encryption_key(
    indexer: &dyn IndexerClient,
    address: &str,
) -> Result<Option<DiscoveredKey>> {
    // Search for transactions from this address
    let transactions = indexer
        .search_transactions(address, None, Some(100))
        .await?;

    // Look for key announcements in the note field
    for tx in transactions {
        if tx.sender != address {
            continue;
        }

        // Check if this is a key announcement (self-transfer with note)
        if tx.receiver != address {
            continue;
        }

        // Try to parse as key announcement
        if let Some(key) = parse_key_announcement(&tx.note, address) {
            return Ok(Some(key));
        }
    }

    Ok(None)
}

/// Decodes an Algorand address to extract the 32-byte Ed25519 public key.
///
/// Algorand addresses are base32-encoded (no padding) and contain:
/// - 32 bytes: Ed25519 public key
/// - 4 bytes: checksum (last 4 bytes of SHA-512/256 of the public key)
///
/// Returns `None` if the address is malformed or the checksum doesn't match.
fn decode_algorand_address(address: &str) -> Option<[u8; 32]> {
    let decoded = data_encoding::BASE32_NOPAD
        .decode(address.as_bytes())
        .ok()?;
    if decoded.len() != 36 {
        return None;
    }
    let public_key = &decoded[..32];
    let checksum = &decoded[32..36];

    // Verify checksum: last 4 bytes of SHA-512/256(public_key)
    use sha2::Digest;
    let hash = sha2::Sha512_256::digest(public_key);
    if checksum != &hash[hash.len() - 4..] {
        return None;
    }

    let mut ed25519_public_key = [0u8; 32];
    ed25519_public_key.copy_from_slice(public_key);
    Some(ed25519_public_key)
}

/// Parses a key announcement from a transaction note.
fn parse_key_announcement(note: &[u8], address: &str) -> Option<DiscoveredKey> {
    // Key announcement format:
    // - 32 bytes: X25519 public key
    // - 64 bytes (optional): Ed25519 signature

    if note.len() < 32 {
        return None;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&note[..32]);

    let is_verified = if note.len() >= 96 {
        // Has signature, verify it using the Ed25519 public key from the Algorand address
        let signature = &note[32..96];
        match decode_algorand_address(address) {
            Some(ed25519_key) => {
                crate::signature::verify_encryption_key_bytes(&public_key, &ed25519_key, signature)
                    .unwrap_or(false)
            }
            None => false,
        }
    } else {
        false
    };

    Some(DiscoveredKey {
        public_key,
        is_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_localnet() {
        let config = AlgorandConfig::localnet();
        assert!(config.algod_url.contains("localhost"));
        assert!(config.indexer_url.is_some());
    }

    #[test]
    fn test_config_testnet() {
        let config = AlgorandConfig::testnet();
        assert!(config.algod_url.contains("testnet"));
    }

    #[test]
    fn test_config_mainnet() {
        let config = AlgorandConfig::mainnet();
        assert!(config.algod_url.contains("mainnet"));
    }

    #[test]
    fn test_config_with_indexer() {
        let config = AlgorandConfig::new("http://localhost:4001", "token123")
            .with_indexer("http://localhost:8980", "idx-token");
        assert_eq!(config.algod_url, "http://localhost:4001");
        assert_eq!(config.algod_token, "token123");
        assert_eq!(
            config.indexer_url,
            Some("http://localhost:8980".to_string())
        );
        assert_eq!(config.indexer_token, Some("idx-token".to_string()));
    }

    #[test]
    fn test_decode_algorand_address_valid() {
        // A valid Algorand address (base32-encoded, 58 chars, 36 bytes decoded)
        // Generate one: 32 bytes pubkey + 4 bytes checksum
        let pubkey = [0u8; 32];
        use sha2::Digest;
        let hash = sha2::Sha512_256::digest(pubkey);
        let checksum = &hash[hash.len() - 4..];
        let mut full = Vec::with_capacity(36);
        full.extend_from_slice(&pubkey);
        full.extend_from_slice(checksum);
        let address = data_encoding::BASE32_NOPAD.encode(&full);

        let decoded = decode_algorand_address(&address);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), pubkey);
    }

    #[test]
    fn test_decode_algorand_address_bad_checksum() {
        // Build an address with correct length but wrong checksum
        let pubkey = [1u8; 32];
        let bad_checksum = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut full = Vec::with_capacity(36);
        full.extend_from_slice(&pubkey);
        full.extend_from_slice(&bad_checksum);
        let address = data_encoding::BASE32_NOPAD.encode(&full);

        let result = decode_algorand_address(&address);
        assert!(result.is_none(), "bad checksum should be rejected");
    }

    #[test]
    fn test_decode_algorand_address_too_short() {
        let result = decode_algorand_address("AAAA");
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_algorand_address_invalid_base32() {
        let result = decode_algorand_address("not-valid-base32!!!");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_key_announcement_too_short() {
        let note = [0u8; 16]; // Less than 32 bytes
        let result = parse_key_announcement(&note, "SOMEADDR");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_key_announcement_valid_unsigned() {
        let mut note = [0u8; 32];
        note[0] = 0x42; // Some key data
        let result = parse_key_announcement(&note, "SOMEADDR");
        assert!(result.is_some());
        let key = result.unwrap();
        assert_eq!(key.public_key[0], 0x42);
        assert!(!key.is_verified); // No signature, so not verified
    }

    #[test]
    fn test_parse_key_announcement_with_bad_signature() {
        // 32 bytes key + 64 bytes bad signature = 96 bytes
        let note = [0u8; 96];
        // Use a valid-looking address (we'll use zeros which decode to a valid key)
        let pubkey = [0u8; 32];
        use sha2::Digest;
        let hash = sha2::Sha512_256::digest(pubkey);
        let checksum = &hash[hash.len() - 4..];
        let mut full = Vec::with_capacity(36);
        full.extend_from_slice(&pubkey);
        full.extend_from_slice(checksum);
        let address = data_encoding::BASE32_NOPAD.encode(&full);

        let result = parse_key_announcement(&note, &address);
        assert!(result.is_some());
        let key = result.unwrap();
        // Bad signature should result in unverified
        assert!(!key.is_verified);
    }

    #[test]
    fn test_transaction_info_debug() {
        let info = TransactionInfo {
            txid: "TXID123".to_string(),
            confirmed_round: Some(1000),
        };
        let debug = format!("{:?}", info);
        assert!(debug.contains("TXID123"));
    }

    #[test]
    fn test_note_transaction_clone() {
        let tx = NoteTransaction {
            txid: "TX1".to_string(),
            sender: "SENDER".to_string(),
            receiver: "RECEIVER".to_string(),
            note: vec![1, 2, 3],
            confirmed_round: 100,
            round_time: 1234567890,
        };
        let cloned = tx.clone();
        assert_eq!(cloned.txid, tx.txid);
        assert_eq!(cloned.note, tx.note);
    }

    #[test]
    fn test_parse_key_announcement_with_valid_signature() {
        use ed25519_dalek::{Signer, SigningKey};

        // Create an Ed25519 keypair
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let ed25519_pubkey = signing_key.verifying_key().to_bytes();

        // Build a valid Algorand address from this Ed25519 public key
        use sha2::Digest;
        let hash = sha2::Sha512_256::digest(ed25519_pubkey);
        let checksum = &hash[hash.len() - 4..];
        let mut addr_bytes = Vec::with_capacity(36);
        addr_bytes.extend_from_slice(&ed25519_pubkey);
        addr_bytes.extend_from_slice(checksum);
        let address = data_encoding::BASE32_NOPAD.encode(&addr_bytes);

        // Create an X25519 encryption key and sign it
        let encryption_key = [0xABu8; 32];
        let signature = signing_key.sign(&encryption_key);

        // Build the note: 32 bytes key + 64 bytes signature
        let mut note = Vec::with_capacity(96);
        note.extend_from_slice(&encryption_key);
        note.extend_from_slice(&signature.to_bytes());

        let result = parse_key_announcement(&note, &address);
        assert!(result.is_some());
        let key = result.unwrap();
        assert_eq!(key.public_key, encryption_key);
        assert!(key.is_verified, "valid signature should be verified");
    }

    #[test]
    fn test_parse_key_announcement_wrong_signer() {
        use ed25519_dalek::{Signer, SigningKey};

        // Sign with one key but use a different key in the address
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let different_key = SigningKey::from_bytes(&[99u8; 32]);
        let different_pubkey = different_key.verifying_key().to_bytes();

        // Build address from the DIFFERENT key
        use sha2::Digest;
        let hash = sha2::Sha512_256::digest(different_pubkey);
        let checksum = &hash[hash.len() - 4..];
        let mut addr_bytes = Vec::with_capacity(36);
        addr_bytes.extend_from_slice(&different_pubkey);
        addr_bytes.extend_from_slice(checksum);
        let address = data_encoding::BASE32_NOPAD.encode(&addr_bytes);

        // Sign with the ORIGINAL key (mismatch)
        let encryption_key = [0xABu8; 32];
        let signature = signing_key.sign(&encryption_key);

        let mut note = Vec::with_capacity(96);
        note.extend_from_slice(&encryption_key);
        note.extend_from_slice(&signature.to_bytes());

        let result = parse_key_announcement(&note, &address);
        assert!(result.is_some());
        let key = result.unwrap();
        assert!(!key.is_verified, "wrong signer should not verify");
    }

    #[test]
    fn test_parse_key_announcement_exactly_32_bytes() {
        // Exactly 32 bytes (no signature)
        let note = [0x42u8; 32];
        let result = parse_key_announcement(&note, "SOMEADDR");
        assert!(result.is_some());
        assert!(!result.unwrap().is_verified);
    }

    #[test]
    fn test_parse_key_announcement_between_32_and_96_bytes() {
        // Between 32 and 96 bytes (partial, no valid signature)
        let note = [0x42u8; 64];
        let result = parse_key_announcement(&note, "SOMEADDR");
        assert!(result.is_some());
        assert!(!result.unwrap().is_verified);
    }

    #[test]
    fn test_parse_key_announcement_over_96_bytes() {
        // More than 96 bytes (has signature at correct position)
        let note = vec![0x42u8; 128];
        // First 32 bytes are the key, bytes 32..96 would be the signature
        // With garbage data, this should not verify
        let result = parse_key_announcement(&note, "SOMEADDR");
        assert!(result.is_some());
        assert!(!result.unwrap().is_verified);
    }

    #[test]
    fn test_decode_algorand_address_various_keys() {
        use sha2::Digest;

        // Test with several different key values
        for i in 0u8..5 {
            let pubkey = [i; 32];
            let hash = sha2::Sha512_256::digest(pubkey);
            let checksum = &hash[hash.len() - 4..];
            let mut full = Vec::with_capacity(36);
            full.extend_from_slice(&pubkey);
            full.extend_from_slice(checksum);
            let address = data_encoding::BASE32_NOPAD.encode(&full);

            let decoded = decode_algorand_address(&address);
            assert!(decoded.is_some(), "key {} should decode", i);
            assert_eq!(decoded.unwrap(), pubkey);
        }
    }

    /// Mock indexer for discover_encryption_key tests
    struct MockDiscoveryIndexer {
        transactions: Vec<NoteTransaction>,
    }

    #[async_trait::async_trait]
    impl IndexerClient for MockDiscoveryIndexer {
        async fn search_transactions(
            &self,
            address: &str,
            _after_round: Option<u64>,
            _limit: Option<u32>,
        ) -> crate::types::Result<Vec<NoteTransaction>> {
            Ok(self
                .transactions
                .iter()
                .filter(|tx| tx.sender == address || tx.receiver == address)
                .cloned()
                .collect())
        }

        async fn search_transactions_between(
            &self,
            _a1: &str,
            _a2: &str,
            _after_round: Option<u64>,
            _limit: Option<u32>,
        ) -> crate::types::Result<Vec<NoteTransaction>> {
            Ok(Vec::new())
        }

        async fn get_transaction(&self, _txid: &str) -> crate::types::Result<NoteTransaction> {
            Err(crate::types::AlgoChatError::TransactionFailed(
                "not found".to_string(),
            ))
        }

        async fn wait_for_indexer(
            &self,
            _txid: &str,
            _timeout: u32,
        ) -> crate::types::Result<NoteTransaction> {
            Err(crate::types::AlgoChatError::TransactionFailed(
                "not found".to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn test_discover_encryption_key_no_transactions() {
        let indexer = MockDiscoveryIndexer {
            transactions: Vec::new(),
        };
        let result = discover_encryption_key(&indexer, "SOMEADDR").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_discover_encryption_key_non_self_transfer() {
        let indexer = MockDiscoveryIndexer {
            transactions: vec![NoteTransaction {
                txid: "TX1".to_string(),
                sender: "ALICE".to_string(),
                receiver: "BOB".to_string(), // Not a self-transfer
                note: vec![0u8; 32],
                confirmed_round: 100,
                round_time: 1700000000,
            }],
        };
        let result = discover_encryption_key(&indexer, "ALICE").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_discover_encryption_key_valid_self_transfer() {
        let key = [0xABu8; 32];
        let address = "MYADDR";

        let indexer = MockDiscoveryIndexer {
            transactions: vec![NoteTransaction {
                txid: "TX1".to_string(),
                sender: address.to_string(),
                receiver: address.to_string(),
                note: key.to_vec(),
                confirmed_round: 100,
                round_time: 1700000000,
            }],
        };
        let result = discover_encryption_key(&indexer, address).await.unwrap();
        assert!(result.is_some());
        let discovered = result.unwrap();
        assert_eq!(discovered.public_key, key);
        assert!(!discovered.is_verified); // Invalid address format, so no signature check
    }

    #[tokio::test]
    async fn test_discover_encryption_key_with_signed_announcement() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::Digest;

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let ed25519_pubkey = signing_key.verifying_key().to_bytes();

        // Build valid Algorand address
        let hash = sha2::Sha512_256::digest(ed25519_pubkey);
        let checksum = &hash[hash.len() - 4..];
        let mut addr_bytes = Vec::with_capacity(36);
        addr_bytes.extend_from_slice(&ed25519_pubkey);
        addr_bytes.extend_from_slice(checksum);
        let address = data_encoding::BASE32_NOPAD.encode(&addr_bytes);

        // Create signed key announcement
        let encryption_key = [0xABu8; 32];
        let signature = signing_key.sign(&encryption_key);
        let mut note = Vec::with_capacity(96);
        note.extend_from_slice(&encryption_key);
        note.extend_from_slice(&signature.to_bytes());

        let indexer = MockDiscoveryIndexer {
            transactions: vec![NoteTransaction {
                txid: "TX1".to_string(),
                sender: address.clone(),
                receiver: address.clone(),
                note,
                confirmed_round: 100,
                round_time: 1700000000,
            }],
        };

        let result = discover_encryption_key(&indexer, &address).await.unwrap();
        assert!(result.is_some());
        let discovered = result.unwrap();
        assert_eq!(discovered.public_key, encryption_key);
        assert!(discovered.is_verified);
    }

    #[tokio::test]
    async fn test_discover_encryption_key_skips_short_notes() {
        let address = "MYADDR";

        let indexer = MockDiscoveryIndexer {
            transactions: vec![NoteTransaction {
                txid: "TX1".to_string(),
                sender: address.to_string(),
                receiver: address.to_string(),
                note: vec![1, 2, 3], // Too short for key announcement
                confirmed_round: 100,
                round_time: 1700000000,
            }],
        };

        let result = discover_encryption_key(&indexer, address).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_suggested_params_debug() {
        let params = SuggestedParams {
            fee: 1000,
            min_fee: 1000,
            first_valid: 100,
            last_valid: 1100,
            genesis_id: "testnet-v1.0".to_string(),
            genesis_hash: [0u8; 32],
        };
        let debug = format!("{:?}", params);
        assert!(debug.contains("testnet-v1.0"));
    }

    #[test]
    fn test_account_info_debug() {
        let info = AccountInfo {
            address: "ADDR123".to_string(),
            amount: 1_000_000,
            min_balance: 100_000,
        };
        let debug = format!("{:?}", info);
        assert!(debug.contains("ADDR123"));
        assert!(debug.contains("1000000"));
    }
}
