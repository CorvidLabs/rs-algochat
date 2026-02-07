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
/// - 4 bytes: checksum (truncated SHA-512/256 of the public key)
fn decode_algorand_address(address: &str) -> Option<[u8; 32]> {
    let decoded = data_encoding::BASE32_NOPAD.decode(address.as_bytes()).ok()?;
    if decoded.len() != 36 {
        return None;
    }
    let mut ed25519_public_key = [0u8; 32];
    ed25519_public_key.copy_from_slice(&decoded[..32]);
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
}
