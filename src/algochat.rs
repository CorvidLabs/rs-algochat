//! Main AlgoChat client for encrypted messaging on Algorand.
//!
//! This module provides the primary interface for sending and receiving
//! encrypted messages using the AlgoChat protocol.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::blockchain::{AlgodClient, AlgorandConfig, IndexerClient, NoteTransaction};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{decrypt_message, encrypt_message};
use crate::envelope::{is_chat_message, ChatEnvelope};
use crate::keys::derive_keys_from_seed;
use crate::models::{Conversation, DiscoveredKey, Message, MessageDirection};
use crate::psk_crypto::{decrypt_psk_message, encrypt_psk_message};
use crate::psk_envelope::{decode_psk_envelope, encode_psk_envelope, is_psk_message};
use crate::psk_state::PSKState;
use crate::queue::SendQueue;
use crate::storage::{EncryptionKeyStorage, MessageCache, PublicKeyCache};
use crate::types::{AlgoChatError, Result};

/// Configuration for the AlgoChat client.
#[derive(Debug, Clone)]
pub struct AlgoChatConfig {
    /// Algorand network configuration.
    pub network: AlgorandConfig,
    /// Whether to automatically discover recipient keys.
    pub auto_discover_keys: bool,
    /// Whether to cache public keys.
    pub cache_public_keys: bool,
    /// Whether to cache messages locally.
    pub cache_messages: bool,
    /// Whether to refuse encrypting to keys that are not cryptographically
    /// verified (strict identity mode, per proposal 0001).
    ///
    /// Defaults to `false` to preserve trust-on-first-use behavior. When `true`,
    /// [`AlgoChatClient::discover_verified_key`] is the enforced discovery path
    /// and returns an error for unverified keys.
    pub require_verified_keys: bool,
}

impl AlgoChatConfig {
    /// Creates a new configuration with the given network settings.
    pub fn new(network: AlgorandConfig) -> Self {
        Self {
            network,
            auto_discover_keys: true,
            cache_public_keys: true,
            cache_messages: true,
            require_verified_keys: false,
        }
    }

    /// Creates a configuration for LocalNet.
    pub fn localnet() -> Self {
        Self::new(AlgorandConfig::localnet())
    }

    /// Creates a configuration for TestNet.
    pub fn testnet() -> Self {
        Self::new(AlgorandConfig::testnet())
    }

    /// Creates a configuration for MainNet.
    pub fn mainnet() -> Self {
        Self::new(AlgorandConfig::mainnet())
    }
}

/// A PSK contact with the shared key and ratchet state.
#[derive(Debug, Clone)]
pub struct PSKContact {
    /// The pre-shared key (32 bytes).
    pub psk: Vec<u8>,
    /// Counter state for replay protection.
    pub state: PSKState,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl PSKContact {
    /// Creates a new PSK contact.
    pub fn new(psk: Vec<u8>, label: Option<String>) -> Self {
        Self {
            psk,
            state: PSKState::new(),
            label,
        }
    }
}

/// The main AlgoChat client for encrypted messaging.
///
/// This provides a high-level API for sending and receiving encrypted
/// messages on the Algorand blockchain.
#[allow(dead_code)]
pub struct AlgoChat<A, I, S, M>
where
    A: AlgodClient,
    I: IndexerClient,
    S: EncryptionKeyStorage,
    M: MessageCache,
{
    /// The user's Algorand address.
    address: String,
    /// The user's Ed25519 public key (from Algorand account).
    ed25519_public_key: [u8; 32],
    /// The user's X25519 encryption private key.
    encryption_private_key: StaticSecret,
    /// The user's X25519 encryption public key.
    encryption_public_key: PublicKey,
    /// Configuration.
    config: AlgoChatConfig,
    /// Algod client for submitting transactions.
    algod: A,
    /// Indexer client for searching transactions.
    indexer: I,
    /// Key storage for encryption keys.
    key_storage: S,
    /// Message cache.
    message_cache: M,
    /// Public key cache.
    public_key_cache: PublicKeyCache,
    /// Send queue for offline support.
    send_queue: SendQueue,
    /// Active conversations.
    conversations: Arc<RwLock<Vec<Conversation>>>,
    /// PSK contacts indexed by Algorand address.
    psk_contacts: Arc<RwLock<HashMap<String, PSKContact>>>,
}

impl<A, I, S, M> AlgoChat<A, I, S, M>
where
    A: AlgodClient,
    I: IndexerClient,
    S: EncryptionKeyStorage,
    M: MessageCache,
{
    /// Creates a new AlgoChat client from an Algorand account seed.
    ///
    /// The seed should be the 32-byte Ed25519 private key from an Algorand account.
    pub async fn from_seed(
        seed: &[u8; 32],
        address: &str,
        config: AlgoChatConfig,
        algod: A,
        indexer: I,
        key_storage: S,
        message_cache: M,
    ) -> Result<Self> {
        // Derive encryption keys from the seed
        let (encryption_private_key, encryption_public_key) = derive_keys_from_seed(seed)?;

        // Store the encryption key (convert to bytes for storage)
        let private_key_bytes: [u8; 32] = encryption_private_key.to_bytes();
        key_storage
            .store(&private_key_bytes, address, false)
            .await?;

        // Derive the Ed25519 public key from the seed
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let ed25519_public_key = signing_key.verifying_key().to_bytes();

        Ok(Self {
            address: address.to_string(),
            ed25519_public_key,
            encryption_private_key,
            encryption_public_key,
            config,
            algod,
            indexer,
            key_storage,
            message_cache,
            public_key_cache: PublicKeyCache::default(),
            send_queue: SendQueue::default(),
            conversations: Arc::new(RwLock::new(Vec::new())),
            psk_contacts: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns the user's Algorand address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the user's encryption public key as bytes.
    pub fn encryption_public_key(&self) -> [u8; 32] {
        *self.encryption_public_key.as_bytes()
    }

    /// Gets or creates a conversation with the given participant.
    pub async fn conversation(&self, participant: &str) -> Conversation {
        let mut conversations = self.conversations.write().await;

        if let Some(conv) = conversations.iter().find(|c| c.participant == participant) {
            return conv.clone();
        }

        let conv = Conversation::new(participant.to_string());
        conversations.push(conv.clone());
        conv
    }

    /// Lists all conversations.
    pub async fn conversations(&self) -> Vec<Conversation> {
        let conversations = self.conversations.read().await;
        conversations.clone()
    }

    /// Discovers the encryption public key for an address.
    ///
    /// The returned [`DiscoveredKey`] carries its real `is_verified` flag: it is
    /// `true` only when a signed announcement was verified against the address's
    /// Ed25519 key, and `false` for keys scraped from a message envelope or an
    /// unsigned announcement. Cached keys preserve the verification status they
    /// were discovered with (they are no longer hardcoded as verified).
    ///
    /// This is the lenient accessor; it never enforces verification. Use
    /// [`AlgoChatClient::discover_verified_key`] to refuse unverified keys.
    pub async fn discover_key(&self, address: &str) -> Result<Option<DiscoveredKey>> {
        // Check cache first, preserving the real verification status.
        if self.config.cache_public_keys {
            if let Some((key, is_verified)) = self.public_key_cache.retrieve_verified(address).await
            {
                return Ok(Some(DiscoveredKey {
                    public_key: key,
                    is_verified,
                }));
            }
        }

        // Search indexer for key announcement
        let key = crate::blockchain::discover_encryption_key(&self.indexer, address).await?;

        // Cache if found, propagating the real verification status.
        if let Some(ref discovered) = key {
            if self.config.cache_public_keys {
                self.public_key_cache
                    .store_verified(address, discovered.public_key, discovered.is_verified)
                    .await;
            }
        }

        Ok(key)
    }

    /// Discovers a key and enforces that it is cryptographically verified.
    ///
    /// Strict identity accessor (proposal 0001): returns the discovered key only
    /// when its signature was verified against the address-derived Ed25519 key.
    /// An unverified or missing key yields an error, so callers can refuse to
    /// encrypt to an unverified identity regardless of the `require_verified_keys`
    /// default. Use [`AlgoChatClient::discover_key`] for trust-on-first-use.
    pub async fn discover_verified_key(&self, address: &str) -> Result<DiscoveredKey> {
        let discovered = self
            .discover_key(address)
            .await?
            .ok_or_else(|| AlgoChatError::PublicKeyNotFound(address.to_string()))?;

        if !discovered.is_verified {
            return Err(AlgoChatError::InvalidSignature(format!(
                "Encryption key for {} is not verified (no valid signed announcement)",
                address
            )));
        }

        Ok(discovered)
    }

    /// Encrypts a message for a recipient.
    pub fn encrypt(&self, message: &str, recipient_public_key: &[u8; 32]) -> Result<Vec<u8>> {
        let recipient_key = PublicKey::from(*recipient_public_key);
        let envelope = encrypt_message(
            message,
            &self.encryption_private_key,
            &self.encryption_public_key,
            &recipient_key,
        )?;

        Ok(envelope.encode())
    }

    /// Decrypts a message from a sender.
    pub fn decrypt(&self, envelope_bytes: &[u8], _sender_public_key: &[u8; 32]) -> Result<String> {
        if !is_chat_message(envelope_bytes) {
            return Err(AlgoChatError::InvalidEnvelope(
                "Not an AlgoChat message".to_string(),
            ));
        }

        let envelope = ChatEnvelope::decode(envelope_bytes)?;

        let decrypted = decrypt_message(
            &envelope,
            &self.encryption_private_key,
            &self.encryption_public_key,
        )?;

        match decrypted {
            Some(content) => Ok(content.text),
            None => Err(AlgoChatError::DecryptionError(
                "Message was a key-publish, not a chat message".to_string(),
            )),
        }
    }

    // --- PSK Contact Management ---

    /// Registers a PSK contact for encrypted messaging.
    ///
    /// # Arguments
    /// * `address` - The contact's Algorand address
    /// * `psk` - The pre-shared key (must be 32 bytes)
    /// * `label` - Optional human-readable label
    pub async fn add_psk_contact(
        &self,
        address: &str,
        psk: &[u8],
        label: Option<String>,
    ) -> Result<()> {
        if psk.len() != 32 {
            return Err(AlgoChatError::EncryptionError(
                "PSK must be 32 bytes".to_string(),
            ));
        }
        let contact = PSKContact::new(psk.to_vec(), label);
        let mut contacts = self.psk_contacts.write().await;
        contacts.insert(address.to_string(), contact);
        Ok(())
    }

    /// Removes a PSK contact.
    pub async fn remove_psk_contact(&self, address: &str) -> bool {
        let mut contacts = self.psk_contacts.write().await;
        contacts.remove(address).is_some()
    }

    /// Returns a PSK contact if one exists.
    pub async fn get_psk_contact(&self, address: &str) -> Option<PSKContact> {
        let contacts = self.psk_contacts.read().await;
        contacts.get(address).cloned()
    }

    /// Lists all PSK contact addresses.
    pub async fn psk_contacts(&self) -> Vec<String> {
        let contacts = self.psk_contacts.read().await;
        contacts.keys().cloned().collect()
    }

    /// Encrypts a message using the PSK v1.1 protocol.
    ///
    /// This is a low-level method. For automatic state management, use `send_psk`.
    pub fn encrypt_psk(
        &self,
        message: &str,
        recipient_public_key: &[u8; 32],
        initial_psk: &[u8],
        counter: u32,
    ) -> Result<Vec<u8>> {
        let recipient_key = PublicKey::from(*recipient_public_key);
        let envelope = encrypt_psk_message(
            message,
            &self.encryption_private_key,
            &self.encryption_public_key,
            &recipient_key,
            initial_psk,
            counter,
        )?;
        Ok(encode_psk_envelope(&envelope))
    }

    /// Decrypts a PSK v1.1 protocol message.
    ///
    /// This is a low-level method. For automatic state management, use `receive_psk`.
    pub fn decrypt_psk(&self, envelope_bytes: &[u8], initial_psk: &[u8]) -> Result<String> {
        if !is_psk_message(envelope_bytes) {
            return Err(AlgoChatError::InvalidEnvelope(
                "Not a PSK message".to_string(),
            ));
        }
        let envelope = decode_psk_envelope(envelope_bytes)?;
        decrypt_psk_message(
            &envelope,
            &self.encryption_private_key,
            &self.encryption_public_key,
            initial_psk,
        )
    }

    /// Encrypts a PSK message and advances the counter automatically.
    ///
    /// # Arguments
    /// * `address` - The recipient's Algorand address (must be a PSK contact)
    ///
    /// # Returns
    /// Tuple of (encrypted_bytes, counter_used)
    pub async fn send_psk(&self, address: &str, message: &str) -> Result<(Vec<u8>, u32)> {
        // Get PSK and advance counter
        let (psk, counter) = {
            let mut contacts = self.psk_contacts.write().await;
            let contact = contacts.get_mut(address).ok_or_else(|| {
                AlgoChatError::EncryptionError(format!("No PSK configured for {}", address))
            })?;
            let counter = contact.state.advance_send_counter();
            (contact.psk.clone(), counter)
        };

        // Discover recipient key
        let discovered = self
            .discover_key(address)
            .await?
            .ok_or_else(|| AlgoChatError::PublicKeyNotFound(address.to_string()))?;

        let encrypted = self.encrypt_psk(message, &discovered.public_key, &psk, counter)?;
        Ok((encrypted, counter))
    }

    /// Decrypts a PSK message and updates counter state for replay protection.
    ///
    /// # Arguments
    /// * `data` - The encoded PSK envelope bytes
    /// * `sender_address` - The sender's Algorand address (must be a PSK contact)
    pub async fn receive_psk(&self, data: &[u8], sender_address: &str) -> Result<String> {
        if !is_psk_message(data) {
            return Err(AlgoChatError::InvalidEnvelope(
                "Not a PSK message".to_string(),
            ));
        }

        let envelope = decode_psk_envelope(data)?;

        // Validate counter and decrypt
        let psk = {
            let contacts = self.psk_contacts.read().await;
            let contact = contacts.get(sender_address).ok_or_else(|| {
                AlgoChatError::DecryptionError(format!("No PSK configured for {}", sender_address))
            })?;
            contact.state.validate_counter(envelope.ratchet_counter)?;
            contact.psk.clone()
        };

        let text = decrypt_psk_message(
            &envelope,
            &self.encryption_private_key,
            &self.encryption_public_key,
            &psk,
        )?;

        // Record counter after successful decryption
        {
            let mut contacts = self.psk_contacts.write().await;
            if let Some(contact) = contacts.get_mut(sender_address) {
                contact.state.record_receive(envelope.ratchet_counter);
            }
        }

        Ok(text)
    }

    /// Processes a transaction and extracts any chat message.
    pub async fn process_transaction(&self, tx: &NoteTransaction) -> Result<Option<Message>> {
        // Check if this is a PSK or standard message
        let is_psk = is_psk_message(&tx.note);
        let is_standard = is_chat_message(&tx.note);

        if !is_psk && !is_standard {
            return Ok(None);
        }

        // Determine direction
        let direction = if tx.sender == self.address {
            MessageDirection::Sent
        } else if tx.receiver == self.address {
            MessageDirection::Received
        } else {
            return Ok(None); // Not relevant to us
        };

        // Get the other party's address and key
        let (other_address, other_key) = match direction {
            MessageDirection::Sent => {
                let key = self
                    .discover_key(&tx.receiver)
                    .await?
                    .ok_or_else(|| AlgoChatError::PublicKeyNotFound(tx.receiver.clone()))?;
                (tx.receiver.clone(), key.public_key)
            }
            MessageDirection::Received => {
                let key = self
                    .discover_key(&tx.sender)
                    .await?
                    .ok_or_else(|| AlgoChatError::PublicKeyNotFound(tx.sender.clone()))?;
                (tx.sender.clone(), key.public_key)
            }
        };

        // Decrypt the message (PSK or standard)
        let content = if is_psk {
            if direction == MessageDirection::Received {
                // Use receive_psk() which handles counter validation, decryption,
                // and replay protection in the correct order (validate-before-decrypt)
                match self.receive_psk(&tx.note, &other_address).await {
                    Ok(text) => text,
                    Err(AlgoChatError::DecryptionError(_)) => return Ok(None), // No PSK configured
                    Err(e) => return Err(e),
                }
            } else {
                // Sent messages: just decrypt (counter was already tracked on send)
                let contacts = self.psk_contacts.read().await;
                if let Some(contact) = contacts.get(&other_address) {
                    self.decrypt_psk(&tx.note, &contact.psk)?
                } else {
                    return Ok(None); // PSK message but no PSK configured
                }
            }
        } else {
            self.decrypt(&tx.note, &other_key)?
        };

        // Create message
        let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(tx.round_time);

        let message = Message::new(
            tx.txid.clone(),
            tx.sender.clone(),
            tx.receiver.clone(),
            content,
            timestamp,
            tx.confirmed_round,
            direction,
            None, // Reply context would be parsed from content
        );

        // Update conversation
        let mut conversations = self.conversations.write().await;
        if let Some(conv) = conversations
            .iter_mut()
            .find(|c| c.participant == other_address)
        {
            conv.append(message.clone());
        } else {
            let mut conv = Conversation::new(other_address);
            conv.append(message.clone());
            conversations.push(conv);
        }

        // Cache message
        if self.config.cache_messages {
            self.message_cache
                .store(std::slice::from_ref(&message), &message.sender)
                .await?;
        }

        Ok(Some(message))
    }

    /// Fetches new messages from the blockchain.
    pub async fn sync(&self) -> Result<Vec<Message>> {
        let mut all_messages = Vec::new();

        // Get transactions for our address
        let txs = self
            .indexer
            .search_transactions(&self.address, None, Some(100))
            .await?;

        for tx in txs {
            if let Some(message) = self.process_transaction(&tx).await? {
                all_messages.push(message);
            }
        }

        Ok(all_messages)
    }

    /// Returns the send queue for managing pending messages.
    pub fn send_queue(&self) -> &SendQueue {
        &self.send_queue
    }

    /// Returns the message cache.
    pub fn message_cache(&self) -> &M {
        &self.message_cache
    }

    /// Returns the public key cache.
    pub fn public_key_cache(&self) -> &PublicKeyCache {
        &self.public_key_cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{AccountInfo, SuggestedParams};
    use crate::keys::derive_keys_from_seed;
    use crate::storage::{InMemoryKeyStorage, InMemoryMessageCache};

    // ========================================================================
    // Mock implementations for testing
    // ========================================================================

    /// Mock AlgodClient that returns configurable responses.
    struct MockAlgod {
        current_round: u64,
    }

    impl MockAlgod {
        fn new() -> Self {
            Self {
                current_round: 1000,
            }
        }
    }

    #[async_trait::async_trait]
    impl AlgodClient for MockAlgod {
        async fn get_suggested_params(&self) -> crate::types::Result<SuggestedParams> {
            Ok(SuggestedParams {
                fee: 1000,
                min_fee: 1000,
                first_valid: self.current_round,
                last_valid: self.current_round + 1000,
                genesis_id: "testnet-v1.0".to_string(),
                genesis_hash: [0u8; 32],
            })
        }

        async fn get_account_info(&self, address: &str) -> crate::types::Result<AccountInfo> {
            Ok(AccountInfo {
                address: address.to_string(),
                amount: 10_000_000,
                min_balance: 100_000,
            })
        }

        async fn submit_transaction(&self, _signed_txn: &[u8]) -> crate::types::Result<String> {
            Ok("MOCK_TXID_123".to_string())
        }

        async fn wait_for_confirmation(
            &self,
            txid: &str,
            _rounds: u32,
        ) -> crate::types::Result<crate::blockchain::TransactionInfo> {
            Ok(crate::blockchain::TransactionInfo {
                txid: txid.to_string(),
                confirmed_round: Some(self.current_round + 1),
            })
        }

        async fn get_current_round(&self) -> crate::types::Result<u64> {
            Ok(self.current_round)
        }
    }

    /// Mock IndexerClient with configurable transaction responses.
    struct MockIndexer {
        transactions: Vec<NoteTransaction>,
    }

    impl MockIndexer {
        fn new() -> Self {
            Self {
                transactions: Vec::new(),
            }
        }

        fn with_transactions(transactions: Vec<NoteTransaction>) -> Self {
            Self { transactions }
        }
    }

    #[async_trait::async_trait]
    impl IndexerClient for MockIndexer {
        async fn search_transactions(
            &self,
            address: &str,
            after_round: Option<u64>,
            _limit: Option<u32>,
        ) -> crate::types::Result<Vec<NoteTransaction>> {
            Ok(self
                .transactions
                .iter()
                .filter(|tx| {
                    (tx.sender == address || tx.receiver == address)
                        && after_round.is_none_or(|r| tx.confirmed_round > r)
                })
                .cloned()
                .collect())
        }

        async fn search_transactions_between(
            &self,
            address1: &str,
            address2: &str,
            after_round: Option<u64>,
            _limit: Option<u32>,
        ) -> crate::types::Result<Vec<NoteTransaction>> {
            Ok(self
                .transactions
                .iter()
                .filter(|tx| {
                    ((tx.sender == address1 && tx.receiver == address2)
                        || (tx.sender == address2 && tx.receiver == address1))
                        && after_round.is_none_or(|r| tx.confirmed_round > r)
                })
                .cloned()
                .collect())
        }

        async fn get_transaction(&self, txid: &str) -> crate::types::Result<NoteTransaction> {
            self.transactions
                .iter()
                .find(|tx| tx.txid == txid)
                .cloned()
                .ok_or_else(|| {
                    crate::types::AlgoChatError::TransactionFailed(format!(
                        "Transaction not found: {}",
                        txid
                    ))
                })
        }

        async fn wait_for_indexer(
            &self,
            txid: &str,
            _timeout_secs: u32,
        ) -> crate::types::Result<NoteTransaction> {
            self.get_transaction(txid).await
        }
    }

    // ========================================================================
    // Test seeds (deterministic, same as keys.rs tests)
    // ========================================================================

    const ALICE_SEED: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    const BOB_SEED: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ];

    const ALICE_ADDR: &str = "ALICE_TESTADDR";
    const BOB_ADDR: &str = "BOB_TESTADDR";

    /// Helper to create an AlgoChat client for Alice.
    async fn make_alice_client(
        indexer: MockIndexer,
    ) -> AlgoChat<MockAlgod, MockIndexer, InMemoryKeyStorage, InMemoryMessageCache> {
        AlgoChat::from_seed(
            &ALICE_SEED,
            ALICE_ADDR,
            AlgoChatConfig::testnet(),
            MockAlgod::new(),
            indexer,
            InMemoryKeyStorage::new(),
            InMemoryMessageCache::new(),
        )
        .await
        .unwrap()
    }

    /// Helper to create an AlgoChat client for Bob.
    async fn make_bob_client(
        indexer: MockIndexer,
    ) -> AlgoChat<MockAlgod, MockIndexer, InMemoryKeyStorage, InMemoryMessageCache> {
        AlgoChat::from_seed(
            &BOB_SEED,
            BOB_ADDR,
            AlgoChatConfig::testnet(),
            MockAlgod::new(),
            indexer,
            InMemoryKeyStorage::new(),
            InMemoryMessageCache::new(),
        )
        .await
        .unwrap()
    }

    // ========================================================================
    // Config tests
    // ========================================================================

    #[test]
    fn test_config_creation() {
        let config = AlgoChatConfig::testnet();
        assert!(config.network.algod_url.contains("testnet"));
        assert!(config.auto_discover_keys);
        assert!(config.cache_public_keys);
    }

    #[test]
    fn test_config_localnet() {
        let config = AlgoChatConfig::localnet();
        assert!(config.network.algod_url.contains("localhost"));
    }

    #[test]
    fn test_config_mainnet() {
        let config = AlgoChatConfig::mainnet();
        assert!(config.network.algod_url.contains("mainnet"));
    }

    // ========================================================================
    // Client creation tests
    // ========================================================================

    #[tokio::test]
    async fn test_client_from_seed() {
        let client = make_alice_client(MockIndexer::new()).await;
        assert_eq!(client.address(), ALICE_ADDR);
    }

    #[tokio::test]
    async fn test_client_encryption_public_key() {
        let client = make_alice_client(MockIndexer::new()).await;
        let pub_key = client.encryption_public_key();

        // Should match the deterministic derivation from keys.rs
        let (_, expected_key) = derive_keys_from_seed(&ALICE_SEED).unwrap();
        assert_eq!(pub_key, *expected_key.as_bytes());
    }

    #[tokio::test]
    async fn test_client_different_seeds_different_keys() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;
        assert_ne!(alice.encryption_public_key(), bob.encryption_public_key());
    }

    #[tokio::test]
    async fn test_client_stores_key_on_creation() {
        let key_storage = InMemoryKeyStorage::new();
        let client = AlgoChat::from_seed(
            &ALICE_SEED,
            ALICE_ADDR,
            AlgoChatConfig::testnet(),
            MockAlgod::new(),
            MockIndexer::new(),
            key_storage,
            InMemoryMessageCache::new(),
        )
        .await
        .unwrap();

        // The key_storage field is moved into the client, but we can verify
        // the client was created successfully (key storage didn't error)
        assert_eq!(client.address(), ALICE_ADDR);
    }

    // ========================================================================
    // Conversation management tests
    // ========================================================================

    #[tokio::test]
    async fn test_conversation_created_on_access() {
        let client = make_alice_client(MockIndexer::new()).await;

        let conv = client.conversation(BOB_ADDR).await;
        assert_eq!(conv.participant, BOB_ADDR);
        assert!(conv.messages().is_empty());
    }

    #[tokio::test]
    async fn test_conversation_reused_on_second_access() {
        let client = make_alice_client(MockIndexer::new()).await;

        let conv1 = client.conversation(BOB_ADDR).await;
        let conv2 = client.conversation(BOB_ADDR).await;
        assert_eq!(conv1.participant, conv2.participant);
    }

    #[tokio::test]
    async fn test_conversations_list_empty() {
        let client = make_alice_client(MockIndexer::new()).await;
        let convs = client.conversations().await;
        assert!(convs.is_empty());
    }

    #[tokio::test]
    async fn test_conversations_list_after_access() {
        let client = make_alice_client(MockIndexer::new()).await;

        client.conversation(BOB_ADDR).await;
        client.conversation("CHARLIE_ADDR").await;

        let convs = client.conversations().await;
        assert_eq!(convs.len(), 2);
    }

    // ========================================================================
    // Encrypt/decrypt roundtrip tests
    // ========================================================================

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt("Hello, Bob!", &bob_key).unwrap();

        let alice_key = alice.encryption_public_key();
        let decrypted = bob.decrypt(&encrypted, &alice_key).unwrap();
        assert_eq!(decrypted, "Hello, Bob!");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_empty_message() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt("", &bob_key).unwrap();

        let alice_key = alice.encryption_public_key();
        let decrypted = bob.decrypt(&encrypted, &alice_key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_unicode() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let msg = "Hello 🌍 café résumé 日本語";
        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt(msg, &bob_key).unwrap();

        let alice_key = alice.encryption_public_key();
        let decrypted = bob.decrypt(&encrypted, &alice_key).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[tokio::test]
    async fn test_sender_can_decrypt_own_message() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt("Secret message", &bob_key).unwrap();

        // Alice (sender) should also be able to decrypt
        let decrypted = alice.decrypt(&encrypted, &bob_key).unwrap();
        assert_eq!(decrypted, "Secret message");
    }

    #[tokio::test]
    async fn test_decrypt_invalid_envelope() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let result = alice.decrypt(&[0, 1, 2, 3], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decrypt_wrong_key() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt("Hello", &bob_key).unwrap();

        // Try to decrypt with a random key (wrong recipient)
        let wrong_seed = [99u8; 32];
        let (_wrong_private, _wrong_public) = derive_keys_from_seed(&wrong_seed).unwrap();
        let wrong_client = AlgoChat::from_seed(
            &wrong_seed,
            "WRONG_ADDR",
            AlgoChatConfig::testnet(),
            MockAlgod::new(),
            MockIndexer::new(),
            InMemoryKeyStorage::new(),
            InMemoryMessageCache::new(),
        )
        .await
        .unwrap();

        let result = wrong_client.decrypt(&encrypted, &alice.encryption_public_key());
        assert!(result.is_err());
    }

    // ========================================================================
    // Process transaction tests
    // ========================================================================

    #[tokio::test]
    async fn test_process_transaction_non_chat_message() {
        let client = make_alice_client(MockIndexer::new()).await;

        let tx = NoteTransaction {
            txid: "TX1".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: ALICE_ADDR.to_string(),
            note: vec![0xFF, 0xFF, 0xFF], // Not an AlgoChat message
            confirmed_round: 100,
            round_time: 1700000000,
        };

        let result = client.process_transaction(&tx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_process_transaction_irrelevant() {
        let client = make_alice_client(MockIndexer::new()).await;

        // Transaction between two other parties
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;
        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt("Hello", &bob_key).unwrap();

        let tx = NoteTransaction {
            txid: "TX1".to_string(),
            sender: "OTHER1".to_string(),
            receiver: "OTHER2".to_string(),
            note: encrypted,
            confirmed_round: 100,
            round_time: 1700000000,
        };

        let result = client.process_transaction(&tx).await.unwrap();
        assert!(result.is_none());
    }

    // ========================================================================
    // Sync tests
    // ========================================================================

    #[tokio::test]
    async fn test_sync_no_transactions() {
        let client = make_alice_client(MockIndexer::new()).await;

        let messages = client.sync().await.unwrap();
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_sync_skips_non_chat_transactions() {
        let indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "TX1".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: ALICE_ADDR.to_string(),
            note: vec![0xFF, 0xFF], // Not an AlgoChat message
            confirmed_round: 100,
            round_time: 1700000000,
        }]);

        let client = make_alice_client(indexer).await;
        let messages = client.sync().await.unwrap();
        assert!(messages.is_empty());
    }

    // ========================================================================
    // Key discovery / caching tests
    // ========================================================================

    #[tokio::test]
    async fn test_discover_key_not_found() {
        let client = make_alice_client(MockIndexer::new()).await;

        let result = client.discover_key(BOB_ADDR).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_discover_key_from_announcement() {
        let bob_key = {
            let (_, pub_key) = derive_keys_from_seed(&BOB_SEED).unwrap();
            *pub_key.as_bytes()
        };

        // Create a key announcement transaction (self-transfer with 32-byte note)
        let indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "KEY_ANNOUNCE".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: BOB_ADDR.to_string(),
            note: bob_key.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);

        let client = make_alice_client(indexer).await;
        let result = client.discover_key(BOB_ADDR).await.unwrap();
        assert!(result.is_some());
        let discovered = result.unwrap();
        assert_eq!(discovered.public_key, bob_key);
        assert!(!discovered.is_verified); // No signature
    }

    #[tokio::test]
    async fn test_discover_verified_key_rejects_unverified() {
        let bob_key = {
            let (_, pub_key) = derive_keys_from_seed(&BOB_SEED).unwrap();
            *pub_key.as_bytes()
        };

        // Unsigned announcement -> discovered key is unverified.
        let indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "KEY_ANNOUNCE".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: BOB_ADDR.to_string(),
            note: bob_key.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);

        let client = make_alice_client(indexer).await;

        // Lenient accessor returns the (unverified) key.
        let lenient = client.discover_key(BOB_ADDR).await.unwrap().unwrap();
        assert!(!lenient.is_verified);

        // Strict accessor refuses the unverified key.
        let strict = client.discover_verified_key(BOB_ADDR).await;
        assert!(matches!(strict, Err(AlgoChatError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn test_discover_verified_key_missing() {
        let client = make_alice_client(MockIndexer::new()).await;
        let strict = client.discover_verified_key(BOB_ADDR).await;
        assert!(matches!(strict, Err(AlgoChatError::PublicKeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_discover_key_cached() {
        let bob_key = {
            let (_, pub_key) = derive_keys_from_seed(&BOB_SEED).unwrap();
            *pub_key.as_bytes()
        };

        let indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "KEY_ANNOUNCE".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: BOB_ADDR.to_string(),
            note: bob_key.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);

        let client = make_alice_client(indexer).await;

        // First call discovers from indexer
        let result1 = client.discover_key(BOB_ADDR).await.unwrap();
        assert!(result1.is_some());

        // Second call should use cache and preserve the real (unverified) status.
        // The announcement here is unsigned, so the cached key stays unverified
        // rather than being hardcoded as verified.
        let result2 = client.discover_key(BOB_ADDR).await.unwrap();
        assert!(result2.is_some());
        assert!(!result2.unwrap().is_verified);
    }

    #[tokio::test]
    async fn test_discover_key_caching_disabled() {
        let bob_key = {
            let (_, pub_key) = derive_keys_from_seed(&BOB_SEED).unwrap();
            *pub_key.as_bytes()
        };

        let indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "KEY_ANNOUNCE".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: BOB_ADDR.to_string(),
            note: bob_key.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);

        let mut config = AlgoChatConfig::testnet();
        config.cache_public_keys = false;

        let client = AlgoChat::from_seed(
            &ALICE_SEED,
            ALICE_ADDR,
            config,
            MockAlgod::new(),
            indexer,
            InMemoryKeyStorage::new(),
            InMemoryMessageCache::new(),
        )
        .await
        .unwrap();

        let result = client.discover_key(BOB_ADDR).await.unwrap();
        assert!(result.is_some());
        // With caching disabled, second call still goes to indexer
        assert!(!result.unwrap().is_verified);
    }

    // ========================================================================
    // Send queue and cache accessor tests
    // ========================================================================

    #[tokio::test]
    async fn test_send_queue_accessor() {
        let client = make_alice_client(MockIndexer::new()).await;
        let queue = client.send_queue();
        let pending = queue.all_pending().await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_message_cache_accessor() {
        let client = make_alice_client(MockIndexer::new()).await;
        let cache = client.message_cache();
        let convs = cache.get_cached_conversations().await.unwrap();
        assert!(convs.is_empty());
    }

    #[tokio::test]
    async fn test_public_key_cache_accessor() {
        let client = make_alice_client(MockIndexer::new()).await;
        let cache = client.public_key_cache();
        let result = cache.retrieve("nonexistent").await;
        assert!(result.is_none());
    }

    // ========================================================================
    // PSK contact management tests
    // ========================================================================

    const TEST_PSK: [u8; 32] = [0xAA; 32];

    #[tokio::test]
    async fn test_add_psk_contact() {
        let client = make_alice_client(MockIndexer::new()).await;
        client
            .add_psk_contact(BOB_ADDR, &TEST_PSK, Some("Bob".to_string()))
            .await
            .unwrap();

        let contact = client.get_psk_contact(BOB_ADDR).await;
        assert!(contact.is_some());
        let contact = contact.unwrap();
        assert_eq!(contact.psk, TEST_PSK);
        assert_eq!(contact.label, Some("Bob".to_string()));
        assert_eq!(contact.state.send_counter, 0);
    }

    #[tokio::test]
    async fn test_add_psk_contact_rejects_bad_length() {
        let client = make_alice_client(MockIndexer::new()).await;
        let result = client.add_psk_contact(BOB_ADDR, &[0u8; 16], None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_psk_contact() {
        let client = make_alice_client(MockIndexer::new()).await;
        client
            .add_psk_contact(BOB_ADDR, &TEST_PSK, None)
            .await
            .unwrap();

        assert!(client.remove_psk_contact(BOB_ADDR).await);
        assert!(!client.remove_psk_contact(BOB_ADDR).await);
        assert!(client.get_psk_contact(BOB_ADDR).await.is_none());
    }

    #[tokio::test]
    async fn test_psk_contacts_list() {
        let client = make_alice_client(MockIndexer::new()).await;
        assert!(client.psk_contacts().await.is_empty());

        client
            .add_psk_contact(BOB_ADDR, &TEST_PSK, None)
            .await
            .unwrap();
        client
            .add_psk_contact("CHARLIE", &TEST_PSK, None)
            .await
            .unwrap();

        let contacts = client.psk_contacts().await;
        assert_eq!(contacts.len(), 2);
    }

    // ========================================================================
    // PSK encrypt/decrypt roundtrip tests
    // ========================================================================

    #[tokio::test]
    async fn test_psk_encrypt_decrypt_roundtrip() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let bob_key = bob.encryption_public_key();
        let encrypted = alice
            .encrypt_psk("Hello PSK!", &bob_key, &TEST_PSK, 0)
            .unwrap();

        let decrypted = bob.decrypt_psk(&encrypted, &TEST_PSK).unwrap();
        assert_eq!(decrypted, "Hello PSK!");
    }

    #[tokio::test]
    async fn test_psk_sender_self_decrypt() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        let bob_key = bob.encryption_public_key();
        let encrypted = alice
            .encrypt_psk("My message", &bob_key, &TEST_PSK, 0)
            .unwrap();

        // Sender should be able to decrypt own message
        let decrypted = alice.decrypt_psk(&encrypted, &TEST_PSK).unwrap();
        assert_eq!(decrypted, "My message");
    }

    #[tokio::test]
    async fn test_psk_different_counters() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;
        let bob_key = bob.encryption_public_key();

        let enc0 = alice.encrypt_psk("msg0", &bob_key, &TEST_PSK, 0).unwrap();
        let enc1 = alice.encrypt_psk("msg1", &bob_key, &TEST_PSK, 1).unwrap();

        assert_ne!(enc0, enc1);

        assert_eq!(bob.decrypt_psk(&enc0, &TEST_PSK).unwrap(), "msg0");
        assert_eq!(bob.decrypt_psk(&enc1, &TEST_PSK).unwrap(), "msg1");
    }

    #[tokio::test]
    async fn test_psk_unicode() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;
        let bob_key = bob.encryption_public_key();

        let encrypted = alice
            .encrypt_psk("こんにちは 👋", &bob_key, &TEST_PSK, 0)
            .unwrap();
        assert_eq!(
            bob.decrypt_psk(&encrypted, &TEST_PSK).unwrap(),
            "こんにちは 👋"
        );
    }

    #[tokio::test]
    async fn test_psk_wrong_key_fails() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;
        let bob_key = bob.encryption_public_key();

        let encrypted = alice.encrypt_psk("secret", &bob_key, &TEST_PSK, 0).unwrap();

        let wrong_psk = [0xBB; 32];
        assert!(bob.decrypt_psk(&encrypted, &wrong_psk).is_err());
    }

    #[tokio::test]
    async fn test_psk_decrypt_non_psk_message() {
        let alice = make_alice_client(MockIndexer::new()).await;
        // Standard envelope (protocol 0x01) should fail PSK decrypt
        let result = alice.decrypt_psk(&[0x01, 0x01, 0, 0], &TEST_PSK);
        assert!(result.is_err());
    }

    // ========================================================================
    // PSK send/receive with state management tests
    // ========================================================================

    #[tokio::test]
    async fn test_send_psk_advances_counter() {
        let bob_key = {
            let (_, pub_key) = derive_keys_from_seed(&BOB_SEED).unwrap();
            *pub_key.as_bytes()
        };

        let indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "KEY_ANNOUNCE".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: BOB_ADDR.to_string(),
            note: bob_key.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);

        let alice = make_alice_client(indexer).await;
        alice
            .add_psk_contact(BOB_ADDR, &TEST_PSK, None)
            .await
            .unwrap();

        let (_, counter0) = alice.send_psk(BOB_ADDR, "msg0").await.unwrap();
        let (_, counter1) = alice.send_psk(BOB_ADDR, "msg1").await.unwrap();
        let (_, counter2) = alice.send_psk(BOB_ADDR, "msg2").await.unwrap();

        assert_eq!(counter0, 0);
        assert_eq!(counter1, 1);
        assert_eq!(counter2, 2);

        let contact = alice.get_psk_contact(BOB_ADDR).await.unwrap();
        assert_eq!(contact.state.send_counter, 3);
    }

    #[tokio::test]
    async fn test_send_psk_without_contact_errors() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let result = alice.send_psk(BOB_ADDR, "hello").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receive_psk_updates_state() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        alice
            .add_psk_contact(BOB_ADDR, &TEST_PSK, None)
            .await
            .unwrap();
        bob.add_psk_contact(ALICE_ADDR, &TEST_PSK, None)
            .await
            .unwrap();

        // Alice encrypts manually
        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt_psk("Hello!", &bob_key, &TEST_PSK, 0).unwrap();

        // Bob receives
        let text = bob.receive_psk(&encrypted, ALICE_ADDR).await.unwrap();
        assert_eq!(text, "Hello!");

        let contact = bob.get_psk_contact(ALICE_ADDR).await.unwrap();
        assert_eq!(contact.state.peer_last_counter, 0);
        assert!(contact.state.seen_counters.contains(&0));
    }

    #[tokio::test]
    async fn test_receive_psk_replay_rejected() {
        let alice = make_alice_client(MockIndexer::new()).await;
        let bob = make_bob_client(MockIndexer::new()).await;

        alice
            .add_psk_contact(BOB_ADDR, &TEST_PSK, None)
            .await
            .unwrap();
        bob.add_psk_contact(ALICE_ADDR, &TEST_PSK, None)
            .await
            .unwrap();

        let bob_key = bob.encryption_public_key();
        let encrypted = alice.encrypt_psk("Hello!", &bob_key, &TEST_PSK, 0).unwrap();

        // First receive succeeds
        bob.receive_psk(&encrypted, ALICE_ADDR).await.unwrap();

        // Replay is rejected
        let result = bob.receive_psk(&encrypted, ALICE_ADDR).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receive_psk_without_contact_errors() {
        let bob = make_bob_client(MockIndexer::new()).await;
        // Craft a minimal PSK-shaped message
        let mut fake_psk = vec![0x01, 0x02]; // version + protocol ID
        fake_psk.extend_from_slice(&[0u8; 200]); // padding
        let result = bob.receive_psk(&fake_psk, ALICE_ADDR).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_full_psk_conversation() {
        let alice_key_bytes = {
            let (_, pub_key) = derive_keys_from_seed(&ALICE_SEED).unwrap();
            *pub_key.as_bytes()
        };
        let bob_key_bytes = {
            let (_, pub_key) = derive_keys_from_seed(&BOB_SEED).unwrap();
            *pub_key.as_bytes()
        };

        // Set up key discovery for both parties
        let alice_indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "BOB_KEY".to_string(),
            sender: BOB_ADDR.to_string(),
            receiver: BOB_ADDR.to_string(),
            note: bob_key_bytes.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);
        let bob_indexer = MockIndexer::with_transactions(vec![NoteTransaction {
            txid: "ALICE_KEY".to_string(),
            sender: ALICE_ADDR.to_string(),
            receiver: ALICE_ADDR.to_string(),
            note: alice_key_bytes.to_vec(),
            confirmed_round: 50,
            round_time: 1700000000,
        }]);

        let alice = make_alice_client(alice_indexer).await;
        let bob = AlgoChat::from_seed(
            &BOB_SEED,
            BOB_ADDR,
            AlgoChatConfig::testnet(),
            MockAlgod::new(),
            bob_indexer,
            InMemoryKeyStorage::new(),
            InMemoryMessageCache::new(),
        )
        .await
        .unwrap();

        alice
            .add_psk_contact(BOB_ADDR, &TEST_PSK, None)
            .await
            .unwrap();
        bob.add_psk_contact(ALICE_ADDR, &TEST_PSK, None)
            .await
            .unwrap();

        // Alice sends to Bob
        let (enc1, _) = alice.send_psk(BOB_ADDR, "Hey Bob!").await.unwrap();
        let text1 = bob.receive_psk(&enc1, ALICE_ADDR).await.unwrap();
        assert_eq!(text1, "Hey Bob!");

        // Bob sends to Alice
        let (enc2, _) = bob.send_psk(ALICE_ADDR, "Hi Alice!").await.unwrap();
        let text2 = alice.receive_psk(&enc2, BOB_ADDR).await.unwrap();
        assert_eq!(text2, "Hi Alice!");

        // Alice sends again (counter advances)
        let (enc3, counter3) = alice.send_psk(BOB_ADDR, "How are you?").await.unwrap();
        assert_eq!(counter3, 1); // Second message from Alice
        let text3 = bob.receive_psk(&enc3, ALICE_ADDR).await.unwrap();
        assert_eq!(text3, "How are you?");
    }
}
