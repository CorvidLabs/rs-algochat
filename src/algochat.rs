//! Main AlgoChat client for encrypted messaging on Algorand.
//!
//! This module provides the primary interface for sending and receiving
//! encrypted messages using the AlgoChat protocol.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::blockchain::{AlgodClient, AlgorandConfig, IndexerClient, NoteTransaction};
use crate::crypto::{decrypt_message, encrypt_message};
use crate::envelope::{decode_envelope, encode_envelope, is_chat_message};
use crate::keys::derive_keys_from_seed;
use crate::models::{
    Conversation, DiscoveredKey, Message, MessageDirection, SendOptions, SendResult,
};
use crate::queue::SendQueue;
use crate::storage::{
    EncryptionKeyStorage, InMemoryKeyStorage, InMemoryMessageCache, MessageCache, PublicKeyCache,
};
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
}

impl AlgoChatConfig {
    /// Creates a new configuration with the given network settings.
    pub fn new(network: AlgorandConfig) -> Self {
        Self {
            network,
            auto_discover_keys: true,
            cache_public_keys: true,
            cache_messages: true,
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

/// The main AlgoChat client for encrypted messaging.
///
/// This provides a high-level API for sending and receiving encrypted
/// messages on the Algorand blockchain.
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
    /// The user's X25519 encryption keys.
    encryption_private_key: [u8; 32],
    encryption_public_key: [u8; 32],
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

        // Store the encryption key
        key_storage
            .store(&encryption_private_key, address, false)
            .await?;

        Ok(Self {
            address: address.to_string(),
            ed25519_public_key: *seed, // The seed is also the Ed25519 public key in Algorand
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
        })
    }

    /// Returns the user's Algorand address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the user's encryption public key.
    pub fn encryption_public_key(&self) -> &[u8; 32] {
        &self.encryption_public_key
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
    pub async fn discover_key(&self, address: &str) -> Result<Option<DiscoveredKey>> {
        // Check cache first
        if self.config.cache_public_keys {
            if let Some(key) = self.public_key_cache.retrieve(address).await {
                return Ok(Some(DiscoveredKey {
                    public_key: key,
                    is_verified: true, // Cached keys are assumed verified
                }));
            }
        }

        // Search indexer for key announcement
        let key = crate::blockchain::discover_encryption_key(&self.indexer, address).await?;

        // Cache if found
        if let Some(ref discovered) = key {
            if self.config.cache_public_keys {
                self.public_key_cache
                    .store(address, discovered.public_key)
                    .await;
            }
        }

        Ok(key)
    }

    /// Encrypts a message for a recipient.
    pub fn encrypt(&self, message: &str, recipient_public_key: &[u8; 32]) -> Result<Vec<u8>> {
        let ciphertext = encrypt_message(
            message.as_bytes(),
            recipient_public_key,
            &self.encryption_private_key,
        )?;

        let envelope = encode_envelope(
            &ciphertext,
            &self.encryption_public_key,
            recipient_public_key,
        )?;

        Ok(envelope)
    }

    /// Decrypts a message from a sender.
    pub fn decrypt(&self, envelope: &[u8], sender_public_key: &[u8; 32]) -> Result<String> {
        if !is_chat_message(envelope) {
            return Err(AlgoChatError::InvalidEnvelope(
                "Not an AlgoChat message".to_string(),
            ));
        }

        let decoded = decode_envelope(envelope)?;

        let plaintext = decrypt_message(
            &decoded.ciphertext,
            sender_public_key,
            &self.encryption_private_key,
        )?;

        String::from_utf8(plaintext).map_err(|e| AlgoChatError::DecryptionFailed(e.to_string()))
    }

    /// Processes a transaction and extracts any chat message.
    pub async fn process_transaction(&self, tx: &NoteTransaction) -> Result<Option<Message>> {
        // Check if this is a chat message
        if !is_chat_message(&tx.note) {
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

        // Decrypt the message
        let content = self.decrypt(&tx.note, &other_key)?;

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
                .store(&[message.clone()], &message.sender)
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

    #[test]
    fn test_config_creation() {
        let config = AlgoChatConfig::testnet();
        assert!(config.network.algod_url.contains("testnet"));
        assert!(config.auto_discover_keys);
        assert!(config.cache_public_keys);
    }
}
