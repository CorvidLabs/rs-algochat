//! Storage interfaces and implementations for AlgoChat.
//!
//! This module provides traits and implementations for storing messages,
//! caching public keys, and persisting encryption keys.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::models::Message;
use crate::types::{AlgoChatError, Result};

// ============================================================================
// Message Cache
// ============================================================================

/// Trait for storing and retrieving messages.
#[async_trait::async_trait]
pub trait MessageCache: Send + Sync {
    /// Store messages for a conversation.
    async fn store(&self, messages: &[Message], participant: &str) -> Result<()>;

    /// Retrieve cached messages for a conversation.
    async fn retrieve(&self, participant: &str, after_round: Option<u64>) -> Result<Vec<Message>>;

    /// Get the last synced round for a conversation.
    async fn get_last_sync_round(&self, participant: &str) -> Result<Option<u64>>;

    /// Set the last synced round for a conversation.
    async fn set_last_sync_round(&self, round: u64, participant: &str) -> Result<()>;

    /// Get all cached conversation participants.
    async fn get_cached_conversations(&self) -> Result<Vec<String>>;

    /// Clear all cached data.
    async fn clear(&self) -> Result<()>;

    /// Clear cached data for a specific conversation.
    async fn clear_for(&self, participant: &str) -> Result<()>;
}

/// In-memory implementation of MessageCache.
#[derive(Default)]
pub struct InMemoryMessageCache {
    messages: Arc<RwLock<HashMap<String, Vec<Message>>>>,
    sync_rounds: Arc<RwLock<HashMap<String, u64>>>,
}

impl InMemoryMessageCache {
    /// Creates a new in-memory message cache.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl MessageCache for InMemoryMessageCache {
    async fn store(&self, messages: &[Message], participant: &str) -> Result<()> {
        let mut cache = self.messages.write().await;
        let entry = cache.entry(participant.to_string()).or_default();

        for message in messages {
            if !entry.iter().any(|m| m.id == message.id) {
                entry.push(message.clone());
            }
        }

        entry.sort_by_key(|m| m.timestamp);
        Ok(())
    }

    async fn retrieve(&self, participant: &str, after_round: Option<u64>) -> Result<Vec<Message>> {
        let cache = self.messages.read().await;

        let messages = cache.get(participant).cloned().unwrap_or_default();

        Ok(match after_round {
            Some(round) => messages
                .into_iter()
                .filter(|m| m.confirmed_round > round)
                .collect(),
            None => messages,
        })
    }

    async fn get_last_sync_round(&self, participant: &str) -> Result<Option<u64>> {
        let rounds = self.sync_rounds.read().await;
        Ok(rounds.get(participant).copied())
    }

    async fn set_last_sync_round(&self, round: u64, participant: &str) -> Result<()> {
        let mut rounds = self.sync_rounds.write().await;
        rounds.insert(participant.to_string(), round);
        Ok(())
    }

    async fn get_cached_conversations(&self) -> Result<Vec<String>> {
        let cache = self.messages.read().await;
        Ok(cache.keys().cloned().collect())
    }

    async fn clear(&self) -> Result<()> {
        let mut messages = self.messages.write().await;
        let mut rounds = self.sync_rounds.write().await;
        messages.clear();
        rounds.clear();
        Ok(())
    }

    async fn clear_for(&self, participant: &str) -> Result<()> {
        let mut messages = self.messages.write().await;
        let mut rounds = self.sync_rounds.write().await;
        messages.remove(participant);
        rounds.remove(participant);
        Ok(())
    }
}

// ============================================================================
// Public Key Cache
// ============================================================================

/// Entry in the public key cache with expiration.
struct CacheEntry {
    key: [u8; 32],
    expires_at: Instant,
}

/// In-memory cache for public keys with TTL expiration.
pub struct PublicKeyCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

impl PublicKeyCache {
    /// Creates a new public key cache with the given TTL (default: 24 hours).
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Creates a cache with default TTL (24 hours).
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(86400))
    }

    /// Store a public key for an address.
    pub async fn store(&self, address: &str, key: [u8; 32]) {
        let mut cache = self.cache.write().await;
        cache.insert(
            address.to_string(),
            CacheEntry {
                key,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Retrieve a public key for an address (returns None if expired).
    pub async fn retrieve(&self, address: &str) -> Option<[u8; 32]> {
        let cache = self.cache.read().await;
        cache.get(address).and_then(|entry| {
            if entry.expires_at > Instant::now() {
                Some(entry.key)
            } else {
                None
            }
        })
    }

    /// Invalidate the cached key for an address.
    pub async fn invalidate(&self, address: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(address);
    }

    /// Clear all cached keys.
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Remove all expired entries.
    pub async fn prune_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for PublicKeyCache {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

// ============================================================================
// Encryption Key Storage
// ============================================================================

/// Trait for storing encryption private keys.
#[async_trait::async_trait]
pub trait EncryptionKeyStorage: Send + Sync {
    /// Store a private key for an address.
    async fn store(
        &self,
        private_key: &[u8; 32],
        address: &str,
        require_biometric: bool,
    ) -> Result<()>;

    /// Retrieve a private key for an address.
    async fn retrieve(&self, address: &str) -> Result<[u8; 32]>;

    /// Check if a key exists for an address.
    async fn has_key(&self, address: &str) -> bool;

    /// Delete a key for an address.
    async fn delete(&self, address: &str) -> Result<()>;

    /// List all stored addresses.
    async fn list_stored_addresses(&self) -> Result<Vec<String>>;
}

/// In-memory implementation of EncryptionKeyStorage (for testing).
///
/// WARNING: This is NOT secure for production use. Keys are stored in memory
/// without encryption and are lost when the process exits.
#[derive(Default)]
pub struct InMemoryKeyStorage {
    keys: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

impl InMemoryKeyStorage {
    /// Creates a new in-memory key storage.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl EncryptionKeyStorage for InMemoryKeyStorage {
    async fn store(
        &self,
        private_key: &[u8; 32],
        address: &str,
        _require_biometric: bool,
    ) -> Result<()> {
        let mut keys = self.keys.write().await;
        keys.insert(address.to_string(), *private_key);
        Ok(())
    }

    async fn retrieve(&self, address: &str) -> Result<[u8; 32]> {
        let keys = self.keys.read().await;
        keys.get(address)
            .copied()
            .ok_or_else(|| AlgoChatError::KeyNotFound(address.to_string()))
    }

    async fn has_key(&self, address: &str) -> bool {
        let keys = self.keys.read().await;
        keys.contains_key(address)
    }

    async fn delete(&self, address: &str) -> Result<()> {
        let mut keys = self.keys.write().await;
        keys.remove(address);
        Ok(())
    }

    async fn list_stored_addresses(&self) -> Result<Vec<String>> {
        let keys = self.keys.read().await;
        Ok(keys.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MessageDirection;
    use std::time::SystemTime;

    fn test_message(id: &str, round: u64) -> Message {
        Message::new(
            id,
            "sender",
            "recipient",
            "content",
            SystemTime::now(),
            round,
            MessageDirection::Sent,
            None,
        )
    }

    #[tokio::test]
    async fn test_message_cache() {
        let cache = InMemoryMessageCache::new();

        let messages = vec![test_message("tx1", 100), test_message("tx2", 200)];

        cache.store(&messages, "participant1").await.unwrap();

        let retrieved = cache.retrieve("participant1", None).await.unwrap();
        assert_eq!(retrieved.len(), 2);

        let after_100 = cache.retrieve("participant1", Some(100)).await.unwrap();
        assert_eq!(after_100.len(), 1);
        assert_eq!(after_100[0].id, "tx2");
    }

    #[tokio::test]
    async fn test_public_key_cache() {
        let cache = PublicKeyCache::new(Duration::from_millis(100));
        let key = [42u8; 32];

        cache.store("addr1", key).await;

        let retrieved = cache.retrieve("addr1").await;
        assert_eq!(retrieved, Some(key));

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        let expired = cache.retrieve("addr1").await;
        assert_eq!(expired, None);
    }

    #[tokio::test]
    async fn test_key_storage() {
        let storage = InMemoryKeyStorage::new();
        let key = [42u8; 32];

        assert!(!storage.has_key("addr1").await);

        storage.store(&key, "addr1", false).await.unwrap();
        assert!(storage.has_key("addr1").await);

        let retrieved = storage.retrieve("addr1").await.unwrap();
        assert_eq!(retrieved, key);

        storage.delete("addr1").await.unwrap();
        assert!(!storage.has_key("addr1").await);
    }
}
