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

// ============================================================================
// File-based Key Storage
// ============================================================================

/// File-based encryption key storage with password protection.
///
/// Stores X25519 encryption keys encrypted with AES-256-GCM, using a password
/// derived key via PBKDF2. Keys are stored in `~/.algochat/keys/`.
///
/// ## Storage Format
///
/// Each key file contains:
/// - Salt: 32 bytes (random, for PBKDF2)
/// - Nonce: 12 bytes (random, for AES-GCM)
/// - Ciphertext: 32 bytes (encrypted private key)
/// - Tag: 16 bytes (authentication tag)
///
/// ## Security
///
/// - Uses PBKDF2 with 100,000 iterations for key derivation
/// - Uses AES-256-GCM for authenticated encryption
/// - Keys are stored with 600 permissions (owner read/write only)
/// - Salt is unique per key file
#[allow(clippy::type_complexity)]
pub struct FileKeyStorage {
    password: Arc<RwLock<Option<String>>>,
    cached_key: Arc<RwLock<Option<([u8; 32], [u8; 32])>>>, // (salt, derived_key)
    base_directory: Option<std::path::PathBuf>,
}

impl FileKeyStorage {
    /// PBKDF2 iteration count
    const PBKDF2_ITERATIONS: u32 = 100_000;

    /// Salt size in bytes
    const SALT_SIZE: usize = 32;

    /// AES-GCM nonce size in bytes
    const NONCE_SIZE: usize = 12;

    /// AES-GCM tag size in bytes
    const TAG_SIZE: usize = 16;

    /// Directory name for key storage
    const DIRECTORY_NAME: &'static str = ".algochat/keys";

    /// Minimum file size (salt + nonce + key + tag)
    const MIN_FILE_SIZE: usize = Self::SALT_SIZE + Self::NONCE_SIZE + 32 + Self::TAG_SIZE;

    /// Creates a new file key storage.
    pub fn new() -> Self {
        Self {
            password: Arc::new(RwLock::new(None)),
            cached_key: Arc::new(RwLock::new(None)),
            base_directory: None,
        }
    }

    /// Creates a new file key storage with a password.
    pub fn with_password(password: impl Into<String>) -> Self {
        Self {
            password: Arc::new(RwLock::new(Some(password.into()))),
            cached_key: Arc::new(RwLock::new(None)),
            base_directory: None,
        }
    }

    /// Creates a new file key storage with a custom base directory.
    ///
    /// This is useful for testing or when you want to store keys in a
    /// non-default location.
    pub fn with_directory(
        directory: impl Into<std::path::PathBuf>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            password: Arc::new(RwLock::new(Some(password.into()))),
            cached_key: Arc::new(RwLock::new(None)),
            base_directory: Some(directory.into()),
        }
    }

    /// Sets the password for encryption/decryption.
    pub async fn set_password(&self, password: impl Into<String>) {
        let mut pwd = self.password.write().await;
        *pwd = Some(password.into());
        let mut cached = self.cached_key.write().await;
        *cached = None;
    }

    /// Clears the password and cached keys from memory.
    pub async fn clear_password(&self) {
        let mut pwd = self.password.write().await;
        *pwd = None;
        let mut cached = self.cached_key.write().await;
        *cached = None;
    }

    /// Gets the key storage directory path.
    fn get_directory(&self) -> Result<std::path::PathBuf> {
        if let Some(ref base) = self.base_directory {
            return Ok(base.clone());
        }
        dirs::home_dir()
            .map(|d| d.join(Self::DIRECTORY_NAME))
            .ok_or_else(|| {
                AlgoChatError::StorageFailed("Could not find home directory".to_string())
            })
    }

    /// Ensures the key storage directory exists.
    fn ensure_directory(&self) -> Result<std::path::PathBuf> {
        let directory = self.get_directory()?;
        if !directory.exists() {
            std::fs::create_dir_all(&directory).map_err(|e| {
                AlgoChatError::StorageFailed(format!("Failed to create directory: {}", e))
            })?;
        }

        // Set directory permissions to 700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&directory, perms).ok();
        }

        Ok(directory)
    }

    /// Returns the file path for a key.
    fn key_file_path(address: &str, directory: &std::path::Path) -> std::path::PathBuf {
        directory.join(format!("{}.key", address))
    }

    /// Derives an encryption key from password using PBKDF2.
    async fn derive_key(&self, password: &str, salt: &[u8; 32]) -> [u8; 32] {
        // Check cache
        {
            let cached = self.cached_key.read().await;
            if let Some((cached_salt, cached_key)) = cached.as_ref() {
                if cached_salt == salt {
                    return *cached_key;
                }
            }
        }

        // Derive key using PBKDF2-HMAC-SHA256
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            salt,
            Self::PBKDF2_ITERATIONS,
            &mut derived_key,
        );

        // Cache for this salt
        {
            let mut cached = self.cached_key.write().await;
            *cached = Some((*salt, derived_key));
        }

        derived_key
    }

    /// Sets restrictive file permissions (600 on Unix).
    #[allow(unused_variables)]
    fn set_restrictive_permissions(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms).ok();
        }
    }
}

impl Default for FileKeyStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EncryptionKeyStorage for FileKeyStorage {
    async fn store(
        &self,
        private_key: &[u8; 32],
        address: &str,
        _require_biometric: bool,
    ) -> Result<()> {
        let password = {
            let pwd = self.password.read().await;
            pwd.clone().ok_or_else(|| {
                AlgoChatError::StorageFailed(
                    "Password is required for file key storage".to_string(),
                )
            })?
        };

        // Ensure directory exists
        let directory = self.ensure_directory()?;

        // Generate random salt and nonce (use OsRng which is Send)
        use rand::RngCore;
        let mut salt = [0u8; Self::SALT_SIZE];
        let mut nonce = [0u8; Self::NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // Derive encryption key from password
        let derived_key = self.derive_key(&password, &salt).await;

        // Encrypt the private key with AES-256-GCM
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| AlgoChatError::EncryptionError(e.to_string()))?;
        let gcm_nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(gcm_nonce, private_key.as_slice())
            .map_err(|e| AlgoChatError::EncryptionError(e.to_string()))?;

        // Combine: salt + nonce + ciphertext (includes tag)
        let capacity = Self::SALT_SIZE + Self::NONCE_SIZE + ciphertext.len();
        let mut file_data = Vec::with_capacity(capacity);
        file_data.extend_from_slice(&salt);
        file_data.extend_from_slice(&nonce);
        file_data.extend_from_slice(&ciphertext);

        // Write to file
        let file_path = Self::key_file_path(address, &directory);
        std::fs::write(&file_path, &file_data)
            .map_err(|e| AlgoChatError::StorageFailed(format!("Failed to write key: {}", e)))?;

        // Set restrictive permissions
        Self::set_restrictive_permissions(&file_path);

        Ok(())
    }

    async fn retrieve(&self, address: &str) -> Result<[u8; 32]> {
        let password = {
            let pwd = self.password.read().await;
            pwd.clone().ok_or_else(|| {
                AlgoChatError::StorageFailed(
                    "Password is required for file key storage".to_string(),
                )
            })?
        };

        let directory = self.get_directory()?;
        let file_path = Self::key_file_path(address, &directory);

        // Check if file exists
        if !file_path.exists() {
            return Err(AlgoChatError::KeyNotFound(address.to_string()));
        }

        // Read the encrypted file
        let file_data = std::fs::read(&file_path)
            .map_err(|e| AlgoChatError::StorageFailed(format!("Failed to read key: {}", e)))?;

        // Validate minimum size
        if file_data.len() < Self::MIN_FILE_SIZE {
            return Err(AlgoChatError::StorageFailed(
                "Invalid key data format".to_string(),
            ));
        }

        // Parse: salt + nonce + ciphertext
        let salt: [u8; 32] = file_data[..Self::SALT_SIZE].try_into().unwrap();
        let nonce: [u8; 12] = file_data[Self::SALT_SIZE..Self::SALT_SIZE + Self::NONCE_SIZE]
            .try_into()
            .unwrap();
        let ciphertext = &file_data[Self::SALT_SIZE + Self::NONCE_SIZE..];

        // Derive decryption key from password
        let derived_key = self.derive_key(&password, &salt).await;

        // Decrypt
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| AlgoChatError::DecryptionError(e.to_string()))?;
        let gcm_nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher
            .decrypt(gcm_nonce, ciphertext)
            .map_err(|_| AlgoChatError::DecryptionError("Decryption failed".to_string()))?;

        if plaintext.len() != 32 {
            return Err(AlgoChatError::StorageFailed(
                "Invalid key data format".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(key)
    }

    async fn has_key(&self, address: &str) -> bool {
        let Ok(directory) = self.get_directory() else {
            return false;
        };
        let file_path = Self::key_file_path(address, &directory);
        file_path.exists()
    }

    async fn delete(&self, address: &str) -> Result<()> {
        let directory = self.get_directory()?;
        let file_path = Self::key_file_path(address, &directory);

        if file_path.exists() {
            std::fs::remove_file(&file_path).map_err(|e| {
                AlgoChatError::StorageFailed(format!("Failed to delete key: {}", e))
            })?;
        }

        Ok(())
    }

    async fn list_stored_addresses(&self) -> Result<Vec<String>> {
        let directory = self.get_directory()?;

        if !directory.exists() {
            return Ok(Vec::new());
        }

        let entries = std::fs::read_dir(&directory)
            .map_err(|e| AlgoChatError::StorageFailed(format!("Failed to list keys: {}", e)))?;

        let mut addresses = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "key" {
                    if let Some(stem) = path.file_stem() {
                        if let Some(name) = stem.to_str() {
                            addresses.push(name.to_string());
                        }
                    }
                }
            }
        }

        Ok(addresses)
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

    #[tokio::test]
    async fn test_key_storage_list_addresses() {
        let storage = InMemoryKeyStorage::new();
        let key = [42u8; 32];

        let addrs = storage.list_stored_addresses().await.unwrap();
        assert!(addrs.is_empty());

        storage.store(&key, "addr1", false).await.unwrap();
        storage.store(&key, "addr2", false).await.unwrap();

        let mut addrs = storage.list_stored_addresses().await.unwrap();
        addrs.sort();
        assert_eq!(addrs, vec!["addr1", "addr2"]);
    }

    #[tokio::test]
    async fn test_key_storage_retrieve_missing() {
        let storage = InMemoryKeyStorage::new();
        let result = storage.retrieve("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_message_cache_dedup() {
        let cache = InMemoryMessageCache::new();
        let msg = test_message("tx1", 100);

        cache.store(&[msg.clone()], "alice").await.unwrap();
        cache.store(&[msg], "alice").await.unwrap();

        let retrieved = cache.retrieve("alice", None).await.unwrap();
        assert_eq!(retrieved.len(), 1);
    }

    #[tokio::test]
    async fn test_message_cache_clear() {
        let cache = InMemoryMessageCache::new();
        let messages = vec![test_message("tx1", 100)];

        cache.store(&messages, "alice").await.unwrap();
        cache.set_last_sync_round(100, "alice").await.unwrap();

        cache.clear().await.unwrap();

        let retrieved = cache.retrieve("alice", None).await.unwrap();
        assert!(retrieved.is_empty());
        assert_eq!(cache.get_last_sync_round("alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_message_cache_clear_for() {
        let cache = InMemoryMessageCache::new();

        cache
            .store(&[test_message("tx1", 100)], "alice")
            .await
            .unwrap();
        cache
            .store(&[test_message("tx2", 200)], "bob")
            .await
            .unwrap();
        cache.set_last_sync_round(100, "alice").await.unwrap();
        cache.set_last_sync_round(200, "bob").await.unwrap();

        cache.clear_for("alice").await.unwrap();

        let alice = cache.retrieve("alice", None).await.unwrap();
        assert!(alice.is_empty());
        assert_eq!(cache.get_last_sync_round("alice").await.unwrap(), None);

        let bob = cache.retrieve("bob", None).await.unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(cache.get_last_sync_round("bob").await.unwrap(), Some(200));
    }

    #[tokio::test]
    async fn test_message_cache_get_conversations() {
        let cache = InMemoryMessageCache::new();

        cache
            .store(&[test_message("tx1", 100)], "alice")
            .await
            .unwrap();
        cache
            .store(&[test_message("tx2", 200)], "bob")
            .await
            .unwrap();

        let mut convs = cache.get_cached_conversations().await.unwrap();
        convs.sort();
        assert_eq!(convs, vec!["alice", "bob"]);
    }

    #[tokio::test]
    async fn test_message_cache_sync_rounds() {
        let cache = InMemoryMessageCache::new();

        assert_eq!(cache.get_last_sync_round("alice").await.unwrap(), None);

        cache.set_last_sync_round(500, "alice").await.unwrap();
        assert_eq!(cache.get_last_sync_round("alice").await.unwrap(), Some(500));

        cache.set_last_sync_round(600, "alice").await.unwrap();
        assert_eq!(cache.get_last_sync_round("alice").await.unwrap(), Some(600));
    }

    #[tokio::test]
    async fn test_public_key_cache_invalidate() {
        let cache = PublicKeyCache::new(Duration::from_secs(3600));
        let key = [42u8; 32];

        cache.store("addr1", key).await;
        assert!(cache.retrieve("addr1").await.is_some());

        cache.invalidate("addr1").await;
        assert!(cache.retrieve("addr1").await.is_none());
    }

    #[tokio::test]
    async fn test_public_key_cache_clear() {
        let cache = PublicKeyCache::new(Duration::from_secs(3600));

        cache.store("addr1", [1u8; 32]).await;
        cache.store("addr2", [2u8; 32]).await;

        cache.clear().await;

        assert!(cache.retrieve("addr1").await.is_none());
        assert!(cache.retrieve("addr2").await.is_none());
    }

    #[tokio::test]
    async fn test_public_key_cache_prune_expired() {
        let cache = PublicKeyCache::new(Duration::from_millis(50));

        cache.store("addr1", [1u8; 32]).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        cache.store("addr2", [2u8; 32]).await;

        cache.prune_expired().await;

        assert!(cache.retrieve("addr1").await.is_none());
        assert!(cache.retrieve("addr2").await.is_some());
    }

    #[tokio::test]
    async fn test_public_key_cache_default_ttl() {
        let cache = PublicKeyCache::default();
        let key = [42u8; 32];

        cache.store("addr1", key).await;
        let retrieved = cache.retrieve("addr1").await;
        assert_eq!(retrieved, Some(key));
    }

    #[tokio::test]
    async fn test_file_key_storage_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password-123");
        let key = [42u8; 32];

        assert!(!storage.has_key("TESTADDR1").await);

        storage.store(&key, "TESTADDR1", false).await.unwrap();
        assert!(storage.has_key("TESTADDR1").await);

        let retrieved = storage.retrieve("TESTADDR1").await.unwrap();
        assert_eq!(retrieved, key);
    }

    #[tokio::test]
    async fn test_file_key_storage_delete() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password-123");
        let key = [42u8; 32];

        storage.store(&key, "TESTADDR1", false).await.unwrap();
        assert!(storage.has_key("TESTADDR1").await);

        storage.delete("TESTADDR1").await.unwrap();
        assert!(!storage.has_key("TESTADDR1").await);

        // Deleting non-existent key should not error
        storage.delete("TESTADDR1").await.unwrap();
    }

    #[tokio::test]
    async fn test_file_key_storage_list_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password-123");

        storage.store(&[1u8; 32], "ADDR_A", false).await.unwrap();
        storage.store(&[2u8; 32], "ADDR_B", false).await.unwrap();

        let mut addrs = storage.list_stored_addresses().await.unwrap();
        addrs.sort();
        assert_eq!(addrs, vec!["ADDR_A", "ADDR_B"]);
    }

    #[tokio::test]
    async fn test_file_key_storage_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "correct-password");
        let key = [42u8; 32];

        storage.store(&key, "TESTADDR1", false).await.unwrap();

        // Try to retrieve with wrong password
        let wrong_storage = FileKeyStorage::with_directory(dir.path(), "wrong-password");
        let result = wrong_storage.retrieve("TESTADDR1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_key_storage_no_password() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage {
            password: Arc::new(RwLock::new(None)),
            cached_key: Arc::new(RwLock::new(None)),
            base_directory: Some(dir.path().to_path_buf()),
        };

        let result = storage.store(&[42u8; 32], "TESTADDR1", false).await;
        assert!(result.is_err());

        let result = storage.retrieve("TESTADDR1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_key_storage_set_clear_password() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "initial-password");
        let key = [42u8; 32];

        storage.store(&key, "TESTADDR1", false).await.unwrap();

        // Clear password, should fail
        storage.clear_password().await;
        let result = storage.retrieve("TESTADDR1").await;
        assert!(result.is_err());

        // Set correct password, should succeed
        storage.set_password("initial-password").await;
        let retrieved = storage.retrieve("TESTADDR1").await.unwrap();
        assert_eq!(retrieved, key);
    }

    #[tokio::test]
    async fn test_file_key_storage_retrieve_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password");

        let result = storage.retrieve("NONEXISTENT").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_key_storage_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password");

        storage.store(&[1u8; 32], "TESTADDR1", false).await.unwrap();
        storage.store(&[2u8; 32], "TESTADDR1", false).await.unwrap();

        let retrieved = storage.retrieve("TESTADDR1").await.unwrap();
        assert_eq!(retrieved, [2u8; 32]);
    }

    #[tokio::test]
    async fn test_file_key_storage_corrupt_data() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password");

        // Write truncated data directly to the file
        let file_path = dir.path().join("CORRUPT.key");
        std::fs::write(&file_path, &[0u8; 10]).unwrap();

        let result = storage.retrieve("CORRUPT").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_key_storage_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password");

        let addrs = storage.list_stored_addresses().await.unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn test_file_key_storage_multiple_keys() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileKeyStorage::with_directory(dir.path(), "test-password");

        // Store multiple keys with different values
        for i in 0u8..5 {
            let key = [i; 32];
            let addr = format!("ADDR{}", i);
            storage.store(&key, &addr, false).await.unwrap();
        }

        // Verify each key
        for i in 0u8..5 {
            let addr = format!("ADDR{}", i);
            let retrieved = storage.retrieve(&addr).await.unwrap();
            assert_eq!(retrieved, [i; 32]);
        }
    }
}
