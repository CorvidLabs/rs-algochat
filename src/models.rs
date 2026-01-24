//! Data models for AlgoChat.
//!
//! This module defines the core types for messages, conversations, accounts,
//! and related structures used throughout the library.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Context for a reply message, linking it to the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyContext {
    /// Transaction ID of the original message.
    pub message_id: String,
    /// Preview of the original message (truncated).
    pub preview: String,
}

impl ReplyContext {
    /// Creates a new reply context.
    pub fn new(message_id: impl Into<String>, preview: impl Into<String>) -> Self {
        Self {
            message_id: message_id.into(),
            preview: preview.into(),
        }
    }

    /// Creates a reply context from a message, truncating the preview.
    pub fn from_message(message: &Message, max_length: usize) -> Self {
        let preview = if message.content.len() > max_length {
            format!("{}...", &message.content[..max_length.saturating_sub(3)])
        } else {
            message.content.clone()
        };

        Self {
            message_id: message.id.clone(),
            preview,
        }
    }
}

/// Direction of a message relative to the current user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageDirection {
    /// Message was sent by the current user.
    Sent,
    /// Message was received by the current user.
    Received,
}

/// A chat message between Algorand addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Unique identifier (transaction ID).
    pub id: String,
    /// Sender's Algorand address.
    pub sender: String,
    /// Recipient's Algorand address.
    pub recipient: String,
    /// Decrypted message content.
    pub content: String,
    /// Timestamp when the message was confirmed on-chain.
    pub timestamp: SystemTime,
    /// The round in which the transaction was confirmed.
    pub confirmed_round: u64,
    /// Message direction relative to the current user.
    pub direction: MessageDirection,
    /// Reply context if this message is a reply.
    pub reply_context: Option<ReplyContext>,
}

impl Message {
    /// Creates a new message.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        content: impl Into<String>,
        timestamp: SystemTime,
        confirmed_round: u64,
        direction: MessageDirection,
        reply_context: Option<ReplyContext>,
    ) -> Self {
        Self {
            id: id.into(),
            sender: sender.into(),
            recipient: recipient.into(),
            content: content.into(),
            timestamp,
            confirmed_round,
            direction,
            reply_context,
        }
    }

    /// Whether this message is a reply to another message.
    pub fn is_reply(&self) -> bool {
        self.reply_context.is_some()
    }

    /// Returns the Unix timestamp in seconds.
    pub fn unix_timestamp(&self) -> u64 {
        self.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

impl std::hash::Hash for Message {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// A conversation between two Algorand addresses.
#[derive(Debug, Clone)]
pub struct Conversation {
    /// The other party's Algorand address.
    pub participant: String,
    /// Cached encryption public key for the participant (32 bytes).
    pub participant_encryption_key: Option<[u8; 32]>,
    /// Messages in chronological order.
    messages: Vec<Message>,
    /// The round of the last fetched message (for pagination).
    pub last_fetched_round: Option<u64>,
}

impl Conversation {
    /// Creates a new conversation.
    pub fn new(participant: impl Into<String>) -> Self {
        Self {
            participant: participant.into(),
            participant_encryption_key: None,
            messages: Vec::new(),
            last_fetched_round: None,
        }
    }

    /// Creates a conversation with a known encryption key.
    pub fn with_key(participant: impl Into<String>, encryption_key: [u8; 32]) -> Self {
        Self {
            participant: participant.into(),
            participant_encryption_key: Some(encryption_key),
            messages: Vec::new(),
            last_fetched_round: None,
        }
    }

    /// Returns the unique identifier (the participant's address).
    pub fn id(&self) -> &str {
        &self.participant
    }

    /// Returns all messages in the conversation.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Returns the most recent message.
    pub fn last_message(&self) -> Option<&Message> {
        self.messages.last()
    }

    /// Returns the most recent received message.
    pub fn last_received(&self) -> Option<&Message> {
        self.messages
            .iter()
            .rev()
            .find(|m| m.direction == MessageDirection::Received)
    }

    /// Returns the most recent sent message.
    pub fn last_sent(&self) -> Option<&Message> {
        self.messages
            .iter()
            .rev()
            .find(|m| m.direction == MessageDirection::Sent)
    }

    /// Returns all received messages.
    pub fn received_messages(&self) -> impl Iterator<Item = &Message> {
        self.messages
            .iter()
            .filter(|m| m.direction == MessageDirection::Received)
    }

    /// Returns all sent messages.
    pub fn sent_messages(&self) -> impl Iterator<Item = &Message> {
        self.messages
            .iter()
            .filter(|m| m.direction == MessageDirection::Sent)
    }

    /// Returns the number of messages.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Whether the conversation has any messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Adds a message to the conversation (maintains chronological order).
    pub fn append(&mut self, message: Message) {
        if self.messages.iter().any(|m| m.id == message.id) {
            return;
        }
        self.messages.push(message);
        self.messages.sort_by_key(|m| m.timestamp);
    }

    /// Merges new messages into the conversation.
    pub fn merge(&mut self, new_messages: impl IntoIterator<Item = Message>) {
        for message in new_messages {
            self.append(message);
        }
    }
}

/// Result of discovering a user's encryption key.
#[derive(Debug, Clone)]
pub struct DiscoveredKey {
    /// The X25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Whether the key was cryptographically verified via Ed25519 signature.
    pub is_verified: bool,
}

impl DiscoveredKey {
    /// Creates a new discovered key.
    pub fn new(public_key: [u8; 32], is_verified: bool) -> Self {
        Self {
            public_key,
            is_verified,
        }
    }
}

/// Options for sending a message.
#[derive(Debug, Clone)]
pub struct SendOptions {
    /// Wait for algod confirmation.
    pub wait_for_confirmation: bool,
    /// Maximum rounds to wait for confirmation.
    pub timeout_rounds: u64,
    /// Wait for indexer visibility.
    pub wait_for_indexer: bool,
    /// Maximum seconds to wait for indexer.
    pub indexer_timeout_secs: u64,
    /// Reply context if replying to a message.
    pub reply_context: Option<ReplyContext>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            wait_for_confirmation: false,
            timeout_rounds: 10,
            wait_for_indexer: false,
            indexer_timeout_secs: 30,
            reply_context: None,
        }
    }
}

impl SendOptions {
    /// Fire-and-forget (no waiting).
    pub fn fire_and_forget() -> Self {
        Self::default()
    }

    /// Wait for algod confirmation only.
    pub fn confirmed() -> Self {
        Self {
            wait_for_confirmation: true,
            ..Default::default()
        }
    }

    /// Wait for both algod and indexer.
    pub fn indexed() -> Self {
        Self {
            wait_for_confirmation: true,
            wait_for_indexer: true,
            ..Default::default()
        }
    }

    /// Create options for replying to a message.
    pub fn replying_to(message: &Message) -> Self {
        Self {
            reply_context: Some(ReplyContext::from_message(message, 80)),
            ..Default::default()
        }
    }

    /// Set the reply context.
    pub fn with_reply(mut self, context: ReplyContext) -> Self {
        self.reply_context = Some(context);
        self
    }
}

/// Result of a successful send operation.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// Transaction ID.
    pub txid: String,
    /// The sent message (for optimistic UI updates).
    pub message: Message,
}

impl SendResult {
    /// Creates a new send result.
    pub fn new(txid: impl Into<String>, message: Message) -> Self {
        Self {
            txid: txid.into(),
            message,
        }
    }
}

/// Status of a pending message in the send queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatus {
    /// Waiting to be sent.
    Pending,
    /// Currently being sent.
    Sending,
    /// Send attempt failed.
    Failed,
    /// Successfully sent.
    Sent,
}

/// A message queued for sending (for offline support).
#[derive(Debug, Clone)]
pub struct PendingMessage {
    /// Unique identifier.
    pub id: String,
    /// Recipient's Algorand address.
    pub recipient: String,
    /// Message content.
    pub content: String,
    /// Reply context if replying.
    pub reply_context: Option<ReplyContext>,
    /// When the message was created.
    pub created_at: SystemTime,
    /// Number of retry attempts.
    pub retry_count: u32,
    /// Last attempt time.
    pub last_attempt: Option<SystemTime>,
    /// Current status.
    pub status: PendingStatus,
    /// Last error message.
    pub last_error: Option<String>,
}

impl PendingMessage {
    /// Creates a new pending message.
    pub fn new(
        recipient: impl Into<String>,
        content: impl Into<String>,
        reply_context: Option<ReplyContext>,
    ) -> Self {
        Self {
            id: uuid_v4(),
            recipient: recipient.into(),
            content: content.into(),
            reply_context,
            created_at: SystemTime::now(),
            retry_count: 0,
            last_attempt: None,
            status: PendingStatus::Pending,
            last_error: None,
        }
    }

    /// Mark as currently sending.
    pub fn mark_sending(&mut self) {
        self.status = PendingStatus::Sending;
        self.last_attempt = Some(SystemTime::now());
    }

    /// Mark as failed with an error.
    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = PendingStatus::Failed;
        self.retry_count += 1;
        self.last_error = Some(error.into());
    }

    /// Mark as successfully sent.
    pub fn mark_sent(&mut self) {
        self.status = PendingStatus::Sent;
    }

    /// Whether the message can be retried.
    pub fn can_retry(&self, max_retries: u32) -> bool {
        self.retry_count < max_retries && self.status == PendingStatus::Failed
    }
}

/// A chat-enabled Algorand account with encryption keys.
///
/// The ChatAccount wraps an Algorand address with derived X25519 encryption keys.
/// The private key should be stored securely using an EncryptionKeyStorage implementation.
#[derive(Clone)]
pub struct ChatAccount {
    /// The Algorand address (58 characters).
    pub address: String,
    /// The Ed25519 public key from the Algorand account (32 bytes).
    pub ed25519_public_key: [u8; 32],
    /// The X25519 private key for decryption.
    encryption_private_key: x25519_dalek::StaticSecret,
    /// The X25519 public key for encryption.
    encryption_public_key: x25519_dalek::PublicKey,
}

impl ChatAccount {
    /// Create a ChatAccount from a 32-byte seed and Ed25519 public key.
    ///
    /// This derives the X25519 encryption keys from the seed using HKDF-SHA256.
    ///
    /// # Arguments
    /// * `address` - The Algorand address
    /// * `seed` - 32-byte seed (first 32 bytes of Algorand secret key)
    /// * `ed25519_public_key` - The Ed25519 public key (last 32 bytes of secret key)
    ///
    /// # Returns
    /// A new ChatAccount instance
    pub fn from_seed(
        address: impl Into<String>,
        seed: &[u8; 32],
        ed25519_public_key: [u8; 32],
    ) -> crate::types::Result<Self> {
        let (private_key, public_key) = crate::keys::derive_keys_from_seed(seed)?;
        Ok(Self {
            address: address.into(),
            ed25519_public_key,
            encryption_private_key: private_key,
            encryption_public_key: public_key,
        })
    }

    /// Create a ChatAccount from an Algorand secret key.
    ///
    /// The Algorand secret key is 64 bytes: the first 32 are the seed,
    /// and the last 32 are the Ed25519 public key.
    ///
    /// # Arguments
    /// * `address` - The Algorand address
    /// * `secret_key` - 64-byte Algorand secret key
    pub fn from_algorand_account(
        address: impl Into<String>,
        secret_key: &[u8; 64],
    ) -> crate::types::Result<Self> {
        let seed: [u8; 32] = secret_key[..32].try_into().unwrap();
        let ed25519_public_key: [u8; 32] = secret_key[32..].try_into().unwrap();

        Self::from_seed(address, &seed, ed25519_public_key)
    }

    /// Create a ChatAccount by providing the raw keys directly.
    ///
    /// This is useful when loading keys from storage.
    ///
    /// # Arguments
    /// * `address` - The Algorand address
    /// * `ed25519_public_key` - The Ed25519 public key (32 bytes)
    /// * `encryption_private_key` - The X25519 private key (32 bytes)
    pub fn from_raw_keys(
        address: impl Into<String>,
        ed25519_public_key: [u8; 32],
        encryption_private_key: [u8; 32],
    ) -> Self {
        let private_key = x25519_dalek::StaticSecret::from(encryption_private_key);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        Self {
            address: address.into(),
            ed25519_public_key,
            encryption_private_key: private_key,
            encryption_public_key: public_key,
        }
    }

    /// The encryption public key as raw bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.encryption_public_key.as_bytes()
    }

    /// The encryption private key as raw bytes (32 bytes).
    ///
    /// Warning: Handle with care. This should only be used for secure storage.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.encryption_private_key.to_bytes()
    }

    /// Get a reference to the X25519 private key.
    pub fn encryption_private_key(&self) -> &x25519_dalek::StaticSecret {
        &self.encryption_private_key
    }

    /// Get a reference to the X25519 public key.
    pub fn encryption_public_key(&self) -> &x25519_dalek::PublicKey {
        &self.encryption_public_key
    }
}

impl std::fmt::Debug for ChatAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatAccount")
            .field("address", &self.address)
            .field("public_key", &hex::encode(self.public_key_bytes()))
            .finish()
    }
}

impl std::fmt::Display for ChatAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChatAccount({})", self.address)
    }
}

/// Generate a simple UUID v4 (for pending message IDs).
fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        (u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0fff) | 0x4000,
        (u16::from_be_bytes([bytes[8], bytes[9]]) & 0x3fff) | 0x8000,
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_context() {
        let ctx = ReplyContext::new("txid123", "Hello world");
        assert_eq!(ctx.message_id, "txid123");
        assert_eq!(ctx.preview, "Hello world");
    }

    #[test]
    fn test_reply_context_truncation() {
        let message = Message::new(
            "txid123",
            "sender",
            "recipient",
            "This is a very long message that should be truncated",
            SystemTime::now(),
            1000,
            MessageDirection::Received,
            None,
        );

        let ctx = ReplyContext::from_message(&message, 20);
        assert!(ctx.preview.ends_with("..."));
        assert!(ctx.preview.len() <= 20);
    }

    #[test]
    fn test_conversation_append() {
        let mut conv = Conversation::new("participant123");
        assert!(conv.is_empty());

        let msg = Message::new(
            "tx1",
            "sender",
            "recipient",
            "Hello",
            SystemTime::now(),
            1000,
            MessageDirection::Sent,
            None,
        );

        conv.append(msg.clone());
        assert_eq!(conv.message_count(), 1);

        // Duplicate should not be added
        conv.append(msg);
        assert_eq!(conv.message_count(), 1);
    }

    #[test]
    fn test_send_options() {
        let opts = SendOptions::default();
        assert!(!opts.wait_for_confirmation);

        let opts = SendOptions::confirmed();
        assert!(opts.wait_for_confirmation);
        assert!(!opts.wait_for_indexer);

        let opts = SendOptions::indexed();
        assert!(opts.wait_for_confirmation);
        assert!(opts.wait_for_indexer);
    }

    #[test]
    fn test_pending_message_lifecycle() {
        let mut msg = PendingMessage::new("recipient", "Hello", None);
        assert_eq!(msg.status, PendingStatus::Pending);

        msg.mark_sending();
        assert_eq!(msg.status, PendingStatus::Sending);

        msg.mark_failed("Network error");
        assert_eq!(msg.status, PendingStatus::Failed);
        assert_eq!(msg.retry_count, 1);
        assert!(msg.can_retry(3));

        msg.mark_sending();
        msg.mark_sent();
        assert_eq!(msg.status, PendingStatus::Sent);
    }

    #[test]
    fn test_uuid_generation() {
        let id1 = uuid_v4();
        let id2 = uuid_v4();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // Standard UUID format
    }
}
