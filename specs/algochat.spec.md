---
module: algochat
version: 1.0.0
status: active
owner: CorvidAgent
files:
  - src/algochat.rs
  - src/blockchain.rs
  - src/models.rs
  - src/storage.rs
  - src/queue.rs
  - src/types.rs
---

# AlgoChat Spec

The AlgoChat protocol: encrypted messaging on the Algorand blockchain. Covers the main client interface, Algorand blockchain integration (algod/indexer traits), message and conversation models, message caching, public key caching, send queue for offline support, and contact/key discovery.

## Public Types

### `AlgoChatConfig`
Configuration for the AlgoChat client.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `network` | `AlgorandConfig` | - | Algorand node connection settings |
| `auto_discover_keys` | `bool` | `true` | Auto-discover recipient encryption keys |
| `cache_public_keys` | `bool` | `true` | Cache discovered public keys |
| `cache_messages` | `bool` | `true` | Cache messages locally |

Methods:
- `fn new(network: AlgorandConfig) -> Self` - Creates config with defaults.
- `fn localnet() -> Self` - LocalNet config (localhost:4001, localhost:8980).
- `fn testnet() -> Self` - TestNet config (Nodely endpoints).
- `fn mainnet() -> Self` - MainNet config (Nodely endpoints).

### `AlgoChat<A, I, S, M>`
Main client, generic over `AlgodClient`, `IndexerClient`, `EncryptionKeyStorage`, `MessageCache`.

| Field | Type | Description |
|-------|------|-------------|
| `address` | `String` | User's Algorand address |
| `ed25519_public_key` | `[u8; 32]` | User's Ed25519 public key |
| `encryption_private_key` | `StaticSecret` | X25519 private key |
| `encryption_public_key` | `PublicKey` | X25519 public key |
| `config` | `AlgoChatConfig` | Client configuration |
| `algod` | `A` | Algod client for submitting transactions |
| `indexer` | `I` | Indexer client for searching transactions |
| `key_storage` | `S` | Encryption key storage |
| `message_cache` | `M` | Message cache |
| `public_key_cache` | `PublicKeyCache` | In-memory public key cache with TTL |
| `send_queue` | `SendQueue` | Offline message queue |
| `conversations` | `Arc<RwLock<Vec<Conversation>>>` | Active conversations |

### `AlgorandConfig`
Algorand node connection configuration.

| Field | Type | Description |
|-------|------|-------------|
| `algod_url` | `String` | Algod node URL |
| `algod_token` | `String` | Algod API token |
| `indexer_url` | `Option<String>` | Indexer URL |
| `indexer_token` | `Option<String>` | Indexer API token |

Methods:
- `fn new(algod_url: &str, algod_token: &str) -> Self`
- `fn with_indexer(self, url: &str, token: &str) -> Self`
- `fn localnet() -> Self` / `fn testnet() -> Self` / `fn mainnet() -> Self`

### `NoteTransaction`
A blockchain transaction with a note field.

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `String` | Transaction ID |
| `sender` | `String` | Sender Algorand address |
| `receiver` | `String` | Receiver Algorand address |
| `note` | `Vec<u8>` | Note field contents |
| `confirmed_round` | `u64` | Confirmation round |
| `round_time` | `u64` | Block timestamp (Unix) |

### `TransactionInfo`
Result of transaction submission.

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `String` | Transaction ID |
| `confirmed_round` | `Option<u64>` | Confirmation round |

### `SuggestedParams`
Network parameters for transaction construction.

| Field | Type | Description |
|-------|------|-------------|
| `fee` | `u64` | Fee per byte (microAlgos) |
| `min_fee` | `u64` | Minimum fee (microAlgos) |
| `first_valid` | `u64` | First valid round |
| `last_valid` | `u64` | Last valid round |
| `genesis_id` | `String` | Genesis ID |
| `genesis_hash` | `[u8; 32]` | Genesis hash |

### `AccountInfo`
Account balance information.

| Field | Type | Description |
|-------|------|-------------|
| `address` | `String` | Account address |
| `amount` | `u64` | Balance (microAlgos) |
| `min_balance` | `u64` | Minimum balance required |

### `Message`
A chat message between Algorand addresses.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Unique identifier (transaction ID) |
| `sender` | `String` | Sender's Algorand address |
| `recipient` | `String` | Recipient's Algorand address |
| `content` | `String` | Decrypted message text |
| `timestamp` | `SystemTime` | On-chain confirmation time |
| `confirmed_round` | `u64` | Confirmation round |
| `direction` | `MessageDirection` | Sent or Received |
| `reply_context` | `Option<ReplyContext>` | Reply metadata |

Methods:
- `fn new(id, sender, recipient, content, timestamp, confirmed_round, direction, reply_context) -> Self`
- `fn is_reply(&self) -> bool` - Whether this message has reply context.
- `fn unix_timestamp(&self) -> u64` - Timestamp as Unix seconds.

Hash implementation: based on `id` field only (two Messages with the same txid hash equally).

### `MessageDirection`
```rust
enum MessageDirection { Sent, Received }
```

### `Conversation`
A conversation between two Algorand addresses.

| Field | Type | Description |
|-------|------|-------------|
| `participant` | `String` | Other party's address |
| `participant_encryption_key` | `Option<[u8; 32]>` | Cached X25519 key |
| `messages` | `Vec<Message>` | Messages (private, chronologically sorted) |
| `last_fetched_round` | `Option<u64>` | Last synced round |

Methods:
- `fn new(participant: impl Into<String>) -> Self`
- `fn with_key(participant, encryption_key: [u8; 32]) -> Self`
- `fn id(&self) -> &str` - Returns participant address.
- `fn messages(&self) -> &[Message]`
- `fn last_message(&self) -> Option<&Message>`
- `fn last_received(&self) -> Option<&Message>` / `fn last_sent(&self) -> Option<&Message>`
- `fn received_messages(&self) -> impl Iterator` / `fn sent_messages(&self) -> impl Iterator`
- `fn message_count(&self) -> usize` / `fn is_empty(&self) -> bool`
- `fn append(&mut self, message: Message)` - Adds a message, deduplicates by ID, re-sorts by timestamp.
- `fn merge(&mut self, new_messages: impl IntoIterator<Item = Message>)` - Appends multiple messages.

### `ReplyContext`
Reply metadata linking a message to its parent.

| Field | Type | Description |
|-------|------|-------------|
| `message_id` | `String` | Transaction ID of original message |
| `preview` | `String` | Truncated preview of original |

Methods:
- `fn new(message_id, preview) -> Self`
- `fn from_message(message: &Message, max_length: usize) -> Self` - Truncates with `...` if needed.

### `DiscoveredKey`
Result of key discovery.

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | `[u8; 32]` | X25519 public key |
| `is_verified` | `bool` | Whether Ed25519 signature was verified |

### `SendOptions`
Options for message sending.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `wait_for_confirmation` | `bool` | `false` | Wait for algod confirmation |
| `timeout_rounds` | `u64` | `10` | Max rounds to wait |
| `wait_for_indexer` | `bool` | `false` | Wait for indexer visibility |
| `indexer_timeout_secs` | `u64` | `30` | Max seconds for indexer |
| `reply_context` | `Option<ReplyContext>` | `None` | Reply metadata |

Factory methods: `fire_and_forget()`, `confirmed()`, `indexed()`, `replying_to(message)`.

### `SendResult`
Successful send result containing `txid: String` and `message: Message`.

### `PendingMessage`
Message queued for sending (offline support).

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | UUID v4 |
| `recipient` | `String` | Recipient address |
| `content` | `String` | Message text |
| `reply_context` | `Option<ReplyContext>` | Reply metadata |
| `created_at` | `SystemTime` | Creation time |
| `retry_count` | `u32` | Number of retries |
| `last_attempt` | `Option<SystemTime>` | Last send attempt |
| `status` | `PendingStatus` | Current status |
| `last_error` | `Option<String>` | Last error message |

### `PendingStatus`
```rust
enum PendingStatus { Pending, Sending, Failed, Sent }
```

### `ChatAccount`
Algorand account with derived encryption keys.

Methods:
- `fn from_seed(address, seed: &[u8; 32], ed25519_public_key: [u8; 32]) -> Result<Self>`
- `fn from_algorand_account(address, secret_key: &[u8; 64]) -> Result<Self>` - First 32 bytes = seed, last 32 = Ed25519 pubkey.
- `fn from_raw_keys(address, ed25519_public_key, encryption_private_key: [u8; 32]) -> Self`
- `fn public_key_bytes(&self) -> [u8; 32]`
- `fn private_key_bytes(&self) -> [u8; 32]`
- `fn encryption_private_key(&self) -> &StaticSecret`
- `fn encryption_public_key(&self) -> &PublicKey`

### `QueueConfig`
Send queue configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_retries` | `u32` | `3` | Maximum retry attempts |
| `retry_delay` | `Duration` | `5s` | Delay between retries |
| `max_queue_size` | `usize` | `100` | Maximum queue size |

### `PublicKeyCache`
In-memory TTL cache for X25519 public keys.

Methods:
- `fn new(ttl: Duration) -> Self`
- `fn with_default_ttl() -> Self` - 24-hour TTL.
- `async fn store(&self, address: &str, key: [u8; 32])`
- `async fn retrieve(&self, address: &str) -> Option<[u8; 32]>` - Returns `None` if expired.
- `async fn invalidate(&self, address: &str)`
- `async fn clear(&self)`
- `async fn prune_expired(&self)` - Removes all expired entries.

## Public Traits

### `AlgodClient`
Async trait for interacting with an Algorand algod node.

| Method | Signature |
|--------|-----------|
| `get_suggested_params` | `async fn get_suggested_params(&self) -> Result<SuggestedParams>` |
| `get_account_info` | `async fn get_account_info(&self, address: &str) -> Result<AccountInfo>` |
| `submit_transaction` | `async fn submit_transaction(&self, signed_txn: &[u8]) -> Result<String>` |
| `wait_for_confirmation` | `async fn wait_for_confirmation(&self, txid: &str, rounds: u32) -> Result<TransactionInfo>` |
| `get_current_round` | `async fn get_current_round(&self) -> Result<u64>` |

### `IndexerClient`
Async trait for searching Algorand transactions.

| Method | Signature |
|--------|-----------|
| `search_transactions` | `async fn search_transactions(&self, address: &str, after_round: Option<u64>, limit: Option<u32>) -> Result<Vec<NoteTransaction>>` |
| `search_transactions_between` | `async fn search_transactions_between(&self, address1: &str, address2: &str, after_round: Option<u64>, limit: Option<u32>) -> Result<Vec<NoteTransaction>>` |
| `get_transaction` | `async fn get_transaction(&self, txid: &str) -> Result<NoteTransaction>` |
| `wait_for_indexer` | `async fn wait_for_indexer(&self, txid: &str, timeout_secs: u32) -> Result<NoteTransaction>` |

### `MessageCache`
Async trait for storing and retrieving messages.

| Method | Signature |
|--------|-----------|
| `store` | `async fn store(&self, messages: &[Message], participant: &str) -> Result<()>` |
| `retrieve` | `async fn retrieve(&self, participant: &str, after_round: Option<u64>) -> Result<Vec<Message>>` |
| `get_last_sync_round` | `async fn get_last_sync_round(&self, participant: &str) -> Result<Option<u64>>` |
| `set_last_sync_round` | `async fn set_last_sync_round(&self, round: u64, participant: &str) -> Result<()>` |
| `get_cached_conversations` | `async fn get_cached_conversations(&self) -> Result<Vec<String>>` |
| `clear` | `async fn clear(&self) -> Result<()>` |
| `clear_for` | `async fn clear_for(&self, participant: &str) -> Result<()>` |

Implementation: `InMemoryMessageCache` - HashMap-based, deduplicates by message ID, sorts by timestamp.

## AlgoChat Client Methods

### Construction

#### `async fn from_seed(seed, address, config, algod, indexer, key_storage, message_cache) -> Result<Self>`
Creates a client from a 32-byte seed. Derives X25519 keys, stores the private key via `EncryptionKeyStorage`, and derives the Ed25519 public key from the seed.

### Accessors

- `fn address(&self) -> &str` - User's Algorand address.
- `fn encryption_public_key(&self) -> [u8; 32]` - User's X25519 public key bytes.
- `fn send_queue(&self) -> &SendQueue` - Reference to the send queue.
- `fn message_cache(&self) -> &M` - Reference to the message cache.
- `fn public_key_cache(&self) -> &PublicKeyCache` - Reference to the public key cache.

### Conversations

#### `async fn conversation(&self, participant: &str) -> Conversation`
Gets or creates a conversation with a participant. Returns existing conversation if one exists, otherwise creates a new empty one.

#### `async fn conversations(&self) -> Vec<Conversation>`
Returns all active conversations.

### Encryption

#### `fn encrypt(&self, message: &str, recipient_public_key: &[u8; 32]) -> Result<Vec<u8>>`
Encrypts a message and returns the encoded envelope bytes.

#### `fn decrypt(&self, envelope_bytes: &[u8], sender_public_key: &[u8; 32]) -> Result<String>`
Decrypts envelope bytes. Validates it's an AlgoChat message first. Returns `DecryptionError` for key-publish messages.

### Key Discovery

#### `async fn discover_key(&self, address: &str) -> Result<Option<DiscoveredKey>>`
Discovers the encryption public key for an address.
1. Checks `PublicKeyCache` first (if caching enabled). Cached keys are returned as `is_verified: true`.
2. Falls back to indexer search via `discover_encryption_key()`.
3. Caches discovered keys (if caching enabled).

### Message Processing

#### `async fn process_transaction(&self, tx: &NoteTransaction) -> Result<Option<Message>>`
Processes a single blockchain transaction:
1. Checks if it's an AlgoChat message (`is_chat_message`).
2. Determines direction (Sent/Received) based on sender/receiver matching our address.
3. Discovers the other party's encryption key.
4. Decrypts the message.
5. Creates a `Message`, updates the conversation, and caches.

#### `async fn sync(&self) -> Result<Vec<Message>>`
Fetches and processes new messages from the blockchain. Searches the indexer for transactions involving our address (limit 100) and processes each one.

### Key Discovery Function

#### `async fn discover_encryption_key(indexer: &dyn IndexerClient, address: &str) -> Result<Option<DiscoveredKey>>`
Standalone function that searches for key announcement transactions:
- Looks for self-transfers (sender == receiver == address) with note >= 32 bytes.
- Note format: X25519 public key (32 bytes) + optional Ed25519 signature (64 bytes).
- If signature present and Algorand address decodes to a valid Ed25519 key, verifies the signature.

## SendQueue Methods

- `fn new(config: QueueConfig) -> Self` / `fn with_defaults() -> Self`
- `async fn enqueue(&self, message: PendingMessage) -> Result<()>` - Adds to queue; prunes failed messages if full.
- `async fn next_pending(&self) -> Option<PendingMessage>` - Next `Pending` status message.
- `async fn all_pending(&self) -> Vec<PendingMessage>` - All `Pending` status messages.
- `async fn ready_for_retry(&self) -> Vec<PendingMessage>` - Failed messages past retry delay.
- `async fn mark_sending(&self, id: &str) -> Result<()>`
- `async fn mark_sent(&self, id: &str) -> Result<()>`
- `async fn mark_failed(&self, id: &str, error: &str) -> Result<()>`
- `async fn remove(&self, id: &str) -> Option<PendingMessage>`
- `async fn prune_sent(&self)` - Removes all `Sent` messages.
- `async fn prune_failed(&self)` - Removes failed messages past max retries.
- `async fn clear(&self)` - Removes all messages.
- `async fn len(&self) -> usize` / `async fn is_empty(&self) -> bool`
- `async fn pending_count(&self) -> usize` / `async fn failed_count(&self) -> usize`
- `async fn messages_for(&self, recipient: &str) -> Vec<PendingMessage>`
- `async fn reset_for_retry(&self, id: &str) -> Result<()>` - Resets `Failed` to `Pending` if retries remain.

## Invariants

1. Messages are identified by transaction ID (`txid`). Two messages with the same txid are considered identical.
2. `Conversation::append` deduplicates by message ID; appending a message with an existing ID is a no-op.
3. Messages within a `Conversation` are always sorted chronologically by `timestamp`.
4. `MessageCache::store` deduplicates by message ID across calls.
5. `PublicKeyCache` entries expire after the configured TTL; `retrieve` returns `None` for expired entries.
6. Key announcements are self-transfers (sender == receiver) with note >= 32 bytes.
7. A key announcement with 96+ byte note includes an Ed25519 signature over the X25519 key at bytes [32..96].
8. `discover_key` returns cached keys as `is_verified: true` (trust-on-first-use).
9. `process_transaction` ignores transactions where neither sender nor receiver matches our address.
10. `process_transaction` ignores non-AlgoChat messages (those failing `is_chat_message` check).
11. The send queue rejects new messages when full (`max_queue_size`), after attempting to prune exhausted failures.
12. `PendingMessage::can_retry` returns `false` when `retry_count >= max_retries` or status is not `Failed`.
13. `ready_for_retry` only returns messages whose `last_attempt` is older than `retry_delay`.
14. `PendingMessage.id` is a UUID v4, unique per message.
15. `SendQueue::mark_sending/mark_sent/mark_failed/reset_for_retry` return `MessageNotFound` for unknown IDs.
16. Algorand address decoding validates the 4-byte SHA-512/256 checksum; invalid checksums are rejected.
17. `Conversation::merge` preserves dedup and chronological sort guarantees.
18. `from_seed` stores the derived encryption private key via `EncryptionKeyStorage` on construction.
19. `encrypt` returns encoded envelope bytes ready for inclusion in a transaction note field.
20. `decrypt` rejects data that doesn't pass the `is_chat_message` check with `InvalidEnvelope`.

## Behavioral Examples

### Client Creation and Key Derivation

```
Given a 32-byte seed and an Algorand address
When AlgoChat::from_seed is called
Then the client's encryption_public_key matches derive_keys_from_seed(seed)
And the private key is stored via EncryptionKeyStorage
And two clients from different seeds have different public keys
```

### Encrypt/Decrypt Roundtrip via Client

```
Given Alice and Bob each have AlgoChat clients from different seeds
When Alice encrypts "Hello, Bob!" using Bob's public key
Then Bob can decrypt the envelope bytes and recover "Hello, Bob!"
And Alice can also decrypt her own message (bidirectional)
```

### Conversation Management

```
Given a fresh AlgoChat client
When conversation("BOB_ADDR") is called
Then a new empty Conversation is created with participant="BOB_ADDR"
And calling conversation("BOB_ADDR") again returns the same conversation
And conversations() returns a list containing one entry
```

### Message Deduplication in Conversation

```
Given a conversation with a message id="tx1"
When append is called with another message with id="tx1"
Then message_count remains 1 (no duplicate)
```

### Key Discovery Flow

```
Given Bob has published a self-transfer transaction with his X25519 key in the note
When Alice calls discover_key("BOB_ADDR")
Then she receives Some(DiscoveredKey) with Bob's public key
And a second call returns the cached key with is_verified=true
```

### Sync New Messages

```
Given the indexer contains AlgoChat transactions for our address
When sync() is called
Then each valid AlgoChat transaction is decrypted and returned as a Message
And conversations are updated with the new messages
And messages are stored in the message cache
```

### Process Non-Chat Transaction

```
Given a NoteTransaction with note bytes that don't match AlgoChat format
When process_transaction is called
Then it returns Ok(None)
```

### Send Queue Lifecycle

```
Given a SendQueue with max_retries=3
When a PendingMessage is enqueued
Then pending_count() returns 1
When mark_sending(id) is called, then pending_count() returns 0
When mark_failed(id, "error") is called, then failed_count() returns 1
When retry_delay has elapsed, then ready_for_retry() includes the message
When mark_sent(id) is called and prune_sent() is called, the queue is empty
```

### Send Queue Full Rejection

```
Given a SendQueue with max_queue_size=2 and 2 pending messages
When a third enqueue is attempted
Then it returns Err(StorageFailed("Queue is full"))
```

### Message Cache with Sync Rounds

```
Given an InMemoryMessageCache
When messages are stored for "alice" and set_last_sync_round(500, "alice") is called
Then get_last_sync_round("alice") returns Some(500)
And retrieve("alice", Some(500)) returns only messages with confirmed_round > 500
```

### Public Key Cache Expiration

```
Given a PublicKeyCache with ttl=100ms
When a key is stored and 150ms elapse
Then retrieve returns None (expired)
```

## Error Cases

| Scenario | Error |
|----------|-------|
| Decrypt non-AlgoChat data | `InvalidEnvelope("Not an AlgoChat message")` |
| Decrypt with wrong key | `DecryptionError("Decryption failed: ...")` |
| Key-publish message decrypted | `DecryptionError("Message was a key-publish, not a chat message")` |
| Discover key, recipient has none | Returns `Ok(None)` |
| Process tx, key not found for peer | `PublicKeyNotFound(address)` |
| Queue full, enqueue fails | `StorageFailed("Queue is full")` |
| Mark unknown message ID | `MessageNotFound(id)` |
| Reset retry on exhausted message | `StorageFailed("Message has exceeded max retries")` |
| Transaction not found | `TransactionFailed("Transaction not found: ...")` |
| Insufficient balance | `InsufficientBalance { required, available }` |
| Key not in storage | `KeyNotFound(address)` |
| Storage operation fails | `StorageFailed(message)` |

## Change Log

| Date | Author | Description |
|------|--------|-------------|
| 2026-03-28 | CorvidAgent | Initial spec covering AlgoChat client, blockchain, models, storage, and queue |
