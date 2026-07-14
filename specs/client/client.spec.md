---
module: client
version: 1.0.1
status: active
owner: CorvidLabs
files:
  - src/algochat.rs
  - src/blockchain.rs
  - src/models.rs
  - src/queue.rs
  - src/storage.rs
db_tables: []
depends_on:
  - protocol
  - psk
---

# Client

## Purpose

Defines the high-level AlgoChat client, Algorand network ports, domain models,
offline queue, and storage abstractions. It owns orchestration and persistence
boundaries while delegating cryptographic wire behavior to `protocol` and `psk`.

## Public API

### Exported Functions and Members

| Symbol | Description |
|--------|-------------|
| `new` | Constructs the owning configuration, model, queue, cache, or storage value with validated initial state. |
| `localnet` | Returns localhost Algorand endpoints and defaults. |
| `testnet` | Returns public Algorand testnet endpoints and defaults. |
| `mainnet` | Returns public Algorand mainnet endpoints and defaults. |
| `with_indexer` | Adds indexer endpoint and token configuration. |
| `DEFAULT_DISCOVERY_PAGE_SIZE` | Bounds one indexer discovery request to 100 transactions. |
| `from_seed` | Derives an AlgoChat client or account from a 32-byte seed. |
| `from_algorand_account` | Builds a chat account from the Algorand 64-byte secret-key representation. |
| `from_raw_keys` | Builds a chat account from explicit signing and encryption keys. |
| `address` | Returns the local Algorand address. |
| `encryption_public_key` | Returns the local X25519 public key bytes. |
| `public_key_bytes` | Returns the account X25519 public key bytes. |
| `private_key_bytes` | Returns the account X25519 private key bytes. |
| `encryption_private_key` | Borrows the account X25519 private key. |
| `conversation` | Returns the conversation for one participant, creating an empty view when absent. |
| `conversations` | Returns snapshots of all current conversations. |
| `discover_key` | Discovers a published encryption key and its verification status. |
| `discover_verified_key` | Requires a discovered key whose Ed25519 ownership proof is valid. |
| `discover_encryption_key` | Finds the newest valid key announcement through the indexer. |
| `discover_encryption_key_paginated` | Scans paginated indexer results with a bounded page size. |
| `encrypt` | Produces a standard encrypted envelope for a recipient key. |
| `decrypt` | Decodes and decrypts a standard envelope for the local client. |
| `add_psk_contact` | Installs a PSK contact and initializes its ratchet state. |
| `remove_psk_contact` | Removes a PSK contact and reports whether it existed. |
| `get_psk_contact` | Returns a snapshot of one PSK contact. |
| `psk_contacts` | Returns the addresses of all configured PSK contacts. |
| `encrypt_psk` | Produces a PSK envelope at the supplied ratchet counter. |
| `decrypt_psk` | Decrypts a PSK envelope with the supplied initial PSK. |
| `send_psk` | Encrypts a contact message and atomically advances its send counter. |
| `receive_psk` | Validates replay state, decrypts a contact message, and records its counter. |
| `process_transaction` | Converts a supported note transaction into a decrypted domain message. |
| `sync` | Fetches, processes, caches, and merges newly indexed messages. |
| `send_queue` | Borrows the offline send queue. |
| `message_cache` | Borrows the configured message cache. |
| `public_key_cache` | Borrows the TTL-bound public-key cache. |
| `fire_and_forget` | Creates send options without confirmation waits. |
| `confirmed` | Creates send options that wait for algod confirmation. |
| `indexed` | Creates send options that also wait for indexer visibility. |
| `replying_to` | Creates send options containing reply metadata for a message. |
| `with_reply` | Adds explicit reply metadata to send options. |
| `from_message` | Creates bounded reply metadata from an existing message. |
| `is_reply` | Reports whether a message contains reply metadata. |
| `unix_timestamp` | Converts a message time to Unix seconds. |
| `with_key` | Creates a conversation with a known participant encryption key. |
| `id` | Returns the participant identifier used as the conversation ID. |
| `messages` | Returns messages in chronological order. |
| `last_message` | Returns the newest message, if any. |
| `last_received` | Returns the newest received message. |
| `last_sent` | Returns the newest sent message. |
| `received_messages` | Iterates only received messages. |
| `sent_messages` | Iterates only sent messages. |
| `message_count` | Returns the number of messages. |
| `is_empty` | Reports whether a conversation or queue contains no items. |
| `append` | Deduplicates a message by ID and preserves chronological ordering. |
| `merge` | Appends multiple messages through the same deduplication rules. |
| `mark_sending` | Moves a pending message to the sending state. |
| `mark_failed` | Records a failed attempt and its diagnostic. |
| `mark_sent` | Marks a pending message as sent. |
| `can_retry` | Checks retry limits for a failed message. |
| `enqueue` | Adds a pending message unless the configured capacity is full. |
| `next_pending` | Returns the next pending message. |
| `all_pending` | Returns snapshots of every queued message. |
| `ready_for_retry` | Returns failed messages whose backoff has elapsed. |
| `remove` | Removes and returns a queued message. |
| `prune_sent` | Removes sent messages from the queue. |
| `prune_failed` | Removes failed messages that exhausted retries. |
| `clear` | Removes all entries from a queue or cache. |
| `len` | Returns the queue length. |
| `pending_count` | Counts pending messages. |
| `failed_count` | Counts failed messages. |
| `messages_for` | Returns queued messages for one recipient. |
| `reset_for_retry` | Returns a failed message to pending state. |
| `with_defaults` | Constructs a queue with default limits and retry policy. |
| `with_default_ttl` | Constructs a public-key cache with its default TTL. |
| `store` | Persists a message, sync round, public key, or private key through the owning storage abstraction. |
| `retrieve` | Retrieves a non-expired cached public key or stored private key. |
| `store_verified` | Caches a public key with its ownership-verification bit. |
| `retrieve_verified` | Returns a non-expired cached key and verification bit. |
| `invalidate` | Removes one cached public key. |
| `prune_expired` | Removes expired public-key entries. |
| `with_password` | Constructs encrypted file storage with a password. |
| `with_directory` | Constructs file storage at a chosen directory with optional password. |
| `set_password` | Replaces the in-memory storage password. |
| `clear_password` | Removes the in-memory storage password. |

### Exported Types

| Type | Description |
|------|-------------|
| `AlgoChatConfig` | Client network, discovery, verification, and caching policy. |
| `PSKContact` | Initial PSK, label, and synchronized ratchet state for one peer. |
| `AlgoChat` | Generic client over algod, indexer, key storage, and message cache ports. |
| `AlgorandConfig` | Algod and optional indexer endpoints and tokens. |
| `TransactionInfo` | Submitted transaction ID and optional confirmation round. |
| `NoteTransaction` | Indexed payment metadata and note bytes. |
| `AlgodClient` | Async port for network parameters, payment submission, confirmation, and account lookup. |
| `SuggestedParams` | Fee, validity window, and genesis data needed to construct a transaction. |
| `AccountInfo` | Address, balance, and minimum-balance state. |
| `PaginatedTransactions` | One page of note transactions plus continuation token. |
| `IndexerClient` | Async port for address transaction and paginated note discovery. |
| `ReplyContext` | Parent transaction ID and bounded preview. |
| `MessageDirection` | Sent or received direction relative to the local account. |
| `Message` | Decrypted immutable chat record with chain ordering metadata. |
| `Conversation` | Deduplicated chronological messages for one participant. |
| `DiscoveredKey` | X25519 key plus Ed25519 ownership-verification result. |
| `SendOptions` | Confirmation, indexer, timeout, and reply behavior. |
| `SendResult` | Submitted transaction ID and resulting local message. |
| `PendingStatus` | Pending, sending, failed, or sent queue state. |
| `PendingMessage` | Retryable offline message and attempt metadata. |
| `ChatAccount` | Algorand identity paired with derived X25519 keys. |
| `QueueConfig` | Queue capacity, retry count, and exponential-backoff policy. |
| `SendQueue` | Concurrent in-memory offline send queue. |
| `MessageCache` | Async persistence port for messages and sync rounds. |
| `InMemoryMessageCache` | Lock-protected process-local message cache. |
| `PublicKeyCache` | TTL-bound process-local discovered-key cache. |
| `EncryptionKeyStorage` | Async persistence port for private encryption keys. |
| `InMemoryKeyStorage` | Process-local private-key storage implementation. |
| `FileKeyStorage` | File-backed private-key storage with optional password encryption. |

## Invariants

1. Conversations deduplicate by transaction ID and remain sorted by timestamp.
2. Verified discovery never returns an announcement whose Ed25519 proof fails.
3. PSK receive state rejects replayed or out-of-window counters before plaintext is returned.
4. Queue state transitions preserve retry counts and never exceed configured capacity.
5. Storage implementations satisfy the same async interfaces without exposing persistence details to the client.

## Behavioral Examples

### Scenario: Verified key discovery

- **Given** an address with signed and unsigned key announcements
- **When** `discover_verified_key` scans the paginated indexer history
- **Then** it returns the newest valid signed key or an explicit verification error

### Scenario: Offline retry

- **Given** a failed pending message below the retry limit
- **When** its exponential-backoff interval elapses
- **Then** `ready_for_retry` includes it and `reset_for_retry` returns it to pending

## Error Cases

| Condition | Behavior |
|-----------|----------|
| Invalid seed or key length | Return the corresponding typed `AlgoChatError`. |
| Missing or unverified required key | Return key-not-found or verification failure without sending. |
| Queue at capacity | Reject enqueue without dropping existing entries. |
| Storage password absent or incorrect | Return a storage error without plaintext key material. |
| Unsupported or malformed note | Ignore non-chat notes or return a typed decoding/decryption error. |

## Dependencies

### Consumes

| Module | What is used |
|--------|-------------|
| `protocol` | Standard envelope encryption, key derivation, signatures, errors, and constants. |
| `psk` | PSK envelopes, ratchet derivation, replay state, and exchange URIs. |

### Consumed By

| Module | What is used |
|--------|-------------|
| `crate` | Re-exports the complete client API. |
| `cross-vectors` | Exercises client-visible protocol interoperability. |

## Change Log

| Date | Author | Change |
|------|--------|--------|
| 2026-07-14 | CorvidLabs | Adopted the existing client contract into SpecSync 5.0.1 at member-level coverage. |
| 2026-07-14 | CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa: Adopt SpecSync 5.0.1 and Trust 1.0.0 governance for the Rust AlgoChat implementation |
