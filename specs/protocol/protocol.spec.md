---
module: protocol
version: 1.0.1
status: active
owner: CorvidLabs
files:
  - src/crypto.rs
  - src/envelope.rs
  - src/keys.rs
  - src/signature.rs
  - src/types.rs
db_tables: []
depends_on: []
---

# Protocol

## Purpose

Defines the standard AlgoChat v1/v2 wire envelope, X25519/HKDF key derivation,
ChaCha20-Poly1305 encryption, signed key announcements, protocol constants, and
typed errors. Version 2 binds header metadata as AEAD associated data while
remaining able to decode version 1 messages.

## Public API

### Exported Functions and Members

| Symbol | Description |
|--------|-------------|
| `derive_keys_from_seed` | Deterministically derives an X25519 keypair from an exact 32-byte seed. |
| `generate_ephemeral_keypair` | Generates a fresh X25519 keypair from the system CSPRNG. |
| `x25519_ecdh` | Produces the 32-byte X25519 shared secret. |
| `encrypt_message` | Encrypts a standard v1 payload using empty AEAD associated data. |
| `encrypt_message_v2` | Encrypts a standard v2 payload while authenticating the 78-byte header prefix. |
| `decrypt_message` | Decrypts v1 or v2 for sender or recipient and decodes reply JSON when present. |
| `encode` | Serializes a standard envelope with fixed-width header fields. |
| `decode` | Parses and validates a standard v1/v2 envelope. |
| `v2_aad` | Reconstructs the canonical v2 standard header prefix. |
| `is_chat_message` | Recognizes supported standard envelope version and protocol bytes at minimum length. |
| `sign_encryption_key` | Signs a 32-byte X25519 public key with Ed25519. |
| `verify_encryption_key` | Verifies an Ed25519 signature using a parsed verifying key. |
| `verify_encryption_key_bytes` | Verifies an Ed25519 signature from raw key bytes. |
| `fingerprint` | Formats the first eight SHA-256 bytes as grouped uppercase hexadecimal. |
| `new` | Constructs decrypted content with text and no reply metadata. |
| `ED25519_SIGNATURE_SIZE` | Public Ed25519 signature width, 64 bytes. |
| `PROTOCOL_VERSION` | Standard legacy envelope version byte 0x01. |
| `PROTOCOL_VERSION_V2` | Standard authenticated-header version byte 0x02. |
| `PROTOCOL_ID` | Standard message protocol discriminator 0x01. |
| `STANDARD_V2_AAD_LEN` | Standard v2 authenticated metadata length, 78 bytes. |
| `PSK_V2_AAD_LEN` | Shared PSK v2 authenticated metadata length, 82 bytes. |
| `HEADER_SIZE` | Standard envelope fixed header length, 126 bytes. |
| `TAG_SIZE` | ChaCha20-Poly1305 authentication tag length, 16 bytes. |
| `ENCRYPTED_SENDER_KEY_SIZE` | Wrapped sender-key field length, 48 bytes. |
| `MAX_PAYLOAD_SIZE` | Largest standard plaintext compatible with an Algorand note, 882 bytes. |
| `NONCE_SIZE` | ChaCha20-Poly1305 nonce length, 12 bytes. |
| `PUBLIC_KEY_SIZE` | X25519 and Ed25519 public-key length, 32 bytes. |
| `KEY_DERIVATION_SALT` | Stable HKDF salt for account-seed X25519 derivation. |
| `KEY_DERIVATION_INFO` | Stable HKDF info string for X25519 derivation. |
| `ENCRYPTION_INFO_PREFIX` | Domain separator for standard recipient encryption keys. |
| `SENDER_KEY_INFO_PREFIX` | Domain separator for standard sender key wrapping. |
| `SIGNATURE_SIZE` | Shared Ed25519 signature width, 64 bytes. |
| `MINIMUM_PAYMENT` | Minimum Algorand payment amount used for chat transactions. |

### Exported Types

| Type | Description |
|------|-------------|
| `ChatEnvelope` | Standard protocol header fields, encrypted sender key, and ciphertext. |
| `DecryptedContent` | Plaintext plus optional reply transaction and preview. |
| `AlgoChatError` | Typed validation, crypto, storage, blockchain, queue, and protocol failures. |
| `Result` | Crate result alias using `AlgoChatError`. |

## Invariants

1. Standard envelopes use protocol ID `0x01`; only versions `0x01` and `0x02` are accepted.
2. V2 encryption authenticates exactly the version, protocol ID, sender key, ephemeral key, and nonce prefix.
3. Plaintext may not exceed 882 bytes, preserving the 1,024-byte Algorand note limit.
4. Seed, public-key, nonce, signature, and fixed header fields are rejected at incorrect lengths.
5. Sender and recipient can decrypt the same envelope through their corresponding ECDH path.

## Behavioral Examples

### Scenario: V2 header binding

- **Given** a valid v2 envelope
- **When** any authenticated header byte is changed
- **Then** `decrypt_message` fails authentication and returns no plaintext

### Scenario: V1 compatibility

- **Given** a valid version `0x01` envelope from an existing implementation
- **When** it is decoded and decrypted
- **Then** empty associated data is used and the legacy plaintext is preserved

## Error Cases

| Condition | Behavior |
|-----------|----------|
| Seed is not 32 bytes | Return `InvalidSeedLength`. |
| Plaintext exceeds 882 bytes | Return `MessageTooLarge`. |
| Envelope is short, malformed, or has an unknown version/protocol | Return a typed envelope/version/protocol error. |
| AEAD tag or authenticated header does not match | Return `DecryptionError`. |
| Signing key, verifying key, or signature has an invalid shape | Return a typed public-key or signature error. |

## Dependencies

### Consumes

| Module | What is used |
|--------|-------------|
| External cryptography crates | X25519, HKDF-SHA256, ChaCha20-Poly1305, Ed25519, SHA-256, and secure randomness. |

### Consumed By

| Module | What is used |
|--------|-------------|
| `client` | Standard message encryption, discovery signatures, and typed errors. |
| `crate` | Re-exports the public protocol API. |
| `cross-vectors` | Checks deterministic known answers, compatibility, and tamper rejection. |

## Change Log

| Date | Author | Change |
|------|--------|--------|
| 2026-07-14 | CorvidLabs | Adopted the existing v1/v2 standard protocol contract into SpecSync 5.0.1. |
| 2026-07-14 | CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa: Adopt SpecSync 5.0.1 and Trust 1.0.0 governance for the Rust AlgoChat implementation |
