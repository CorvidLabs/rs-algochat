---
module: psk
version: 1.0.1
status: active
owner: CorvidLabs
files:
  - src/psk_crypto.rs
  - src/psk_envelope.rs
  - src/psk_exchange.rs
  - src/psk_ratchet.rs
  - src/psk_state.rs
  - src/psk_types.rs
db_tables: []
depends_on:
  - protocol
---

# Psk

## Purpose

Defines PSK v1/v2 envelopes, hybrid ECDH+PSK encryption, two-level deterministic
ratchet derivation, replay-window state, and out-of-band exchange URIs. V2 binds
the counter and remaining header metadata into AEAD authentication.

## Public API

### Exported Functions and Members

| Symbol | Description |
|--------|-------------|
| `encrypt_psk_message` | Encrypts a PSK v1 payload with hybrid ECDH and ratcheted PSK material. |
| `encrypt_psk_message_v2` | Encrypts a PSK v2 payload and authenticates the 82-byte header prefix. |
| `decrypt_psk_message` | Decrypts a supported PSK envelope for sender or recipient. |
| `encode_psk_envelope` | Serializes fixed PSK header fields and ciphertext. |
| `decode_psk_envelope` | Parses and validates a PSK v1/v2 envelope. |
| `is_psk_message` | Recognizes supported PSK version/protocol bytes at minimum length. |
| `derive_session_psk` | Derives the PSK for a 100-message session using HKDF-SHA256. |
| `derive_position_psk` | Derives the within-session PSK for a counter position. |
| `derive_psk_at_counter` | Maps a global counter to session and position derivations. |
| `derive_hybrid_symmetric_key` | Derives recipient encryption material from ECDH and current PSK. |
| `derive_sender_key` | Derives the sender-side key-encryption material. |
| `new` | Constructs an exchange URI value or replay state at its initial counter. |
| `encode` | Percent- and base64url-encodes a PSK exchange URI. |
| `parse` | Validates and decodes an `algochat-psk://v1` URI. |
| `v2_aad` | Reconstructs the canonical PSK v2 authenticated header prefix. |
| `validate_counter` | Rejects replayed and out-of-window receive counters. |
| `record_receive` | Records a valid counter and prunes obsolete replay entries. |
| `advance_send_counter` | Returns the current send counter and advances with wrapping semantics. |
| `PSK_VERSION` | Legacy PSK envelope version byte 0x01. |
| `PSK_VERSION_V2` | Authenticated-header PSK version byte 0x02. |
| `PSK_PROTOCOL_ID` | PSK message protocol discriminator 0x02. |
| `PSK_HEADER_SIZE` | PSK envelope fixed header length, 130 bytes. |
| `PSK_TAG_SIZE` | PSK ChaCha20-Poly1305 tag length, 16 bytes. |
| `PSK_ENCRYPTED_SENDER_KEY_SIZE` | PSK wrapped sender-key field length, 48 bytes. |
| `PSK_MAX_PAYLOAD_SIZE` | Largest PSK plaintext compatible with an Algorand note, 878 bytes. |
| `PSK_SESSION_SIZE` | Number of ratchet positions per session, 100. |
| `PSK_COUNTER_WINDOW` | Accepted receive-counter replay window, 200. |

### Exported Types

| Type | Description |
|------|-------------|
| `PSKEnvelope` | PSK version, ratchet counter, keys, nonce, wrapped key, and ciphertext. |
| `PSKExchangeURI` | Peer address, exact 32-byte PSK, and optional human label. |
| `PSKState` | Send counter, highest peer counter, and bounded replay set. |

## Invariants

1. PSK envelopes use protocol ID `0x02`; only versions `0x01` and `0x02` are accepted.
2. V2 authentication covers version, protocol ID, ratchet counter, both public keys, and nonce.
3. Each counter deterministically selects one session PSK and one position PSK.
4. The replay set rejects duplicates and counters more than 200 behind the highest accepted counter.
5. PSK plaintext may not exceed 878 bytes, preserving the Algorand note limit.
6. Exchange URIs require scheme/version, address, and an exact 32-byte base64url PSK.

## Behavioral Examples

### Scenario: Ratchet interoperability

- **Given** equal initial PSKs and counter values in two implementations
- **When** each derives the current PSK
- **Then** the 32-byte known answer is identical

### Scenario: Replay rejection

- **Given** a successfully received counter already recorded in state
- **When** the same PSK envelope is received again
- **Then** validation fails before plaintext is returned

## Error Cases

| Condition | Behavior |
|-----------|----------|
| Initial PSK or exchange URI key is not 32 bytes | Return a typed derivation or URI error. |
| Plaintext exceeds 878 bytes | Return `MessageTooLarge`. |
| Envelope has invalid length, version, or protocol ID | Return the corresponding typed protocol error. |
| Header, counter, ciphertext, or key material is altered | AEAD authentication fails. |
| Counter was seen or falls outside the replay window | Return a decryption/replay error. |

## Dependencies

### Consumes

| Module | What is used |
|--------|-------------|
| `protocol` | Shared errors, version-2 AAD length, keys, and cryptographic primitives. |

### Consumed By

| Module | What is used |
|--------|-------------|
| `client` | PSK contact orchestration and synchronized counter state. |
| `crate` | Re-exports the complete PSK API. |
| `cross-vectors` | Checks PSK known answers and header tamper rejection. |

## Change Log

| Date | Author | Change |
|------|--------|--------|
| 2026-07-14 | CorvidLabs | Adopted the existing PSK v1/v2 and ratchet contract into SpecSync 5.0.1. |
| 2026-07-14 | CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa: Adopt SpecSync 5.0.1 and Trust 1.0.0 governance for the Rust AlgoChat implementation |
