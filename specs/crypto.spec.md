---
module: crypto
version: 1.0.0
status: active
owner: CorvidAgent
sources:
  - src/crypto.rs
  - src/keys.rs
  - src/envelope.rs
  - src/signature.rs
  - src/psk_crypto.rs
  - src/psk_envelope.rs
  - src/psk_exchange.rs
  - src/psk_ratchet.rs
  - src/psk_state.rs
  - src/psk_types.rs
  - src/types.rs
---

# Crypto Spec

End-to-end encryption for the AlgoChat protocol. Covers X25519 key derivation, ChaCha20-Poly1305 message encryption/decryption, PSK (pre-shared key) ratchet encryption, envelope wire formats, Ed25519 signature verification, and encryption key storage.

## Public Types

### `DecryptedContent`
Decrypted message payload.

| Field | Type | Description |
|-------|------|-------------|
| `text` | `String` | The message text |
| `reply_to_id` | `Option<String>` | Transaction ID this message replies to |
| `reply_to_preview` | `Option<String>` | Preview of the replied message |

Methods:
- `fn new(text: impl Into<String>) -> Self` - Creates a `DecryptedContent` with text only (no reply context).

### `ChatEnvelope`
Standard AlgoChat message envelope (protocol v1, protocol ID 0x01).

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `version` | `u8` | 1 | Protocol version (0x01) |
| `protocol_id` | `u8` | 1 | Protocol ID (0x01) |
| `sender_public_key` | `[u8; 32]` | 32 | Sender's X25519 public key |
| `ephemeral_public_key` | `[u8; 32]` | 32 | Per-message ephemeral X25519 key |
| `nonce` | `[u8; 12]` | 12 | ChaCha20-Poly1305 nonce |
| `encrypted_sender_key` | `Vec<u8>` | 48 | Encrypted symmetric key for sender decryption |
| `ciphertext` | `Vec<u8>` | variable | Encrypted message + 16-byte auth tag |

Methods:
- `fn encode(&self) -> Vec<u8>` - Serializes the envelope to bytes (126-byte header + ciphertext).
- `fn decode(data: &[u8]) -> Result<Self>` - Deserializes bytes into an envelope. Validates version and protocol ID.

### `PSKEnvelope`
PSK protocol message envelope (protocol v1, protocol ID 0x02).

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `ratchet_counter` | `u32` | 4 | Ratchet counter (big-endian in wire format) |
| `sender_public_key` | `[u8; 32]` | 32 | Sender's X25519 public key |
| `ephemeral_public_key` | `[u8; 32]` | 32 | Per-message ephemeral X25519 key |
| `nonce` | `[u8; 12]` | 12 | ChaCha20-Poly1305 nonce |
| `encrypted_sender_key` | `Vec<u8>` | 48 | Encrypted symmetric key for sender decryption |
| `ciphertext` | `Vec<u8>` | variable | Encrypted message + 16-byte auth tag |

### `PSKExchangeURI`
Parsed PSK exchange URI for out-of-band key sharing.

| Field | Type | Description |
|-------|------|-------------|
| `address` | `String` | Algorand address of the peer |
| `psk` | `Vec<u8>` | Pre-shared key (32 bytes) |
| `label` | `Option<String>` | Optional human-readable label |

Methods:
- `fn new(address: impl Into<String>, psk: Vec<u8>, label: Option<String>) -> Self`
- `fn encode(&self) -> String` - Encodes to `algochat-psk://v1?addr=<address>&psk=<base64url>&label=<label>`.
- `fn parse(uri: &str) -> Result<Self>` - Parses a PSK exchange URI string.

### `PSKState`
Per-peer PSK conversation state for counter tracking and replay protection.

| Field | Type | Description |
|-------|------|-------------|
| `send_counter` | `u32` | Next counter value for outgoing messages |
| `peer_last_counter` | `u32` | Highest counter received from peer |
| `seen_counters` | `HashSet<u32>` | Recently seen counters for replay detection |

Methods:
- `fn new() -> Self` - Creates state with all counters at zero.
- `fn validate_counter(&self, counter: u32) -> Result<bool>` - Checks if a counter is valid (not replayed, within window).
- `fn record_receive(&mut self, counter: u32)` - Records a received counter, prunes old entries.
- `fn advance_send_counter(&mut self) -> u32` - Returns and increments the send counter (wrapping).

### `AlgoChatError` (crypto-relevant variants)

| Variant | Description |
|---------|-------------|
| `InvalidSeedLength(usize)` | Seed is not 32 bytes |
| `MessageTooLarge(usize)` | Plaintext exceeds `MAX_PAYLOAD_SIZE` (882) or `PSK_MAX_PAYLOAD_SIZE` (878) |
| `EncryptionError(String)` | HKDF, cipher init, or AEAD encryption failure |
| `DecryptionError(String)` | HKDF, cipher init, AEAD decryption, or replay detection failure |
| `KeyDerivationFailed(String)` | PSK ratchet or hybrid key derivation failure |
| `InvalidPublicKey(String)` | Key is not 32 bytes |
| `InvalidSignature(String)` | Signature is not 64 bytes or malformed |
| `InvalidEnvelope(String)` | Envelope too short or malformed |
| `UnknownVersion(u8)` | Unrecognized protocol version byte |
| `UnknownProtocolId(u8)` | Unrecognized protocol ID byte |

## Public Functions

### Key Derivation

#### `derive_keys_from_seed(seed: &[u8]) -> Result<(StaticSecret, PublicKey)>`
Derives an X25519 key pair from a 32-byte seed using HKDF-SHA256.
- Salt: `b"AlgoChat-v1-encryption"`
- Info: `b"x25519-key"`
- Errors if seed length != 32.
- Deterministic: same seed always produces the same key pair.

#### `generate_ephemeral_keypair() -> (StaticSecret, PublicKey)`
Generates a random X25519 key pair using the system CSPRNG. Used once per message.

#### `x25519_ecdh(private_key: &StaticSecret, public_key: &PublicKey) -> [u8; 32]`
Performs X25519 Diffie-Hellman key exchange. Returns a 32-byte shared secret.

### Standard Encryption

#### `encrypt_message(plaintext: &str, sender_private_key: &StaticSecret, sender_public_key: &PublicKey, recipient_public_key: &PublicKey) -> Result<ChatEnvelope>`
Encrypts a message for a recipient using ephemeral ECDH + ChaCha20-Poly1305.
1. Validates `plaintext.len() <= MAX_PAYLOAD_SIZE` (882 bytes).
2. Generates a fresh ephemeral key pair.
3. Derives a symmetric key via ECDH(ephemeral_private, recipient_public) + HKDF-SHA256.
4. Generates a random 12-byte nonce.
5. Encrypts the plaintext with ChaCha20-Poly1305.
6. Derives a sender key via ECDH(ephemeral_private, sender_public) + HKDF-SHA256 for bidirectional decryption.
7. Encrypts the symmetric key with the sender key (same nonce).

#### `decrypt_message(envelope: &ChatEnvelope, my_private_key: &StaticSecret, my_public_key: &PublicKey) -> Result<Option<DecryptedContent>>`
Decrypts a message from an envelope.
- Auto-detects sender vs. recipient role by comparing `my_public_key` to `envelope.sender_public_key`.
- Returns `None` for key-publish payloads (`{"type":"key-publish"}`).
- Parses JSON payloads with `text`, `replyTo.txid`, and `replyTo.preview` fields.
- Falls back to plain text for non-JSON payloads.

### Envelope Functions

#### `is_chat_message(data: &[u8]) -> bool`
Returns `true` if data has >= 126 bytes and starts with version=0x01, protocolId=0x01.

#### `encode_psk_envelope(envelope: &PSKEnvelope) -> Vec<u8>`
Serializes a PSK envelope to bytes (130-byte header + ciphertext).

#### `decode_psk_envelope(data: &[u8]) -> Result<PSKEnvelope>`
Deserializes bytes into a PSK envelope. Validates version=0x01 and protocolId=0x02.

#### `is_psk_message(data: &[u8]) -> bool`
Returns `true` if data has >= 130 bytes and starts with version=0x01, protocolId=0x02.

### PSK Encryption

#### `encrypt_psk_message(plaintext: &str, sender_private_key: &StaticSecret, sender_public_key: &PublicKey, recipient_public_key: &PublicKey, initial_psk: &[u8], ratchet_counter: u32) -> Result<PSKEnvelope>`
Encrypts a message with dual-layer ECDH + PSK security.
1. Validates `plaintext.len() <= PSK_MAX_PAYLOAD_SIZE` (878 bytes).
2. Derives current PSK from initial PSK and ratchet counter.
3. Generates ephemeral key pair + ECDH shared secret.
4. Derives hybrid symmetric key: HKDF(IKM=shared_secret||current_psk, salt=ephemeral_pub, info=prefix||sender_pub||recipient_pub).
5. Encrypts with ChaCha20-Poly1305.
6. Derives sender key for bidirectional decryption (same hybrid approach).

#### `decrypt_psk_message(envelope: &PSKEnvelope, my_private_key: &StaticSecret, my_public_key: &PublicKey, initial_psk: &[u8]) -> Result<String>`
Decrypts a PSK-encrypted message. Auto-detects sender/recipient role.

### PSK Ratchet

#### `derive_session_psk(initial_psk: &[u8], session_index: u32) -> Result<[u8; 32]>`
Derives a session PSK using HKDF-SHA256(salt=`b"AlgoChat-PSK-Session"`, IKM=initial_psk, info=session_index).

#### `derive_position_psk(session_psk: &[u8], position: u32) -> Result<[u8; 32]>`
Derives a position PSK using HKDF-SHA256(salt=`b"AlgoChat-PSK-Position"`, IKM=session_psk, info=position).

#### `derive_psk_at_counter(initial_psk: &[u8], counter: u32) -> Result<[u8; 32]>`
Combines session + position derivation:
- `session_index = counter / PSK_SESSION_SIZE` (100)
- `position = counter % PSK_SESSION_SIZE` (100)

#### `derive_hybrid_symmetric_key(shared_secret, current_psk, ephemeral_public_key, sender_public_key, recipient_public_key) -> Result<[u8; 32]>`
Derives a hybrid key combining ECDH and PSK. IKM = shared_secret || current_psk.

#### `derive_sender_key(sender_shared_secret, current_psk, ephemeral_public_key, sender_public_key) -> Result<[u8; 32]>`
Derives a sender key for bidirectional PSK decryption.

### Signature

#### `sign_encryption_key(encryption_public_key: &[u8], signing_key: &SigningKey) -> Result<[u8; 64]>`
Signs a 32-byte X25519 public key with an Ed25519 signing key. Returns 64-byte signature.

#### `verify_encryption_key(encryption_public_key: &[u8], verifying_key: &VerifyingKey, signature: &[u8]) -> Result<bool>`
Verifies a signature over an encryption public key.

#### `verify_encryption_key_bytes(encryption_public_key: &[u8], ed25519_public_key: &[u8], signature: &[u8]) -> Result<bool>`
Same as above but accepts raw 32-byte Ed25519 public key bytes.

#### `fingerprint(public_key: &[u8]) -> String`
Returns a human-readable SHA-256 fingerprint: `"A7B3 C9D1 E5F2 8A4B"` (first 8 bytes, grouped in pairs).

## Public Traits

### `EncryptionKeyStorage`
Async trait for securely storing X25519 private keys.

| Method | Signature | Description |
|--------|-----------|-------------|
| `store` | `async fn store(&self, private_key: &[u8; 32], address: &str, require_biometric: bool) -> Result<()>` | Stores a private key |
| `retrieve` | `async fn retrieve(&self, address: &str) -> Result<[u8; 32]>` | Retrieves a private key |
| `has_key` | `async fn has_key(&self, address: &str) -> bool` | Checks if a key exists |
| `delete` | `async fn delete(&self, address: &str) -> Result<()>` | Deletes a key |
| `list_stored_addresses` | `async fn list_stored_addresses(&self) -> Result<Vec<String>>` | Lists all stored addresses |

Implementations:
- `InMemoryKeyStorage` - HashMap-based, for testing only.
- `FileKeyStorage` - Password-protected file storage using PBKDF2 (100k iterations) + AES-256-GCM. Keys stored in `~/.algochat/keys/<address>.key` with 600 permissions. File format: salt(32) + nonce(12) + ciphertext(32) + tag(16) = 92 bytes.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION` | `0x01` | Standard protocol version |
| `PROTOCOL_ID` | `0x01` | Standard protocol ID |
| `HEADER_SIZE` | `126` | Standard envelope header size |
| `MAX_PAYLOAD_SIZE` | `882` | Max plaintext bytes (standard) |
| `NONCE_SIZE` | `12` | ChaCha20-Poly1305 nonce |
| `PUBLIC_KEY_SIZE` | `32` | X25519/Ed25519 key size |
| `TAG_SIZE` | `16` | AEAD authentication tag |
| `ENCRYPTED_SENDER_KEY_SIZE` | `48` | 32-byte key + 16-byte tag |
| `SIGNATURE_SIZE` | `64` | Ed25519 signature |
| `MINIMUM_PAYMENT` | `1000` | Min payment in microAlgos |
| `PSK_VERSION` | `0x01` | PSK protocol version |
| `PSK_PROTOCOL_ID` | `0x02` | PSK protocol ID |
| `PSK_HEADER_SIZE` | `130` | PSK envelope header size |
| `PSK_MAX_PAYLOAD_SIZE` | `878` | Max plaintext bytes (PSK) |
| `PSK_SESSION_SIZE` | `100` | Positions per session |
| `PSK_COUNTER_WINDOW` | `200` | Replay protection window |
| `PSK_ENCRYPTED_SENDER_KEY_SIZE` | `48` | 32-byte key + 16-byte tag |

## Invariants

1. `derive_keys_from_seed` is deterministic: identical seeds produce identical key pairs.
2. Seed must be exactly 32 bytes; any other length returns `InvalidSeedLength`.
3. Every call to `encrypt_message` generates a fresh ephemeral key pair; two encryptions of the same plaintext produce different ciphertexts.
4. A 12-byte nonce is generated from the system CSPRNG for every encryption.
5. Both sender and recipient can decrypt a `ChatEnvelope` (bidirectional decryption).
6. `ChatEnvelope::encode()` followed by `ChatEnvelope::decode()` is lossless.
7. `encrypt_message` rejects plaintext > 882 bytes with `MessageTooLarge`.
8. `encrypt_psk_message` rejects plaintext > 878 bytes with `MessageTooLarge`.
9. Standard envelopes use protocolId=0x01; PSK envelopes use protocolId=0x02. These are mutually exclusive.
10. `ChatEnvelope::decode` rejects data < 126 bytes, wrong version, or wrong protocol ID.
11. `decode_psk_envelope` rejects data < 130 bytes, wrong version, or wrong protocol ID.
12. PSK ratchet derivation is deterministic: same (initial_psk, counter) always produces the same derived key.
13. Different ratchet counters produce different derived keys (with overwhelming probability).
14. Session boundaries occur at multiples of `PSK_SESSION_SIZE` (100): counter 99 and 100 use different session PSKs.
15. `PSKState::validate_counter` rejects previously-seen counters (replay protection).
16. `PSKState::validate_counter` rejects counters more than `PSK_COUNTER_WINDOW` (200) behind `peer_last_counter`.
17. `PSKState::advance_send_counter` wraps from `u32::MAX` to 0.
18. `PSKState::record_receive` prunes seen counters below `peer_last_counter - PSK_COUNTER_WINDOW`.
19. Decryption with the wrong PSK fails with `DecryptionError`.
20. Ed25519 signatures are exactly 64 bytes; `sign_encryption_key` rejects non-32-byte keys.
21. `verify_encryption_key` rejects non-64-byte signatures.
22. `PSKExchangeURI::parse` requires the `algochat-psk://v1?` prefix and both `addr` and `psk` parameters.
23. PSK exchange URIs use base64url-no-pad encoding for the PSK bytes.
24. `FileKeyStorage` requires a password; operations fail with `StorageFailed` if no password is set.

## Behavioral Examples

### Standard Encrypt/Decrypt Roundtrip

```
Given Alice and Bob each have X25519 key pairs derived from distinct seeds
When Alice encrypts "Hello, Bob!" for Bob's public key
Then Bob can decrypt the envelope and recover "Hello, Bob!"
And Alice can also decrypt the same envelope (bidirectional)
```

### Wrong Key Rejection

```
Given Alice encrypts a message for Bob
When Charlie (with a different key pair) attempts to decrypt the envelope
Then decryption fails with DecryptionError
```

### Message Size Limit

```
Given a plaintext of 883 bytes (one byte over MAX_PAYLOAD_SIZE)
When Alice calls encrypt_message
Then the result is Err(MessageTooLarge(883))
```

### PSK Encrypt/Decrypt with Ratchet

```
Given Alice and Bob share initial_psk = [0xAA; 32]
When Alice encrypts "Secret" at ratchet_counter=42
Then Bob can decrypt using the same initial_psk (counter is embedded in envelope)
And the derived key at counter=42 differs from counter=41 and counter=43
```

### PSK Wrong Key Rejection

```
Given Alice encrypts with psk_a = [0xAA; 32]
When Bob tries to decrypt with psk_b = [0xBB; 32]
Then decryption fails with DecryptionError
```

### Replay Protection

```
Given PSKState has recorded counter=5
When validate_counter(5) is called again
Then it returns Err(DecryptionError("Replay detected: counter 5 already seen"))
```

### Counter Window Enforcement

```
Given peer_last_counter=300
When validate_counter(50) is called (gap=250 > PSK_COUNTER_WINDOW=200)
Then it returns Err(DecryptionError("Counter 50 is outside the acceptable window"))
```

### PSK Exchange URI Roundtrip

```
Given address="ALGO_ADDR", psk=[0xAA; 32], label="Test Label"
When PSKExchangeURI::new(address, psk, Some(label)).encode() is called
Then the result starts with "algochat-psk://v1?"
And PSKExchangeURI::parse(encoded) recovers the original address, psk, and label
```

### Envelope Wire Format Roundtrip

```
Given a ChatEnvelope with known field values
When encode() then decode() are called
Then the decoded envelope equals the original (field-by-field)
```

### Ed25519 Signature Verification

```
Given an Ed25519 signing key signs a 32-byte X25519 public key
When verify_encryption_key is called with the matching verifying key
Then it returns Ok(true)
And when called with a different verifying key, it returns Ok(false)
```

### FileKeyStorage Password Protection

```
Given a FileKeyStorage with password "correct"
When a key is stored and then retrieved with password "wrong"
Then retrieval fails with DecryptionError
And retrieval with "correct" succeeds and returns the original key
```

## Error Cases

| Scenario | Error |
|----------|-------|
| Seed length != 32 | `InvalidSeedLength(len)` |
| Plaintext > 882 bytes (standard) | `MessageTooLarge(len)` |
| Plaintext > 878 bytes (PSK) | `MessageTooLarge(len)` |
| Decryption with wrong private key | `DecryptionError("Decryption failed: ...")` |
| Decryption with wrong PSK | `DecryptionError("PSK decryption failed: ...")` |
| Envelope data < 126 bytes | `InvalidEnvelope("Data too short: ...")` |
| PSK envelope data < 130 bytes | `InvalidEnvelope("PSK data too short: ...")` |
| Wrong protocol version | `UnknownVersion(byte)` |
| Wrong protocol ID | `UnknownProtocolId(byte)` |
| Replayed counter | `DecryptionError("Replay detected: ...")` |
| Counter outside window | `DecryptionError("Counter ... is outside the acceptable window")` |
| Signing non-32-byte key | `InvalidPublicKey("... must be 32 bytes, got ...")` |
| Verifying non-64-byte signature | `InvalidSignature("... must be 64 bytes, got ...")` |
| PSK URI missing prefix | `InvalidEnvelope("Invalid PSK URI scheme or version")` |
| PSK URI missing addr param | `InvalidEnvelope("Missing 'addr' parameter")` |
| PSK URI missing psk param | `InvalidEnvelope("Missing 'psk' parameter")` |
| FileKeyStorage no password set | `StorageFailed("Password is required ...")` |
| FileKeyStorage wrong password | `DecryptionError("Decryption failed")` |
| FileKeyStorage key not found | `KeyNotFound(address)` |

## Change Log

| Date | Author | Description |
|------|--------|-------------|
| 2026-03-28 | CorvidAgent | Initial spec covering all crypto modules |
