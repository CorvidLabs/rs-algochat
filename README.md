# rs-algochat

[![CI](https://img.shields.io/github/actions/workflow/status/CorvidLabs/rs-algochat/ci.yml?label=CI&branch=main)](https://github.com/CorvidLabs/rs-algochat/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/algochat)](https://crates.io/crates/algochat)
[![License](https://img.shields.io/github/license/CorvidLabs/rs-algochat)](https://github.com/CorvidLabs/rs-algochat/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/CorvidLabs/rs-algochat?display_name=tag)](https://github.com/CorvidLabs/rs-algochat/releases)
![spec coverage](https://img.shields.io/endpoint?url=https://corvidlabs.github.io/rs-algochat/badges/coverage.json)

> **Pre-1.0 Notice**: This library is under active development. The API may change between minor versions until 1.0.

Rust implementation of the AlgoChat protocol for encrypted messaging on Algorand.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
algochat = "0.2"
```

## Usage

### Client API

```rust
use algochat::{AlgoChatClient, AlgorandConfig};

// Create client from a 32-byte seed
let client = AlgoChatClient::from_seed(seed, AlgorandConfig::localnet()).await?;

// Discover a recipient's public key on-chain
let key = client.discover_key("RECIPIENT_ADDR").await?;

// Encrypt a message
let recipient_pk = key.unwrap().public_key;
let envelope = client.encrypt("Hello, World!", &recipient_pk)?;

// Decrypt a received message
let text = client.decrypt(&envelope, &sender_pk)?;

// Sync and process new messages
let messages = client.sync().await?;
```

### Low-Level Crypto

```rust
use algochat::{derive_keys_from_seed, encrypt_message, decrypt_message, ChatEnvelope};

let (sender_private, sender_public) = derive_keys_from_seed(&seed)?;
let (recipient_private, recipient_public) = derive_keys_from_seed(&recipient_seed)?;

let envelope = encrypt_message(
    "Hello, World!",
    &sender_private,
    &sender_public,
    &recipient_public,
)?;

let encoded = envelope.encode();
let decoded = ChatEnvelope::decode(&encoded)?;
let result = decrypt_message(&decoded, &recipient_private, &recipient_public)?;
```

## Protocol

AlgoChat uses:
- **X25519** for key agreement
- **ChaCha20-Poly1305** for authenticated encryption
- **HKDF-SHA256** for key derivation

The protocol supports bidirectional decryption, allowing senders to decrypt their own messages.



## PSK Protocol (v1.1)

The PSK (Pre-Shared Key) protocol extends AlgoChat with an additional layer of symmetric key security:

- **Hybrid encryption**: Combines X25519 ECDH with a pre-shared key
- **Two-level ratchet**: Session + position derivation for forward secrecy
- **Replay protection**: Counter-based state tracking with configurable window
- **Exchange URI**: Out-of-band key sharing via `algochat-psk://` URIs
- **Zeroized key material**: Sensitive keys are zeroized after use

### PSK Usage (Client API)

The `AlgoChatClient` manages PSK contacts and counter state automatically:

```rust
use algochat::{AlgoChatClient, AlgorandConfig, PSKContact, PSKExchangeURI};

let client = AlgoChatClient::from_seed(seed, AlgorandConfig::localnet()).await?;

// Add a PSK contact (exchanged out-of-band via URI)
let uri = PSKExchangeURI::decode("algochat-psk://v1?addr=ADDR&psk=...&label=Alice")?;
client.add_psk_contact(&uri.address, PSKContact::new(uri.psk, uri.label)).await;

// Send — counter management is automatic
let (envelope_bytes, counter) = client.send_psk("RECIPIENT_ADDR", "Hello with PSK!").await?;

// Receive — replay protection is automatic
let text = client.receive_psk(&envelope_bytes, "SENDER_ADDR").await?;
```

### Low-Level PSK API

For direct control over encryption and counters:

```rust
use algochat::{
    encrypt_psk_message, decrypt_psk_message,
    encode_psk_envelope, decode_psk_envelope, is_psk_message,
    PSKState,
};

let psk = [0xAA; 32];
let mut state = PSKState::new();

// Encrypt with PSK
let counter = state.advance_send_counter();
let envelope = encrypt_psk_message(
    "Hello with PSK!",
    &sender_private,
    &sender_public,
    &recipient_public,
    &psk,
    counter,
)?;

// Encode for transmission
let encoded = encode_psk_envelope(&envelope);

// Decode and decrypt
let decoded = decode_psk_envelope(&encoded)?;
let text = decrypt_psk_message(&decoded, &recipient_private, &recipient_public, &psk)?;
```
## Cross-Implementation Compatibility

This implementation is fully compatible with:
- [swift-algochat](https://github.com/CorvidLabs/swift-algochat) (Swift)
- [ts-algochat](https://github.com/CorvidLabs/ts-algochat) (TypeScript)
- [py-algochat](https://github.com/CorvidLabs/py-algochat) (Python)
- [kt-algochat](https://github.com/CorvidLabs/kt-algochat) (Kotlin)

## License

MIT
