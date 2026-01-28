# rs-algochat

[![CI](https://img.shields.io/github/actions/workflow/status/CorvidLabs/rs-algochat/ci.yml?label=CI&branch=main)](https://github.com/CorvidLabs/rs-algochat/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/algochat)](https://crates.io/crates/algochat)
[![License](https://img.shields.io/github/license/CorvidLabs/rs-algochat)](https://github.com/CorvidLabs/rs-algochat/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/CorvidLabs/rs-algochat?display_name=tag)](https://github.com/CorvidLabs/rs-algochat/releases)

> **Pre-1.0 Notice**: This library is under active development. The API may change between minor versions until 1.0.

Rust implementation of the AlgoChat protocol for encrypted messaging on Algorand.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
algochat = "0.1"
```

## Usage

```rust
use algochat::{derive_keys_from_seed, encrypt_message, decrypt_message, ChatEnvelope};

// Derive keys from a 32-byte seed (e.g., from Algorand account)
let (sender_private, sender_public) = derive_keys_from_seed(&seed)?;
let (recipient_private, recipient_public) = derive_keys_from_seed(&recipient_seed)?;

// Encrypt a message
let envelope = encrypt_message(
    "Hello, World!",
    &sender_private,
    &sender_public,
    &recipient_public,
)?;

// Encode for transmission
let encoded = envelope.encode();

// Decode received message
let decoded = ChatEnvelope::decode(&encoded)?;

// Decrypt as recipient
let result = decrypt_message(&decoded, &recipient_private, &recipient_public)?;
if let Some(content) = result {
    println!("{}", content.text);
}
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

### PSK Usage

```rust
use algochat::{
    derive_keys_from_seed, encrypt_psk_message, decrypt_psk_message,
    encode_psk_envelope, decode_psk_envelope, is_psk_message,
    PSKState, PSKExchangeURI,
};

// Both parties share a 32-byte PSK (exchanged out-of-band)
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

// Check message type
assert!(is_psk_message(&encoded));

// Decode and decrypt
let decoded = decode_psk_envelope(&encoded)?;
let text = decrypt_psk_message(&decoded, &recipient_private, &recipient_public, &psk)?;

// Exchange PSK via URI
let uri = PSKExchangeURI::new("ALGO_ADDRESS", psk.to_vec(), Some("Alice".into()));
let uri_string = uri.encode();
// -> algochat-psk://v1?addr=ALGO_ADDRESS&psk=...&label=Alice
```
## Cross-Implementation Compatibility

This implementation is fully compatible with:
- [swift-algochat](https://github.com/CorvidLabs/swift-algochat) (Swift)
- [ts-algochat](https://github.com/CorvidLabs/ts-algochat) (TypeScript)
- [py-algochat](https://github.com/CorvidLabs/py-algochat) (Python)
- [kt-algochat](https://github.com/CorvidLabs/kt-algochat) (Kotlin)

## License

MIT
