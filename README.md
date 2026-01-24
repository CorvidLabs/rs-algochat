# rs-algochat

[![CI](https://img.shields.io/github/actions/workflow/status/CorvidLabs/rs-algochat/ci.yml?label=CI&branch=main)](https://github.com/CorvidLabs/rs-algochat/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/algochat)](https://crates.io/crates/algochat)
[![License](https://img.shields.io/github/license/CorvidLabs/rs-algochat)](https://github.com/CorvidLabs/rs-algochat/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/CorvidLabs/rs-algochat)](https://github.com/CorvidLabs/rs-algochat/releases)

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

## Cross-Implementation Compatibility

This implementation is fully compatible with:
- [swift-algochat](https://github.com/CorvidLabs/swift-algochat) (Swift)
- [ts-algochat](https://github.com/CorvidLabs/ts-algochat) (TypeScript)
- [py-algochat](https://github.com/CorvidLabs/py-algochat) (Python)
- [kt-algochat](https://github.com/CorvidLabs/kt-algochat) (Kotlin)

## License

MIT
