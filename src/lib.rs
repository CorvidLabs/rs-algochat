//! AlgoChat - Encrypted messaging on Algorand
//!
//! Rust implementation of the AlgoChat protocol using X25519 + ChaCha20-Poly1305.
//!
//! ## Overview
//!
//! AlgoChat provides end-to-end encrypted messaging on the Algorand blockchain.
//! Messages are stored as encrypted transaction notes, providing immutable,
//! decentralized messaging with cryptographic proof of authenticity.
//!
//! ## Modules
//!
//! - [`algochat`] - Main client interface
//! - [`crypto`] - Message encryption and decryption
//! - [`envelope`] - Wire format for encrypted messages
//! - [`keys`] - Key derivation from Algorand accounts
//! - [`signature`] - Ed25519 signature verification for key ownership
//! - [`models`] - Data types for messages, conversations, etc.
//! - [`storage`] - Message cache, public key cache, and key storage
//! - [`queue`] - Message queue for offline support
//! - [`blockchain`] - Algorand integration interfaces
//! - [`types`] - Protocol constants and error types
//! - [`psk_types`] - PSK protocol v1.1 constants and types
//! - [`psk_ratchet`] - Two-level PSK ratchet key derivation
//! - [`psk_envelope`] - PSK envelope encoding/decoding
//! - [`psk_state`] - PSK counter state management
//! - [`psk_exchange`] - PSK exchange URI format
//! - [`psk_crypto`] - PSK encryption and decryption

mod algochat;
mod blockchain;
mod crypto;
mod envelope;
mod keys;
mod models;
mod psk_crypto;
mod psk_envelope;
mod psk_exchange;
mod psk_ratchet;
mod psk_state;
mod psk_types;
mod queue;
mod signature;
mod storage;
mod types;

pub use algochat::*;
pub use blockchain::*;
pub use crypto::*;
pub use envelope::*;
pub use keys::*;
pub use models::*;
pub use psk_crypto::*;
pub use psk_envelope::*;
pub use psk_exchange::*;
pub use psk_ratchet::*;
pub use psk_state::*;
pub use psk_types::*;
pub use queue::*;
pub use signature::*;
pub use storage::*;
pub use types::*;
