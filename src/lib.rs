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

mod algochat;
mod blockchain;
mod crypto;
mod envelope;
mod keys;
mod models;
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
pub use queue::*;
pub use signature::*;
pub use storage::*;
pub use types::*;
