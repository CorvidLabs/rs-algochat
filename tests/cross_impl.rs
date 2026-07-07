//! Cross-implementation tests for AlgoChat.
//!
//! These tests verify that Rust can decrypt messages encrypted by other
//! implementations, ensuring full protocol compatibility.
//!
//! Supports both standard v1.0 envelopes and PSK v1.1 envelopes.

use algochat::{
    decode_psk_envelope, decrypt_message, decrypt_psk_message, derive_keys_from_seed,
    is_chat_message, is_psk_message, ChatEnvelope,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Alice's seed is available for future cross-implementation tests (e.g. verifying Alice's sent messages).
const _ALICE_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const BOB_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";

/// Standard PSK used across all implementations for cross-impl testing.
const TEST_PSK_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn test_messages() -> HashMap<&'static str, &'static str> {
    let mut messages = HashMap::new();
    messages.insert("empty", "");
    messages.insert("single_char", "X");
    messages.insert("whitespace", "   \t\n   ");
    messages.insert("numbers", "1234567890");
    messages.insert("punctuation", "!@#$%^&*()_+-=[]{}\\|;':\",./<>?");
    messages.insert("newlines", "Line 1\nLine 2\nLine 3");
    messages.insert("emoji_simple", "Hello 👋 World 🌍");
    messages.insert("emoji_zwj", "Family: 👨‍👩‍👧‍👦");
    messages.insert("chinese", "你好世界 - Hello World");
    messages.insert("arabic", "مرحبا بالعالم");
    messages.insert("japanese", "こんにちは世界 カタカナ 漢字");
    messages.insert("korean", "안녕하세요 세계");
    messages.insert("accents", "Café résumé naïve");
    messages.insert("cyrillic", "Привет мир");
    messages.insert("json", r#"{"key": "value", "num": 42}"#);
    messages.insert("html", r#"<div class="test">Content</div>"#);
    messages.insert("url", "https://example.com/path?q=test&lang=en");
    messages.insert("code", r#"func hello() { print("Hi") }"#);
    messages
}

fn long_text() -> String {
    "The quick brown fox jumps over the lazy dog. ".repeat(11)
}

fn max_payload() -> String {
    "A".repeat(882)
}

fn psk_max_payload() -> String {
    "A".repeat(878)
}

fn bob_keys() -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
    let seed = hex::decode(BOB_SEED_HEX).unwrap();
    derive_keys_from_seed(&seed).unwrap()
}

fn decrypt_envelope_file(
    path: &Path,
    bob_private: &x25519_dalek::StaticSecret,
    bob_public: &x25519_dalek::PublicKey,
) -> Option<String> {
    let hex_content = fs::read_to_string(path).ok()?.trim().to_string();
    let envelope_bytes = hex::decode(&hex_content).ok()?;

    if !is_chat_message(&envelope_bytes) {
        return None;
    }

    let envelope = ChatEnvelope::decode(&envelope_bytes).ok()?;
    let result = decrypt_message(&envelope, bob_private, bob_public).ok()??;
    Some(result.text)
}

fn find_envelope_dir(impl_name: &str) -> Option<std::path::PathBuf> {
    // Try CI path first (when rs-algochat is checked out inside test-algochat)
    let ci_path_str = format!("../test-envelopes-{}", impl_name);
    let ci_path = Path::new(&ci_path_str);
    if ci_path.exists() {
        return Some(ci_path.to_path_buf());
    }
    // Try local dev path (when repos are siblings)
    let dev_path_str = format!("../test-algochat/test-envelopes-{}", impl_name);
    let dev_path = Path::new(&dev_path_str);
    if dev_path.exists() {
        return Some(dev_path.to_path_buf());
    }
    None
}

#[test]
fn test_decrypt_swift_envelopes() {
    let Some(swift_dir) = find_envelope_dir("swift") else {
        println!("Skipping Swift envelope tests - directory not found");
        return;
    };

    let (bob_private, bob_public) = bob_keys();
    let messages = test_messages();
    let mut passed = 0;
    let mut failed = 0;

    for (key, expected) in &messages {
        let path = swift_dir.join(format!("{}.hex", key));
        if !path.exists() {
            continue;
        }

        match decrypt_envelope_file(&path, &bob_private, &bob_public) {
            Some(text) if text == *expected => {
                passed += 1;
                println!("✓ {}", key);
            }
            Some(text) => {
                failed += 1;
                println!("✗ {} - mismatch: got {:?}", key, text);
            }
            None => {
                failed += 1;
                println!("✗ {} - failed to decrypt", key);
            }
        }
    }

    // Test long_text and max_payload separately
    let long_path = swift_dir.join("long_text.hex");
    if long_path.exists() {
        if let Some(text) = decrypt_envelope_file(&long_path, &bob_private, &bob_public) {
            if text == long_text() {
                passed += 1;
                println!("✓ long_text");
            } else {
                failed += 1;
            }
        }
    }

    let max_path = swift_dir.join("max_payload.hex");
    if max_path.exists() {
        if let Some(text) = decrypt_envelope_file(&max_path, &bob_private, &bob_public) {
            if text == max_payload() {
                passed += 1;
                println!("✓ max_payload");
            } else {
                failed += 1;
            }
        }
    }

    println!("Swift cross-impl: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "Some Swift envelopes failed to decrypt");
}

#[test]
fn test_decrypt_typescript_envelopes() {
    let Some(ts_dir) = find_envelope_dir("ts") else {
        println!("Skipping TypeScript envelope tests - directory not found");
        return;
    };

    let (bob_private, bob_public) = bob_keys();
    let messages = test_messages();
    let mut passed = 0;
    let mut failed = 0;

    for (key, expected) in &messages {
        let path = ts_dir.join(format!("{}.hex", key));
        if !path.exists() {
            continue;
        }

        match decrypt_envelope_file(&path, &bob_private, &bob_public) {
            Some(text) if text == *expected => {
                passed += 1;
            }
            _ => {
                failed += 1;
            }
        }
    }

    println!(
        "TypeScript cross-impl: {}/{} passed",
        passed,
        passed + failed
    );
    assert_eq!(failed, 0, "Some TypeScript envelopes failed to decrypt");
}

#[test]
fn test_decrypt_python_envelopes() {
    let Some(py_dir) = find_envelope_dir("python") else {
        println!("Skipping Python envelope tests - directory not found");
        return;
    };

    let (bob_private, bob_public) = bob_keys();
    let messages = test_messages();
    let mut passed = 0;
    let mut failed = 0;

    for (key, expected) in &messages {
        let path = py_dir.join(format!("{}.hex", key));
        if !path.exists() {
            continue;
        }

        match decrypt_envelope_file(&path, &bob_private, &bob_public) {
            Some(text) if text == *expected => {
                passed += 1;
            }
            _ => {
                failed += 1;
            }
        }
    }

    println!("Python cross-impl: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "Some Python envelopes failed to decrypt");
}

#[test]
fn test_decrypt_kotlin_envelopes() {
    let Some(kt_dir) = find_envelope_dir("kotlin") else {
        println!("Skipping Kotlin envelope tests - directory not found");
        return;
    };

    let (bob_private, bob_public) = bob_keys();
    let messages = test_messages();
    let mut passed = 0;
    let mut failed = 0;

    for (key, expected) in &messages {
        let path = kt_dir.join(format!("{}.hex", key));
        if !path.exists() {
            continue;
        }

        match decrypt_envelope_file(&path, &bob_private, &bob_public) {
            Some(text) if text == *expected => {
                passed += 1;
            }
            _ => {
                failed += 1;
            }
        }
    }

    println!("Kotlin cross-impl: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "Some Kotlin envelopes failed to decrypt");
}

#[test]
fn test_decrypt_rust_envelopes() {
    let Some(rust_dir) = find_envelope_dir("rust") else {
        println!("Skipping Rust envelope tests - directory not found");
        return;
    };

    let (bob_private, bob_public) = bob_keys();
    let messages = test_messages();
    let mut passed = 0;
    let mut failed = 0;

    for (key, expected) in &messages {
        let path = rust_dir.join(format!("{}.hex", key));
        if !path.exists() {
            continue;
        }

        match decrypt_envelope_file(&path, &bob_private, &bob_public) {
            Some(text) if text == *expected => {
                passed += 1;
            }
            _ => {
                failed += 1;
            }
        }
    }

    // Test long_text and max_payload separately
    let long_path = rust_dir.join("long_text.hex");
    if long_path.exists() {
        if let Some(text) = decrypt_envelope_file(&long_path, &bob_private, &bob_public) {
            if text == long_text() {
                passed += 1;
            } else {
                failed += 1;
            }
        }
    }

    let max_path = rust_dir.join("max_payload.hex");
    if max_path.exists() {
        if let Some(text) = decrypt_envelope_file(&max_path, &bob_private, &bob_public) {
            if text == max_payload() {
                passed += 1;
            } else {
                failed += 1;
            }
        }
    }

    println!("Rust cross-impl: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "Some Rust envelopes failed to decrypt");
}

// ============================================================================
// PSK v1.1 cross-implementation tests
// ============================================================================

fn test_psk() -> Vec<u8> {
    hex::decode(TEST_PSK_HEX).unwrap()
}

fn decrypt_psk_envelope_file(
    path: &Path,
    bob_private: &x25519_dalek::StaticSecret,
    bob_public: &x25519_dalek::PublicKey,
    psk: &[u8],
) -> Option<String> {
    let hex_content = fs::read_to_string(path).ok()?.trim().to_string();
    let envelope_bytes = hex::decode(&hex_content).ok()?;

    if !is_psk_message(&envelope_bytes) {
        return None;
    }

    let envelope = decode_psk_envelope(&envelope_bytes).ok()?;
    decrypt_psk_message(&envelope, bob_private, bob_public, psk).ok()
}

fn find_psk_envelope_dir(impl_name: &str) -> Option<std::path::PathBuf> {
    // Try CI path first (when rs-algochat is checked out inside test-algochat)
    let ci_path_str = format!("../test-envelopes-{}/psk", impl_name);
    let ci_path = Path::new(&ci_path_str);
    if ci_path.exists() {
        return Some(ci_path.to_path_buf());
    }
    // Try local dev path (when repos are siblings)
    let dev_path_str = format!("../test-algochat/test-envelopes-{}/psk", impl_name);
    let dev_path = Path::new(&dev_path_str);
    if dev_path.exists() {
        return Some(dev_path.to_path_buf());
    }
    None
}

fn run_psk_cross_impl_test(impl_name: &str) {
    let Some(psk_dir) = find_psk_envelope_dir(impl_name) else {
        println!(
            "Skipping {} PSK envelope tests - directory not found",
            impl_name
        );
        return;
    };

    let (bob_private, bob_public) = bob_keys();
    let psk = test_psk();
    let messages = test_messages();
    let mut passed = 0;
    let mut failed = 0;

    for (key, expected) in &messages {
        let path = psk_dir.join(format!("{}.hex", key));
        if !path.exists() {
            continue;
        }

        match decrypt_psk_envelope_file(&path, &bob_private, &bob_public, &psk) {
            Some(text) if text == *expected => {
                passed += 1;
                println!("  PSK ✓ {}", key);
            }
            Some(text) => {
                failed += 1;
                println!("  PSK ✗ {} - mismatch: got {:?}", key, text);
            }
            None => {
                failed += 1;
                println!("  PSK ✗ {} - failed to decrypt", key);
            }
        }
    }

    // Test long_text and max_payload
    let long_path = psk_dir.join("long_text.hex");
    if long_path.exists() {
        if let Some(text) = decrypt_psk_envelope_file(&long_path, &bob_private, &bob_public, &psk) {
            if text == long_text() {
                passed += 1;
                println!("  PSK ✓ long_text");
            } else {
                failed += 1;
                println!("  PSK ✗ long_text - mismatch");
            }
        }
    }

    let max_path = psk_dir.join("max_payload.hex");
    if max_path.exists() {
        if let Some(text) = decrypt_psk_envelope_file(&max_path, &bob_private, &bob_public, &psk) {
            if text == psk_max_payload() {
                passed += 1;
                println!("  PSK ✓ max_payload");
            } else {
                failed += 1;
                println!("  PSK ✗ max_payload - mismatch");
            }
        }
    }

    // Test session boundary (counter=100)
    let boundary_path = psk_dir.join("session_boundary.hex");
    if boundary_path.exists() {
        if let Some(text) =
            decrypt_psk_envelope_file(&boundary_path, &bob_private, &bob_public, &psk)
        {
            if text == "Session boundary test" {
                passed += 1;
                println!("  PSK ✓ session_boundary (counter=100)");
            } else {
                failed += 1;
                println!("  PSK ✗ session_boundary - mismatch: got {:?}", text);
            }
        }
    }

    // Test mid-session (counter=42)
    let mid_path = psk_dir.join("mid_session.hex");
    if mid_path.exists() {
        if let Some(text) = decrypt_psk_envelope_file(&mid_path, &bob_private, &bob_public, &psk) {
            if text == "Mid-session test at counter 42" {
                passed += 1;
                println!("  PSK ✓ mid_session (counter=42)");
            } else {
                failed += 1;
                println!("  PSK ✗ mid_session - mismatch: got {:?}", text);
            }
        }
    }

    println!(
        "{} PSK cross-impl: {}/{} passed",
        impl_name,
        passed,
        passed + failed
    );
    assert_eq!(
        failed, 0,
        "Some {} PSK envelopes failed to decrypt",
        impl_name
    );
}

#[test]
fn test_decrypt_swift_psk_envelopes() {
    run_psk_cross_impl_test("swift");
}

#[test]
fn test_decrypt_typescript_psk_envelopes() {
    run_psk_cross_impl_test("ts");
}

#[test]
fn test_decrypt_python_psk_envelopes() {
    run_psk_cross_impl_test("python");
}

#[test]
fn test_decrypt_kotlin_psk_envelopes() {
    run_psk_cross_impl_test("kotlin");
}

#[test]
fn test_decrypt_rust_psk_envelopes() {
    run_psk_cross_impl_test("rust");
}

// ============================================================================
// Proposal 0001: v2 AEAD header binding + identity verification vectors
//
// These are the canonical (reference) known-answer vectors generated by the rs
// implementation. Other implementations (ts/py/swift/kt) port against them.
//
// Fixed inputs:
//   sender_seed    = 01 * 32   -> X25519 sender key
//   recipient_seed = 02 * 32   -> X25519 recipient (Bob) key
//   ephemeral_seed = 03 * 32   -> X25519 ephemeral key (deterministic for KAT)
//   nonce          = 04 * 12
//   initial_psk    = AA * 32   (PSK vector only), ratchet_counter = 0
//   plaintext      = {"text":"Hello, AlgoChat!"}
// ============================================================================

use algochat::{
    derive_hybrid_symmetric_key, derive_psk_at_counter, derive_sender_key, encode_psk_envelope,
    encrypt_message_v2, encrypt_psk_message_v2, verify_encryption_key_bytes, x25519_ecdh,
    PSKEnvelope, PROTOCOL_VERSION_V2, PSK_VERSION_V2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

const KAT_SENDER_SEED: [u8; 32] = [0x01u8; 32];
const KAT_RECIPIENT_SEED: [u8; 32] = [0x02u8; 32];
const KAT_EPHEMERAL_SEED: [u8; 32] = [0x03u8; 32];
const KAT_NONCE: [u8; 12] = [0x04u8; 12];
const KAT_PSK: [u8; 32] = [0xAAu8; 32];
const KAT_PLAINTEXT: &str = r#"{"text":"Hello, AlgoChat!"}"#;

const ENCRYPTION_INFO_PREFIX: &[u8] = b"AlgoChatV1";
const SENDER_KEY_INFO_PREFIX: &[u8] = b"AlgoChatV1-SenderKey";

// Expected outputs (canonical, generated by the rs reference).
const STANDARD_V2_ENVELOPE_HEX: &str = "0201cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86ca56fa4362f0646d8818192d769727ca9dca7fc60730b69b632fc7bb370757f53040404040404040404040404da920f09c621960fa09f1da7218c88dd53e6a04a6053635c9c38aa9dfb52f142804a3308ce3c60ebfedd7b0c46a123cffe1961dd7e1b600f439b401d2e68ed121ccc9ee49affb0c854e467f4c63941da90af99042db87319b91865";

const PSK_V2_ENVELOPE_HEX: &str = "020200000000cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86ca56fa4362f0646d8818192d769727ca9dca7fc60730b69b632fc7bb370757f530404040404040404040404041e52d902edadbb55263ded7fdd3cbaf39224813d2b528ac8977ad7a826a2a7490c30c7940dcdbcd0d001561f39489860e12310ee1bb20af305c081c781ca5c812851be7463629020db38b1b980ae68f7519f54f1c5a8cf652a1b3f";

fn kat_keys() -> (
    x25519_dalek::StaticSecret,
    x25519_dalek::PublicKey, // sender
    x25519_dalek::StaticSecret,
    x25519_dalek::PublicKey, // recipient
    x25519_dalek::StaticSecret,
    x25519_dalek::PublicKey, // ephemeral
) {
    let (sp, spk) = derive_keys_from_seed(&KAT_SENDER_SEED).unwrap();
    let (rp, rpk) = derive_keys_from_seed(&KAT_RECIPIENT_SEED).unwrap();
    let (ep, epk) = derive_keys_from_seed(&KAT_EPHEMERAL_SEED).unwrap();
    (sp, spk, rp, rpk, ep, epk)
}

/// Standard v2 known-answer vector: deterministic encryption produces the
/// canonical envelope, and it round-trips back to the plaintext.
#[test]
fn test_v2_standard_known_answer_vector() {
    let (_sp, spk, rp, rpk, ep, epk) = kat_keys();
    let sender_pub = *spk.as_bytes();
    let recipient_pub = *rpk.as_bytes();
    let ephemeral_pub = *epk.as_bytes();

    // Reconstruct the deterministic envelope using the fixed ephemeral + nonce.
    let shared = x25519_ecdh(&ep, &rpk);
    let mut info = Vec::new();
    info.extend_from_slice(ENCRYPTION_INFO_PREFIX);
    info.extend_from_slice(&sender_pub);
    info.extend_from_slice(&recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&ephemeral_pub), &shared);
    let mut sym = [0u8; 32];
    hk.expand(&info, &mut sym).unwrap();

    let mut env = ChatEnvelope {
        version: PROTOCOL_VERSION_V2,
        protocol_id: 0x01,
        sender_public_key: sender_pub,
        ephemeral_public_key: ephemeral_pub,
        nonce: KAT_NONCE,
        encrypted_sender_key: vec![],
        ciphertext: vec![],
    };
    let aad = env.v2_aad();
    let nonce = Nonce::from_slice(&KAT_NONCE);
    let cipher = ChaCha20Poly1305::new_from_slice(&sym).unwrap();
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: KAT_PLAINTEXT.as_bytes(),
                aad: &aad,
            },
        )
        .unwrap();

    let sender_shared = x25519_ecdh(&ep, &spk);
    let mut sinfo = Vec::new();
    sinfo.extend_from_slice(SENDER_KEY_INFO_PREFIX);
    sinfo.extend_from_slice(&sender_pub);
    let shk = Hkdf::<Sha256>::new(Some(&ephemeral_pub), &sender_shared);
    let mut skey = [0u8; 32];
    shk.expand(&sinfo, &mut skey).unwrap();
    let scipher = ChaCha20Poly1305::new_from_slice(&skey).unwrap();
    let esk = scipher
        .encrypt(
            nonce,
            Payload {
                msg: &sym,
                aad: &aad,
            },
        )
        .unwrap();

    env.encrypted_sender_key = esk;
    env.ciphertext = ct;
    let encoded = env.encode();

    assert_eq!(hex::encode(&encoded), STANDARD_V2_ENVELOPE_HEX);
    assert_eq!(encoded[0], PROTOCOL_VERSION_V2);

    // Round-trips: recipient and sender both recover the plaintext.
    let decoded = ChatEnvelope::decode(&encoded).unwrap();
    let dec = decrypt_message(&decoded, &rp, &rpk).unwrap().unwrap();
    assert_eq!(dec.text, "Hello, AlgoChat!");
    let _ = ep; // ephemeral private not needed past encryption
}

/// PSK v2 known-answer vector.
#[test]
fn test_v2_psk_known_answer_vector() {
    let (_sp, spk, rp, rpk, ep, epk) = kat_keys();
    let sender_pub = *spk.as_bytes();
    let recipient_pub = *rpk.as_bytes();
    let ephemeral_pub = *epk.as_bytes();

    let current_psk = derive_psk_at_counter(&KAT_PSK, 0).unwrap();
    let shared = x25519_ecdh(&ep, &rpk);
    let sym = derive_hybrid_symmetric_key(
        &shared,
        &current_psk,
        &ephemeral_pub,
        &sender_pub,
        &recipient_pub,
    )
    .unwrap();

    let mut env = PSKEnvelope {
        version: PSK_VERSION_V2,
        ratchet_counter: 0,
        sender_public_key: sender_pub,
        ephemeral_public_key: ephemeral_pub,
        nonce: KAT_NONCE,
        encrypted_sender_key: vec![],
        ciphertext: vec![],
    };
    let aad = env.v2_aad();
    let nonce = Nonce::from_slice(&KAT_NONCE);
    let cipher = ChaCha20Poly1305::new_from_slice(&sym).unwrap();
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: KAT_PLAINTEXT.as_bytes(),
                aad: &aad,
            },
        )
        .unwrap();

    let sender_shared = x25519_ecdh(&ep, &spk);
    let skey =
        derive_sender_key(&sender_shared, &current_psk, &ephemeral_pub, &sender_pub).unwrap();
    let scipher = ChaCha20Poly1305::new_from_slice(&skey).unwrap();
    let esk = scipher
        .encrypt(
            nonce,
            Payload {
                msg: &sym,
                aad: &aad,
            },
        )
        .unwrap();

    env.encrypted_sender_key = esk;
    env.ciphertext = ct;
    let encoded = encode_psk_envelope(&env);

    assert_eq!(hex::encode(&encoded), PSK_V2_ENVELOPE_HEX);
    assert_eq!(encoded[0], PSK_VERSION_V2);

    let decoded = decode_psk_envelope(&encoded).unwrap();
    let dec = decrypt_psk_message(&decoded, &rp, &rpk, &KAT_PSK).unwrap();
    assert_eq!(dec, KAT_PLAINTEXT);
}

/// Header-tamper vector: flipping one AAD byte of a v2 envelope MUST fail
/// decryption. Asserted for both the standard and PSK profiles.
#[test]
fn test_v2_header_tamper_vector() {
    let (sp, spk, rp, rpk, _ep, _epk) = kat_keys();

    // Standard: random ephemeral is fine here; we only need tamper behavior.
    let env = encrypt_message_v2("tamper", &sp, &spk, &rpk).unwrap();
    let mut encoded = env.encode();
    // Flip a byte inside the AAD region (offset 2 = first sender_public_key byte).
    encoded[2] ^= 0x01;
    let tampered = ChatEnvelope::decode(&encoded).unwrap();
    assert!(decrypt_message(&tampered, &rp, &rpk).is_err());

    // PSK: flip a byte in the ratchet_counter (offset 2..6, bound by PSK v2 AAD).
    let psk_env = encrypt_psk_message_v2("tamper", &sp, &spk, &rpk, &KAT_PSK, 1).unwrap();
    let mut psk_encoded = encode_psk_envelope(&psk_env);
    psk_encoded[2] ^= 0x01;
    let psk_tampered = decode_psk_envelope(&psk_encoded).unwrap();
    assert!(decrypt_psk_message(&psk_tampered, &rp, &rpk, &KAT_PSK).is_err());
}

/// Signed-announcement vector: an announcement signed by account A verifies
/// against A's Ed25519 key and fails against any other account's key.
#[test]
fn test_announcement_verify_vector() {
    use ed25519_dalek::{Signer, SigningKey};

    // The X25519 key being announced (Bob's encryption key).
    let (_, x25519_pub) = derive_keys_from_seed(&KAT_RECIPIENT_SEED).unwrap();
    let x25519_bytes = *x25519_pub.as_bytes();

    // Account A and B Ed25519 keys (these are the keys an Algorand address
    // decodes to). Fixed seeds for reproducibility across implementations.
    let signing_a = SigningKey::from_bytes(&[0x11u8; 32]);
    let ed_a = *signing_a.verifying_key().as_bytes();
    let signing_b = SigningKey::from_bytes(&[0x22u8; 32]);
    let ed_b = *signing_b.verifying_key().as_bytes();

    // A signs the X25519 key.
    let sig_a = signing_a.sign(&x25519_bytes).to_bytes();

    // Verification passes for A.
    assert!(verify_encryption_key_bytes(&x25519_bytes, &ed_a, &sig_a).unwrap());
    // Verification fails for B (wrong identity).
    assert!(!verify_encryption_key_bytes(&x25519_bytes, &ed_b, &sig_a).unwrap());

    // Canonical expected values (ported by other implementations).
    assert_eq!(
        hex::encode(ed_a),
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    );
    assert_eq!(
        hex::encode(sig_a),
        "558d91c66ed93617177c76aa01f559957eb8f904ff1db4383844c96c9fc95d99c4cad9dc5b516026d6cd4517e975ec68c08f14d50bc68fddf291210bba98a70a"
    );
}
