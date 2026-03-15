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
