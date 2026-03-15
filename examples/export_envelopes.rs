//! Export test envelopes for cross-implementation verification.
//!
//! Exports both standard v1.0 and PSK v1.1 envelopes.

use algochat::{
    derive_keys_from_seed, encode_psk_envelope, encrypt_message, encrypt_psk_message,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const ALICE_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const BOB_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000002";

/// Standard PSK used across all implementations for cross-impl testing.
const TEST_PSK_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn test_messages() -> HashMap<&'static str, String> {
    let mut messages: HashMap<&'static str, String> = HashMap::new();
    messages.insert("empty", String::new());
    messages.insert("single_char", "X".to_string());
    messages.insert("whitespace", "   \t\n   ".to_string());
    messages.insert("numbers", "1234567890".to_string());
    messages.insert(
        "punctuation",
        "!@#$%^&*()_+-=[]{}\\|;':\",./<>?".to_string(),
    );
    messages.insert("newlines", "Line 1\nLine 2\nLine 3".to_string());
    messages.insert("emoji_simple", "Hello 👋 World 🌍".to_string());
    messages.insert("emoji_zwj", "Family: 👨‍👩‍👧‍👦".to_string());
    messages.insert("chinese", "你好世界 - Hello World".to_string());
    messages.insert("arabic", "مرحبا بالعالم".to_string());
    messages.insert("japanese", "こんにちは世界 カタカナ 漢字".to_string());
    messages.insert("korean", "안녕하세요 세계".to_string());
    messages.insert("accents", "Café résumé naïve".to_string());
    messages.insert("cyrillic", "Привет мир".to_string());
    messages.insert("json", r#"{"key": "value", "num": 42}"#.to_string());
    messages.insert("html", r#"<div class="test">Content</div>"#.to_string());
    messages.insert("url", "https://example.com/path?q=test&lang=en".to_string());
    messages.insert("code", r#"func hello() { print("Hi") }"#.to_string());
    messages.insert(
        "long_text",
        "The quick brown fox jumps over the lazy dog. ".repeat(11),
    );
    messages.insert("max_payload", "A".repeat(882));
    messages
}

fn psk_test_messages() -> HashMap<&'static str, String> {
    let mut messages: HashMap<&'static str, String> = HashMap::new();
    messages.insert("empty", String::new());
    messages.insert("single_char", "X".to_string());
    messages.insert("whitespace", "   \t\n   ".to_string());
    messages.insert("numbers", "1234567890".to_string());
    messages.insert(
        "punctuation",
        "!@#$%^&*()_+-=[]{}\\|;':\",./<>?".to_string(),
    );
    messages.insert("newlines", "Line 1\nLine 2\nLine 3".to_string());
    messages.insert("emoji_simple", "Hello 👋 World 🌍".to_string());
    messages.insert("emoji_zwj", "Family: 👨‍👩‍👧‍👦".to_string());
    messages.insert("chinese", "你好世界 - Hello World".to_string());
    messages.insert("arabic", "مرحبا بالعالم".to_string());
    messages.insert("japanese", "こんにちは世界 カタカナ 漢字".to_string());
    messages.insert("korean", "안녕하세요 세계".to_string());
    messages.insert("accents", "Café résumé naïve".to_string());
    messages.insert("cyrillic", "Привет мир".to_string());
    messages.insert("json", r#"{"key": "value", "num": 42}"#.to_string());
    messages.insert("html", r#"<div class="test">Content</div>"#.to_string());
    messages.insert("url", "https://example.com/path?q=test&lang=en".to_string());
    messages.insert("code", r#"func hello() { print("Hi") }"#.to_string());
    messages.insert(
        "long_text",
        "The quick brown fox jumps over the lazy dog. ".repeat(11),
    );
    messages.insert("max_payload", "A".repeat(878));
    messages
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("test-envelopes-rust");

    let alice_seed = hex::decode(ALICE_SEED_HEX).unwrap();
    let bob_seed = hex::decode(BOB_SEED_HEX).unwrap();

    let (alice_private, alice_public) = derive_keys_from_seed(&alice_seed).unwrap();
    let (_, bob_public) = derive_keys_from_seed(&bob_seed).unwrap();

    let output_path = Path::new(output_dir);
    fs::create_dir_all(output_path).unwrap();

    // Export standard v1.0 envelopes
    let messages = test_messages();
    let mut count = 0;

    for (key, message) in &messages {
        let envelope =
            encrypt_message(message, &alice_private, &alice_public, &bob_public).unwrap();
        let encoded = envelope.encode();
        let hex_encoded = hex::encode(&encoded);

        let file_path = output_path.join(format!("{}.hex", key));
        fs::write(&file_path, &hex_encoded).unwrap();
        println!("  v1.0 ✓ {}", key);
        count += 1;
    }

    println!("Rust: exported {} standard v1.0 envelopes", count);

    // Export PSK v1.1 envelopes
    let psk = hex::decode(TEST_PSK_HEX).unwrap();
    let psk_dir = output_path.join("psk");
    fs::create_dir_all(&psk_dir).unwrap();

    let psk_messages = psk_test_messages();
    let mut psk_count = 0;

    // Export at counter 0 (standard test counter)
    for (key, message) in &psk_messages {
        let envelope =
            encrypt_psk_message(message, &alice_private, &alice_public, &bob_public, &psk, 0)
                .unwrap();
        let encoded = encode_psk_envelope(&envelope);
        let hex_encoded = hex::encode(&encoded);

        let file_path = psk_dir.join(format!("{}.hex", key));
        fs::write(&file_path, &hex_encoded).unwrap();
        println!("  v1.1 ✓ {} (counter=0)", key);
        psk_count += 1;
    }

    // Export at counter 100 (session boundary) with a representative message
    let boundary_envelope = encrypt_psk_message(
        "Session boundary test",
        &alice_private,
        &alice_public,
        &bob_public,
        &psk,
        100,
    )
    .unwrap();
    let boundary_encoded = encode_psk_envelope(&boundary_envelope);
    fs::write(
        psk_dir.join("session_boundary.hex"),
        hex::encode(&boundary_encoded),
    )
    .unwrap();
    println!("  v1.1 ✓ session_boundary (counter=100)");
    psk_count += 1;

    // Export at counter 42 (arbitrary mid-session)
    let mid_envelope = encrypt_psk_message(
        "Mid-session test at counter 42",
        &alice_private,
        &alice_public,
        &bob_public,
        &psk,
        42,
    )
    .unwrap();
    let mid_encoded = encode_psk_envelope(&mid_envelope);
    fs::write(psk_dir.join("mid_session.hex"), hex::encode(&mid_encoded)).unwrap();
    println!("  v1.1 ✓ mid_session (counter=42)");
    psk_count += 1;

    println!(
        "Rust: exported {} PSK v1.1 envelopes to {}/psk",
        psk_count, output_dir
    );
    println!(
        "Total: {} envelopes exported to {}",
        count + psk_count,
        output_dir
    );
}
