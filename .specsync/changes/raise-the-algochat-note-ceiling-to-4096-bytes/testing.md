---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: testing
---

# Testing

- `test_legacy_882_byte_plaintext_succeeds` and `test_legacy_878_byte_plaintext_succeeds` encrypt the old maxima and keep those notes at or below 1024 bytes.
- `test_max_plaintext_encodes_to_4096` in standard and PSK crypto asserts an encoded length of 4096.
- Existing too-large tests reject one byte past `MAX_PAYLOAD_SIZE` and `PSK_MAX_PAYLOAD_SIZE` before encoding returns.
- `test_payment_fees_at_min_fee_1000` expects 1000, 1098, and 1308.
- Format, clippy, `cargo test`, and `specsync check --strict --force` are the gate. Cross-implementation vectors for 882 and 878 stay in place.
