---
spec: protocol.spec.md
---

## Automated Testing

| Test File | Type | What It Covers |
|-----------|------|----------------|
| src/crypto.rs tests | Rust unit | v1/v2 encrypt/decrypt, payload forms, limits, and wrong keys. |
| src/envelope.rs tests | Rust unit | Encoding, decoding, recognition, versions, and malformed input. |
| src/keys.rs tests | Rust unit | Deterministic derivation, length checks, and ECDH agreement. |
| src/signature.rs tests | Rust unit | Signing, verification, malformed input, and fingerprinting. |
| tests/cross_impl.rs | Rust integration | Known answers, tamper, identity, Unicode, and external compatibility. |

## Manual Testing

No manual cryptographic acceptance substitutes for deterministic native and cross-vector suites.

## Edge Cases & Boundary Conditions

| Scenario | Expected Behavior |
|----------|-------------------|
| 883-byte plaintext | Reject with MessageTooLarge. |
| Unknown version or protocol | Reject with typed protocol error. |
| Mutated v2 header | Fail AEAD authentication. |
| Wrong recipient key | Fail without plaintext. |
| Invalid signature length | Return typed signature error. |
