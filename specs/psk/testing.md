---
spec: psk.spec.md
---

## Automated Testing

| Test File | Type | What It Covers |
|-----------|------|----------------|
| src/psk_crypto.rs tests | Rust unit | Hybrid encryption, sender/recipient decryption, limits, versions, and wrong keys. |
| src/psk_envelope.rs tests | Rust unit | Fixed encoding, decoding, recognition, and malformed input. |
| src/psk_ratchet.rs tests | Rust unit | Session/position derivation and committed known answers. |
| src/psk_state.rs tests | Rust unit | Counter advance, replay, window, pruning, and serialization. |
| src/psk_exchange.rs tests | Rust unit | URI roundtrip, labels, malformed forms, and PSK length. |
| tests/cross_impl.rs | Rust integration | PSK interoperability, v2 known answer, and header tamper. |

## Manual Testing

No manual plaintext inspection replaces deterministic vectors and replay tests.

## Edge Cases & Boundary Conditions

| Scenario | Expected Behavior |
|----------|-------------------|
| 879-byte plaintext | Reject with MessageTooLarge. |
| Repeated receive counter | Reject as replay. |
| Counter older than window | Reject before decrypting. |
| Mutated v2 counter/header | Fail AEAD authentication. |
| URI with non-32-byte PSK | Reject parsing. |
