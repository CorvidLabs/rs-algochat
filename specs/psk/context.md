---
spec: psk.spec.md
---

## Key Decisions

- Combine current PSK material with ephemeral ECDH through HKDF-SHA256.
- Divide counters into deterministic sessions of 100 positions.
- Retain a 200-counter receive window with explicit replay tracking.
- Authenticate the counter and header only in version 2 while preserving v1.

## Files to Read First

- src/psk_types.rs and src/psk_envelope.rs define the wire contract.
- src/psk_crypto.rs and src/psk_ratchet.rs define key use and derivation.
- src/psk_state.rs and src/psk_exchange.rs define replay and sharing boundaries.

## Current Status

- PSK versions 1 and 2 are active and covered by unit and known-answer vectors.

## Notes

- Proposal 0001 governs v2 AEAD header binding.
