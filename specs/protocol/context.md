---
spec: protocol.spec.md
---

## Key Decisions

- Preserve version 1 empty-AAD compatibility.
- Require version 2 to authenticate its 78-byte metadata prefix.
- Derive X25519 keys deterministically from exact 32-byte seed material.
- Sign published X25519 keys with the account Ed25519 identity.

## Files to Read First

- src/types.rs and src/envelope.rs define the standard wire contract.
- src/crypto.rs defines sender/recipient encryption and payload decoding.
- src/keys.rs and src/signature.rs define identity primitives.

## Current Status

- Versions 1 and 2 are active and tested; adoption changes governance only.

## Notes

- specs/proposals/0001-aead-header-binding-and-identity-verification.md explains v2.
