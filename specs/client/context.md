---
spec: client.spec.md
---

## Key Decisions

- Network access stays behind AlgodClient and IndexerClient async traits.
- Persistence stays behind MessageCache and EncryptionKeyStorage.
- Verified discovery requires Ed25519 ownership proof for an X25519 key.
- Each PSK contact synchronizes its ratchet state.

## Files to Read First

- src/algochat.rs for orchestration and PSK contact flows.
- src/blockchain.rs for network ports and signed-key discovery.
- src/models.rs for domain state; src/storage.rs and src/queue.rs for persistence.

## Current Status

- This is the active implementation contract; adoption changes no product behavior.
- Native unit and cross-implementation verification are the release truth.

## Notes

- Proposal 0001 remains canonical for v2 header authentication and identity verification.
