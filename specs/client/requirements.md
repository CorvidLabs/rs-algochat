---
spec: client.spec.md
---

## Requirements

### REQ-client-001 — Verified discovery

The client SHALL distinguish unsigned discovery from verified discovery and SHALL reject a required key whose Ed25519 ownership proof is absent or invalid.

### REQ-client-002 — Conversation integrity

Conversations SHALL deduplicate messages by transaction ID and SHALL preserve chronological ordering across append, merge, transaction processing, and sync.

### REQ-client-003 — Offline queue integrity

The send queue SHALL enforce capacity, retry count, backoff, and explicit state transitions without silently discarding existing messages.

### REQ-client-004 — Storage boundaries

Message caches and encryption-key storage SHALL remain replaceable through their async traits; file storage SHALL not expose plaintext key material on password failure.

### REQ-client-005 — PSK contact state

PSK send and receive operations SHALL synchronize contact counters and SHALL validate replay state before returning received plaintext.

## Acceptance Criteria

- Member-level SpecSync validation covers every public client symbol.
- Native tests cover models, queues, caches, storage, discovery, sync, and PSK contacts.

## Constraints

- Algorand note size, protocol compatibility, async thread-safety, and public trait signatures remain unchanged.

## Out of Scope

- Cryptographic primitives and wire formats are owned by protocol and psk.
- Live-node credentials, deployment, and release publication are outside this migration.

### REQ-client-001

Verified discovery SHALL reject a required encryption key whose Ed25519 ownership proof is absent or invalid.

Acceptance Criteria
- Native discovery and identity tests pass.

### REQ-client-002

Conversations SHALL deduplicate by transaction ID and preserve chronological ordering.

Acceptance Criteria
- Native model and sync tests pass.

### REQ-client-003

The offline queue SHALL enforce capacity, retry, backoff, and explicit state transitions.

Acceptance Criteria
- Native queue tests pass.

### REQ-client-004

Cache and key-storage implementations SHALL preserve their async abstraction boundaries and SHALL not expose key material on password failure.

Acceptance Criteria
- Native cache and storage tests pass.

### REQ-client-005

PSK contact operations SHALL synchronize counters and validate replay state before returning received plaintext.

Acceptance Criteria
- Native PSK contact and replay tests pass.

