---
spec: client.spec.md
---

## Automated Testing

| Test File | Type | What It Covers |
|-----------|------|----------------|
| src/algochat.rs tests | Rust unit | Configuration, discovery, PSK contact, transaction, and sync behavior. |
| src/blockchain.rs tests | Rust unit | Network configuration, pagination, announcements, and identity verification. |
| src/models.rs tests | Rust unit | Messages, conversations, send options, pending state, and accounts. |
| src/queue.rs tests | Rust unit | Capacity, retries, backoff, transitions, pruning, and filtering. |
| src/storage.rs tests | Rust unit | Message cache, TTL key cache, memory storage, and encrypted files. |

## Manual Testing

No live Algorand operation is required for this governance-only migration; deployment and release workflows remain unchanged.

## Edge Cases & Boundary Conditions

| Scenario | Expected Behavior |
|----------|-------------------|
| Duplicate transaction | Existing message remains singular and ordered. |
| Full queue | Enqueue returns a queue error. |
| Expired cached key | Retrieval misses and discovery can refresh it. |
| Invalid ownership signature | Verified discovery rejects the key. |
| Wrong storage password | Retrieval fails without returning key bytes. |
