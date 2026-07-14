---
module: cross-vectors
version: 1.0.1
status: active
owner: CorvidLabs
files:
  - tests/cross_impl.rs
db_tables: []
depends_on:
  - client
  - protocol
  - psk
---

# Cross Vectors

## Purpose

Defines the interoperability boundary for Rust against Swift, TypeScript, Python,
Kotlin, Go, and C# envelope producers plus deterministic proposal-0001 vectors.
External envelope directories are optional locally; canonical known-answer,
tamper, and identity vectors always run from data embedded in the Rust tests.

## Public API

### Verification Groups

| Group | Description |
|-------|-------------|
| External standard envelopes | Decrypts discovered sibling fixtures for every supported implementation and compares exact Unicode plaintext. |
| External PSK envelopes | Decrypts available PSK fixtures using the shared initial PSK and expected payload corpus. |
| Standard v2 known answer | Reproduces deterministic proposal-0001 envelope bytes and plaintext. |
| PSK v2 known answer | Reproduces deterministic hybrid/ratchet envelope bytes and plaintext. |
| Header tamper | Flips authenticated metadata and requires decryption failure. |
| Signed announcement | Requires account A's signature to verify for A and fail for account B. |

This test module intentionally exports no library API.

## Invariants

1. Present external fixtures must decrypt to byte-for-byte expected plaintext; mismatches never silently skip.
2. Missing optional sibling fixture directories are reported and skipped only for local portability.
3. Embedded v2 known-answer vectors always execute and are independent of sibling repositories.
4. The corpus covers empty text, whitespace, punctuation, JSON/HTML/code, multiple scripts, emoji/ZWJ, long text, and maximum payloads.
5. Any authenticated v2 header mutation must fail before plaintext is exposed.

## Behavioral Examples

### Scenario: Cross-language fixture

- **Given** a sibling implementation's envelope directory is present
- **When** Rust decodes every available corpus entry
- **Then** all decrypted strings match exactly and the test fails on any mismatch

### Scenario: Portable CI

- **Given** sibling fixture directories are absent on a standalone checkout
- **When** the cross-implementation target runs
- **Then** optional external groups report their skip while embedded known-answer and security vectors still execute

## Error Cases

| Condition | Behavior |
|-----------|----------|
| Present fixture is invalid or plaintext differs | Fail the test with the implementation and corpus entry. |
| Optional fixture directory is absent | Print a scoped skip and continue to embedded vectors. |
| Embedded known-answer bytes drift | Fail, identifying protocol incompatibility. |
| Tampered header decrypts or wrong identity verifies | Fail as a security regression. |

## Dependencies

### Consumes

| Module | What is used |
|--------|-------------|
| `client` | Key derivation and public API entry points. |
| `protocol` | Standard envelope decoding/decryption and signature verification. |
| `psk` | PSK envelope decoding/decryption and ratchet behavior. |

### Consumed By

| Module | What is used |
|--------|-------------|

## Change Log

| Date | Author | Change |
|------|--------|--------|
| 2026-07-14 | CorvidLabs | Made the existing external and embedded vector boundary canonical in SpecSync 5.0.1. |
| 2026-07-14 | CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa: Adopt SpecSync 5.0.1 and Trust 1.0.0 governance for the Rust AlgoChat implementation |
