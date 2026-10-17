---
id: raise-the-algochat-note-ceiling-to-4096-bytes
state: draft
type: feature
base_commit: dbb480736cbec3c96431688f7891f66c8a24ccfc
---

# Raise the AlgoChat note ceiling to 4096 bytes

## Intent

Raise the AlgoChat note ceiling to 4096 bytes

## Affected Canonical Specs

- `protocol`
- `psk`
- `client`

## Acceptance Criteria

- An 882-byte standard plaintext and an 878-byte PSK plaintext still encrypt, and those notes are at most 1024 bytes. Plaintexts of 3954 and 3950 bytes encode to exactly 4096 bytes. One extra byte fails before a transaction is built. payment_fee at min_fee 1000 returns 1000, 1098, and 1308 for notes of 1024, 2000, and 4096. Headers stay 126 and 130 and the tag stays 16. Cargo.toml is 0.3.0.

## No-spec Rationale

Not applicable
