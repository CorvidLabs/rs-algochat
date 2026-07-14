---
module: crate
version: 1.0.1
status: active
owner: CorvidLabs
files:
  - src/lib.rs
db_tables: []
depends_on:
  - client
  - protocol
  - psk
---

# Crate

## Purpose

Defines the `algochat` crate boundary. Internal implementation modules remain
private and their supported public items are re-exported from the crate root.

## Public API

### Re-export Boundary

The root publicly re-exports the supported client, blockchain, model, queue,
storage, standard cryptography, envelope, key, signature, shared type, PSK
cryptography, PSK envelope, exchange, ratchet, state, and PSK type APIs. The
implementation modules themselves remain private and expose no separate module symbol.

### Exported Types

| Type | Description |
|------|-------------|

## Invariants

1. Supported API items are reachable from the crate root without exposing implementation modules.
2. The crate root contains no independent protocol behavior; behavior remains owned by its canonical module contract.

## Behavioral Examples

### Scenario: Consumer import

- **Given** a downstream Rust consumer
- **When** it imports `algochat::ChatEnvelope` or `algochat::AlgoChat`
- **Then** the item is available through the crate-root re-export surface

## Error Cases

| Condition | Behavior |
|-----------|----------|
| Public item is removed from its root re-export | Member-level SpecSync validation reports API drift. |

## Dependencies

### Consumes

| Module | What is used |
|--------|-------------|
| `client` | Client, ports, models, queue, and storage API. |
| `protocol` | Standard crypto and shared API. |
| `psk` | PSK crypto, ratchet, and exchange API. |

### Consumed By

| Module | What is used |
|--------|-------------|

## Change Log

| Date | Author | Change |
|------|--------|--------|
| 2026-07-14 | CorvidLabs | Added an explicit SpecSync contract for the crate re-export boundary. |
| 2026-07-14 | CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa: Adopt SpecSync 5.0.1 and Trust 1.0.0 governance for the Rust AlgoChat implementation |
