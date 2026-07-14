---
spec: crate.spec.md
---

## Requirements

### REQ-crate-001 — Root availability

Supported client, standard protocol, and PSK public items SHALL remain reachable from the algochat crate root.

### REQ-crate-002 — Encapsulation

Implementation modules SHALL remain private and src/lib.rs SHALL not introduce an independent protocol behavior path.

## Acceptance Criteria

- Member-level validation covers src/lib.rs.
- Examples, unit tests, and integration tests compile through the crate-root API.

## Constraints

- Removing or renaming a re-export is a public compatibility change requiring SDD review.

## Out of Scope

- Runtime, wire, crypto, storage, and queue semantics belong to their module contracts.

### REQ-crate-001

Supported API items SHALL remain reachable from the algochat crate root.

Acceptance Criteria
- Native examples and integration tests compile.

### REQ-crate-002

Implementation modules SHALL remain private and the crate root SHALL not duplicate protocol behavior.

Acceptance Criteria
- Source review and member-level validation pass.

