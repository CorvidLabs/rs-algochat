---
spec: cross-vectors.spec.md
---

## Requirements

### REQ-cross-vectors-001 — External fixture truth

When an implementation fixture directory is present, every available envelope SHALL decrypt to the exact corpus text and any mismatch SHALL fail.

### REQ-cross-vectors-002 — Standalone portability

The integration target SHALL run in a standalone checkout; absent optional sibling fixtures MAY skip only their scoped external group.

### REQ-cross-vectors-003 — Mandatory known answers

Embedded standard-v2 and PSK-v2 known-answer vectors SHALL always execute and SHALL fail if encoded bytes or plaintext drift.

### REQ-cross-vectors-004 — Mandatory security vectors

Authenticated-header tampering SHALL fail decryption, and a signed key announcement SHALL verify only for the signing identity.

### REQ-cross-vectors-005 — Corpus breadth

The corpus SHALL retain empty, whitespace, punctuation, structured text, multiple scripts, emoji, long, and maximum-size payload cases.

## Acceptance Criteria

- The 14-test cross-implementation target passes.
- Mandatory embedded tests execute without external files.
- Present external fixtures never produce a false-green skip.

## Constraints

- Canonical vector inputs and expected bytes are deterministic.
- Optional discovery supports CI and sibling-development layouts only.

## Out of Scope

- Other-language fixture generation belongs to those implementation repositories.
- Protocol semantics are owned by protocol and psk.

### REQ-cross-vectors-001

Present external fixtures SHALL decrypt to exact corpus text and any mismatch SHALL fail.

Acceptance Criteria
- External groups pass whenever sibling fixtures are present.

### REQ-cross-vectors-002

The integration target SHALL remain portable in a standalone checkout, with skips limited to absent optional fixture groups.

Acceptance Criteria
- The standalone cross-implementation target passes.

### REQ-cross-vectors-003

Embedded standard-v2 and PSK-v2 known-answer vectors SHALL always execute.

Acceptance Criteria
- Both deterministic vectors pass without sibling files.

### REQ-cross-vectors-004

Authenticated-header tampering SHALL fail and signed announcements SHALL verify only for the signing identity.

Acceptance Criteria
- Tamper and identity vectors pass.

### REQ-cross-vectors-005

The corpus SHALL retain Unicode, structured, boundary, long, empty, and maximum-size payloads.

Acceptance Criteria
- Corpus-driven integration tests pass.

