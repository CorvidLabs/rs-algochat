## ADDED

### REQUIREMENT REQ-cross-vectors-001
Present external fixtures SHALL decrypt to exact corpus text and any mismatch SHALL fail.

Acceptance Criteria
- External groups pass whenever sibling fixtures are present.

### REQUIREMENT REQ-cross-vectors-002
The integration target SHALL remain portable in a standalone checkout, with skips limited to absent optional fixture groups.

Acceptance Criteria
- The standalone cross-implementation target passes.

### REQUIREMENT REQ-cross-vectors-003
Embedded standard-v2 and PSK-v2 known-answer vectors SHALL always execute.

Acceptance Criteria
- Both deterministic vectors pass without sibling files.

### REQUIREMENT REQ-cross-vectors-004
Authenticated-header tampering SHALL fail and signed announcements SHALL verify only for the signing identity.

Acceptance Criteria
- Tamper and identity vectors pass.

### REQUIREMENT REQ-cross-vectors-005
The corpus SHALL retain Unicode, structured, boundary, long, empty, and maximum-size payloads.

Acceptance Criteria
- Corpus-driven integration tests pass.
