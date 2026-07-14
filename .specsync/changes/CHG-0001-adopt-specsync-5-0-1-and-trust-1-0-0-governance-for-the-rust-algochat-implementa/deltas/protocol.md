## ADDED

### REQUIREMENT REQ-protocol-001
Standard envelopes SHALL preserve protocol ID 0x01, supported versions, and fixed field ordering.

Acceptance Criteria
- Envelope and cross-implementation tests pass.

### REQUIREMENT REQ-protocol-002
Version 2 SHALL authenticate the exact 78-byte standard metadata prefix.

Acceptance Criteria
- Known-answer and tamper vectors pass.

### REQUIREMENT REQ-protocol-003
Standard payload and cryptographic fields SHALL enforce their committed size bounds.

Acceptance Criteria
- Boundary and malformed-input tests pass.

### REQUIREMENT REQ-protocol-004
Standard envelopes SHALL support sender and recipient decryption and SHALL not return plaintext after authentication failure.

Acceptance Criteria
- Roundtrip and wrong-key tests pass.

### REQUIREMENT REQ-protocol-005
Encryption-key signatures SHALL verify only for the signing identity.

Acceptance Criteria
- Signature and identity vectors pass.
