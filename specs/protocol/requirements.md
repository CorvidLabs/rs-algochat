---
spec: protocol.spec.md
---

## Requirements

### REQ-protocol-001 — Wire compatibility

Standard envelopes SHALL use protocol ID 0x01, SHALL decode versions 0x01 and 0x02, and SHALL retain the fixed-width field order.

### REQ-protocol-002 — V2 header authentication

Version 2 SHALL authenticate the exact 78-byte metadata prefix so version, protocol, key, or nonce tampering fails authentication.

### REQ-protocol-003 — Payload and key bounds

The implementation SHALL enforce the 3954-byte payload maximum and exact seed, key, nonce, signature, and fixed-field lengths. A plaintext of 882 bytes SHALL still encrypt. One byte past 3954 SHALL fail before a transaction is built. A note payment fee at a minimum fee of 1000 microAlgos SHALL be 1000, 1098, and 1308 for notes of 1024, 2000, and 4096 bytes.

### REQ-protocol-004 — Bidirectional decryption

An envelope SHALL be decryptable by sender or recipient through the corresponding ECDH path and SHALL never return plaintext after tag failure.

### REQ-protocol-005 — Identity proof

Published encryption-key signatures SHALL verify only for the signing identity, and malformed keys or signatures SHALL return typed errors.

## Acceptance Criteria

- Member-level validation covers all standard protocol symbols.
- Unit and embedded vectors cover v1/v2 roundtrips, known answers, tamper, and signatures.

## Constraints

- Version 1 compatibility is preserved. The Algorand note ceiling is 4096 bytes, protocol revision 1.2.1, not 1.3.
- Random values use the system CSPRNG; fixed material exists only in deterministic tests.

## Out of Scope

- PSK ratcheting and PSK envelopes are owned by psk.
- Blockchain discovery and persistence are owned by client.

### REQ-protocol-001

Standard envelopes SHALL preserve protocol ID 0x01, supported versions, and fixed field ordering.

Acceptance Criteria
- Envelope and cross-implementation tests pass.

### REQ-protocol-002

Version 2 SHALL authenticate the exact 78-byte standard metadata prefix.

Acceptance Criteria
- Known-answer and tamper vectors pass.

### REQ-protocol-003

Standard payload and cryptographic fields SHALL enforce their committed size bounds.

Acceptance Criteria
- Boundary and malformed-input tests pass.

### REQ-protocol-004

Standard envelopes SHALL support sender and recipient decryption and SHALL not return plaintext after authentication failure.

Acceptance Criteria
- Roundtrip and wrong-key tests pass.

### REQ-protocol-005

Encryption-key signatures SHALL verify only for the signing identity.

Acceptance Criteria
- Signature and identity vectors pass.

