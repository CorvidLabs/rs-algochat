## ADDED

### REQUIREMENT REQ-psk-001
PSK encryption SHALL combine ephemeral ECDH and counter-derived PSK material.

Acceptance Criteria
- Hybrid encryption tests pass for sender and recipient.

### REQUIREMENT REQ-psk-002
Equal initial PSKs and counters SHALL derive equal ratchet material.

Acceptance Criteria
- Ratchet known-answer tests pass.

### REQUIREMENT REQ-psk-003
Version 2 SHALL authenticate the exact 82-byte PSK header including its counter.

Acceptance Criteria
- PSK known-answer and tamper vectors pass.

### REQUIREMENT REQ-psk-004
Receive state SHALL reject duplicate and out-of-window counters before returning plaintext.

Acceptance Criteria
- Replay and window tests pass.

### REQUIREMENT REQ-psk-005
Exchange URIs SHALL validate scheme, version, address, and exact 32-byte PSK material.

Acceptance Criteria
- URI roundtrip and malformed-input tests pass.
