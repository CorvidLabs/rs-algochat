## ADDED

### REQUIREMENT REQ-client-001
Verified discovery SHALL reject a required encryption key whose Ed25519 ownership proof is absent or invalid.

Acceptance Criteria
- Native discovery and identity tests pass.

### REQUIREMENT REQ-client-002
Conversations SHALL deduplicate by transaction ID and preserve chronological ordering.

Acceptance Criteria
- Native model and sync tests pass.

### REQUIREMENT REQ-client-003
The offline queue SHALL enforce capacity, retry, backoff, and explicit state transitions.

Acceptance Criteria
- Native queue tests pass.

### REQUIREMENT REQ-client-004
Cache and key-storage implementations SHALL preserve their async abstraction boundaries and SHALL not expose key material on password failure.

Acceptance Criteria
- Native cache and storage tests pass.

### REQUIREMENT REQ-client-005
PSK contact operations SHALL synchronize counters and validate replay state before returning received plaintext.

Acceptance Criteria
- Native PSK contact and replay tests pass.
