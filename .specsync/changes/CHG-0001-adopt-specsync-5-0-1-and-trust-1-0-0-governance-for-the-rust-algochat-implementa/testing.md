---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa
artifact: testing
---

# Testing

- Run cargo fmt and clippy with warnings denied.
- Run cargo build and all 225 library tests.
- Run the 14-test cross-implementation suite explicitly.
- Run strict SpecSync validation at 100% file, LOC, and member-level API coverage.
- Verify all four agents and run Trust doctor and Trust verify.
- Confirm the stable, beta, and Rust 1.85 hosted matrix remains green.

Evidence: REQ-client-001, REQ-client-002, REQ-client-003, REQ-client-004,
REQ-client-005, REQ-protocol-001, REQ-protocol-002, REQ-protocol-003,
REQ-protocol-004, REQ-protocol-005, REQ-psk-001, REQ-psk-002, REQ-psk-003,
REQ-psk-004, REQ-psk-005, REQ-crate-001, REQ-crate-002,
REQ-cross-vectors-001, REQ-cross-vectors-002, REQ-cross-vectors-003,
REQ-cross-vectors-004, and REQ-cross-vectors-005 map to the canonical testing
companions and the successful native commands recorded by this verification gate.
