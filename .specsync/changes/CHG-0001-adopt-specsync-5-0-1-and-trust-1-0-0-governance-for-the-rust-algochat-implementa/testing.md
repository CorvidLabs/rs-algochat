---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa
artifact: testing
---

# Testing

- Run cargo fmt and clippy with warnings denied.\n- Run cargo build and all 225 library tests.\n- Run the 14-test cross-implementation suite explicitly.\n- Run strict SpecSync validation at advisory threshold 0.\n- Verify all four agents and run Trust doctor and Trust verify.\n- Confirm the stable, beta, and Rust 1.85 hosted matrix remains green.

