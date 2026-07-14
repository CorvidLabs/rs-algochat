---
spec: crate.spec.md
---

## Automated Testing

| Test File | Type | What It Covers |
|-----------|------|----------------|
| All colocated unit modules | Compile/test | Public items resolve through the crate implementation. |
| tests/cross_impl.rs | External-crate integration | Consumer-style imports from algochat. |
| examples/export_envelopes.rs | Example build | Public encryption and envelope exports remain usable. |

## Manual Testing

No manual flow is needed; Cargo build, test, and example compilation protect this boundary.

## Edge Cases & Boundary Conditions

| Scenario | Expected Behavior |
|----------|-------------------|
| Root re-export removed | Consumer compilation or SpecSync validation fails. |
