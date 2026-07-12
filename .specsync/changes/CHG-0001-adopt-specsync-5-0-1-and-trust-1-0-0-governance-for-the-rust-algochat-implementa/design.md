---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-rust-algochat-implementa
artifact: design
---

# Design

Migrate legacy SpecSync configuration into .specsync, retain spec status and semantics, and add type-level indexes only. Remove the duplicate v2 specs job and add an independent immutable Trust job. Standard Trust uses blocking risk, soft provenance, threshold 0, and disables managed Atlas because the existing Pages workflow remains authoritative.

