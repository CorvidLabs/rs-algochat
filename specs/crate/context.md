---
spec: crate.spec.md
---

## Key Decisions

- Keep implementation modules private and re-export supported items at crate root.
- Keep behavior in the owning module rather than duplicating logic in src/lib.rs.

## Files to Read First

- src/lib.rs for the crate boundary, then the owning canonical module spec.

## Current Status

- The existing crate-root surface is active; this migration changes governance only.

## Notes

- Cargo package metadata and release publication remain independent workflows.
