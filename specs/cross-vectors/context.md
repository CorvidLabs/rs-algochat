---
spec: cross-vectors.spec.md
---

## Key Decisions

- Keep sibling fixture directories optional for standalone portability.
- Keep v2 known-answer, header-tamper, and identity vectors embedded and mandatory.
- Compare decrypted Unicode payloads byte-for-byte.

## Files to Read First

- tests/cross_impl.rs for the corpus, fixture discovery, and embedded vectors.
- Proposal 0001 for deterministic v2 inputs and security properties.

## Current Status

- Fourteen integration tests are active; external groups run when fixtures exist.
- Missing sibling fixtures are not proof of interoperability; embedded vectors remain mandatory.

## Notes

- CI checks out this repository standalone, so portable verification cannot require siblings.
