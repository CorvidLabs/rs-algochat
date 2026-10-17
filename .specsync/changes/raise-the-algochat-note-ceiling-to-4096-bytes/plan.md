---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: plan
---

# Plan

1. Raise the note and payload constants and add `payment_fee` in the protocol types.
2. Keep header and tag sizes unchanged. Cover 882, 878, the new 4096-byte maxima, the extra-byte rejection, and the three fee points with unit tests.
3. Update the protocol, PSK, and client specs so the written bounds match the code.
4. Bump the crate from 0.2.1 to 0.3.0.
5. Run format, clippy, tests, and `specsync check --strict --force`. Do not approve this change, merge, tag, or publish.
