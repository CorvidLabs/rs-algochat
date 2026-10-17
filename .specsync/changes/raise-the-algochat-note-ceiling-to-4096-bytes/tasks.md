---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: tasks
---

# Tasks

- [x] Set `MAX_NOTE_SIZE` to 4096, `MAX_PAYLOAD_SIZE` to 3954, and `PSK_MAX_PAYLOAD_SIZE` to 3950.
- [x] Add `payment_fee` using one minimum fee plus the note surcharge.
- [x] Test legacy sizes, exact 4096-byte notes, the extra-byte failure, and fees 1000, 1098, and 1308.
- [x] Update canonical specs and bump the crate to 0.3.0.
- [ ] Human definition approval remains with the owner. Do not accept or archive this change from the implementation session.
