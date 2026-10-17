---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: requirements
---

# Requirements

- `MAX_NOTE_SIZE` is 4096. `MAX_PAYLOAD_SIZE` is 3954. `PSK_MAX_PAYLOAD_SIZE` is 3950.
- Standard header stays 126. PSK header stays 130. The Poly1305 tag stays 16.
- An 882-byte standard plaintext and an 878-byte PSK plaintext still encrypt, and those notes are at most 1024 bytes.
- The new maxima encode to exactly 4096 bytes. One extra byte fails before a transaction is built.
- `payment_fee` at min fee 1000 returns 1000, 1098, and 1308 for notes of 1024, 2000, and 4096.
- Crate version is 0.3.0. Canonical specs match these bounds.
