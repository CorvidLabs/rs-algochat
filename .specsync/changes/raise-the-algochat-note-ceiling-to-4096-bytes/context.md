---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: context
---

# Context

Algorand consensus accepts a 4096-byte note and rejects 4097. The first 1024 bytes cost one minimum fee. Each byte past 1024 adds one ten-thousandth of the minimum fee, rounded up once.

This crate has no Falcon signer. The payment fee is one minimum fee plus that surcharge. Do not add a Falcon implementation in this change.

Envelope layout is unchanged. No new version byte. No ML-KEM. Protocol revision is 1.2.1, not 1.3. Existing 882-byte and 878-byte plaintexts must still encrypt. Do not merge, tag, or publish.
