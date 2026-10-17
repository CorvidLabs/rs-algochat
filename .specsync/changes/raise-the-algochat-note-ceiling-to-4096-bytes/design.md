---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: design
---

# Design

Derive the plaintext maxima from the note ceiling and the unchanged header and tag sizes.

```
MAX_PAYLOAD_SIZE = 4096 - 126 - 16 = 3954
PSK_MAX_PAYLOAD_SIZE = 4096 - 130 - 16 = 3950
```

Fee, for an allowed note, with no Falcon signer:

```
over = max(0, note_bytes - 1024)
surcharge = (over * min_fee + 9999) / 10000
fee = min_fee + surcharge
```

Reject a note larger than 4096 before returning a fee. Encryption already rejects one extra plaintext byte before any transaction is built. Wire versions stay 0x01 and 0x02.
