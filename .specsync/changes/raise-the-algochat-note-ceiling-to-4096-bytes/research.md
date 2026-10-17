---
change: raise-the-algochat-note-ceiling-to-4096-bytes
artifact: research
---

# Research

Confirmed against consensus: a note of 4096 bytes is accepted and 4097 is rejected. At min fee 1000, an Ed25519 payment costs 1000, 1098, and 1308 microAlgos for notes of 1024, 2000, and 4096 bytes.

The integer formula is:

```
over = max(0, note_bytes - 1024)
surcharge = (over * min_fee + 9999) / 10000
fee = min_fee + surcharge
```

Falcon-1024 would add two extra minimum fees on top of that surcharge. This crate has no Falcon signer, so that term is not implemented. Header sizes stay 126 and 130. The tag stays 16. Plaintext maxima are therefore 3954 and 3950. Protocol revision for this capacity change is 1.2.1, not 1.3.
