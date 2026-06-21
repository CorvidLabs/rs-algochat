---
proposal: 0001
title: AEAD header binding (v2) and enforced identity verification
status: proposed
authors: CorvidLabs
affects: [rs-algochat, ts-algochat, py-algochat, swift-algochat, kt-algochat]
supersedes: none
---

# Proposal 0001 — AEAD header binding (v2) + enforced identity verification

## Summary

Two protocol-level hardening changes, both surfaced by a cross-implementation
security audit and confirmed present in **every** implementation:

1. **AEAD header binding (new protocol version `0x02`).** Today the
   ChaCha20-Poly1305 tag covers only the ciphertext; the envelope header
   (`version`, `protocol_id`, PSK `ratchet_counter`, public keys, `nonce`) is
   transmitted in cleartext and authenticated by nothing. This adds a backward
   compatible `v2` that binds the fixed header as Associated Data (AAD).
2. **Enforced identity verification.** `DiscoveredKey.is_verified` is computed
   loosely (or hardcoded) and **never checked before a key is used**, and some
   implementations verify the announcement signature against the wrong key. This
   specifies address→Ed25519 verification and makes `is_verified` enforceable.

Neither change breaks the existing wire format; `v1` envelopes remain valid.

## Motivation

- The header carries security-relevant metadata. `version`/`protocol_id` are
  fully unauthenticated, enabling protocol/version downgrade (e.g. forcing a PSK
  `0x02` peer down to standard `0x01`). The public keys and PSK counter are only
  *indirectly* bound via HKDF `info`/`salt`, so tampering generally yields a key
  mismatch — but that is a side effect, not an integrity guarantee, and does not
  cover `version`/`protocol_id`.
- Discovery is trust-on-first-use: the X25519 encryption key is scraped from an
  on-chain envelope (or an unsigned announcement) and used without verifying it
  belongs to the Algorand account. A malicious/compromised indexer can substitute
  a key (full MITM) unless the user manually compares the out-of-band safety
  number. The library already ships `sign_encryption_key` /
  `verify_encryption_key`, but they are not on the enforced discovery path; worse,
  py/kt/swift call `verify_encryption_key_bytes(x25519, x25519, sig)` — verifying
  against the encryption key itself rather than the account's Ed25519 key, so
  verification can never succeed.

## Part 1 — AEAD header binding (protocol `v2`)

### New constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION_V2` | `0x02` | Standard/PSK envelope version with header AAD |

`protocol_id` is unchanged (`0x01` standard, `0x02` PSK). Only the leading
`version` byte distinguishes `v1` (no AAD) from `v2` (header AAD). Wire layout,
header sizes (126 / 130), and field offsets are **identical** to `v1`.

### AAD definition

The AAD is the **metadata prefix** of the header — every header byte up to (but
not including) `encrypted_sender_key`. This binds version, protocol id, PSK
counter, both public keys, and the nonce, while avoiding any ordering dependency
on the two AEAD outputs (`encrypted_sender_key`, `ciphertext`), which carry their
own tags.

- Standard `v2`: `AAD = bytes[0..78)` = `version(1) ‖ protocol_id(1) ‖
  sender_public_key(32) ‖ ephemeral_public_key(32) ‖ nonce(12)`.
- PSK `v2`: `AAD = bytes[0..82)` = `version(1) ‖ protocol_id(1) ‖
  ratchet_counter(4, big-endian) ‖ sender_public_key(32) ‖
  ephemeral_public_key(32) ‖ nonce(12)`.

**Both** AEAD operations in an envelope (the message cipher and the
`encrypted_sender_key` cipher) use this same AAD on `v2`. `v1` continues to use
empty AAD.

### Encrypt (v2)

Identical to `v1` except `version = 0x02` and every `chacha20poly1305.encrypt`
call passes the metadata AAD above (e.g. the `Payload { msg, aad }` form in Rust;
the `authenticating:` parameter in Swift CryptoKit; the 4-arg `AEADParameters`
in Kotlin/BouncyCastle; the third `aad` argument in Python `cryptography`; the
AAD option in `@noble/ciphers`).

### Decrypt (dispatch + downgrade defense)

- `is_chat_message` / `is_psk_message` MUST accept **both** `version == 0x01` and
  `version == 0x02` (with the matching `protocol_id`).
- The receiver branches on the version byte: `v1` → decrypt with empty AAD
  (unchanged); `v2` → reconstruct the metadata AAD from the received header bytes
  and decrypt with it. A header tampered in transit fails the tag on `v2`.
- **Downgrade defense:** when a peer is known to support `v2` (advertised in
  their signed key announcement, Part 2), a receiver MUST reject inbound `v1`
  from that peer (treat as a downgrade attempt), and MUST reject a standard
  `0x01` message from a peer with an established PSK (`0x02`) channel.

### Negotiation / rollout (no break)

- A sender emits `v2` only when the recipient is known to support it; otherwise
  it emits `v1`. Capability is signalled in the key announcement (Part 2,
  `min_version`/capabilities byte). Same-deployment peers (e.g. two clients on
  the same library version) MAY default to `v2`.
- Because `v1` remains fully valid and every implementation continues to decode
  it, there is no flag-day: deployments opt into `v2` independently and
  interoperate at `v1` until both ends support `v2`.

### Invariants (additions)

- A `v2` envelope whose header bytes are modified in transit fails decryption
  with `DecryptionError` (the `v1` envelope does not — that is the gap).
- `encode`→`decode` remains lossless for `v2` (only the version byte differs).
- A `v2` round-trip with unchanged header decrypts to the original plaintext.

## Part 2 — Enforced identity verification

### Signed key announcement

A key announcement is a **self-transfer** (`sender == receiver == account`) whose
note is:

```
note = x25519_public_key(32) ‖ ed25519_signature(64)   // 96 bytes
     [ ‖ capabilities(1) ]                              // optional, 97 bytes (v2-aware)
```

- `ed25519_signature = Ed25519-Sign(account_signing_key, x25519_public_key)`.
- Optional trailing `capabilities` byte: bit 0 = "supports v2 (header AAD)".
  Notes shorter than 97 bytes are treated as `capabilities = 0` (v1-only),
  preserving compatibility with existing announcements.

### Address → Ed25519 verifying key (normative)

Discovery MUST derive the verifying key from the **Algorand address**, not from
the encryption key:

1. base32-decode the 58-char address to 36 bytes.
2. `ed25519_public_key = bytes[0..32]`; `checksum = bytes[32..36]`.
3. Verify `checksum == SHA512/256(ed25519_public_key)[28..32]`; reject otherwise
   (`InvalidPublicKey`).

### Verification + enforcement (normative)

- On discovery, verify with
  `verify_encryption_key_bytes(x25519_key, ed25519_from_address, signature)` and
  set `is_verified = true` **only** on success. An announcement with no signature
  (legacy / scraped-from-message) is `is_verified = false`.
- **Cached keys MUST carry their real `is_verified` value** — implementations
  MUST NOT hardcode cached keys as verified.
- Implementations MUST NOT silently encrypt to an `is_verified = false` key. One
  of two modes:
  - **Strict** (recommended default): refuse with an error until a verified
    announcement is found.
  - **TOFU+confirm**: allow first use but mark the conversation unverified and
    require an out-of-band safety-number confirmation before treating it as
    trusted. The full-digest safety number (not the 8-byte `fingerprint`) is the
    confirmation primitive.

### Invariants (additions)

- A key announcement signed by account A verifies against A's address-derived
  Ed25519 key and fails against any other address.
- `discover_*` returns `is_verified = false` for keys taken from a message
  envelope or an unsigned announcement.
- Encrypting to an unverified key either errors (strict) or yields an
  explicitly-unverified conversation requiring confirmation (TOFU+confirm); it is
  never silently trusted.

## Per-implementation deltas (informative)

| Impl | v2 AAD work | Identity work |
|------|-------------|---------------|
| rs   | switch 4 `encrypt`/`decrypt` sites to `Payload{msg, aad}`, version dispatch | stop hardcoding cached `is_verified`; enforce before use |
| ts   | pass AAD to `@noble/ciphers`; version dispatch | enforce `is_verified`; address-derived verify |
| py   | pass `aad` (currently `None`); version dispatch | fix verify-against-address; implement enforcement; (also: fix broken client API, add FileKeyStorage) |
| swift| pass `authenticating:`; version dispatch | call existing `SignatureVerifier` in discovery; (also: replace fake PBKDF2 with real PBKDF2-100k) |
| kt   | pass AAD via `AEADParameters`; version dispatch | add address base32+checksum decode; verify against Ed25519; (also: add FileKeyStorage) |

(The parenthetical items are separate per-repo bugs, tracked outside this
proposal; listed here for coordination.)

## Test vectors (to add to the cross-impl harness)

- A `v2` standard + PSK known-answer vector (fixed seeds/PSK/nonce → expected
  ciphertext) generated by the rs reference, asserted by every impl.
- A header-tamper vector: flip one AAD byte of a `v2` envelope; every impl MUST
  fail decryption.
- A signed-announcement vector: announcement signed by address A; verification
  passes for A, fails for B; `is_verified` reflects the result.

## Rollout

1. Land this proposal (spec). 2. Implement `v2` + identity enforcement in rs
(reference) with vectors. 3. Port to ts/py/swift/kt against the shared vectors in
`test-algochat`. 4. Once two endpoints both advertise `v2`, enable downgrade
rejection. `v1` decode support is retained indefinitely for archived messages.
