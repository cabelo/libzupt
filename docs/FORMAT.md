# libzupt application format v2

All sizes below are in bytes. This document specifies the C++/binding API;
it does not describe TLS, X.509 or the separate zupt compression container.
Library version 2.0.0, key format 2 and encryption discriminator 3 are distinct.

## API keys

| Offset | Public key | Size |
| --- | --- | --- |
| 0 | ASCII `ZKEY` | 4 |
| 4 | Version `0x02` | 1 |
| 5 | Flags `0x00` | 1 |
| 6 | Reserved, zero | 2 |
| 8 | FIPS 203 ML-KEM-768 encapsulation key | 1,184 |
| 1192 | X25519 public key | 32 |

A private key has the same first 1,224 bytes except flags `0x01`, followed by
the 2,400-byte ML-KEM decapsulation key and the 32-byte X25519 private key.
Its total size is 3,656 bytes. These buffers have no trailing checksum.
Historical archive helpers add an eight-byte XXH64 checksum; those files are
not directly interchangeable with these API buffers.

## Encryption header

| Offset | Field | Size |
| --- | --- | --- |
| 0 | Discriminator `0x03` | 1 |
| 1 | ML-KEM-768 ciphertext | 1,088 |
| 1089 | Ephemeral X25519 public key | 32 |
| 1121 | Per-message base nonce | 16 |

Total: 1,137 bytes. New encryption rejects v1 public keys. Normal decryption
requires a v2 private key and exactly this header/discriminator.

## Hybrid key derivation

Compute the 32-byte ML-KEM secret `ml_ss` and 32-byte X25519 secret `x_ss`.
Reject an all-zero `x_ss`. With concatenation denoted by `||`:

```
material = SHA3-512(ml_ss || x_ss || ml_ct || ephemeral_pk || "libzupt/hybrid/v2")
aes_key = material[0:32]
record_mac_key = material[32:64]
envelope_mac_key = HMAC-SHA256(record_mac_key, "libzupt/envelope/key/v2")
```

The v2 ASCII context strings exclude a terminating NUL. This is an
application-specific hybrid construction requiring independent review.
ML-KEM primitive interoperability does not imply whole-format compatibility
with other libraries' hybrid file formats.

## Ciphertext envelope

```
"ZUP2" || u64le(total_plaintext_length) || record_0 || ... || record_n || final_tag
```

Each record is:

```
u32le(payload_length) || nonce[16] || AES256CTR(payload) || record_tag[32]
record_tag = HMAC-SHA256(record_mac_key, nonce || encrypted_payload)
```

Payloads have at most 4 MiB. There is at least one record, including for an
empty message. The first eight base-nonce bytes are XORed with the
little-endian block index to derive each record nonce. AES-CTR increments
the final eight nonce bytes as a big-endian counter. A zero-length record
is valid only as the sole record of a zero-length message.

```
final_tag = HMAC-SHA256(envelope_mac_key,
    "libzupt/envelope/v2" || encryption_header || envelope_without_final_tag)
```

The final tag is 32 bytes. Empty-message ciphertext is 12 + 52 + 32 = 96 bytes.
For a nonempty `L`-byte plaintext, ciphertext size is
`12 + L + 52 * ceil(L / 4194304) + 32`, excluding the separate header.

Decryption checks framing/version, derives keys and verifies `final_tag`
before parsing lengths/decrypting records. It bounds each record, verifies
its nonce/index and tag, and requires the decoded total to match the declared
length. No plaintext is returned on failure. Appending, dropping or reordering
records invalidates the complete-envelope MAC.

Replaying an entire valid envelope is not detected. Applications needing
freshness must track message IDs or sequence state outside this format.
V1 uses discriminator `0x02`, different KEM/KDF behavior and no complete-envelope
tag. It is accepted only by explicit digest-checked recovery.
