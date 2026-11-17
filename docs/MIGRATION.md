# Recover v1 data and migrate to v2

Back up original keys, ciphertext and matching encryption headers before an
upgrade. Keep the original v1 software available until recovery is verified.
Do not relabel a v1 key/header as v2: the KEM matrix and secret derivation differ.

V1 does not authenticate complete-message length. Obtain the SHA-256 of the
complete original plaintext from an independent trusted record or a trusted
original backup. A digest supplied next to attacker-controlled ciphertext
provides no such assurance. If no trusted digest/original exists, this tool
cannot prove completeness; preserve the originals and resolve provenance first.

## CLI

Build examples, generate fresh v2 keys, then recover and re-encrypt:

```sh
build/examples/zupt_example_file genkey new-private.key new-public.key
build/examples/zupt_migrate old-private.key old.cipher old.cipher.header \
  TRUSTED_64_HEX_DIGIT_SHA256 new-public.key new.cipher
build/examples/zupt_example_file decrypt new-private.key new.cipher \
  restored.bin new.cipher.header
```

On Windows, executables are normally under `build/examples/Release/`.
The migration tool requires the legacy API-format 3,656-byte private key,
not a checksummed archive-key file. It performs explicit v1 recovery, checks
the expected digest, and only then produces v2 ciphertext. Recovered plaintext
is not written to a temporary file. Output files are created exclusively;
existing files are not overwritten. The result includes `new.cipher.header`.

Compare the restored plaintext hash with the trusted original record before
retiring old software or keys. Keep v1 backups until normal recovery procedures
have been exercised with the new software. Do not delete originals as part of
migration automation.

## API

`zupt_hybrid_decrypt_legacy` takes v1 key/ciphertext/header buffers, an expected
32-byte plaintext SHA-256 and an output-length pointer. It returns NULL on
bad authentication/digest, wrong versions or malformed input. Normal
`zupt_hybrid_decrypt` has no legacy fallback. Re-encrypt a successful recovery
with a freshly generated v2 public key and release native memory with `zupt_free`.

Legacy zero-byte ciphertext without an authentication record is not accepted.
Recover a known empty original from its trusted source and encrypt it as a new
v2 message instead of treating a decryption error as an empty message.
