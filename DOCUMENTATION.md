# libzupt API guide (2.0)

[Build](INSTALL.md) · [Wire format](docs/FORMAT.md) ·
[Migration](docs/MIGRATION.md) · [Security](SECURITY.md)

## C++ interface

Include `<zupt.hpp>` and link `libzupt::zupt_shared` or
`libzupt::zupt_static`. The authoritative declarations are in `include/zupt.hpp`.

| API | Purpose / ownership |
| --- | --- |
| `KeyGenerator::generateKeyPair()` | Fresh v2 recipient key pair |
| `saveKeyPair(keys, filename)` | Store private key; POSIX protections described in SECURITY.md |
| `loadKeyPair(filename)` | Load an API-format private key; v1 is only useful for explicit recovery |
| `exportPublicKey(privateFile, publicFile)` | Export public portion, preserving key version |
| `loadPublicKey(filename)` | Load a public API key buffer |
| `Encryptor(publicKey)` | Require a valid v2 public key; no speculative encryption |
| `encryptMemory(data, size)` | Return `{ciphertextEnvelope, encryptionHeader}` |
| `encryptFile(filename)` | Read complete file, then use the same envelope format |
| `Decryptor(privateKey)` | Own a private-key copy |
| `decryptMemory(ciphertext, header)` | Return complete authenticated plaintext or throw `ZuptError` |
| `decryptFile(filename, header)` | Same validation for a ciphertext file |
| `decryptMemorySecure(ciphertext, header)` | Return a native `SecureBuffer` |
| `getVersion()` | SDK library version |

`encryptMemory(nullptr, 0)` is valid and produces a 96-byte authenticated empty
envelope. Empty plaintext and an authentication failure are distinct outcomes.
Each operation generates fresh encapsulation and nonce material; keep its
matching encryption header with the ciphertext.

```cpp
#include <zupt.hpp>
int main() {
    const auto keys = zupt::KeyGenerator().generateKeyPair();
    const auto sealed = zupt::Encryptor(keys.public_key).encryptMemory(
        std::vector<uint8_t>{1, 2, 3});
    return zupt::Decryptor(keys.secret_key).decryptMemory(
        sealed.first, sealed.second) == std::vector<uint8_t>{1, 2, 3} ? 0 : 1;
}
```

The installed-package tests compile this usage with shared and static targets
and verify version reporting after installation is relocated.

## C and FFI interface

Include `<zupt_cxx.h>`. Public/private/header buffers have sizes
1,224 / 3,656 / 1,137 bytes respectively. Callers must allocate buffers of those
sizes for `zupt_hybrid_keygen_c` and the encryption header.

`zupt_hybrid_encrypt` and `zupt_hybrid_decrypt` return allocated memory, or
`NULL` on failure. Check the return pointer before using the output length.
Failure sets the corresponding ciphertext/plaintext output length to zero.
An empty successful plaintext is represented by a non-NULL allocation and
length zero. Release native allocations with `zupt_free(ptr)`.

`zupt_hybrid_decrypt_legacy` is an explicit recovery operation with an additional
32-byte trusted expected SHA-256 argument. There is no automatic downgrade.
The [migration tool](docs/MIGRATION.md) validates the digest before writing new
ciphertext and never stores the recovered plaintext in an intermediate file.

Use `zupt_write_private_key(path, key, size)` for API private keys; its POSIX
writer rejects links/nonregular files and applies mode 0600 before writing.
Windows callers still need a controlled directory/file ACL.

The public API header also declares file I/O helpers. `zupt_write_file` is a
general-purpose writer, not private-key encryption or a protected keystore.

## Error and storage rules

C++ failures throw `zupt::ZuptError`; inspect `code()` if needed, but present a
single authentication failure to untrusted peers. Never return partial plaintext
or suppress an error by substituting an empty result. Files and the memory API
currently load the whole message into RAM; this is not an incremental streaming
API. Applications must impose input-size limits appropriate to their service.

C++/binding key buffers omit the extra eight-byte checksum used by historical
low-level archive key-file helpers. Consult FORMAT.md before exchanging keys.
Generate API reference HTML with `doxygen Doxyfile`; output is outside the checkout.
