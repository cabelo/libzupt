/**
 * @page page-seguranca Security notes
 *
 * @brief What the cryptographic design protects, what depends on the caller and
 *         the failures observed in the code.
 *
 * @details
 *
 * # Implemented construction
 *
 * - Confidentiality and integrity of blocks: AES-256-CTR with HMAC-SHA256 in
 *   the Encrypt-then-MAC order. The MAC covers `nonce || ciphertext`, so a
 *   block that is altered or that has a swapped nonce is rejected before the
 *   plaintext is returned (`src/zupt_crypto.c`, `zupt_encrypt_buffer` and
 *   `zupt_decrypt_buffer`).
 * - Key derivation from a password: PBKDF2-HMAC-SHA256 with
 *   `ZUPT_KDF_ITERATIONS` iterations over a 32-byte salt, producing 64
 *   bytes split into a cipher key and a MAC key.
 * - Post-quantum hybrid mode: ML-KEM-768 encapsulation combined with X25519; the
 *   session key comes from a KDF over the two shared secrets, the ciphertext and
 *   the ephemeral public key (`hybrid_kdf()` in
 *   `src/zupt_crypto.c`).
 * - Randomness: `getrandom()` or `/dev/urandom` in `zupt_random_bytes()`.
 *
 * # What the caller must ensure
 *
 * - Never reuse the (keyring, `block_seq`) pair. The block nonce is the base
 *   nonce with the low 8 bytes XOR `block_seq`; repeating the pair reuses the
 *   keystream and breaks the confidentiality of both blocks.
 * - Generate a fresh salt and nonce per file with `zupt_random_bytes()`.
 * - Keep the private key protected by file permission and do not serialize it to
 *   logs. `zupt_write_private_key()` opens the file with `0600`, but does not call
 *   `fsync()` and does not protect the write on the `_WIN32` path.
 *
 * # Failures and gaps observed
 *
 * The items below were read from the code during the documentation review. They
 * are recorded here as the result of the reading, not as a fix applied.
 *
 * - `ZUPT_FLAG_CKSUM_XXH64` is defined as `(0u << 5)` in `include/zupt.h`,
 *   that is, it sets no bit. A file that selects this option writes the
 *   same flag value as a file without a checksum.
 * - `zupt_aes256_ctx` holds only the cipher rounds (`rk[60]`). There is no
 *   scheduling to decrypt AES blocks in ECB/CBC mode; decryption depends
 *   exclusively on CTR mode.
 * - The AES-NI and AVX dispatch in `src/zupt_crypto.c` (under `ZUPT_USE_JASMIN`)
 *   consults `zupt_cpu` and `zupt_detect_cpu`, symbols declared in
 *   `include/zupt_cpuid.h` but with no definition in `src/`. The behavior
 *   therefore depends on a definition external to the library.
 * - `include/zupt_keccak.h` has no `extern "C"` guard, which breaks the link
 *   when the header is consumed from C++.
 * - `keccak_finalize()` in `src/zupt_keccak.c` does a `memset` with size
 *   `rate - pt - 1`; when `pt == rate` the size requested is `-1`.
 * - Calling `keccak_finalize()` twice on the same context produces wrong
 *   output without any error signal.
 * - `zupt_legacy_mlkem768_decaps()` uses a key derivation different from the
 *   FIPS path, so legacy containers and new containers are not
 *   interchangeable.
 * - `ZUPT_FLAG_DISK_IMAGE` is declared, appears in `zupt_disk_backup()` and is
 *   never consulted in any `src/*.c`.
 *
 * # Native bindings layer
 *
 * The examples with Node.js, Python and Java bindings add no cryptographic
 * logic, but they move sensitive data across managed memory boundaries, and
 * that is where the most relevant gaps of this layer are.
 *
 * **Java (`examples_java/zupt_jni.cpp`)**
 *
 * - `Encryptor.java` is the only class in the package with native methods that
 *   does not call `System.loadLibrary("Jzupt")`; using it alone, `JNI_OnLoad`
 *   does not run and the first call fails with `UnsatisfiedLinkError`.
 * - `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` and
 *   `Java_com_libzupt_Decryptor_decryptMemorySecure` are implemented, but they
 *   do not appear in the `encryptorMethods`/`decryptorMethods` tables nor as
 *   `native` in the corresponding Java files: unreachable code.
 * - The "secure" methods of `Encryptor.java` and `Decryptor.java` call
 *   `buffer.toBytes()`, which returns an ordinary copy; the `zupt::SecureBuffer`
 *   does not reach the native call, so its protection is lost at the boundary.
 * - There is no call to `zupt::secureWipe()` anywhere in the JNI path: the
 *   private key arrives as plaintext `byte[]` copies that are never zeroed, and
 *   so are the local vectors that contain them.
 * - There is no `JNI_OnUnload`, so the global references
 *   `zuptErrorClass` and `keyPairClass` are never freed.
 * - `JNI_OnLoad` counts the elements of the method tables with literals, and not
 *   with `sizeof`: a method added to the table without updating the literal
 *   is left without a binding, silently. If `FindClass` fails, the whole block is
 *   skipped and the function still returns `JNI_VERSION_1_8`.
 *
 * **Python (`examples_python/zupt_pybind.cpp`)**
 *
 * - `py::register_exception<zupt::ZuptError>` does not carry `code()`: only the
 *   message reaches Python, and the library's error code is lost.
 * - `encrypt_memory`, `decrypt_memory` and `secure_wipe` accept any
 *   integer as an address. `encrypt_memory(0, 16)` ends in `SIGSEGV` inside
 *   the process, and `secure_wipe` writes to any address, including
 *   interpreter memory.
 * - `private_key` is exposed with `def_readonly`, which prevents reassigning the
 *   attribute, but does not prevent reading or changing the content: the private
 *   key stays alive in plaintext in the process heap.
 * - `generate_keypair` does not clean the local `zupt::KeyPair`, unlike the
 *   Node.js binding.
 *
 * **Node.js (`examples_nodejs/src/zupt_napi.cpp`)**
 *
 * - The constructors of `Encryptor` and `Decryptor` take `info[0]` without
 *   checking `IsBuffer()`; an argument of the wrong type aborts the process
 *   instead of raising `TypeError`.
 * - `randomBytes` uses `Uint32Value()`, which accepts negative numbers:
 *   `randomBytes(-1)` becomes a 4 GiB allocation attempt.
 * - `LoadKeyPair` does not apply `secureWipe` to the object read, while
 *   `GenerateKeyPair` does.
 * - In none of the three bindings is the private key removed from the managed
 *   side (JavaScript, Python, JVM): the cleaning only happens on the native copy,
 *   and even then only on some paths.
 *
 * @see \ref page-limitacoes, \ref page-memoria and \ref page-formato.
 */
