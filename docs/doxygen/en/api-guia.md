/**
 * @page page-api-guia Public API guide
 *
 * Conventions, types and the correct order of calls. `include/zupt.h` is the
 * public C front, `include/zupt.hpp` the C++ front and `include/zupt_cxx.h`
 * the front shared with the native bindings (Java and Node.js).
 *
 * @see @ref page-inventario, the complete list of files and symbols.
 * @see @ref page-erros, the enumeration of codes and where it is used.
 *
 * # Five return formats
 *
 * - Enumerated error code. The archiving operations return
 *   ::zupt_error_t, with @ref ZUPT_OK (0) on success:
 *   @ref zupt_compress_solid, @ref zupt_compress_files,
 *   @ref zupt_extract_archive, @ref zupt_list_archive,
 *   @ref zupt_test_archive, @ref zupt_disk_backup and
 *   @ref zupt_disk_restore.
 * - `int` with `0` on success and negative on error. Examples:
 *   @ref zupt_hybrid_keygen, @ref zupt_hybrid_export_pubkey,
 *   @ref zupt_hybrid_encrypt_init, @ref zupt_hybrid_decrypt_init,
 *   @ref zupt_hybrid_encrypt_init_mem, @ref zupt_hybrid_decrypt_init_mem,
 *   @ref zupt_mlock_keys, @ref zupt_detect_filetype,
 *   @ref zupt_write_varint, @ref zupt_read_varint.
 * - Byte count in `size_t`, with `0` on failure: @ref zupt_lz_compress,
 *   @ref zupt_lzh_compress, @ref zupt_lz_decompress,
 *   @ref zupt_lzh_decompress and the bound functions
 *   @ref zupt_lz_bound, @ref zupt_lzh_bound.
 * - Newly allocated pointer, with `NULL` as the only failure signal:
 *   @ref zupt_encrypt_buffer, @ref zupt_decrypt_buffer and, in
 *   `include/zupt_cxx.h`, @ref zupt_hybrid_encrypt,
 *   @ref zupt_hybrid_decrypt and @ref zupt_hybrid_decrypt_legacy.
 * - No return value (`void`): the primitives (@ref zupt_sha256,
 *   @ref zupt_aes256_ctr, @ref zupt_hmac_sha256, @ref zupt_pbkdf2_sha256,
 *   @ref zupt_secure_wipe, @ref zupt_derive_keys, @ref zupt_sha3_256,
 *   @ref zupt_shake128), @ref zupt_munlock_keys and @ref zupt_random_bytes.
 *
 * `zupt_random_bytes` is the only `void` function that can terminate the process:
 * if the system delivers fewer bytes than requested, it calls `exit(1)`.
 *
 * # Output buffers and memory ownership
 *
 * @ref zupt_encrypt_buffer and @ref zupt_decrypt_buffer allocate the result and
 * write the size into `size_t *olen`. In @ref zupt_decrypt_buffer the
 * `NULL` return groups distinct causes — invalid MAC, divergent nonce,
 * inconsistent length and allocation failure — with no way of
 * distinguishing them through this interface.
 *
 * The compression functions receive the caller's buffer and capacity:
 * @ref zupt_lz_compress receives `dst` and `dcap` and returns how many bytes
 * it wrote. Reserve `zupt_lz_bound(slen)` bytes so as not to lose the result.
 *
 * What the library allocates becomes the caller's, which frees it with `free()`.
 * Sensitive material must be wiped with @ref zupt_secure_wipe before
 * being freed.
 *
 * # Encrypting data in memory
 *
 * The password, the salt and the base nonce become keys through
 * @ref zupt_derive_keys, which fills the fields of ::zupt_keyring_t with
 * PBKDF2-HMAC-SHA256. The password is measured with `strlen`, so an embedded
 * `'\0'` truncates the input without any warning.
 *
 * @code
 * zupt_keyring_t kr;
 * uint8_t salt[ZUPT_SALT_SIZE], nonce[ZUPT_NONCE_SIZE];
 *
 * memset(&kr, 0, sizeof kr);
 * zupt_random_bytes(salt, sizeof salt);
 * zupt_random_bytes(nonce, sizeof nonce);
 * zupt_derive_keys(&kr, senha, salt, nonce, ZUPT_KDF_ITERATIONS);
 * @endcode
 *
 * From there @ref zupt_encrypt_buffer produces an
 * Encrypt-then-MAC envelope, `[16-byte nonce][encrypted plen][32-byte
 * HMAC-SHA256]`, and writes `16 + plen + 32` into `*olen`:
 *
 * @code
 * uint64_t seq = 0;
 * size_t olen = 0;
 * uint8_t *env = zupt_encrypt_buffer(&kr, plain, plen, seq, &olen);
 * if (env) {
 *   // usa env[0..olen-1]
 *   free(env);
 * }
 * @endcode
 *
 * The (key, `seq`) pair must not repeat: the block nonce is the `base_nonce`
 * of the keyring with the 8 least significant bytes XOR `seq`, and the
 * keystream would be reused.
 *
 * @ref zupt_encrypt_buffer, declared in `include/zupt.h:1019`, has no
 * definition in this tree; the description above is the interface contract, not
 * observable behavior of the `libzupt` compiled here. The native
 * bindings implement their own envelope, described in @ref page-formato.
 *
 * # Decrypting an envelope in memory
 *
 * The sequence and the salt are not inside the envelope: they come from
 * outside and must be the same as those used for encryption.
 *
 * @code
 * size_t plen = 0;
 * uint8_t *plain = zupt_decrypt_buffer(&kr, env, olen, seq, &plen);
 * if (plain) {
 *   // plain[0..plen-1]
 *   zupt_secure_wipe(plain, plen);
 *   free(plain);
 * }
 * @endcode
 *
 * The HMAC is recomputed and checked before any copy; the nonce of the
 * envelope is compared with the one expected for `seq`.
 *
 * # C++ API
 *
 * `include/zupt.hpp`, namespace `zupt`:
 *
 * - ::zupt::SecureBuffer — fixed-size buffer, not copyable, with
 *   `zeroize()`.
 * - ::zupt::KeyGenerator — `generateKeyPair()`, `loadKeyPair()`,
 *   `loadPublicKey()`, `exportPublicKey()`, `saveKeyPair()`.
 * - ::zupt::Encryptor — built with the public key; `encryptFile()` and
 *   the three overloads of `encryptMemory()` return a
 *   `std::pair<std::vector<uint8_t>, std::vector<uint8_t>>` of
 *   `[ciphertext][cipher header]`. The header size comes from
 *   `Encryptor::getEncryptionHeaderSize()`, a `static constexpr`.
 * - ::zupt::Decryptor — built with the private key; `decryptFile()`,
 *   `decryptMemory()` and `decryptMemorySecure()` take the cipher header
 *   as a separate argument.
 * - Free functions: @ref zupt::randomBytes, @ref zupt::sha256 (two
 *   overloads), @ref zupt::sha3_512, @ref zupt::secureWipe,
 *   @ref zupt::getVersion and @ref zupt::getLibraryName.
 * - ::zupt::ZuptError, exception derived from `std::runtime_error` that carries
 *   a code from `enum class zupt::ErrorCode` (`OK = 0`, `ERR_IO = -1`,
 *   `ERR_CORRUPT = -2`, `ERR_BAD_MAGIC = -3` and so on).
 *
 * @see @ref page-concorrencia before sharing an instance between
 *      threads.
 * @see @ref page-limitacoes — the version returned by @ref zupt::getVersion
 *      does not match the one the C header proclaims.
 */
