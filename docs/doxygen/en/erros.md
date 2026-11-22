/**
 * @page page-erros Error codes and error handling
 *
 * @brief ::zupt_error_t, the functions that do not use it and what each code means.
 *
 * @details
 *
 * # The enumeration
 *
 * @ref zupt_error_t defines one zero value and ten negative codes:
 *
 * | Constant | Value | Meaning |
 * | --- | --- | --- |
 * | `ZUPT_OK` | 0 | Success |
 * | `ZUPT_ERR_IO` | -1 | Read or write failure on disk |
 * | `ZUPT_ERR_CORRUPT` | -2 | Inconsistent internal structure |
 * | `ZUPT_ERR_BAD_MAGIC` | -3 | Invalid magic |
 * | `ZUPT_ERR_BAD_VERSION` | -4 | Unsupported format version |
 * | `ZUPT_ERR_BAD_CHECKSUM` | -5 | Divergent checksum |
 * | `ZUPT_ERR_NOMEM` | -6 | Memory allocation failed |
 * | `ZUPT_ERR_OVERFLOW` | -7 | Output larger than the capacity given |
 * | `ZUPT_ERR_INVALID` | -8 | Invalid argument, for example `NULL` |
 * | `ZUPT_ERR_NOT_FOUND` | -9 | Entry or file does not exist |
 * | `ZUPT_ERR_UNSUPPORTED` | -10 | Feature not implemented |
 * | `ZUPT_ERR_AUTH_FAIL` | -11 | Authentication failed, divergent MAC |
 *
 * The `zupt_strerror()` function returns a textual description of the code. In
 * this revision of the repository it is declared in `include/zupt.h` but has no
 * definition in `src/`.
 *
 * # Where the error code is not used
 *
 * A large part of the API returns another type, and those cases do not go
 * through `zupt_error_t`:
 *
 * - Low-level cipher functions (`zupt_sha256_update()`,
 *   `zupt_aes256_ctr()`, `zupt_hmac_sha256()`) return `void`: size validation is
 *   the caller's responsibility.
 * - `zupt_encrypt_buffer()` and `zupt_decrypt_buffer()` return `uint8_t *` and
 *   `NULL` on failure. `NULL` does not distinguish invalid MAC, inconsistent
 *   length and out of memory.
 * - `zupt_derive_keys()` returns `void` and reports no error.
 * - `zupt_random_bytes()` returns `void`. If the randomness source fails, the
 *   process is terminated with `exit(1)` in `src/zupt_crypto.c`, which makes it
 *   unsafe for use in a library inside a process that needs to handle the
 *   failure.
 * - The compression functions (`zupt_lz_compress()`, `zupt_lzh_decompress()`)
 *   return `size_t` and use `0` as a failure signal.
 *
 * # Caller conventions
 *
 * - Treat any value other than `ZUPT_OK` as failure, including
 *   `ZUPT_OK` followed by empty output.
 * - After `ZUPT_ERR_AUTH_FAIL`, discard the input buffer: the container is
 *   either from a wrong password or from a tampered file.
 * - `ZUPT_ERR_BAD_VERSION` usually indicates a file written by another version of
 *   the library; the version divergences recorded in \ref page-limitacoes
 *   make this diagnosis ambiguous.
 */
