/**
 * @page page-memoria Memory ownership and wiping
 *
 * @brief Who allocates, who frees, what is zeroed and what is locked in RAM.
 *
 * @details
 *
 * # Buffer ownership
 *
 * | Origin | Release |
 * | --- | --- |
 * | Caller-provided buffer with capacity (`dst`, `out`, `h`, `buf`) | The caller keeps ownership; the library only writes |
 * | Pointer returned by `zupt_encrypt_buffer()`, `zupt_decrypt_buffer()`, `zupt_read_file()` | The caller frees it with `free()` |
 * | `char **paths` inside `zupt_filelist_t` | Life cycle that cannot be confirmed in this tree: `zupt_filelist_free()`, which should free it, is declared in `include/zupt.h` but has no definition in `src/` |
 * | Contexts (`zupt_sha256_ctx`, `zupt_aes256_ctx`, `zupt_keccak_ctx`, `zupt_keyring_t`) | Caller variables, on the stack or on the heap; no internal release |
 *
 * There is no reallocation contract: when the capacity given is smaller than
 * what is needed, the functions that receive a buffer and a capacity return `0`
 * (@ref zupt_lz_compress, @ref zupt_lzh_compress) instead of growing the buffer.
 *
 * # Cleaning of sensitive material
 *
 * - `zupt_secure_wipe()`, `static inline` in `include/zupt.h:748`, has four
 *   branches: `SecureZeroMemory()` on Windows, `explicit_bzero()` when the glibc
 *   is 2.25 or newer and also on FreeBSD/OpenBSD, and a `for` loop over a
 *   `volatile uint8_t *` copy in the remaining cases. The last branch is the
 *   barrier that prevents the optimizer from eliminating the cleaning. The
 *   non-Linux branches are not compiled in this build.
 * - `zupt_keyring_check()` checks the `canary_head` and `canary_tail` fields
 *   against `ZUPT_CANARY`. It detects overwrite of the keyring structure, not of
 *   an isolated key, and the behavior upon detection is to stop the process.
 * - `src/zupt_mlock.c` defines `zupt_mlock_keys()` and `zupt_munlock_keys()` in three
 *   branches. In the POSIX/BSD/Apple branch, a refused `mlock()` prints a warning to
 *   `stderr` and returns `-1`. The Windows branch uses `VirtualLock()`. In the fallback
 *   branch (neither of the previous two) `zupt_mlock_keys()` ignores the arguments and
 *   always returns `-1`, and `zupt_munlock_keys()` only performs the cleaning.
 *
 * @warning `mlock()` depends on the `RLIMIT_MEMLOCK` limit. Without privilege, or
 *          in containers with a low limit, the locking fails: the return `-1`
 *          indicates that the pages remained pageable and a warning goes to
 *          `stderr`. No call to `zupt_mlock_keys()` in `src/` tests that
 *          return value.
 *
 * # Points that deserve attention
 *
 * - `zupt_derive_keys()` derives 64 bytes into a local variable (`material`),
 *   distributes `enc_key` and `mac_key` and cleans `material` with
 *   `zupt_secure_wipe()` before returning. The password, however, is read with
 *   `strlen()`: a password containing a null byte is silently truncated and the
 *   resulting key differs from the expected one.
 * - The same function calls `zupt_mlock_keys()` over `enc_key` and `mac_key`
 *   separately and discards the return values. When the keyring is a variable on
 *   the stack, the two regions are not page-aligned and `mlock()` tends to fail,
 *   so the key may end up in swap even on the success path.
 * - `zupt_decrypt_buffer()` checks the HMAC and the nonce before allocating the
 *   plaintext, but **always decrypts**, even when the authentication failed: the
 *   stated goal is to avoid a timing oracle that would reveal valid MACs. The
 *   decrypted plaintext is then zeroed and freed, and `NULL` is returned. While
 *   it lasts, however, there is a buffer with decrypted bytes of unauthenticated
 *   data.
 *
 * @see \ref page-seguranca and \ref page-limitacoes.
 */
