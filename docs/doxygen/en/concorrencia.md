/**
 * @page page-concorrencia Concurrency and reentrancy
 *
 * @brief What can be called from several threads and what cannot.
 *
 * @details
 *
 * # Global state
 *
 * The analysis of `src/*.c` and `src/*.cpp` found no mutable global or
 * file-static variable. The only static entities are constant tables (AES
 * S-boxes, XXH64 tables, curve constants) and static functions. There is no
 * `pthread`, mutex, atomic or `strtok_r` in any of the sources.
 *
 * # Consequences
 *
 * - The cryptographic primitives (`zupt_sha256*`, `zupt_aes256*`,
 *   `zupt_hmac_sha256`, `zupt_pbkdf2_sha256`, `zupt_keccak`/SHA-3,
 *   `zupt_mlkem*`, `zupt_x25519`) operate only on state provided by the
 *   caller, so they can be used by concurrent threads as long as each
 *   thread has its own context.
 * - Two threads must not share the same `zupt_sha256_ctx`,
 *   `zupt_aes256_ctx` or `zupt_keyring_t`: the library performs no
 *   internal protection.
 * - A `zupt_keyring_t` embedded in `zupt_options_t` must not be passed by
 *   reference to two threads that encrypt different blocks, because the
 *   `block_seq` that makes up the nonce is the caller's responsibility.
 *
 * # Exceptions
 *
 * - `zupt_random_bytes()` queries the kernel on every call. It is safe with
 *   regard to data, but it terminates the process with `exit(1)` when the source
 *   fails — a behavior that no thread can handle.
 * - `zupt_mlock_keys()` changes process state, not library state. Calling it from
 *   several threads over the same region is defined by the kernel.
 * - The file functions (`zupt_disk_backup()`, `zupt_extract_archive()` and
 *   the like) depend on `FILE *` and on `chdir`; the library offers no
 *   mechanism against concurrent use of the current directory.
 *
 * @see \ref page-limitacoes for the functions declared without definition.
 */
