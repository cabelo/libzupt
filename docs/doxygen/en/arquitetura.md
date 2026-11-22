/**
 * @page page-arquitetura Architecture and layers
 *
 * The library is composed of layers that only depend on the layers below.
 * This page describes what the code in `src/` does; file and symbol names
 * are the real ones from the tree.
 *
 * \section arch-camadas The layers
 *
 * \dotfile camadas.dot "Dependency graph between layers: each edge was verified in the code (call or inclusion directive)"
 *
 * \subsection arch-l0 Primitives (layer 0)
 *
 * - `src/zupt_sha256.c` — incremental SHA-256 (FIPS 180-4)
 *   (@ref zupt_sha256_init, @ref zupt_sha256_update, @ref zupt_sha256_final) and
 *   the one-pass version @ref zupt_sha256. The `K[64]` table is generated in the
 *   file itself; context @ref zupt_sha256_ctx.
 * - `src/zupt_keccak.c` — Keccak-f[1600] sponge with a variable rate:
 *   `keccak_init`, `keccak_absorb`, `keccak_squeeze`, `keccak_finalize`, and the
 *   shortcuts `zupt_sha3_*` / `zupt_shake*`. Context @ref zupt_keccak_ctx.
 * - `src/zupt_xxh.c` — XXH32 and XXH64 (non-cryptographic
 *   checksums).
 * - `src/zupt_aes256.c` — AES-256 in single-block ECB mode
 *   (@ref zupt_aes256_encrypt_block) with key expansion in
 *   @ref zupt_aes256_ctx. There are two paths: portable tables and, under
 *   `__GNUC__`/`__clang__` on x86 and without `ZUPT_FORCE_PORTABLE_AES`, the
 *   AES-NI instruction via `aesni_encrypt_block()`, protected by
 *   `__builtin_cpu_supports("aes")`. Only encryption exists: the structure does
 *   not keep a decryption schedule, because the mode used by the library is CTR.
 *
 * \subsection arch-l1 KEM and key exchange (layer 1)
 *
 * - `src/zupt_mlkem.c` — ML-KEM-768: NTT of degree 256 over `q = 3329`,
 *   sampling by deterministic expansion, encapsulation/decapsulation and the
 *   verification routines @ref zupt_mlkem768_public_key_check,
 *   @ref zupt_mlkem768_secret_key_check, @ref zupt_mlkem768_selftest. It also
 *   implements the legacy decapsulation path
 *   (@ref zupt_legacy_mlkem768_decaps), with secret derivation functions
 *   different from the current path.
 * - `src/zupt_x25519.c` — X25519 (RFC 7748) in 5-limb 51-bit
 *   arithmetic, with @ref zupt_x25519 and @ref zupt_x25519_base. The original
 *   comments in the file claim 4 limbs of 64 bits (donna64); the code
 *   implements 5×51. See @ref page-limitacoes.
 *
 * \subsection arch-l2 Cryptographic glue (layer 2)
 *
 * - `src/zupt_crypto.c` — HMAC-SHA256, PBKDF2-HMAC-SHA256 (RFC 8018),
 *   @ref zupt_aes256_ctr, @ref zupt_derive_keys, @ref zupt_encrypt_buffer,
 *   @ref zupt_decrypt_buffer and @ref zupt_random_bytes. It also defines the
 *   serialized hybrid key format (`ZKEY`) and the initialization fronts
 *   @ref zupt_hybrid_keygen, @ref zupt_hybrid_encrypt_init and
 *   @ref zupt_hybrid_decrypt_init, in addition to the in-memory variants. The
 *   `zupt_cpu`-accelerated dispatch lives in a branch under `ZUPT_USE_JASMIN`
 *   (`src/zupt_crypto.c:427-433`). The function @ref zupt_secure_wipe, used by
 *   this file, is not here: it is `static inline` in `include/zupt.h`.
 * - `src/zupt_mlock.c` — @ref zupt_mlock_keys / @ref zupt_munlock_keys,
 *   pinning of secret pages in memory (`mlock`) with a Windows branch.
 *
 * \subsection arch-l3 Fronts (layer 3)
 *
 * - `src/zupt_cxx.c` — the C front of the envelope and file API: the routines
 *   declared in `include/zupt_cxx.h` (@ref zupt_hybrid_keygen_c,
 *   @ref zupt_free and the file read/write operations), the envelope header and
 *   prefix macros and the wrappers that reuse the primitives of
 *   `zupt_crypto.c`.
 * - `src/zupt_crypto.cpp` — the same front in C++ in the `zupt` namespace
 *   (@ref zupt::KeyGenerator, @ref zupt::Encryptor,
 *   @ref zupt::Decryptor, @ref zupt::SecureBuffer, @ref zupt::randomBytes,
 *   @ref zupt::sha256, @ref zupt::sha3_512), with exceptions in place of
 *   error codes (@ref zupt::ZuptError).
 *
 * \section arch-dependências Real dependencies between modules
 *
 * The edges below come from the inclusion directives of each file:
 *
 * - `zupt_mlkem.c` includes `zupt_mlkem.h`, `zupt_keccak.h` (SHA3/SHAKE),
 *   `zupt.h`, `zupt_acsl.h` and `zupt_jasmin.h` — it uses @ref zupt_random_bytes
 *   (defined in `zupt_crypto.c`) and @ref zupt_secure_wipe (inline in
 *   `include/zupt.h`). That is, layer 1 depends on layer 2 for
 *   randomness.
 * - `zupt_x25519.c` includes `zupt_x25519.h`, `zupt_jasmin.h` and `zupt_cpuid.h`;
 *   no symbol declared by `zupt_cpuid.h` is used in the code of the file.
 * - `zupt_aes256.c` includes `zupt.h` and `zupt_acsl.h` and uses
 *   @ref zupt_secure_wipe, the inline function from the header.
 * - `zupt_crypto.c` includes `zupt.h`, `zupt_acsl.h`, `zupt_cxx.h`,
 *   `zupt_jasmin.h` and `zupt_cpuid.h` at the top; `zupt_mlkem.h`, `zupt_x25519.h`
 *   and `zupt_keccak.h` appear further along in the same file, without
 *   conditional protection, at the point where the hybrid keys section begins
 *   (`src/zupt_crypto.c:810-812`).
 *
 * \section arch-acsl ACSL, Jasmin and what the build does not do
 *
 * Several points in the code carry ACSL blocks (`/*@ ... */`) for
 * verification in FRAMA-C, and annotation headers exist
 * (`include/zupt_acsl.h`, `include/zupt_jasmin.h`). No target of
 * `CMakeLists.txt` runs FRAMA-C, KB-MODELS or the Jasmin compiler, and the
 * tree contains no `.jasmin` files and no `.s`/`.S` assembly. The annotations
 * are, therefore, formal documentation not verified by this build. Where an
 * ACSL contract describes something different from what the function does, the
 * documentation records the scope that is actually executed.
 *
 * \section arch-cpu Processor dispatch
 *
 * There are two independent dispatch mechanisms:
 *
 * - `zupt_aes256_encrypt_block()` queries `__builtin_cpu_supports("aes")` at the
 *   point of use, with no global state.
 * - In `src/zupt_crypto.c`, the branch under `-DZUPT_USE_JASMIN` decides on the
 *   pair `zupt_cpu.has_aesni && zupt_cpu.has_avx`. `zupt_cpu` is declared in
 *   `include/zupt_cpuid.h` and so is `zupt_detect_cpu()`: <b>neither of the two
 *   has a definition in `src/`</b>. A link that does not provide these symbols
 *   does not resolve; if the program defines them as zero, the accelerated branch
 *   is never chosen. Each point of use documents this explicitly.
 *
 * \section arch-onde-olhar Where to start reading
 *
 * - For the compression container: @ref zupt_archive_header_t,
 *   @ref zupt_footer_t, @ref zupt_index_entry_t and @ref page-formato.
 * - For the cryptographic envelope: @ref zupt::Encryptor and `docs/FORMAT.md`.
 * - For primitives: @ref zupt_sha256, @ref zupt_sha3_256,
 *   @ref zupt_aes256_ctr, @ref zupt_x25519, @ref zupt_mlkem768_encaps.
 *
 * \section arch-fluxo Hybrid cipher flow
 *
 * The diagram below summarizes the call sequence of the v2 envelope, with the
 * sizes the code actually writes. The two fronts (`zupt_cxx.c` and the
 * C++ layer) reach the same result: `zupt_cxx.c` calls the keyring and the
 * HMAC by hand, while `include/zupt.hpp` uses `Encryptor`/`Decryptor`.
 *
 * \dotfile fluxo.dot "Call sequence of the hybrid cipher and hybrid decipher (sizes verified in src/zupt_crypto.c and src/zupt_cxx.c)"
 */
