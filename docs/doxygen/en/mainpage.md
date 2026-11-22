@mainpage page-mainpage libzupt — overview

<b>libzupt</b> is a C11 library with a C++17 interface that combines
hybrid authenticated encryption (ML-KEM-768 + X25519) with a block compression
container. The documentation generated here was written by reading the code
in `src/` and `include/`; where the code diverges from the original comments,
from `README.md` or from `docs/FORMAT.md`, the text describes the behavior of
the code and records the divergence. See @ref page-limitacoes.

\section main-pq Documentation for this revision

- Configuration: the `Doxyfile` at the repository root. Command: `doxygen Doxyfile`.
- HTML output: `build/apidocs/html/` (generated, not versioned).
- Documentation language: English; symbol, type and file names
  remain in English.
- Only comments were added to the sources. No line of code,
  signature, macro value or ACSL block was changed.
- Two languages from the same sources: `Doxyfile` generates the Portuguese
  version and `Doxyfile.en` generates the English one (`OUTPUT_LANGUAGE =
  English`, output in `build/apidocs-en/html/`). Each documentation comment
  holds both texts in successive conditional sections, selected by the
  `ENABLED_SECTIONS` value of the configuration; the diagrams use
  `docs/doxygen/dot/pt/` in the Portuguese version and
  `docs/doxygen/dot/en/` in the English one.
- Code browsing (`SOURCE_BROWSER = YES`) publishes the source exactly as it
  is on disk, so the `*_source.html` pages show both languages and the
  markers of the conditional sections. This is expected: filtering the source
  text would misalign the line numbers quoted by the documentation.

\section main-arquivos What exists in the tree

| Path | Contents |
|---|---|
| `include/` | 10 public and internal headers |
| `src/` | 10 implementation files (9 `.c` and 1 `.cpp`) |
| `tests/` | C/C++ unit tests, test vectors, Python harness |
| `examples*` | bridges for Python, Node.js, Java, .NET, Go, PHP, Rust and C++ examples |
| `docs/FORMAT.md` | API envelope format (ZUP2), distinct from the compression container |

Most of the surface declared in `include/zupt.h` has no definition
in `src/`. This is not a documentation error: the tree ships the complete
interface, but several functions (LZ compaction, extraction, deduplication,
file utilities, disk backup) are absent. The exact list is
in @ref page-inventario. Where this affects usage, the documented symbol carries
the corresponding note.

\section main-duas-familias Two API families coexisting

The library has two independent surfaces that share the same
`zupt_` prefix:

- <b>Compression container</b> (`include/zupt.h`): the types
  @ref zupt_archive_header_t, @ref zupt_footer_t, @ref zupt_index_entry_t,
  @ref zupt_options_t, @ref zupt_error_t, the `ZUPT_BLOCK_*` macros and file
  functions such as @ref zupt_compress_files. This is the file format described
  in @ref page-formato.
- <b>API cryptographic envelope</b> (`include/zupt.hpp`,
  `include/zupt_cxx.h`): the classes @ref zupt::KeyGenerator,
  @ref zupt::Encryptor and @ref zupt::Decryptor, with @ref zupt::SecureBuffer
  for the in-memory material and @ref zupt::ZuptError for the errors.
  This is the `ZUP2` format specified in `docs/FORMAT.md`.

The two families use common primitives (AES-256-CTR, HMAC-SHA256, SHA-3)
but they are <b>not</b> interchangeable: magic, headers, key derivation and
framing are different. See @ref page-arquitetura.

\section main-advertencias Summarized warnings

The @ref page-limitacoes and @ref page-seguranca pages detail each item;
the five most relevant to anyone who is going to use the library:

- `include/zupt_keccak.h` has no `extern "C"` guard. Including it from a
  C++ file produces symbols with name mangling and a link failure against
  `libzupt` compiled as C.
- @ref ZUPT_FLAG_CKSUM_XXH64 is `(0u << 5)`, that is, `0`. Testing or setting
  that bit in `global_flags` has no effect at all.
- `zupt_decrypt_buffer` returns `NULL` for distinct causes (authentication
  failure, corrupted data, out of memory), with no channel to
  distinguish them.
- `keccak_finalize()` applied twice to the same context silently produces a
  wrong digest.
- The library version appears as `1.0.15`, `2.1.5` and `2.0.0` in three
  different places. See @ref page-compilacao.

\section main-indice Pages in this documentation

- @ref page-arquitetura — layers, dependencies between modules, CPU dispatch.
- @ref page-api-guia — how to use the two API families, with the actual contracts.
- @ref page-formato — on-disk layout of the container and of the envelope.
- @ref page-memoria — who allocates, who frees, what is wiped.
- @ref page-erros — @ref zupt_error_t and the alternative ways of signaling errors.
- @ref page-concorrencia — what the code guarantees and what it does not guarantee.
- @ref page-seguranca — primitives, protection of secrets, findings.
- @ref page-compilacao — CMake, options, versions, tests.
- @ref page-exemplos — the examples in the tree and what each one exercises.
- @ref page-limitacoes — recorded divergences and defects, not fixed.
- @ref page-inventario — table of documented symbols by file.
