/**
 * @page page-compilacao Compilation, configuration and tests
 *
 * @brief How the project is assembled by CMake, which options exist and what
 *         the tests cover.
 *
 * @details
 *
 * # CMake
 *
 * `CMakeLists.txt` requires CMake 3.15 or higher and declares the project in
 * C and C++. The version comes from a regex over `include/libzupt_version.h`,
 * exactly the line that defines `LIBZUPT_VERSION_STRING`:
 *
 * @code
 * file(STRINGS "include/libzupt_version.h" LIBZUPT_VERSION_LINE
 *     REGEX "^#define LIBZUPT_VERSION_STRING")
 * string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" LIBZUPT_VERSION "${LIBZUPT_VERSION_LINE}")
 * project(libzupt VERSION ${LIBZUPT_VERSION} LANGUAGES C CXX)
 * @endcode
 *
 * Today this results in `1.0.15`. In the shared library, `VERSION` receives
 * that whole value and `SOVERSION` receives only `PROJECT_VERSION_MAJOR`, that
 * is `1`; in the compiled tree this appears as `libzupt.so` →
 * `libzupt.so.1` → `libzupt.so.1.0.15`. See \ref page-limitacoes for the
 * other versions in the repository.
 *
 * ## Targets
 *
 * | Target | Type | Contents |
 * | --- | --- | --- |
 * | `zupt_shared` | `SHARED` | The nine `src/*.c` listed in `LIBZUPT_C_SOURCES` (`CMakeLists.txt:36-46`) plus all the `src/*.cpp` picked up by `file(GLOB)` (`CMakeLists.txt:48-49`) |
 * | `zupt_static` | `STATIC` | Same sources |
 * | `zupt` | `ALIAS` | Alias for `zupt_shared` |
 *
 * `zupt_shared` compiles with the private definition `ZUPT_EXPORTS`
 * (`CMakeLists.txt:65`), which controls the symbol export macro, and
 * requires C++17 (`cxx_std_17`, `CMakeLists.txt:66`). `zupt_static` marks
 * `ZUPT_STATIC` as `PUBLIC` (`CMakeLists.txt:102`).
 *
 * ## Options
 *
 * | Option | Default | Effect |
 * | --- | --- | --- |
 * | `LIBZUPT_BUILD_TESTS` | `ON` | Calls `enable_testing()` and adds `tests/`, where the cases are registered in CTest (`CMakeLists.txt:190-194`) |
 * | `LIBZUPT_BUILD_EXAMPLES` | `ON` | Adds `examples/`, with the four executables and the migration test (`CMakeLists.txt:196-198`) |
 * | `LIBZUPT_BUILD_PYTHON` | `OFF` | Adds `examples_python/`, which requires pybind11 found by CMake (`CMakeLists.txt:200-202`) |
 * | `LIBZUPT_SANITIZERS` | `OFF` | Enables AddressSanitizer and UndefinedBehaviorSanitizer (`CMakeLists.txt:11`) |
 * | `LIBZUPT_BUILD_FUZZERS` | `OFF` | Builds the `zupt_fuzz_decrypt` harness; requires Clang **and** `LIBZUPT_SANITIZERS=ON`, otherwise CMake stops with `FATAL_ERROR` (`CMakeLists.txt:20-25`, `204-212`) |
 *
 * There is no option for the Java bindings: `examples_java/` is not referenced
 * by any `add_subdirectory` and does not enter the CMake build.
 *
 * Installation publishes the two libraries (`CMakeLists.txt:126-131`), the
 * CMake configuration files (`:133-136`, `:172-176`), the `libzupt.pc`
 * generated from `libzupt.pc.in` (`:146-155`) and exactly three headers —
 * `zupt.hpp`, `zupt_cxx.h` and `libzupt_version.h` (`:138-143`) — see
 * \ref page-limitacoes.
 *
 * # build.sh
 *
 * `build.sh` is the shortcut: it creates `build/`, configures in `Release`
 * with `LIBZUPT_BUILD_TESTS=ON` and `CMAKE_INSTALL_PREFIX=/usr/local`, runs
 * `make -j` and then `make test`. The file has no executable bit in the
 * repository, so it must be invoked as `bash build.sh`.
 *
 * # Preprocessor definitions that change the result
 *
 * | Macro | Where | Effect |
 * | --- | --- | --- |
 * | `ZUPT_STATIC` | `include/zupt_cxx.h:84` | Under Windows/Cygwin, makes `ZUPT_API` empty (static linking); CMake defines it `PUBLIC` on the static target (`CMakeLists.txt:102`) |
 * | `ZUPT_EXPORTS` | CMake, private in `zupt_shared` | Under Windows/Cygwin, selects `dllexport` when compiling the DLL |
 * | `ZUPT_TESTING` | `src/zupt_mlkem.c:1143` | Exposes the KAT entry points consumed only by the tests |
 * | `ZUPT_USE_JASMIN` | `include/zupt_jasmin.h`, `src/zupt_crypto.c` | Enables the Jasmin/AES-NI and AVX dispatch; without it the portable path is the one used |
 * | `ZUPT_FORCE_PORTABLE_AES` | `src/zupt_aes256.c` | Disables the `__builtin_cpu_supports("aes")` check and forces table-based AES |
 *
 * No CMake target runs FRAMA-C or the Jasmin compiler, and this tree
 * contains no `.acsl` or `.jasmin` file: the specifications exist
 * only as ACSL comments inside the sources, and the Jasmin declarations only in
 * `include/zupt_jasmin.h` — see \ref page-limitacoes.
 *
 * # Tests
 *
 * `tests/CMakeLists.txt` generates one `zupt_test_<nome>` executable per test
 * source (function `add_zupt_test`, `tests/CMakeLists.txt:4-20`), which links
 * `zupt_shared` and forces `-UNDEBUG` so that the `assert` checks stay active
 * in `Release`. The Python cases are invoked through `${Python3_EXECUTABLE}`
 * against the library already built. With the default options, the suite has
 * fourteen cases, all runnable on this machine (gcc/g++ 12.3.0, cmake 3.28.3,
 * python 3.11.10). Thirteen come from `tests/CMakeLists.txt`;
 * `zupt_test_migration_cli` is the only one registered elsewhere —
 * `examples/CMakeLists.txt:25-29`:
 *
 * - `zupt_test_keygen`
 * - `zupt_test_encrypt`
 * - `zupt_test_decrypt`
 * - `zupt_test_roundtrip`
 * - `zupt_test_file_ops`
 * - `zupt_test_authentication`
 * - `zupt_test_secure_buffer`
 * - `zupt_test_fuzz_smoke`
 * - `zupt_test_key_storage` (only under `UNIX`, `tests/CMakeLists.txt:31-33`)
 * - `zupt_test_acvp` (Python, label `python`)
 * - `zupt_test_aes_portable` (C, compiled with `ZUPT_FORCE_PORTABLE_AES`)
 * - `zupt_test_primitives` (Python, label `python`)
 * - `zupt_test_legacy` (Python, label `python`)
 * - `zupt_test_migration_cli` (Python, label `python`)
 *
 * The ACVP test consumes a helper library `zupt_kat`
 * (`tests/CMakeLists.txt:36-42`), built for it alone from
 * `src/zupt_mlkem.c`, `src/zupt_keccak.c` and `tests/mlkem_support.c` with
 * `-DZUPT_TESTING`. With `LIBZUPT_BUILD_PYTHON=ON` and
 * `LIBZUPT_BUILD_TESTS=ON` there also appears `zupt_test_python_binding`
 * (`examples_python/CMakeLists.txt:9-13`), which does not run in this
 * configuration because pybind11 is not installed.
 *
 * `tests/CMakeLists.txt:59-63` also generates `build/run_tests.sh` from
 * `run_tests.sh.in`.
 *
 * The result obtained with the documentation changes was
 * `100% tests passed, 0 tests failed out of 14`.
 *
 * @see \ref page-exemplos for the bindings outside the main build.
 */
