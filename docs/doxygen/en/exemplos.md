/**
 * @page page-exemplos Ready-made examples and how to build them
 *
 * The tree contains four sets of examples, each with a different build
 * mechanism. Only the C++ ones take part in the main CMake; the Python
 * ones depend on an option that is off by default, and the Java and Node.js
 * ones have their own projects, outside the library's `CMakeLists.txt`.
 *
 * # C++ — `examples/`
 *
 * Four executables, declared in `examples/CMakeLists.txt`:
 *
 * - `zupt_example_basic` (`example_basic.cpp`) — generates a key pair with
 *   `zupt::KeyGenerator::generateKeyPair()`, encrypts and decrypts a snippet in
 *   memory with `zupt::Encryptor` / `zupt::Decryptor` and prints
 *   `zupt::getVersion()`.
 * - `zupt_example_file` (`example_file.cpp`) — encrypts and decrypts a file,
 *   loading the key pair from disk with `loadKeyPair()`; it handles the
 *   failures with `catch (const zupt::ZuptError& e)`.
 * - `zupt_example_binary` (`example_binary.cpp`) — round trip of binary data
 *   generated locally.
 * - `zupt_migrate` (`migrate_v1.cpp`) — converts material from the old
 *   format, using `zupt::SecureBuffer` and `zupt::secureWipe` over the key
 *   that was read.
 *
 * All link `zupt_shared` on UNIX platforms and `zupt_static` on
 * Windows (`examples/CMakeLists.txt:3-7`) and are installed into the binary
 * directory (`examples/CMakeLists.txt:32-33`). The whole block is only
 * added to the build if `LIBZUPT_BUILD_EXAMPLES` is on, which is the
 * default (`CMakeLists.txt:184`, `:196-198`).
 *
 * There is a CTest test for the migrator: `zupt_test_migration_cli` runs
 * `scripts/check-migration-cli.py` passing `zupt_example_file` and
 * `zupt_migrate`, and carries the `python` label
 * (`examples/CMakeLists.txt:23-29`). It only appears when
 * `LIBZUPT_BUILD_TESTS` is on.
 *
 * @see @ref page-compilacao for the configuration commands.
 *
 * # Python — `examples_python/`
 *
 * The five scripts (`example_basic.py`, `example_file.py`,
 * `example_keygen.py`, `example_random.py`, `example_secure_buffer.py`)
 * import a single module, `import zupt`, which is the pybind11 extension
 * built by the `zupt_python_bindings` target with `OUTPUT_NAME zupt`
 * (`examples_python/CMakeLists.txt:6-7`). Registration happens in the
 * `PYBIND11_MODULE(zupt, m)` macro (`examples_python/zupt_pybind.cpp:78`), and
 * the target links `zupt_shared`.
 *
 * None of this happens by default: `LIBZUPT_BUILD_PYTHON` is `OFF`
 * (`CMakeLists.txt:185`) and the subdirectory is only entered at `:200-202`.
 * When on, the `find_package(pybind11 CONFIG REQUIRED)` of
 * `examples_python/CMakeLists.txt:5` makes the configuration fail if the
 * pybind11 library is not installed.
 *
 * With the option on, the CTest test `zupt_test_python_binding` appears, which
 * runs `tests/python_binding.py` pointing to the extension directory
 * (`examples_python/CMakeLists.txt:9-13`).
 *
 * # Node.js — `examples_nodejs/`
 *
 * The `libzupt-examples` package (version `2.1.5` in `package.json`) has
 * `gypfile: true` and `install`/`build` scripts that run
 * `node-gyp rebuild`. The `zupt` target, of type `loadable_module`
 * (`binding.gyp:4-5`), compiles `src/zupt_napi.cpp`, the two bridge files and
 * eight files from `../src/` listed one by one
 * (`binding.gyp:6-19`): the addon does not link `libzupt`, it recompiles the
 * primitives.
 *
 * In addition, the two bridge files include a text source code file:
 * `examples_nodejs/src/zupt_crypto_c_bridge.c:41` pulls in
 * `../../src/zupt_crypto.c`, and
 * `examples_nodejs/src/zupt_crypto_cpp_bridge.cpp:51` pulls in
 * `../../src/zupt_crypto.cpp`. Both translations exist in both places —
 * in the library and in the addon —, each with its own set of flags.
 *
 * `index.js` tries to load `build/Release/zupt.node`. If the load
 * fails, it exports a JavaScript fallback implementation that does no
 * cryptography: `KeyGenerator::generateKeyPair`, `Encryptor::encryptMemory`
 * and `Decryptor::decryptMemory` throw an error reporting the reason for the
 * failure, and `getVersion()` returns the literal string `'2.1.5'`. The package
 * test, `npm test`, runs `example_basic.js`.
 *
 * # Java — `examples_java/`
 *
 * The `com.libzupt` package has the classes `SecureBuffer`, `KeyPair`,
 * `KeyGenerator`, `Encryptor`, `Decryptor`, `NativeLib` and `ZuptError`, plus
 * five example executables (`ExampleBasic`, `ExampleKeygen`,
 * `ExampleFile`, `ExampleRandom`, `ExampleSecureBuffer`).
 *
 * The native bridge is `zupt_jni.cpp`, compiled by the `zupt_jni` target
 * (`examples_java/CMakeLists.txt:40`), which gets `libzupt` from a
 * `find_package(libzupt 1.0.15 CONFIG)` or, alternatively, embeds the local
 * tree via `add_subdirectory` with the four build options turned off
 * (`examples_java/CMakeLists.txt:8-33`). The native classes are registered
 * in `JNI_OnLoad`: five for `KeyGenerator`, two for `Encryptor`, two
 * for `Decryptor` and three for `NativeLib`
 * (`examples_java/zupt_jni.cpp:523-541`). The native calls catch
 * `const std::exception&` and translate the C++ exception into a JNI error.
 *
 * Two mismatches deserve mention. The target defines `OUTPUT_NAME Jzupt` with
 * `PREFIX "lib"` (`examples_java/CMakeLists.txt:43`), producing
 * `libJzupt.so`, but the `build.sh` of the directory itself tries to copy
 * `zupt.so` (`examples_java/build.sh:64`) with the error suppressed; and it
 * tests for the existence of `libzupt.a`, a name the library's `CMakeLists.txt`
 * does not generate — the static target is called `zupt_static`.
 *
 * @see @ref page-limitacoes, the section on limitations by linkage.
 */
