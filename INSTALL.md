# Build and install libzupt 2.0

The native library needs CMake 3.15+ and C11/C++17 compilers. Tests additionally
need Python 3; portable C++ test paths use `std::filesystem` (GCC 9+ recommended).
Python bindings are opt-in and require pybind11.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix "$PWD/install"
```

On Windows use the Visual Studio developer environment and `--config Release`.
The tests copy the shared DLL beside native test executables. On POSIX, set
`LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) when a language runtime
cannot locate a non-system installation.

```sh
cmake -S tests/package -B consumer -DCMAKE_PREFIX_PATH="$PWD/install"
cmake --build consumer --config Release --parallel 2
ctest --test-dir consumer -C Release --output-on-failure
```

| Option | Default | Meaning |
| --- | --- | --- |
| `LIBZUPT_BUILD_TESTS` | ON | Native and offline Python reference checks |
| `LIBZUPT_BUILD_EXAMPLES` | ON | Examples and explicit v1 migration tool |
| `LIBZUPT_BUILD_PYTHON` | OFF | Actual pybind11 extension |
| `LIBZUPT_SANITIZERS` | OFF | GCC/Clang address and undefined-behavior instrumentation |
| `LIBZUPT_BUILD_FUZZERS` | OFF | Clang libFuzzer; requires sanitizers |

Use `-DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_EXAMPLES=OFF` for a minimal native
installation. Shared/static CMake targets propagate include directories and
C++17 requirements. The native core has no downloaded build dependencies.
Bindings have separate toolchains and development dependencies.

Format v2 requires new keys. See [MIGRATION.md](docs/MIGRATION.md) before
upgrading any application that stores v1 keys or ciphertext.
