# libzupt

Hybrid public-key encryption for files and memory, with a C11/C++17 native
core and bindings/examples for Python, Go, Rust, Java, Node.js, .NET and PHP.
Licensed under MIT; see [LICENSE](LICENSE).

[Português](docs/pt-BR/README.md) · [API](DOCUMENTATION.md) ·
[Security](SECURITY.md) · [Format](docs/FORMAT.md) · [Migration](docs/MIGRATION.md)

## Version 2.0.0 migration

This is a breaking format update. New encryption uses FIPS 203 ML-KEM-768,
X25519, a domain-separated hybrid KDF, AES-256-CTR and HMAC-SHA256.
The complete encryption header, plaintext length and ciphertext stream are
bound by a final HMAC. Removing complete final blocks is rejected.

| Object | New version | Size |
| --- | --- | --- |
| SDK library | 2.0.0 | platform dependent |
| `ZKEY` public key | 2 | 1,224 bytes |
| `ZKEY` private key | 2 | 3,656 bytes |
| Encryption header | discriminator `0x03` | 1,137 bytes |
| Empty ciphertext envelope | `ZUP2` | 96 bytes |

Generate new v2 recipient keys. A v1 key is not relabeled as a FIPS 203 key.
Normal decryption never falls back to the older scheme. Explicit v1 recovery
requires an independently trusted SHA-256 of the complete original plaintext;
see [migration](docs/MIGRATION.md).

## Build and verify

Use CMake 3.15+, C11/C++17 compilers and Python 3 for tests. GCC 9+,
Clang and current MSVC are the intended CI toolchains. Python bindings are
optional and require CMake 3.18+, Python development headers and pybind11; the native library downloads no dependencies.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix "$PWD/install"
```

The CI matrix includes Linux x86-64 (GCC/Clang), Linux ARM64, macOS and Windows.
Configured jobs are not proof of a passing platform: inspect the actual job
results for the commit/release you use.

## C++ example

```cpp
#include <zupt.hpp>

int main() {
    const auto keys = zupt::KeyGenerator().generateKeyPair();
    zupt::Encryptor encryptor(keys.public_key);
    const std::vector<uint8_t> message = {1, 2, 3};
    const auto sealed = encryptor.encryptMemory(message);
    const auto restored = zupt::Decryptor(keys.secret_key).decryptMemory(
        sealed.first, sealed.second);
    return restored == message ? 0 : 1;
}
```

An installed CMake consumer uses:

```cmake
find_package(libzupt 2.0 CONFIG REQUIRED)
add_executable(example main.cpp)
target_link_libraries(example PRIVATE libzupt::zupt_shared)
# Or use libzupt::zupt_static.
```

Keep the ciphertext and its matching encryption header together. Treat a
`ZuptError` as failure; do not convert failures into empty plaintext.
Use `zupt_free()` to release allocations returned by the C API, including
across Windows CRT and language-FFI boundaries.

## Verification evidence

Offline regression fixtures include 80 NIST ACVP ML-KEM-768 cases and 25
additional decapsulation checks against those fixtures: 105 checks total.
Their upstream commit and SHA-256 hashes are pinned in
[tests/vectors/sources.json](tests/vectors/sources.json).

The test suite also checks SHA/SHAKE/HMAC against independent Python reference
implementations, AES known-answer vectors (including forced portable AES),
message mutation/truncation rejection and digest-checked legacy recovery.
[Testing instructions](docs/TESTING.md) describe cross-implementation tests,
sanitizers, fuzzing, benchmarks and reproducible-build checks.

ML-KEM-768 is the NIST security-category-3 parameter set. The hybrid file
format is libzupt-specific, not TLS/X.509 or a standardized Signal protocol.
Passing tests does not confer CAVP/CMVP certification. No independent audit,
FIPS 140-3 validation or CNSA 2.0 compliance is claimed for this release candidate.

## Language integrations

| Language | Source and instructions |
| --- | --- |
| C++ / C API | [DOCUMENTATION.md](DOCUMENTATION.md) |
| Python | [examples_python](examples_python) |
| Go | [examples_go](examples_go) |
| Rust | [examples_rust](examples_rust) |
| Java / JNI | [examples_java](examples_java) |
| Node.js | [examples_nodejs](examples_nodejs) |
| .NET | [examples_dotnet](examples_dotnet) |
| PHP / FFI | [examples_php](examples_php) |

All integrations must be rebuilt against v2. Private-key persistence and
host-language copies have their own boundaries; see [SECURITY.md](SECURITY.md).
Native primitives being tested does not imply every binding has been audited.

## Project and reporting

Author/maintainer: Alessandro de Oliveira Faria (Cabelo), MultiCortex.
The underlying zupt work is by Cristian Cezar Moisés; PHP integration includes
contributions by Er Galvão Abbott. See repository history for all contributors.

Report vulnerabilities privately through [SECURITY.md](SECURITY.md).
[Release instructions](docs/RELEASING.md) cover signed tags, source inventories,
checksums and maintainer signatures. [CHANGES.md](CHANGES.md) records compatibility.

References: [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203),
[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748),
[NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server).
