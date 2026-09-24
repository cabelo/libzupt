# libzupt documentation

[Português (Brasil)](../pt-BR/README.md) · [API reference](../../DOCUMENTATION.md) · [Changes](../../CHANGES.md)

## Build and test

Use CMake 3.15 or newer and a C11/C++17 compiler. The core library has no
downloaded build dependencies. Python bindings and the other language examples
have their own toolchains and build instructions in their directories.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

The Python CMake option currently adds an examples directory; it does not build
the Python extension. Use the instructions in `examples_python` for that step.
Linux CI tests GCC and Clang. Windows CI currently validates compilation only;
the existing file tests use POSIX paths. A successful Windows build is not a
Windows runtime test result.

## Use the installed library

```cmake
cmake_minimum_required(VERSION 3.15)
project(example LANGUAGES CXX)
find_package(libzupt 1.0.14 CONFIG REQUIRED)
add_executable(example main.cpp)
target_link_libraries(example PRIVATE libzupt::zupt_shared)
# For static linking, use libzupt::zupt_static.
```

Pass `-DCMAKE_PREFIX_PATH=/path/to/install` when configuring the consumer.
Both imported targets supply the include directory and C++17 requirement.
`zupt::getVersion()` reports the library version from `libzupt_version.h`.
The package tests in `tests/package` exercise both targets after relocation.

```cpp
#include <zupt.hpp>

int main() {
    const auto keys = zupt::KeyGenerator().generateKeyPair();
    zupt::Encryptor encryptor(keys.public_key);
    const std::vector<uint8_t> message = {1, 2, 3};
    const auto encrypted = encryptor.encryptMemory(message);
    const auto restored = zupt::Decryptor(keys.secret_key).decryptMemory(
        encrypted.first, encrypted.second);
    return restored == message ? 0 : 1;
}
```

Keep the ciphertext and its matching encryption header together. Treat a
`zupt::ZuptError` as failure; never substitute empty plaintext on an error.

## Data format and security boundaries

The C++ API uses 1,224-byte public keys, 3,656-byte private keys and a
1,137-byte encryption header. These API key buffers do not include an extra
checksum. Older low-level file helpers use a different checksummed layout;
do not substitute those files for C++ API buffers.

Each ciphertext record has a 4-byte little-endian payload length, a 16-byte
nonce, the encrypted payload and a 32-byte HMAC. Payloads are at most 4 MiB.
In 1.0.14, an empty message is a 52-byte authenticated record. Legacy zero-byte
ciphertexts are rejected because they carry no authentication tag. Re-encrypt
trusted original empty data to migrate it; do not reinterpret a failed decrypt
as an empty message. Older readers may reject the new authenticated empty record.
Nonempty ciphertext produced by earlier versions retains its record format.

Decryption checks the MAC and the nonce expected for each block position.
It rejects reordered/replayed blocks, a changed header nonce, malformed length
records and zero-length records appended to a nonempty message.
**The format does not authenticate the total message length or an end marker.**
Removing complete trailing blocks can still leave a valid prefix. Applications
requiring completeness must authenticate an expected length or digest through
a separate trusted channel/container. This release does not claim whole-message
truncation protection, cryptographic certification or a comprehensive audit of
all language bindings and primitive implementations.

`SecureBuffer` wipes owned memory on destruction and before move assignment;
moved-from buffers are empty. Converting to `std::vector` or `std::string` creates
ordinary copies that are not automatically wiped. On POSIX, `saveKeyPair` writes
through one checked descriptor with mode 0600 and rejects symlinks, hard links
and nonregular files. Store keys in a directory controlled by the key owner.
Windows callers must configure directory/file ACLs themselves.

## Release procedure and project statistics

Use the next sequential version and keep `include/libzupt_version.h`, the tag
and the newest `CHANGES.md` entry aligned. Sign every new commit with GPG and
create a signed tag, for example `git tag -s v1.0.14 -m "Release libzupt 1.0.14"`.
Verify with `git verify-commit HEAD` and `git verify-tag v1.0.14`.

Run the tests above and the installed-package tests before packaging:

```sh
cmake -S tests/package -B consumer -DCMAKE_PREFIX_PATH="$PWD/install"
cmake --build consumer --parallel 2
ctest --test-dir consumer --output-on-failure
python3 scripts/package-release.py v1.0.14 ../libzupt-1.0.14-release
```

The packaging script requires a locally installed `zupt` compressor, verifies
the signed tag/version, exports the tagged source, and creates `.tar.gz` and
`.zupt` source assets outside the checkout. It uses level 9 with solid compression,
embeds the current changes as the archive comment, tests/extracts the archive,
compares the restored source tar and writes `SHA256SUMS`. The `.zupt` asset contains
a source tar; extract it, then unpack that tar. It is a source distribution, not
a precompiled library. No token or signing key is embedded in any package.

The tag workflow validates the build and uploads Linux binary artifacts. It
does not publish as a bot. Authenticate `gh` locally as the releasing maintainer,
verify `gh api user --jq .login`, and configure HTTPS Git authentication with
`gh auth setup-git`. Push the signed branch and tag, wait for release validation,
then publish with the maintainer's token:

```sh
gh release create v1.0.14 --verify-tag --title "libzupt 1.0.14" \
  --notes-file ../libzupt-1.0.14-release/release-notes.txt \
  ../libzupt-1.0.14-release/libzupt-1.0.14-src.tar.gz \
  ../libzupt-1.0.14-release/libzupt-1.0.14-src.zupt \
  ../libzupt-1.0.14-release/SHA256SUMS
```

CI summaries report the tested commit, platform/compiler and actual CTest
results. Release packages report byte sizes and SHA-256 digests. Keep generated
statistics, build output and audit working notes outside version control;
never turn unexecuted checks into a passing badge or test count.
