# libzupt - Rust Examples

This directory contains Rust examples using the libzupt library through its C API (`zupt_cxx.h`, `zupt.h` and `zupt_keccak.h`), called via FFI using `bindgen`.

## Prerequisites

- Rust toolchain (1.70+ recommended)
- CMake 3.15 or higher
- A C/C++ compiler (gcc/clang)
- The built `libzupt.so` shared library (in `../build/`)

### Install Rust

If Rust is not installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Build

### Build the libzupt shared library (if not present in `../build/`):

```bash
cd ..
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_PYTHON=OFF
make -j$(nproc)
```

### Build all Rust examples:

```bash
cd examples_rust
./build.sh
```

Or manually with cargo:

```bash
cd examples_rust
cargo build --release
```

## Run the Examples

Run a specific example:

```bash
cargo run --release --example example_basic
cargo run --release --example example_file
cargo run --release --example example_keygen
cargo run --release --example example_random
cargo run --release --example example_secure_buffer
```

Or run all examples at once:

```bash
for ex in example_basic example_file example_keygen example_random example_secure_buffer; do
  cargo run --release --example $ex
  echo
done
```

## Examples

1. **example_basic** - Basic encryption/decryption with in-memory data, including wrong-key rejection test.
2. **example_file** - Encrypting and decrypting files (write plaintext to disk, encrypt, save ciphertext, decrypt back).
3. **example_keygen** - Key pair generation, saving/loading keys from disk, and exporting public keys.
4. **example_random** - Generating random bytes, computing SHA-256 and SHA3-512 hashes, and key derivation.
5. **example_secure_buffer** - Using `SecureBuffer` for automatic memory zeroization of sensitive data.

## API Reference

### Key Management

- `generate_keypair() -> Result<KeyPair, ZuptError>` - Generate a new hybrid key pair
- `export_public_key(priv_key, pub_key) -> Result<(), ZuptError>` - Export public key from secret key
- `save_keypair(keypair, path) -> Result<(), ZuptError>` - Save key pair to file
- `load_keypair(path) -> Result<KeyPair, ZuptError>` - Load key pair from file
- `load_public_key(path) -> Result<Vec<u8>, ZuptError>` - Load public key from file

### Encryption / Decryption

- `encrypt(pub_key, plaintext) -> Result<(Vec<u8>, Vec<u8>), ZuptError>` - Encrypt data in memory
- `decrypt(priv_key, ciphertext, enc_header) -> Result<Vec<u8>, ZuptError>` - Decrypt data in memory
- `encrypt_file(pub_key, path) -> Result<(Vec<u8>, Vec<u8>), ZuptError>` - Encrypt a file
- `decrypt_file(priv_key, path, enc_header) -> Result<Vec<u8>, ZuptError>` - Decrypt a file

### Utility Functions

- `random_bytes(count) -> Vec<u8>` - Generate cryptographically secure random bytes
- `sha256(data) -> Vec<u8>` - Compute SHA-256 hash
- `sha3_512(data) -> Vec<u8>` - Compute SHA3-512 hash
- `secure_wipe(buf)` - Securely wipe memory (zeroing with volatile writes)
- `read_file(path) -> Result<Vec<u8>, ZuptError>` - Read file contents via libzupt
- `write_file(path, data) -> Result<(), ZuptError>` - Write data to file via libzupt

### SecureBuffer

- `SecureBuffer::from_bytes(data) -> Self` - Create from byte slice
- `SecureBuffer::new(size) -> Self` - Create empty buffer of given size
- `zeroize()` - Manually zero out buffer contents
- `as_slice()` / `as_mut_slice()` - Access underlying data
- Memory is automatically zeroed on drop

### Constants

| Constant | Value |
|---|---|
| `MLKEM_PUBLICKEYBYTES` | 1184 |
| `MLKEM_SECRETKEYBYTES` | 2400 |
| `MLKEM_CIPHERTEXTBYTES` | 1088 |
| `MLKEM_SSBYTES` | 32 |
| `X25519_KEYBYTES` | 32 |
| `HYBRID_PUB_KEY_SIZE` | 1224 |
| `HYBRID_PRIV_KEY_SIZE` | 3656 |
| `HYBRID_ENC_HEADER_SIZE` | 1137 |
| `AES_KEY_SIZE` | 32 |
| `AES_NONCE_SIZE` | 16 |
| `HMAC_SIZE` | 32 |

## Project Structure

```
examples_rust/
  Cargo.toml          - Package manifest and dependencies
  build.rs            - Build script (generates FFI bindings via bindgen)
  build.sh            - Convenience build script (builds libzupt + Rust examples)
  src/
    lib.rs            - Safe Rust wrapper around libzupt C API
  examples/
    example_basic.rs
    example_file.rs
    example_keygen.rs
    example_random.rs
    example_secure_buffer.rs
```

## How It Works

The `build.rs` script uses `bindgen` to automatically generate Rust FFI bindings from the libzupt C header files at compile time. The `src/lib.rs` wraps the raw FFI calls in safe Rust functions with proper error handling (`Result<T, ZuptError>`).

The build process:

1. `bindgen` reads `zupt_cxx.h`, `zupt.h`, and `zupt_keccak.h` from `../include/`
2. Generated bindings are written to `$OUT_DIR/bindings.rs`
3. The crate links against `libzupt.so` (shared) or `libzupt_static.a` (static) from `../build/`

## License

SPDX-License-Identifier: MIT
