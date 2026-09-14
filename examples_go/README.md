# libzupt - Go Examples

This directory contains Go examples using the libzupt library through its C API
(`libzupt_cxx.h`, `zupt.h` and `zupt_keccak.h`), called via cgo.

## Prerequisites

- Go 1.21 or higher
- A C compiler supported by cgo (gcc/clang)
- CMake 3.15 or higher
- The built `libzupt.so` shared library (in `../build/`)

## Build

### Build the libzupt shared library (if not present in `../build/`):

```bash
cd ..
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_PYTHON=OFF
make -j$(nproc)
```

### Build the Go examples:

```bash
cd examples_go
./build.sh
```

This compiles the examples into a single `zupt_example` binary.

## Run the examples

Run all examples at once (default):

```bash
cd examples_go
LD_LIBRARY_PATH=../build ./zupt_example
```

Or run a single example:

```bash
LD_LIBRARY_PATH=../build ./zupt_example basic
LD_LIBRARY_PATH=../build ./zupt_example file
LD_LIBRARY_PATH=../build ./zupt_example keygen
LD_LIBRARY_PATH=../build ./zupt_example random
LD_LIBRARY_PATH=../build ./zupt_example secure_buffer
```

## Examples

1. **example_basic.go** - Basic encryption/decryption with memory data
2. **example_file.go** - Encrypting and decrypting files
3. **example_keygen.go** - Key generation and management
4. **example_random.go** - Generating random bytes and computing hashes
5. **example_secure_buffer.go** - Using SecureBuffer for zeroizing sensitive data

## API Reference

### KeyGenerator
- `GenerateKeyPair()` - Generate a new hybrid key pair
- `LoadKeyPair(filename)` - Load a key pair from file
- `LoadPublicKey(filename)` - Load a public key from file
- `ExportPublicKey(privFile, pubFile)` - Export public key from private key file
- `SaveKeyPair(keyPair, filename)` - Save a key pair to file

### Encryptor
- `Encrypt(data)` - Encrypt bytes in memory
- `EncryptSecure(buffer)` - Encrypt a SecureBuffer
- `EncryptFile(filename)` - Encrypt a file
- `HeaderSize()` - Size of encryption header

### Decryptor
- `Decrypt(ciphertext, encHeader)` - Decrypt bytes
- `DecryptSecure(ciphertext, encHeader)` - Decrypt to a SecureBuffer
- `DecryptFile(filename, encHeader)` - Decrypt a file

### SecureBuffer
- `NewSecureBuffer(data)` - Create from bytes
- `NewSecureBufferSize(size)` - Create empty buffer
- `Zeroize()` - Securely wipe memory
- `ToBytes()` - Convert to byte slice
- `String()` - Convert to string

### Helper Functions
- `RandomBytes(size)` - Generate cryptographically secure random bytes
- `Sha256(data)` - Compute SHA-256 hash
- `Sha3_512(data)` - Compute SHA3-512 hash
- `SecureWipe(data)` - Securely wipe memory
- `ReadFile(path)` / `WriteFile(path, data)` - File I/O through libzupt

### Constants
- `MLKEMPublicKeyBytes`, `MLKEMSecretKeyBytes`
- `MLKEMCiphertextBytes`, `MLKEMSSBytes`
- `X25519KeyBytes`
- `HybridPubKeySize`, `HybridPrivKeySize`, `HybridEncHeaderSize`
- `AESKeySize`, `AESNonceSize`, `HMACSize`

## License

SPDX-License-Identifier: MIT