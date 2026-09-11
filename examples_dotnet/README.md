# libzupt - .NET Examples

This directory contains C# examples using the libzupt library through its C API
(`libzupt_cxx.h`), P/Invoked from .NET 8.

## Prerequisites

- .NET SDK 8.0 or higher
- CMake 3.15 or higher
- A C/C++17 compatible compiler
- The built `libzupt.so` shared library (in `../build/`)

## Build

### Build the libzupt shared library (if not present in `../build/`):

```bash
cd ..
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_PYTHON=OFF
make -j$(nproc)
```

### Build the .NET examples:

```bash
cd examples_dotnet
./build.sh
```

## Run the examples

Run all examples at once (default):

```bash
export LD_LIBRARY_PATH="../build:$LD_LIBRARY_PATH"
dotnet run --project ZuptExample.csproj
```

Or run a single example:

```bash
dotnet run --project ZuptExample.csproj -- basic
dotnet run --project ZuptExample.csproj -- file
dotnet run --project ZuptExample.csproj -- keygen
dotnet run --project ZuptExample.csproj -- random
dotnet run --project ZuptExample.csproj -- secure_buffer
```

## Examples

1. **ExampleBasic** - Basic encryption/decryption with memory data
2. **ExampleFile** - Encrypting and decrypting files
3. **ExampleKeygen** - Key generation and management
4. **ExampleSecureBuffer** - Using SecureBuffer for zeroizing sensitive data
5. **ExampleRandom** - Generating random bytes and computing hashes

## API Reference

### KeyGenerator
- `GenerateKeyPair()` - Generate a new hybrid key pair
- `LoadKeyPair(filename)` - Load a key pair from file
- `LoadPublicKey(filename)` - Load a public key from file
- `ExportPublicKey(privFile, pubFile)` - Export public key from private key file
- `SaveKeyPair(keyPair, filename)` - Save a key pair to file

### Encryptor
- `Encrypt(data)` / `EncryptMemory(data)` - Encrypt bytes in memory
- `EncryptMemory(SecureBuffer)` - Encrypt a SecureBuffer
- `EncryptFile(filename)` - Encrypt a file
- `HeaderSize` - Size of encryption header

### Decryptor
- `Decrypt(ciphertext, encHeader)` / `DecryptMemory(...)` - Decrypt bytes
- `DecryptMemorySecure(ciphertext, encHeader)` - Decrypt to a SecureBuffer
- `DecryptFile(filename, encHeader)` - Decrypt a file

### SecureBuffer
- `SecureBuffer(byte[])` - Create from bytes
- `SecureBuffer(size)` - Create empty buffer
- `Zeroize()` - Securely wipe memory
- `ToBytes()` - Convert to byte array
- `ToUtf8String()` - Convert to string

### Zupt (helper functions)
- `RandomBytes(size)` - Generate cryptographically secure random bytes
- `Sha256(data)` - Compute SHA-256 hash
- `Sha3_512(data)` - Compute SHA3-512 hash
- `SecureWipe(data)` - Securely wipe memory

### Constants (ZuptConstants)
- `MlkEmPublicKeyBytes`, `MlkEmSecretKeyBytes`
- `MlkEmCiphertextBytes`, `MlkEmSsBytes`
- `X25519KeyBytes`
- `HybridPubKeySize`, `HybridPrivKeySize`, `HybridEncHeaderSize`
- `AesKeySize`, `AesNonceSize`, `HmacSize`

## License

SPDX-License-Identifier: MIT