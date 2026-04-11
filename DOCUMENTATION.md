# libzupt Documentation

## Index

- [Overview](#overview)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [API Reference](#API-reference)
- [Examples](#examples)
- [Security](#security)
- [Architecture](#architecture)

## Overview

libzupt is a dynamic C++ library that provides encryption and decryption of files and binary data in memory using post-quantum hybrid cryptography **ML-KEM-768 + X25519**.

### Features

- **Post-quantum hybrid cryptography**: Combines ML-KEM-768 (FIPS 203) with X25519 (RFC 7748)
- **Security in case of failure**: Secure if at least one of the algorithms remains secure
- **Modern C++ API**: Object-oriented interface with exception handling
- **File and memory support**: File and memory buffer encryption
- **Secure memory wipe**: Sensitive data is wiped after use

## Installation

### Requirements

- CMake 3.10 or higher
- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- System libraries: `libm`

### Compilation

```bash
cd libzupt
mkdir build && cd build
cmake..
make -j$(nproc)
sudo make install
```

### Usage in CMake

```cmake
find_package(libzupt REQUIRED)
target_link_libraries(my_program zupt::zupt_shared)
```

## Basic Usage

### Generate Key Pair

```cpp
#include "zupt.hpp"

zupt::KeyGenerator keygen;
zupt::KeyPair keypair = keygen.generateKeyPair();

// Save keys
keygen.saveKeyPair(keypair, "private.key");
keygen.exportPublicKey("private.key", "public.key");
```

### Encrypt Data

```cpp
#include "zupt.hpp"

zupt::KeyGenerator keygen;
std::vector<uint8_t> publicKey = keygen.loadPublicKey("public.key");

zupt::Encryptor encryptor(publicKey);
const std::string plaintext = "Secret message";
auto [ciphertext, encHeader] = encryptor.encryptMemory(
reinterpret_cast<const uint8_t*>(plaintext.data()),
plaintext.size()
);
```

### Decrypt Data

```cpp
#include "zupt.hpp"

zupt::KeyGenerator keygen;
zupt::KeyPair keypair = keygen.loadKeyPair("private.key");

zupt::Decryptor decryptor(keypair.secret_key);
std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext, encHeader);
std::string result(decrypted.begin(), decrypted.end());
```

## API Reference

### zupt::KeyGenerator

```cpp
class KeyGenerator {
public:
KeyPair generateKeyPair(); // Generate new key pair
void saveKeyPair(const KeyPair&, const string&); // Save keys to file
KeyPair loadKeyPair(const string&); // Load keys from file
void exportPublicKey(const string&, const string&); // Export public key
vector<uint8_t> loadPublicKey(const string&); // Load public key
};
```

### zupt::Encryptor

```cpp
class Encryptor {
public:
explicit Encryptor(const vector<uint8_t>& publicKey);
pair<vector<uint8_t>, vector<uint8_t>> encryptMemory(const uint8_t*, size_t);
pair<vector<uint8_t>, vector<uint8_t>> encryptFile(const string&);
};
```

### zupt::Decryptor

```cpp
class Decryptor {
public:
explicit Decryptor(const vector<uint8_t>& privateKey);
vector<uint8_t> decryptMemory(const uint8_t*, size_t, const vector<uint8_t>&);
vector<uint8_t> decryptFile(const string&, const vector<uint8_t>&);
SecureBuffer decryptMemorySecure(const SecureBuffer&, const vector<uint8_t>&);
};
```

### zupt::SecureBuffer

```cpp
class SecureBuffer {
public:
explicit SecureBuffer(size_t size);
SecureBuffer(const uint8_t* data, size_t size);
void zeroize() noexcept; // Clear buffer manually
uint8_t* data() noexcept;
size_t size() const noexcept;
};
```

### Auxiliary Functions

```cpp
std::vector<uint8_t> randomBytes(size_t size); // Generate safe random bytes
std::vector<uint8_t> sha256(const uint8_t* data, size_t size); // SHA-256
std::vector<uint8_t> sha3_512(const uint8_t* data, size_t size); //SHA3-512
void secureWipe(void* ptr, size_t size); // Clear memory safely
const char* getVersion(); // Library Version

```

## Examples

See examples in `examples/`:

```bash

# Run basic example
./zupt_example_basic

# Generate keys
./zupt_example_file genkey private.key public.key

# Encrypt file
./zupt_example_file encrypt public.key input.txt output.zupt

# Decrypt file
./zupt_example_file decrypt private.key output.zupt output.txt output.zupt.header
```

## Security

See [SECURITY.md](SECURITY.md) for details on:

- Security model
- Implemented algorithms
- Protections against attacks
- Best practices

## Architecture

### Structure of Files

```
libzupt/
├── include/
│   ├── zupt.hpp      # C++ API principal
│   └── zupt_cxx.h    # C API para wrappers
├── src/
│   ├── zupt_crypto.cpp  # Implementação C++ da API
│   └── zupt_cxx.c       # Wrapper C para funções C++
├── examples/          # Exemplos de uso
├── tests/            # Suite de testes
└── CMakeLists.txt    # Build configuration
```

### Cryptographic Flow tography


```
1. Key Generation:
   - ML-KEM-768: gera pk (1184 bytes), sk (2400 bytes)
   - X25519: gera pk (32 bytes), sk (32 bytes)

2. Encryption:
   - ML-KEM-768: encapsula, gera ct (1088 bytes), ss (32 bytes)
   - X25519: ECDH, gera ss (32 bytes)
   - Hybrid: ikm = ml_ss XOR x_ss
   - Derive: SHA3-512(ikm || ct || pk || "ZUPT-HYBRID-v1")
   - Encrypt: AES-256-CTR + HMAC-SHA256

3. Decryption:
   - ML-KEM-768: decapsula, recupera ss
   - X25519: ECDH com chave pública efêmera
   - Derive: mesma fórmula
   - Decrypt: AES-256-CTR + HMAC-SHA256
```
## Sizes

| Component | Size |
|------------|---------|
| ML-KEM Public Key | 1184 bytes |
| ML-KEM Secret Key | 2400 bytes |
| X25519 Key | 32 bytes |
| Hybrid Public Key | 1224 bytes |
| Hybrid Secret Key | 2504 bytes |
| ML-KEM Ciphertext | 1088 bytes |
| Encryption Header | 1137 bytes |
