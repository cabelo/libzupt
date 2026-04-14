# libzupt - Post-Quantum Hybrid Cryptography Library

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]() [![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](#build) [![CMake on multiple platforms](https://github.com/cabelo/libzupt/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/cabelo/libzupt/actions/workflows/cmake-multi-platform.yml)

**libzupt** is a library that provides encryption and decryption of files and binary data in memory using post-quantum hybrid cryptography **ML-KEM-768 + X25519** in various languages.

The **libzupt** is an SDK designed to simplify the implementation of encryption and decryption for files and in-memory binary data, using a modern approach based on hybrid post-quantum cryptography **ML-KEM-768 + X25519**. Initially developed in **C++ and Python**, the library is built to be efficient, portable, and easy to integrate into applications that require advanced security. There are also plans to expand support to **Java and Node.js**, further increasing its adoption across different development ecosystems.

The main goal of libzupt is to enable current applications to be protected against emerging threats from quantum computing, even when running on classical computers. By combining traditional cryptographic techniques with quantum-resistant mechanisms, the library provides an additional layer of security that anticipates future scenarios where classical algorithms may be broken. This allows developers to build more resilient systems, ensuring long-term data confidentiality and integrity.

The name **zupt** is atribute to the original project created by [**Cristian Cezar Moisés**](https://github.com/cristiancmoises), acknowledging his fundamental contribution to the conceptual and technical foundation of this solution. This inspiration reinforces the library’s commitment to innovation, security, and the evolution of ideas that drive modern applied cryptography forward.

<div align="center">
<img width="480" height="487" alt="image" src="https://github.com/user-attachments/assets/df6a4a01-ca23-4b34-a5bf-d38a4c31d48c" />
</div>

## Overview

The library provides:

- **Post-quantum hybrid encryption**: Combines ML-KEM-768 (FIPS 203) with X25519 (RFC 7748)
- **Fail-safe security**: Secure as long as at least one of the algorithms (ML-KEM-768 or X25519) remains secure
- **Modern C++ API**: Object-oriented interface with exception handling
- **File and memory support**: Encryption for files and memory buffers
- **Secure memory cleanup**: Sensitive data is wiped after use


### Requirements

- CMake 3.10 or higher
- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- System libraries: `libm`

### Build

```bash
# Clone libzupt
git clone https://github.com/cabelo/libzupt.git

# Build
cd libzupt
mkdir build && cd build
cmake ..
make -j$(nproc)

# Install (optional)
sudo make install
```

### Install via vcpkg (Windows/Linux)

```bash
vcpkg install libzupt:x64-linux
# ou
vcpkg install libzupt:x64-windows
```

## Basic Usage

### Generate Key Pair

```cpp
#include "zupt.hpp"

zupt::KeyGenerator keygen;
zupt::KeyPair keypair = keygen.generateKeyPair();

// Salvar chaves em arquivos
keygen.saveKeyPair(keypair, "private.key");
keygen.exportPublicKey("private.key", "public.key");
```

### Encrypt Data in Memory

```cpp
#include "zupt.hpp"

// Carregar chave pública
zupt::KeyGenerator keygen;
std::vector<uint8_t> publicKey = keygen.loadPublicKey("public.key");

// Criptografar
zupt::Encryptor encryptor(publicKey);
const std::string plaintext = "Mensagem secreta";
auto [ciphertext, encHeader] = encryptor.encryptMemory(
    reinterpret_cast<const uint8_t*>(plaintext.data()),
    plaintext.size()
);
```

### Decrypt Data in Memory

```cpp
#include "zupt.hpp"

// Carregar chave privada
zupt::KeyGenerator keygen;
zupt::KeyPair keypair = keygen.loadKeyPair("private.key");

// Descriptografar
zupt::Decryptor decryptor(keypair.secret_key);
std::vector<uint8_t> decrypted = decryptor.decryptMemory(ciphertext, encHeader);
std::string result(decrypted.begin(), decrypted.end());
```

###  Encrypt File

```cpp
#include "zupt.hpp"

zupt::KeyGenerator keygen;
std::vector<uint8_t> publicKey = keygen.loadPublicKey("public.key");
zupt::Encryptor encryptor(publicKey);

auto [ciphertext, encHeader] = encryptor.encryptFile("input.txt");

// Salvar ciphertext e header
std::ofstream("output.zupt", std::ios::binary).write(
    reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
std::ofstream("output.zupt.header", std::ios::binary).write(
    reinterpret_cast<const char*>(encHeader.data()), encHeader.size());
```

## API

### Main Classes

#### `zupt::KeyGenerator`

Generates and manages hybrid key pairs.

```cpp
class KeyGenerator {
public:
    KeyPair generateKeyPair();                    // Gera novo par de chaves
    void saveKeyPair(const KeyPair&, const string&);  // Salva chaves em arquivo
    KeyPair loadKeyPair(const string&);           // Carrega chaves de arquivo
    void exportPublicKey(const string&, const string&); // Exporta chave pública
    vector<uint8_t> loadPublicKey(const string&); // Carrega chave pública
};
```

#### `zupt::Encryptor`

Performs encryption using a public key.

```cpp
class Encryptor {
public:
    explicit Encryptor(const vector<uint8_t>& publicKey);
    pair<vector<uint8_t>, vector<uint8_t>> encryptMemory(const uint8_t*, size_t);
    pair<vector<uint8_t>, vector<uint8_t>> encryptFile(const string&);
};
```

#### `zupt::Decryptor`

Performs decryption using a private key.

```cpp
class Decryptor {
public:
    explicit Decryptor(const vector<uint8_t>& privateKey);
    vector<uint8_t> decryptMemory(const uint8_t*, size_t, const vector<uint8_t>&);
    vector<uint8_t> decryptFile(const string&, const vector<uint8_t>&);
    SecureBuffer decryptMemorySecure(const SecureBuffer&, const vector<uint8_t>&);
};
```

#### `zupt::SecureBuffer`

Buffer that automatically wipes its memory upon destruction.

```cpp
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size);
    SecureBuffer(const uint8_t* data, size_t size);
    void zeroize() noexcept;  // Limpa buffer manualmente
    uint8_t* data() noexcept;
    size_t size() const noexcept;
};
```

### Helper Function

```cpp
std::vector<uint8_t> randomBytes(size_t size);       // Generates safe random bytes.
std::vector<uint8_t> sha256(const uint8_t* data, size_t size);  // SHA-256
std::vector<uint8_t> sha3_512(const uint8_t* data, size_t size); // SHA3-512
void secureWipe(void* ptr, size_t size);              // Safely clears memory.
const char* getVersion();                             // Library version
const char* getLibraryName();                         // Library name
```

## Examples

See the complete examples in `examples/`:

```bash
# Generate keys 
./zupt_example_file genkey private.key public.key

# Encrypt file
./zupt_example_file encrypt public.key input.txt output.zupt

# Decrypt file
./zupt_example_file decrypt private.key output.zupt output.txt output.zupt.header

# Run basic example
./zupt_example_basic
```

## Key Format Specification

The keys are stored in the format `.zupt-key`:

```
[4B]  "ZKEY" - Magic number
[1B]  Version (0x01)
[1B]  Flags (bit 0 = 1 if there is a private key)
[2B]  Reserved
[1184B] ML-KEM-768 Public Key
[32B]   X25519 Public Key
[2400B] ML-KEM-768 Secret Key (private key)
[32B]   X25519 Secret Key (private key)
[8B]  XXH64 Checksum
```

Total size:
- Public key: 1224 bytes
- Private key: 2504 bytes


### Combined Algorithms

1. **ML-KEM-768** (FIPS 203): Post-quantum key encapsulation algorithm
2. **X25519** (RFC 7748): (RFC 7748): Diffie-Hellman elliptic curve 25519

### Key Derivation Process

```
1. ML-KEM-768 Encaps: generates ciphertext (1088 bytes) and shared secret (32 bytes)
2. X25519 ECDH: generates shared secret (32 bytes) with recipient's public key
3. Hybrid IKM = ML-KEM-SS XOR X25519-SS (32 bytes)
4. Archive Key = SHA3-512(hybrid_ikm || ml_ct || eph_pk || "ZUPT-HYBRID-v1")
- enc_key = archive_key[0:32]
- mac_key = archive_key[32:64]
5. AES-256-CTR + HMAC-SHA256 for data encryption
```

### Tamanhos dos Dados

| Component | Size |
|------------|---------|
| ML-KEM Public Key | 1184 bytes |
| ML-KEM Secret Key | 2400 bytes |
| X25519 Key | 32 bytes |
| ML-KEM Ciphertext | 1088 bytes |
| Encryption Header | 1137 bytes |

## Security

### Security Models

The library follows the security model of **Signal PQXDH** and **iMessage PQ3**:

> Encryption is considered secure if at least one of the algorithms (ML-KEM-768 or X25519) remains resistant to attacks.

### Implemented Protections
- **Secure Memory Wipe**: Keys and sensitive data are zeroed out after use
- **Implicit Encapsulation**: ML-KEM-768 implements implicit rejection to prevent timing attacks
- **Constant Comparison**: HMAC verification uses constant comparison to prevent timing attacks
- **Cryptographic Randomness**: Uses system CSPRNG (getrandom, /dev/urandom, RtlGenRandom)

### Security Warnings

- **DO NOT use password modes (`-p`)** for post-quantum protection - use only `--pq` with keys
- Private keys must be stored in secure locations
- DO NOT reuse cryptographic headers with different keys


<img width="480" height="720" alt="image" src="https://github.com/user-attachments/assets/788b3357-05a4-4c9e-abcd-fdb00f083574"  align="right" width="150"/>

### License

MIT License - see the [LICENSE](LICENSE) file for details.

### Author

Alessandro de Oliveira Faria (A.K.A.CABELO)
- Founder MultiCortex
- Intel Innvator
- openSUSE Ambassador and Member
- Chapter Leader OWASP SP
- Senior AI Researcher - Soberania Project
- Member of the Foton Institute
- Professor at FIA
- Member i2Ai and ABRIA

Contact: cabelo@opensuse.org
 
### References

- [ML-KEM-768 - FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [X25519 - RFC 7748](https://tools.ietf.org/html/rfc7748)
- [Signal PQXDH](https://signal.org/docs/specifications/pqx/)
- [Libsodium](https://github.com/jedisct1/libsodium)

[<img width="225" height="134" alt="image" src="https://github.com/user-attachments/assets/95eea4cf-9ec8-4a68-9b26-1cb7ce19534c" />](https://www.paypal.com/donate/?hosted_button_id=7X8GVQG2J78LW)
