# libzupt Security

## Overview

libzupt implements post-quantum hybrid cryptography using **ML-KEM-768** (FIPS 203) combined with **X25519** (RFC 7748). This document describes the security model, implemented protections, and best practices.

## Security Model

### Post-Quantum Hybrid

Cryptography is considered secure if **at least one** of the algorithms (ML-KEM-768 or X25519) remains resistant to attacks:

``` Security = ML-KEM-768 (post-quantum) XOR X25519 (classical)

```

This approach is used by:

- Signal (PQXDH)
- iMessage (PQ3)
- OpenSSH 9.0+

### Security Levels

| Component | Size | Security |

|------------|------------|-----------|
| ML-KEM-768 Public Key | 1184 bytes | ~128 bits (post-quantum) |
| ML-KEM-768 Secret Key | 2400 bytes | - |
| X25519 Key | 32 bytes | ~128 bits (classic) |
| Hybrid Shared Secret | 32 bytes | ~128 bits |

## Implemented Algorithms

### 1. ML-KEM-768 (FIPS 203)
- **Type**: Key Encapsulation Mechanism (KEM)
- **Parameters**: k=3, η₁=2, η₂=2, d_u=10, d_v=4
- **Ciphertext**: 1088 bytes
- **Shared Secret**: 32 bytes
- **Security**: Resistant to quantum attacks

### 2. X25519 (RFC 7748)
- **Type**: Diffie-Hellman ECDH
- **Curve**: Curve25519
- **Key Size**: 32 bytes
- **Security**: Resistant to timing attacks

### 3. Key Derivation
- **Algorithm**: SHA3-512
- **Input**: `SHA3-512(hybrid_ikm || ml_ct || eph_pk || "ZUPT-HYBRID-v1")`
- **Output**: 64 bytes (enc_key[32] + mac_key[32])

### 4. Data Encryption
- **Algorithm**: AES-256-CTR
- **Key Size**: 32 bytes
- **Nonce Size**: 16 bytes

### 5. Authentication
- **Algorithm**: HMAC-SHA256
- **MAC Size**: 32 bytes

## Implemented Protections

### 1. Secure Memory Wipe
```cpp
// Keys and sensitive data are zeroed after use
void secureWipe(void* ptr, size_t size);

```

### 2. Constant Comparison
HMAC verification uses constant comparison to prevent timing attacks:

```cpp
// XOR accumulation for constant comparison
uint64_t diff = 0;

for (int i = 0; i < 32; i++)

diff |= (uint64_t)(expected_mac[i] ^ stored_mac[i]);

```

### 3. Implicit Encapsulation
ML-KEM-768 implements implicit rejection to prevent timing attacks:
- Invalid ciphertexts produce pseudorandom shared secrets
- No visible distinction between success and failure

### 4. Cryptographic Randomness
Use of system CSPRNG:

- Linux: `getrandom(2)` or `/dev/urandom`
- macOS/BSD: `getrandom(2)` or `/dev/urandom`
- Windows: `RtlGenRandom`

## Threat Models

### Attacks Against Which We Are Protected

| Attack | Protection |

|--------|----------|

| Cryptographic Breaking | Hybrid (at least one algorithm must be broken) |

| Quantum Attacks | ML-KEM-768 (post-quantum) |

| Time Attacks | Constant Comparison, Montgomery Ladder |

| Reverse Engineering | Memory Wipe |

| Replay | Unique Nonces per Block |

| Data Corruption | HMAC-SHA256 per Block |

### Out-of-Scope Attacks

| Attack | Note |

|--------|------|

| Channel-Side Attacks | Requires further analysis |

| Malware | Operating System Protection |

| Supply Chain Attacks | Integrity Verification |

| Physical Attacks | Physical System Protection |

## Best Practices

### 1. Key Management

```cpp
// CORRECT: Save keys in a secure location `keygen.saveKeyPair(keypair, "/etc/ssl/private/mykey.key");`

// WRONG: Save in an accessible location `keygen.saveKeyPair(keypair, "/tmp/mykey.key");`

### 2. Do Not Reuse Headers

Each encryption should use a unique header:

```cpp
// CORRECT: Create a new encryptor for each operation
Encryptor e1(publicKey);

auto [ct1, hdr1] = e1.encryptMemory(data);

// WRONG: Reusing headers with different keys
// This compromises security

```

### 3. Verify Integrity

Always verify the integrity of the decrypted data:

```cpp

try {

auto decrypted = decryptor.decryptMemory(ciphertext, header);

// Verify integrity of decrypted data
} catch (const ZuptError& e) {

// Handle authentication failure
}
```

### 4. Using SecureBuffer for Sensitive Data

```cpp
// CORRECT: SecureBuffer automatically clears
SecureBuffer password(reinterpret_cast<const uint8_t*>(pw), len);

// INCORRECT: Normal buffer is not cleared
std::vector<uint8_t> password = ...;

```

## Security Verification

### Security Tests

Tests include:

- `keygen.cpp`: Key generation and validation
- `encrypt.cpp`: Encryption and validation
- `decrypt.cpp`: Decryption and validation
- `roundtrip.cpp`: Full round-trip tests
- `file_ops.cpp`: File operations

### Validation

To validate the implementation:
```bash
cd libzupt/build
make test
```

## Security Warnings

### DO NOT USE
- Password modes (`-p`) for post-quantum protection
- Keys generated on untrusted systems
- Reuse of headers between different keys
- Plaintext key storage

### USE
- Locally generated keys with `keygen`
- Secure key storage
Private
- Unique headers per operation
- `SecureBuffer` for sensitive data

## References

- [FIPS 203 - ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [RFC 7748 - X25519](https://tools.ietf.org/html/rfc7748)
- [Signal PQXDH](https://signal.org/docs/specifications/pqx/)
- [OpenSSH 9.0 - PQ](https://www.openssh.com/txt/release-9.0)
