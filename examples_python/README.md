# libzupt - Python Examples

This directory contains Python examples using the libzupt library through pybind11 bindings.

## Prerequisites

- Python 3.8 or higher
- pybind11
- CMake 3.15 or higher
- A C++17 compatible compiler

## Installation

### Build the module:

```bash
cd examples_python
./build.sh
```

### Use the module (after build):

```bash
export PYTHONPATH="build:$PYTHONPATH"
python3 example_basic.py
```

### Or install system-wide:

```bash
cd build
python3 -m pip install .
```

## Examples

1. **example_basic.py** - Basic encryption/decryption with memory data
2. **example_file.py** - Encrypting and decrypting files
3. **example_keygen.py** - Key generation and management
4. **example_secure_buffer.py** - Using SecureBuffer for zeroizing sensitive data
5. **example_random.py** - Generating random bytes and computing hashes

## API Reference

### KeyGenerator
- `generate_keypair()` - Generate a new hybrid key pair
- `load_keypair(filename)` - Load a key pair from file
- `load_public_key(filename)` - Load a public key from file
- `export_public_key(privfile, pubfile)` - Export public key from private key file
- `save_keypair(keypair, filename)` - Save a key pair to file

### Encryptor
- `encrypt(data)` - Encrypt bytes in memory
- `encrypt_secure(buffer)` - Encrypt SecureBuffer
- `encrypt_file(filename)` - Encrypt a file
- `HEADER_SIZE` - Size of encryption header

### Decryptor
- `decrypt(ciphertext, enc_header)` - Decrypt bytes
- `decrypt_secure(ciphertext, enc_header)` - Decrypt to SecureBuffer
- `decrypt_file(filename, enc_header)` - Decrypt a file

### SecureBuffer
- `SecureBuffer(data)` - Create from bytes
- `SecureBuffer(size)` - Create empty buffer
- `zeroize()` - Securely wipe memory
- `to_bytes()` - Convert to bytes
- `to_string()` - Convert to string

### Helper Functions
- `random_bytes(size)` - Generate cryptographically secure random bytes
- `sha256(data)` - Compute SHA-256 hash
- `sha3_512(data)` - Compute SHA3-512 hash
- `secure_wipe(data, size)` - Securely wipe memory

## License

SPDX-License-Identifier: MIT