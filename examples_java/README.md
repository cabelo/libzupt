# libzupt - Java JNI Examples

This directory contains Java examples using JNI bindings for the libzupt library.

## Prerequisites

- Java 11 or higher
- C++ compiler (g++ with C++17 support)
- libzupt built with static library


## Manual Build

```bash
mkdir build
cd build

cmake .. -DLIBZUPT_ROOT=../../

export LD_LIBRARY_PATH=/dados/fontes/libzupt/examples_java/build
javac -d classes ../src/com/libzupt/*.java

java -cp classes com.libzupt.ExampleBasic
java -cp classes com.libzupt.ExampleKeygen
java -cp classes com.libzupt.ExampleFile
java -cp classes com.libzupt.ExampleRandom
java -cp classes com.libzupt.ExampleSecureBuffer
```

## Easy Build

```bash
cd examples_java
./build.sh
```

The build script will:
1. Build libzupt if needed
2. Compile the JNI shared library
3. Place `libzupt.so` in the current directory

## Running Examples

```bash
# Set library path
export LD_LIBRARY_PATH=".:$LD_LIBRARY_PATH"

# Compile Java classes
javac -cp . com/libzupt/*.java com/libzupt/ExampleBasic.java

# Run example
java -cp . -Djava.library.path=. com.libzupt.ExampleBasic
```

## Examples

1. **ExampleBasic.java** - Basic encryption/decryption
2. **ExampleKeygen.java** - Key generation and management
3. **ExampleFile.java** - File encryption/decryption
4. **ExampleSecureBuffer.java** - SecureBuffer usage
5. **ExampleRandom.java** - Random bytes and hashing

## API

### KeyGenerator
- `generateKeyPair()` - Generate a new key pair
- `loadKeyPair(filename)` - Load a key pair from file
- `loadPublicKey(filename)` - Load public key from file
- `exportPublicKey(privFile, pubFile)` - Export public key
- `saveKeyPair(keyPair, filename)` - Save key pair to file

### Encryptor
- `encryptMemory(data)` - Encrypt data in memory
- `encryptMemorySecure(buffer)` - Encrypt SecureBuffer
- `encryptFile(filename)` - Encrypt a file

### Decryptor
- `decryptMemory(ciphertext, header)` - Decrypt in memory
- `decryptMemorySecure(ciphertext, header)` - Decrypt to SecureBuffer
- `decryptFile(filename, header)` - Decrypt a file

### NativeLib
- `randomBytes(size)` - Generate random bytes
- `sha256(data)` - Compute SHA-256 hash
- `sha3512(data)` - Compute SHA3-512 hash

### SecureBuffer
- `SecureBuffer(size)` - Create buffer of size
- `SecureBuffer(data)` - Create from byte array
- `size()` - Get buffer size
- `toBytes()` - Get buffer content
- `toString()` - Get string representation
- `zeroize()` - Securely wipe buffer
- `close()` - Auto-wipe buffer

## License

MIT
