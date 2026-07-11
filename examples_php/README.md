# libzupt — PHP FFI Examples

This directory contains PHP examples equivalent to those in `examples_python`, using the `libzupt` C ABI directly through the PHP FFI extension.

## Requirements

* Linux or macOS;
* PHP 8.1 or later;
* the `FFI` extension enabled;
* a compiled or installed `libzupt.so`/`libzupt.dylib`;
* C ABI symbols defined in `include/zupt_cxx.h`.

Check your environment:

```bash
php -v
php -m | grep -i '^FFI$'
```

## Building libzupt

From the project root directory:

```bash
mkdir -p build
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

The wrapper searches for the library in the following order:

1. the path passed to the `ZuptFFI` constructor;
2. the `LIBZUPT_PATH` environment variable;
3. `build/libzupt.so` in the project root directory;
4. common system paths and library names available through the dynamic loader.

To explicitly specify the library file:

```bash
export LIBZUPT_PATH="$PWD/build/libzupt.so"
```

If the library was installed in a non-standard directory, you may also need to set:

```bash
export LD_LIBRARY_PATH="$(dirname "$LIBZUPT_PATH"):${LD_LIBRARY_PATH:-}"
```

## Running the Examples

```bash
cd examples_php
php -d ffi.enable=1 example_basic.php
php -d ffi.enable=1 example_file.php
php -d ffi.enable=1 example_keygen.php
php -d ffi.enable=1 example_random.php
php -d ffi.enable=1 example_secure_buffer.php
```

Or run all examples at once:

```bash
./run_all.sh
```

## Examples

* `example_basic.php`: key generation and in-memory encryption/decryption;
* `example_file.php`: file encryption and restoration;
* `example_keygen.php`: save, load, and export keys;
* `example_random.php`: random bytes, SHA-256, and SHA3-512;
* `example_secure_buffer.php`: zeroizable native buffer designed to reduce the lifetime of sensitive data in memory;
* `Zupt.php`: reusable FFI wrapper.

## Minimal Usage

```php
<?php
require_once __DIR__ . '/Zupt.php';

$zupt = new ZuptFFI();
$keys = $zupt->generateKeyPair();

$encrypted = $zupt->encrypt($keys['publicKey'], 'secret message');
$plaintext = $zupt->decrypt(
    $keys['secretKey'],
    $encrypted['ciphertext'],
    $encrypted['encHeader']
);

echo $plaintext, PHP_EOL;
```

## Data Format and Sizes

The values below follow the current C ABI implementation:

* hybrid public key: `1224` bytes;
* hybrid private key: `3656` bytes;
* encryption header: `1137` bytes;
* composition: ML-KEM-768 + X25519.

The ciphertext and encryption header contain binary data. Do not use text-processing functions that may alter their bytes or encoding.

## `ZuptSecureBuffer` Security Considerations

`ZuptSecureBuffer` allocates native memory and overwrites it with zeros when `zeroize()` is called or when the object is destroyed. This reduces the lifetime of the contents stored in that specific buffer.

PHP may retain temporary copies in strings, logs, exceptions, or internal data structures. Therefore, this example does not provide an absolute guarantee that every trace of the information will be removed from the process memory.

## Windows Note

The current ABI returns buffers allocated with `malloc()` and does not provide a public `zupt_free()` function. To avoid freeing memory through an incompatible C runtime, these examples prevent execution on Windows.

A recommended ABI improvement is to export:

```c
void zupt_free(void *ptr);
```

This would allow PHP, Node.js, and other languages to safely return allocated buffers to the same library in a portable manner.

## License

SPDX-License-Identifier: MIT
