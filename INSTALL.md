# Installing libzupt

## Requirements

- CMake 3.10 or higher
- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- System libraries: `libm`

## Method 1: Manual Compilation

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

## Method 2: Using the Build Script

```bash
cd libzupt
chmod +x build.sh
./build.sh
```

## Method 3: Installation via vcpkg

```bash
vcpkg install libzupt:x64-linux
# or
vcpkg install libzupt:x64-windows
```

## Installation

After construction, you? You can install the library:

```bash
sudo make install
```

Does this install?:

- Libraries: `/usr/local/lib/libzupt.so` (or `.dylib` on macOS)
- Headers: `/usr/local/include/zupt.hpp`

- pkg-config files: `/usr/local/lib/pkgconfig/libzupt.pc`

## Usage in CMake

Add to your `CMakeLists.txt`:

```cmake
find_package(libzupt REQUIRED)

add_executable(my_program main.cpp)
target_link_libraries(my_program zupt::zupt_shared)

```

## Usage in GCC/Clang

```bash
g++ -std=c++17 my_program.cpp -o my_program \
-I/usr/local/include\
-L/usr/local/lib -lzupt
```

## Installation Verification

Compile and run the basic example:

```bash
cd libzupt/build
./zupt_example_basic
```

You? duty? see output like:

```
libzupt - Hybrid Post-Quantum Encryption Example
Library version: 1.0.0

Step 1: Generating hybrid key pair (ML-KEM-768 + X25519)...
Public key size: 1224 bytes
Secret key size: 2504 bytes
Public key (first 16 bytes): [8a 3b ...]

Step 2: Encrypting data in memory...
Plaintext: Hello, Post-Quantum World! This is a secret message.
Ciphertext size: 224 bytes
Encryption header size: 1137 bytes

Step 3: Decrypting data in memory...
Decrypted: Hello, Post-Quantum World! This is a secret message.

Step 4: Verifying decryption...
SUCCESS: Decrypted text matches original!

All examples completed successfully!
```
