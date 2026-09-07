#!/bin/bash
# Build script for libzupt Rust examples
# Builds libzupt (if needed) and then compiles all Rust examples

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build"

echo "=== libzupt Rust Examples Build Script ==="
echo ""

# Build libzupt shared library if needed
if [ ! -f "$BUILD_DIR/libzupt.so" ] && [ ! -f "$BUILD_DIR/libzupt.so.1.0.6" ]; then
    echo "Building libzupt (shared library)..."
    cd "$PROJECT_DIR"
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_PYTHON=OFF >/dev/null 2>&1
    make zupt_shared -j$(nproc) >/dev/null 2>&1
    cd "$SCRIPT_DIR"
    echo "  libzupt built successfully."
    echo ""
else
    echo "libzupt shared library already built."
    echo ""
fi

# Check for Rust toolchain
if ! command -v cargo &> /dev/null; then
    echo "ERROR: cargo not found. Please install Rust toolchain."
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "Building Rust examples..."
cd "$SCRIPT_DIR"
cargo build --release 2>&1

echo ""
echo "Build successful!"
echo ""
echo "To run examples:"
echo "  cargo run --release --example example_basic"
echo "  cargo run --release --example example_file"
echo "  cargo run --release --example example_keygen"
echo "  cargo run --release --example example_random"
echo "  cargo run --release --example example_secure_buffer"
echo ""
echo "Or run all at once:"
echo "  for ex in example_basic example_file example_keygen example_random example_secure_buffer; do"
echo "    cargo run --release --example \$ex"
echo "    echo"
echo "  done"
echo ""
