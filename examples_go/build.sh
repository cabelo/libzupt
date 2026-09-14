#!/bin/bash
# Build script for libzupt Go examples (cgo)
# Builds libzupt (if needed) and then compiles the Go examples

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build"

echo "=== libzupt Go Examples Build Script ==="
echo ""

# Check for Go toolchain
if ! command -v go &> /dev/null; then
    echo "ERROR: go not found."
    echo "  Install Go 1.21+ from: https://go.dev/dl/"
    exit 1
fi

# Build libzupt shared library if needed
if [ ! -f "$BUILD_DIR/libzupt.so" ]; then
    echo "Building libzupt (shared library)..."
    cd "$PROJECT_DIR"
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_PYTHON=OFF >/dev/null 2>&1
    make -j"$(nproc)" >/dev/null 2>&1
    cd "$SCRIPT_DIR"
    echo "  libzupt built successfully."
    echo ""
else
    echo "libzupt shared library already built."
    echo ""
fi

# Build the Go examples
echo "Building Go examples (cgo)..."
cd "$SCRIPT_DIR"
export CGO_ENABLED=1
export LD_LIBRARY_PATH="$BUILD_DIR:${LD_LIBRARY_PATH:-}"
go build -o zupt_example .

echo ""
echo "Build successful!"
echo ""
echo "To run an example:"
echo "  LD_LIBRARY_PATH=../build ./zupt_example <basic|file|keygen|random|secure_buffer>"
echo ""
echo "Or run all examples at once (default):"
echo "  LD_LIBRARY_PATH=../build ./zupt_example"
echo ""