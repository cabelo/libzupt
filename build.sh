#!/bin/bash
# Build script for libzupt

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=== libzupt Build Script ==="
echo ""

# Check for CMake
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake is required but not installed."
    exit 1
fi


# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with CMake
echo "Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DLIBZUPT_BUILD_TESTS=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local

# Build
echo "Building..."
make -j$(nproc)

# Run tests
echo ""
echo "Running tests..."
make test

echo ""
echo "Build successful!"
echo ""
echo "To install, run:"
echo "  sudo make install"
