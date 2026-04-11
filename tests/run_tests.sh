#!/bin/bash
# Run all libzupt tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

echo "=========================================="
echo "  libzupt Test Suite"
echo "=========================================="
echo ""

# Check if build exists
if [ ! -f "$BUILD_DIR/zupt_test_keygen" ]; then
    echo "Building library and tests..."
    cd "$SCRIPT_DIR/.."
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Debug
    make -j$(nproc)
    echo ""
fi

# Run tests
echo "Running key generation tests..."
echo "----------------------------------------"
"$BUILD_DIR/zupt_test_keygen"
echo ""

echo "Running encryption tests..."
echo "----------------------------------------"
"$BUILD_DIR/zupt_test_encrypt"
echo ""

echo "Running decryption tests..."
echo "----------------------------------------"
"$BUILD_DIR/zupt_test_decrypt"
echo ""

echo "Running roundtrip tests..."
echo "----------------------------------------"
"$BUILD_DIR/zupt_test_roundtrip"
echo ""

echo "Running file operations tests..."
echo "----------------------------------------"
"$BUILD_DIR/zupt_test_file_ops"
echo ""

echo "=========================================="
echo "  All Tests Passed!"
echo "=========================================="