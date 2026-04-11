#!/bin/bash
# Demo script for libzupt

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=========================================="
echo "  libzupt - Hybrid Post-Quantum Demo"
echo "=========================================="
echo ""

# Check if build exists
if [ ! -f "$BUILD_DIR/zupt_example_basic" ]; then
    echo "Building library and examples..."
    cd "$SCRIPT_DIR"
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    echo ""
fi

echo "Running basic example..."
echo "----------------------------------------"
"$BUILD_DIR/zupt_example_basic"
echo ""

echo "=========================================="
echo "  Generating keys for file demo..."
echo "=========================================="
echo ""

# Generate keys
"$BUILD_DIR/zupt_example_file" genkey /tmp/demo_private.key /tmp/demo_public.key

echo ""
echo "=========================================="
echo "  Creating test file..."
echo "=========================================="
echo ""
cat > /tmp/demo_input.txt << 'EOF'
This is a secret message for the libzupt demo.
Line 2: More confidential data.
Line 3: End of message.
EOF

echo "Input file content:"
cat /tmp/demo_input.txt
echo ""

echo "=========================================="
echo "  Encrypting file..."
echo "=========================================="
echo ""
"$BUILD_DIR/zupt_example_file" encrypt /tmp/demo_public.key /tmp/demo_input.txt /tmp/demo_output.zupt

echo ""
echo "Encrypted file size: $(wc -c < /tmp/demo_output.zupt) bytes"
echo "Encrypted file (first 64 bytes, hex):"
xxd -l 64 /tmp/demo_output.zupt
echo ""

echo "=========================================="
echo "  Decrypting file..."
echo "=========================================="
echo ""
"$BUILD_DIR/zupt_example_file" decrypt /tmp/demo_private.key /tmp/demo_output.zupt /tmp/demo_output_decrypted.txt /tmp/demo_output.zupt.header

echo ""
echo "Decrypted file content:"
cat /tmp/demo_output_decrypted.txt
echo ""

echo "=========================================="
echo "  Verifying decryption..."
echo "=========================================="
echo ""
if diff -q /tmp/demo_input.txt /tmp/demo_output_decrypted.txt > /dev/null; then
    echo "SUCCESS: Decrypted file matches original!"
else
    echo "ERROR: Files do not match!"
    exit 1
fi
echo ""

echo "=========================================="
echo "  Cleanup..."
echo "=========================================="
rm -f /tmp/demo_*.key /tmp/demo_*.txt /tmp/demo_*.zupt*

echo ""
echo "Demo completed successfully!"
echo ""
echo "For more examples, see:"
echo "  $SCRIPT_DIR/examples/"