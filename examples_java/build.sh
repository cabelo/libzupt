#!/bin/bash
# Build script for Java JNI bindings

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
LIB_DIR="$(cd .. && pwd)"

echo "=== libzupt Java JNI Build Script ==="
echo ""

# Get Java home
if [ -z "$JAVA_HOME" ]; then
    JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac))))
fi

echo "Java Home: $JAVA_HOME"
echo ""

# Check for C++ compiler
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ not found"
    exit 1
fi

# Check for cmake
if ! command -v cmake &> /dev/null; then
    echo "Error: cmake not found"
    exit 1
fi

# Build libzupt if needed
if [ ! -f "$SCRIPT_DIR/../build/libzupt.a" ] && [ ! -f "$SCRIPT_DIR/../build/libzupt.so" ]; then
    echo "Building libzupt first..."
    #cd "$SCRIPT_DIR/../.."
    cd "$SCRIPT_DIR/.."
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_EXAMPLES=OFF -DLIBZUPT_BUILD_PYTHON=OFF 
    make -j$(nproc) >/dev/null 2>&1
    cd "$SCRIPT_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Compile JNI library using CMake
echo "Compiling JNI library with CMake..."
cd "$BUILD_DIR"


echo $BUILD_DIR
echo $SCRIPT_DIR
echo $LIB_DIR
# Check if CMakeLists.txt exists and is up to date
if [ ! -f CMakeLists.txt ] || [ "$SCRIPT_DIR/CMakeLists.txt" -nt CMakeLists.txt ]; then
    cmake "$SCRIPT_DIR"  -DLIBZUPT_ROOT="$LIB_DIR" 
fi

make -j$(nproc) >/dev/null 2>&1

# Copy to current directory
cp zupt.so "$SCRIPT_DIR/" 2>/dev/null || true

echo ""
echo "Build successful!"
echo ""
echo "To run examples:"
echo "  export LD_LIBRARY_PATH=\"$BUILD_DIR:\$LD_LIBRARY_PATH\""
echo "  cd $SCRIPT_DIR"
echo "  javac -d classes src/com/libzupt/*.java"
echo "  java -cp classes com.libzupt.ExampleBasic"
echo "  java -cp classes com.libzupt.ExampleKeygen"
echo "  java -cp classes com.libzupt.ExampleFile"
echo "  java -cp classes com.libzupt.ExampleRandom"
echo "  java -cp classes com.libzupt.ExampleSecureBuffer"

echo ""
