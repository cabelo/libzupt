#!/bin/bash
# Build script for Python examples with pybind11 - direct compilation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=== libzupt Python Bindings Build Script ==="
echo ""

# Check for pybind11
if ! python3 -c "import pybind11" 2>/dev/null; then
    echo "Installing pybind11..."
    pip install pybind11
fi

# Get paths
PYBIND11_INCLUDE=$(python3 -c "import pybind11; print(pybind11.get_include())")
# Use python3.11 explicitly for compilation
PYTHON_INCLUDE=$(python3.11-config --includes 2>/dev/null || python3 -c "import sysconfig; print(sysconfig.get_path('include'))")
ZUPT_INCLUDE="$SCRIPT_DIR/../include"
ZUPT_CXX_INCLUDE="$SCRIPT_DIR/../src"
ZUPT_LIB_DIR="$SCRIPT_DIR/../build"
# Use absolute path for library directory
ZUPT_LIB_DIR_ABS="$(cd "$ZUPT_LIB_DIR" && pwd)"
ZUPT_CORE_INCLUDE="$SCRIPT_DIR/../../zupt/include"

# Build libzupt if needed using CMake
if [ ! -f "$ZUPT_LIB_DIR/libzupt.a" ]; then
    echo "Building libzupt first using CMake..."
    cd "$SCRIPT_DIR/.."
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_TESTS=OFF -DLIBZUPT_BUILD_PYTHON=OFF >/dev/null 2>&1
    make zupt_static -j$(nproc) >/dev/null 2>&1
    cd "$SCRIPT_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

echo "Compiling Python extension..."
echo "  PYBIND11 include: $PYBIND11_INCLUDE"
echo "  ZUPT lib dir: $ZUPT_LIB_DIR"

# Compile pybind11 module
echo "  Compiling zupt_pybind.cpp..."
g++ -c zupt_pybind.cpp -o "$BUILD_DIR/zupt_pybind.o" \
    -std=c++17 -O2 -Wall -fPIC \
    -I"$PYBIND11_INCLUDE" \
    -I"$PYTHON_INCLUDE" \
    -I"$ZUPT_INCLUDE" \
    -I"$ZUPT_CXX_INCLUDE" \
    -I"$ZUPT_CORE_INCLUDE" \
    $(python3.11-config --cflags 2>/dev/null || echo "")

# Link into shared library
echo "  Linking shared library..."
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")
g++ -shared -o "$BUILD_DIR/zupt.cpython-${PYTHON_VERSION}-x86_64-linux-gnu.so" \
    "$BUILD_DIR/zupt_pybind.o" \
    -L"$ZUPT_LIB_DIR_ABS" \
    -lzupt \
    -Wl,-rpath,"$ZUPT_LIB_DIR_ABS"

# Copy to current directory for convenience
cp "$BUILD_DIR"/zupt*.so . 2>/dev/null || true

echo ""
echo "Build successful!"
echo ""
echo "To use the module:"
echo "  export PYTHONPATH=\"$BUILD_DIR:\$PYTHONPATH\""
echo "  python3 $SCRIPT_DIR/example_basic.py"
echo ""
echo "Or to install:"
echo "  cd $BUILD_DIR"
echo "  python3 -m pip install ."
echo ""
