#!/bin/bash
# Build script for libzupt .NET examples
# Builds libzupt (if needed) and then compiles/runs the C# examples

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build"

echo "=== libzupt .NET Examples Build Script ==="
echo ""

# Check for dotnet SDK
if ! command -v dotnet &> /dev/null; then
    echo "ERROR: dotnet not found."
    echo "  Install .NET SDK 8.0+ from: https://dotnet.microsoft.com/download"
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

# Build the .NET project
echo "Building .NET project..."
cd "$SCRIPT_DIR"
export LD_LIBRARY_PATH="$BUILD_DIR:$LD_LIBRARY_PATH"
dotnet build -c Release ZuptExample.csproj

# Copy the shared library next to the build output so DllImport can resolve it
OUT_DIR="$SCRIPT_DIR/bin/Release/net8.0"
mkdir -p "$OUT_DIR"
cp -P "$BUILD_DIR"/libzupt.so* "$OUT_DIR"/ 2>/dev/null || true

echo ""
echo "Build successful!"
echo ""
echo "To run an example:"
echo "  dotnet run --project ZuptExample.csproj -- <basic|file|keygen|random|secure_buffer>"
echo ""
echo "Or run all examples at once (default):"
echo "  dotnet run --project ZuptExample.csproj"
echo ""