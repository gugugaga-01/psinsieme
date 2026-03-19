#!/bin/bash
# Build YYH26 upstream dependencies from source and install to a prefix.
#
# This script builds the C++ libraries that the YYH26 protocol links against
# and installs both libraries and headers to a prefix directory.
#
# Usage:
#   bash setup.sh [PREFIX]
#
# Default PREFIX is /usr/local.
# After running, configure CMake with:
#   cmake .. -DMPSI_BUILD_YYH26=ON -DYYH26_DEPS_PREFIX=PREFIX
#
# Prerequisites:
#   - CMake >= 3.16, make, g++, clang++
#   - Boost (system, thread): sudo apt install libboost-system-dev libboost-thread-dev
#   - NTL, GMP: sudo apt install libntl-dev libgmp-dev
#   - OpenSSL (for libOLE cryptoTools): sudo apt install libssl-dev

set -e

PREFIX="${1:-/usr/local}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
YYH26_ROOT="$REPO_ROOT/experiments/yyh26"

if [ ! -d "$YYH26_ROOT" ]; then
    echo "ERROR: experiments/yyh26 not found at $YYH26_ROOT"
    echo "This script builds from the experiments source tree."
    exit 1
fi

echo "=== Building YYH26 upstream dependencies ==="
echo "Source: $YYH26_ROOT"
echo "Prefix: $PREFIX"
echo ""

# Step 1: Build upstream (cryptoTools + libOTe + miracl + libOPRF)
echo "--- Building upstream stack (cryptoTools, libOTe, libOPRF) ---"
cd "$YYH26_ROOT"
if [ -f setup.sh ]; then
    bash setup.sh
fi
mkdir -p build && cd build
cmake "$YYH26_ROOT" -DCMAKE_BUILD_TYPE=Release
# Only build the libOPRF library target (not frontend, which has GCC 11+ compat issues)
make libOPRF -j"$(nproc)"
cd "$YYH26_ROOT"

# Step 2: Build libOLE
echo ""
echo "--- Building libOLE (gazelle) ---"
cd "$YYH26_ROOT/libOLE"
make -j"$(nproc)" 2>/dev/null || {
    echo "WARNING: libOLE make failed. Trying with Makefile.src..."
    make -f Makefile.src -j"$(nproc)" 2>/dev/null || true
}

# Step 3: Install libraries
echo ""
echo "--- Installing libraries to $PREFIX/lib ---"
mkdir -p "$PREFIX/lib"

install_lib() {
    local src="$1"
    local name="$(basename "$1")"
    if [ -f "$src" ]; then
        cp "$src" "$PREFIX/lib/$name"
        echo "  Installed: $name"
    else
        echo "  WARNING: $src not found"
    fi
}

install_lib "$YYH26_ROOT/lib/liblibOPRF.a"
install_lib "$YYH26_ROOT/upstream/lib/liblibOTe.a"
install_lib "$YYH26_ROOT/upstream/lib/libcryptoTools.a"
install_lib "$YYH26_ROOT/upstream/thirdparty/linux/miracl/miracl/source/libmiracl.a"

if [ -f "$YYH26_ROOT/libOLE/bin/lib/libgazelle.so" ]; then
    cp "$YYH26_ROOT/libOLE/bin/lib/libgazelle.so" "$PREFIX/lib/"
    echo "  Installed: libgazelle.so"
fi

if [ -f "$YYH26_ROOT/libOLE/third_party/cryptoTools/lib/libcryptoTools.a" ]; then
    cp "$YYH26_ROOT/libOLE/third_party/cryptoTools/lib/libcryptoTools.a" "$PREFIX/lib/libcryptoTools_ole.a"
    echo "  Installed: libcryptoTools_ole.a (libOLE version)"
fi

# Step 4: Install headers
echo ""
echo "--- Installing headers to $PREFIX/include/yyh26 ---"
INCLUDE_DIR="$PREFIX/include/yyh26"
mkdir -p "$INCLUDE_DIR"

# Upstream cryptoTools headers (Bt* networking version)
if [ -d "$YYH26_ROOT/upstream/cryptoTools" ]; then
    mkdir -p "$INCLUDE_DIR/cryptoTools"
    cp -r "$YYH26_ROOT/upstream/cryptoTools/Common" "$INCLUDE_DIR/cryptoTools/" 2>/dev/null
    cp -r "$YYH26_ROOT/upstream/cryptoTools/Crypto" "$INCLUDE_DIR/cryptoTools/" 2>/dev/null
    cp -r "$YYH26_ROOT/upstream/cryptoTools/Network" "$INCLUDE_DIR/cryptoTools/" 2>/dev/null
    echo "  Installed: cryptoTools headers"
fi

# libOTe headers
if [ -d "$YYH26_ROOT/upstream/libOTe" ]; then
    mkdir -p "$INCLUDE_DIR/libOTe"
    cp -r "$YYH26_ROOT/upstream/libOTe/NChooseOne" "$INCLUDE_DIR/libOTe/" 2>/dev/null
    cp -r "$YYH26_ROOT/upstream/libOTe/TwoChooseOne" "$INCLUDE_DIR/libOTe/" 2>/dev/null
    cp -r "$YYH26_ROOT/upstream/libOTe/Base" "$INCLUDE_DIR/libOTe/" 2>/dev/null
    cp -r "$YYH26_ROOT/upstream/libOTe/Tools" "$INCLUDE_DIR/libOTe/" 2>/dev/null
    echo "  Installed: libOTe headers"
fi

# MIRACL headers
if [ -d "$YYH26_ROOT/upstream/thirdparty/linux/miracl/miracl/include" ]; then
    mkdir -p "$INCLUDE_DIR/miracl/include"
    cp "$YYH26_ROOT/upstream/thirdparty/linux/miracl/miracl/include/"*.h "$INCLUDE_DIR/miracl/include/" 2>/dev/null
    echo "  Installed: miracl headers"
fi

# libOLE headers
if [ -d "$YYH26_ROOT/libOLE/src/lib" ]; then
    mkdir -p "$INCLUDE_DIR/libOLE/src/lib"
    cp -r "$YYH26_ROOT/libOLE/src/lib/pke" "$INCLUDE_DIR/libOLE/src/lib/" 2>/dev/null
    cp -r "$YYH26_ROOT/libOLE/src/lib/math" "$INCLUDE_DIR/libOLE/src/lib/" 2>/dev/null
    cp -r "$YYH26_ROOT/libOLE/src/lib/bigint" "$INCLUDE_DIR/libOLE/src/lib/" 2>/dev/null
    cp -r "$YYH26_ROOT/libOLE/src/lib/utils" "$INCLUDE_DIR/libOLE/src/lib/" 2>/dev/null
    echo "  Installed: libOLE headers"
fi

# libOLE's vendored cryptoTools (newer version)
if [ -d "$YYH26_ROOT/libOLE/third_party/cryptoTools/cryptoTools" ]; then
    mkdir -p "$INCLUDE_DIR/libOLE/third_party/cryptoTools"
    cp -r "$YYH26_ROOT/libOLE/third_party/cryptoTools/cryptoTools" "$INCLUDE_DIR/libOLE/third_party/cryptoTools/" 2>/dev/null
    echo "  Installed: libOLE cryptoTools headers"
fi

echo ""
echo "=== Done ==="
echo ""
echo "To build the service with YYH26 support:"
echo "  mkdir -p build && cd build"
echo "  cmake .. -DMPSI_BUILD_YYH26=ON -DYYH26_DEPS_PREFIX=$PREFIX"
echo "  make -j\$(nproc)"
