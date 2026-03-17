#!/bin/bash
# Build YYH26 upstream dependencies from source and install to a prefix.
#
# This script builds the C++ libraries that the YYH26 protocol links against:
#   - cryptoTools (upstream version, Bt* networking)
#   - libOTe (oblivious transfer extensions)
#   - miracl (big-number / ECC library)
#   - libOLE (oblivious linear evaluation via Gazelle)
#   - libOLE's vendored cryptoTools (newer version, async networking)
#
# Headers are already vendored in this directory; this script only builds
# the .a/.so libraries.
#
# Usage:
#   bash setup.sh [PREFIX]
#
# Default PREFIX is /usr/local. Libraries are installed to PREFIX/lib/.
# After running, configure CMake with:
#   cmake .. -DMPSI_BUILD_YYH26=ON -DCMAKE_PREFIX_PATH=PREFIX
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
make -j"$(nproc)"
cd "$YYH26_ROOT"

# Step 2: Build libOLE
echo ""
echo "--- Building libOLE (gazelle) ---"
cd "$YYH26_ROOT/libOLE"
make -j"$(nproc)" 2>/dev/null || {
    echo "WARNING: libOLE make failed. Trying with Makefile.src..."
    make -f Makefile.src -j"$(nproc)" 2>/dev/null || true
}

# Step 3: Install libraries to prefix
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

# gazelle needs special handling (shared library)
if [ -f "$YYH26_ROOT/libOLE/bin/lib/libgazelle.so" ]; then
    cp "$YYH26_ROOT/libOLE/bin/lib/libgazelle.so" "$PREFIX/lib/"
    echo "  Installed: libgazelle.so"
fi

# libOLE's cryptoTools (different version)
if [ -f "$YYH26_ROOT/libOLE/third_party/cryptoTools/lib/libcryptoTools.a" ]; then
    cp "$YYH26_ROOT/libOLE/third_party/cryptoTools/lib/libcryptoTools.a" "$PREFIX/lib/libcryptoTools_ole.a"
    echo "  Installed: libcryptoTools_ole.a (libOLE version)"
fi

echo ""
echo "=== Done ==="
echo ""
echo "To build the service with YYH26 support:"
echo "  mkdir -p build && cd build"
echo "  cmake .. -DMPSI_BUILD_YYH26=ON -DCMAKE_PREFIX_PATH=$PREFIX"
echo "  make -j\$(nproc)"
