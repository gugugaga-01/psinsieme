#!/bin/bash
#
# Build upstream dependencies for yyh26_ndss_tt-mpsi.
#
# This script:
#   1. Initialises the git submodules (upstream, libOLE)
#   2. Patches upstream cryptoTools for modern Boost (>= 1.70) / GCC 13+
#   3. Builds miracl, cryptoTools, libOTe  -> upstream/lib/
#   4. Patches and builds libOLE (namespace rename, stdexcept, -fPIC)
#
# Prerequisites (install first):
#   sudo apt-get install build-essential cmake nasm \
#       libboost-system-dev libboost-thread-dev \
#       libgmp-dev libgmpxx4ldbl libmpfr-dev \
#       libbenchmark-dev
#   Also install NTL: https://libntl.org/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Initialise submodules ==="
git submodule update --init --recursive

echo ""
echo "=== Step 2: Patch upstream for modern compilers ==="

# Patch 1: boost::asio::strand became a class template in Boost 1.70.
# Replace with boost::asio::io_service::strand which works across all versions.
SOCKET_H="upstream/cryptoTools/Network/BtSocket.h"
if grep -q 'boost::asio::strand mSendStrand' "$SOCKET_H"; then
    sed -i 's/boost::asio::strand mSendStrand/boost::asio::io_service::strand mSendStrand/' "$SOCKET_H"
    echo "  Patched $SOCKET_H (Boost strand)"
else
    echo "  $SOCKET_H already patched"
fi

# Patch 2: std::random_shuffle was removed in GCC 13+ / C++17.
# These calls shuffle begin-to-begin (no-op), so comment them out.
AKN_FILE="upstream/libOTe/NChooseK/AknOtReceiver.cpp"
if grep -q 'std::random_shuffle' "$AKN_FILE"; then
    sed -i 's/std::random_shuffle/\/\/std::random_shuffle/' "$AKN_FILE"
    echo "  Patched $AKN_FILE (random_shuffle)"
else
    echo "  $AKN_FILE already patched"
fi

echo ""
echo "=== Step 3: Build miracl ==="
(
    cd upstream/thirdparty/linux/miracl/miracl/source
    if [ ! -f libmiracl.a ]; then
        bash linux64
        echo "  miracl built"
    else
        echo "  miracl already built"
    fi
)

echo ""
echo "=== Step 4: Build upstream (cryptoTools + libOTe) ==="
(
    cd upstream
    cmake . -DCMAKE_BUILD_TYPE=Release \
        -DBoost_USE_STATIC_RUNTIME=OFF \
        -DBoost_NO_BOOST_CMAKE=ON
    # Only build the two libraries we need (not upstream's own libOPRF/frontend)
    make cryptoTools libOTe -j"$(nproc)"
    echo "  upstream built -> upstream/lib/"
)

echo ""
echo "=== Step 5: Patch and build libOLE ==="

# Patch 3: Rename osuCrypto -> osuCryptoNew in libOLE's cryptoTools and source.
# This avoids namespace collisions with the OPPRF cryptoTools (upstream).
if grep -q 'namespace osuCrypto$' libOLE/third_party/cryptoTools/cryptoTools/Common/Timer.h 2>/dev/null; then
    echo "  Renaming osuCrypto -> osuCryptoNew in libOLE..."
    find libOLE/third_party/cryptoTools/cryptoTools/ libOLE/src/lib/ libOLE/src/demo/ \
        -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.c" \) \
        -exec grep -l "osuCrypto" {} \; | \
        xargs sed -i 's/osuCrypto/osuCryptoNew/g'
    echo "  Namespace rename done"
else
    echo "  Namespace already renamed"
fi

# Patch 4: Add missing #include <stdexcept> to libOLE's Timer.h (GCC 13+).
TIMER_H="libOLE/third_party/cryptoTools/cryptoTools/Common/Timer.h"
if ! grep -q '<stdexcept>' "$TIMER_H" 2>/dev/null; then
    sed -i '/<string>/a #include <stdexcept>' "$TIMER_H"
    echo "  Patched $TIMER_H (stdexcept)"
else
    echo "  $TIMER_H already patched"
fi

# Patch 5: Fix #include paths in libOLE source files to use relative paths
# to libOLE's own cryptoTools (not the OPPRF one via include path).
for f in libOLE/src/lib/pke/gazelle-network.h libOLE/src/lib/pke/ole.h \
         libOLE/src/lib/math/distributiongenerator.h libOLE/src/lib/math/distributiongenerator.cpp; do
    if grep -q '#include <cryptoTools/' "$f" 2>/dev/null; then
        sed -i 's|#include <cryptoTools/\(.*\)>|#include "../../../third_party/cryptoTools/cryptoTools/\1"|' "$f"
        echo "  Patched $f (include paths)"
    fi
done

# Patch 6: Qualify Channel& as osuCryptoNew::Channel& in libOLE headers
# to avoid ambiguity with osuCrypto::Channel from OPPRF.
for f in libOLE/src/lib/pke/gazelle-network.h libOLE/src/lib/pke/ole.h; do
    if grep -q 'Channel& chl' "$f" 2>/dev/null && ! grep -q 'osuCryptoNew::Channel& chl' "$f" 2>/dev/null; then
        sed -i 's/\bChannel& chl/osuCryptoNew::Channel\& chl/g' "$f"
        echo "  Patched $f (qualified Channel)"
    fi
done

# Patch 7: Symlink upstream miracl for libOLE's linker.
MIRACL_TARGET="libOLE/third_party/cryptoTools/thirdparty/linux/miracl/miracl/source"
if [ ! -f "$MIRACL_TARGET/libmiracl.a" ]; then
    mkdir -p "$MIRACL_TARGET"
    ln -sf "$(pwd)/upstream/thirdparty/linux/miracl/miracl/source/libmiracl.a" \
        "$MIRACL_TARGET/libmiracl.a"
    echo "  Symlinked miracl for libOLE"
fi

# Build libOLE's cryptoTools with -fPIC and renamed namespace.
(
    cd libOLE/third_party/cryptoTools
    cmake . -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    make cryptoTools -j"$(nproc)"
    echo "  libOLE cryptoTools built"
)

# Build libgazelle.
(
    cd libOLE
    make -j"$(nproc)" || true  # demo binaries may fail to link; library is ok
    if [ -f bin/lib/libgazelle.so ]; then
        echo "  libgazelle built -> libOLE/bin/lib/"
    else
        echo "  ERROR: libgazelle.so not found"
        exit 1
    fi
)

echo ""
echo "=== Done ==="
echo "Now build the project:"
echo "  mkdir -p build && cd build"
echo "  cmake .. -DCMAKE_BUILD_TYPE=Release"
echo "  make -j\$(nproc)"
