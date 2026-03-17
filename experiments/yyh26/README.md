# TT-MPSI (YYH26 NDSS)

Threshold-Transparent Multi-Party Private Set Intersection.

## Overview

This experiment implements the YYH26 TT-MPSI protocol using OPPRF, KKRT OT extensions, and BFV-based BOLE. It communicates over plaintext TCP via cryptoTools' BtEndpoint.

## Project Structure

This experiment contains only our code (libOPRF + frontend). Upstream dependencies are referenced as git submodules:

- `upstream/` — [osu-crypto/MultipartyPSI](https://github.com/osu-crypto/MultipartyPSI) (branch: implement) — provides cryptoTools, libOTe, and thirdparty/miracl
- `libOLE/` — [leodec/ole_wahc](https://github.com/leodec/ole_wahc) — provides gazelle and cryptoTools for OLE

Our code:
- `libOPRF/` — OPPRF implementation (the paper's core contribution)
- `frontend/` — Main executable and protocol driver
- `tools/` — Benchmark scripts

## Prerequisites

See the [root README](../../README.md#prerequisites) for the full dependency list (Core + YYH26).

## Building

### Using setup.sh (recommended)

The `setup.sh` script handles initialising submodules, patching upstream sources for modern compilers (Boost >= 1.70, GCC 13+), and building all dependencies:

```bash
cd experiments/yyh26
bash setup.sh
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Binary: `build/bin/frontend.exe`

### Manual build (fallback)

If `setup.sh` doesn't work in your environment, the individual steps are:

```bash
cd experiments/yyh26

# 1. Initialise submodules
git submodule update --init --recursive

# 2. Build miracl
cd upstream/thirdparty/linux/miracl/miracl/source && bash linux64 && cd -

# 3. Build upstream (cryptoTools + libOTe)
cd upstream && cmake . -DCMAKE_BUILD_TYPE=Release && make cryptoTools libOTe -j$(nproc) && cd ..

# 4. Build libOLE (see setup.sh for required patches)
cd libOLE && make -j$(nproc) && cd ..

# 5. Build this project
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Note: The manual path requires several source patches for modern compilers. See `setup.sh` for the exact patches applied.

## Running

### Parameters

| Flag | Description | Default |
|------|-------------|---------|
| `-n` | Number of parties | **Required** |
| `-t` | Threshold | **Required** |
| `-m` | Set size (log2) | **Required** |
| `-p` | Party ID (0 to n-1) | **Required** |

### Example: 5 parties, threshold 2, set size 2^5

```bash
./bin/frontend.exe -n 5 -t 2 -m 5 -p 0 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 1 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 2 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 3 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 4 &
```

## Benchmarking

```bash
bash ./tools/run_benchmark.sh
```

---

**Disclaimer**: Research code for experimental purposes.
