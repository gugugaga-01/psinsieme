# TT-MPSI (YYH26 NDSS)

Threshold-Transparent Multi-Party Private Set Intersection.

## Project Structure

This experiment contains only our code (libOPRF + frontend). Upstream
dependencies are referenced as git submodules:

- `upstream/` — [osu-crypto/MultipartyPSI](https://github.com/osu-crypto/MultipartyPSI) (branch: implement) — provides cryptoTools, libOTe, and thirdparty/miracl
- `libOLE/` — [leodec/ole_wahc](https://github.com/leodec/ole_wahc) — provides gazelle and cryptoTools for OLE

Our code:
- `libOPRF/` — OPPRF implementation (the paper's core contribution)
- `frontend/` — Main executable and protocol driver
- `tools/` — Benchmark scripts

## Required Libraries

- Boost (system, thread)
- GMP + MPFR
- NTL
- CMake, nasm, build-essential

## Building

```bash
# 1. Clone with submodules
git clone --recurse-submodules <repo-url>
cd experiments/yyh26_ndss_tt-mpsi

# 2. Install system dependencies
sudo apt-get install build-essential cmake nasm libgmp-dev libgmpxx4ldbl libmpfr-dev libbenchmark-dev

# 3. Install Boost, GMP, NTL (see below)

# 4. Build upstream dependencies
cd upstream
# Build miracl
cd thirdparty/linux/miracl/miracl/source && bash linux64 && cd -
cd thirdparty/linux/miracl/miracl_osmt/source && bash linux64_cpp && cd -
# Build upstream
cmake . && make
cd ..

# 5. Build libOLE
cd libOLE && make && cd ..

# 6. Build this project
cmake . -DCMAKE_BUILD_TYPE=Release
make
```

## Running

```bash
# Example: 5 parties, threshold 2, set size 2^5
./bin/frontend.exe -n 5 -t 2 -m 5 -p 0 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 1 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 2 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 3 &
./bin/frontend.exe -n 5 -t 2 -m 5 -p 4 &

# Or use the benchmark script
bash ./tools/run_benchmark.sh
```

**Flags:**
```
-n    number of parties
-m    set size (log2)
-p    party ID
-t    threshold
```
