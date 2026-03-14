# YYH26 TT-MPSI (T-Threshold Multi-Party Private Set Intersection)

Reference implementation of the TT-MPSI protocol (NDSS 2026).

## Optimizations over original

- **2 CRT moduli** instead of 4 — elements must fit in 24 bits (`< 2^24`)
- **64-bit packed shares** (low32 = mod0, high32 = mod1)
- **2 BOLE calls per pair** instead of 4
- Modular source structure

## Build

Requires system packages: `libntl-dev`, `libgmp-dev`, `libboost-all-dev`, `libmpfr-dev`, `libbenchmark-dev`.

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Run

```bash
# 3-party, threshold=2, 32 elements per party
./bin/yyh26_v2.exe -n 3 -t 2 -m 32 -p 0 &
./bin/yyh26_v2.exe -n 3 -t 2 -m 32 -p 1 &
./bin/yyh26_v2.exe -n 3 -t 2 -m 32 -p 2
```

## Structure

```
src/            # Protocol implementation
  config.h      # Constants (CRT moduli, ports, BFV params)
  types.h       # Type aliases and conversions
  shamir.h/cpp  # Shamir secret sharing
  crt.h/cpp     # CRT pack/unpack utilities
  channels.h/cpp # Network channel management (OPPRF + OLE)
  bole_wrapper.h # BOLE sender/receiver wrappers
  reconstruction.h/cpp # Lagrange interpolation + reconstruction
  protocol.h/cpp # Main TT-MPSI protocol (4 phases)
  main.cpp      # CLI entry point
libOPRF/        # OPPRF library (from osu-crypto)
deps/           # Pre-built headers and libraries
  include/      # Headers for cryptoTools, libOTe, gazelle, miracl
  lib/          # Pre-built static/shared libraries
```
