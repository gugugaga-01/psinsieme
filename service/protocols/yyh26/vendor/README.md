# YYH26 Vendored Dependencies

This directory contains the vendored source for libOPRF (our code) and a setup
script that builds and installs the upstream dependencies.

## Structure

```
vendor/
├── libOPRF/          # Full source (our code) — built as static library by CMake
│   ├── OPPRF/        # Oblivious programmable PRF implementation
│   └── Hashing/      # Cuckoo/simple hashing for OPPRF
├── setup.sh          # Builds upstream deps from experiments/ and installs to a prefix
└── README.md         # This file
```

## Building upstream dependencies

The YYH26 protocol depends on several upstream C++ libraries. The `setup.sh`
script builds them from the `experiments/yyh26/` source tree and installs
headers + libraries to a prefix:

```bash
bash service/protocols/yyh26/vendor/setup.sh [PREFIX]
```

Default prefix is `/usr/local`. This installs:
- **Libraries** to `PREFIX/lib/`: liblibOTe.a, libcryptoTools.a, libmiracl.a, libgazelle.so, libcryptoTools_ole.a
- **Headers** to `PREFIX/include/yyh26/`: cryptoTools, libOTe, miracl, libOLE

Then build the service:

```bash
cmake .. -DMPSI_BUILD_YYH26=ON -DYYH26_DEPS_PREFIX=PREFIX
make -j$(nproc)
```

## Prerequisites

- CMake >= 3.16, make, g++, clang++
- Boost (system, thread): `sudo apt install libboost-system-dev libboost-thread-dev`
- NTL, GMP: `sudo apt install libntl-dev libgmp-dev`
- OpenSSL: `sudo apt install libssl-dev`

## Note on dual cryptoTools versions

The project links against two different versions of cryptoTools:
- **Upstream** (used by libOPRF, libOTe): Older, Bt* socket networking
- **libOLE** (used by Gazelle): Newer, async I/O, TLS support

These are installed separately (`libcryptoTools.a` and `libcryptoTools_ole.a`).
