# YYH26 Vendored Dependencies

This directory contains vendored headers and source for the YYH26 TT-MPSI protocol's dependencies. The goal is to decouple the service build from the `experiments/` directory.

## Structure

```
vendor/
├── libOPRF/          # Full source (our code) — built as static library
│   ├── OPPRF/        # Oblivious programmable PRF implementation
│   └── Hashing/      # Cuckoo/simple hashing for OPPRF
├── cryptoTools/      # Headers only (upstream version, Bt* networking)
│   ├── Common/       # Core types, BitVector, Timer
│   ├── Crypto/       # AES, PRNG, SHA1, ECC
│   └── Network/      # BtEndpoint, BtIOService, Channel
├── libOTe/           # Headers only (oblivious transfer extensions)
│   ├── NChooseOne/   # KKRT N-choose-1 OT
│   ├── TwoChooseOne/ # Base 2-choose-1 OT
│   ├── Base/         # Naor-Pinkas base OT
│   └── Tools/        # Linear codes, utilities
├── miracl/           # Headers only (big-number / ECC library)
│   └── include/
├── libOLE/           # Headers only (oblivious linear evaluation)
│   ├── src/lib/      # PKE (Gazelle/BFV), math, bigint
│   └── third_party/  # libOLE's own cryptoTools (newer version)
├── setup.sh          # Builds pre-built libraries from experiments/
└── README.md         # This file
```

## Origins

| Component | Origin | Notes |
|-----------|--------|-------|
| libOPRF | `experiments/yyh26/libOPRF/` | Our code, vendored in full |
| cryptoTools | `experiments/yyh26/upstream/cryptoTools/` | Older version with Bt* networking (c++14) |
| libOTe | `experiments/yyh26/upstream/libOTe/` | KKRT OT extensions |
| miracl | `experiments/yyh26/upstream/thirdparty/linux/miracl/` | Big-number crypto library |
| libOLE | `experiments/yyh26/libOLE/` | Gazelle homomorphic encryption |
| libOLE cryptoTools | `experiments/yyh26/libOLE/third_party/cryptoTools/` | Newer version with async I/O (c++17) |

## Pre-built Libraries

The vendored headers are sufficient for compilation, but linking requires pre-built static/shared libraries:

- `liblibOPRF.a` — Built from vendored source by CMake
- `liblibOTe.a` — Pre-built, found via `find_library`
- `libcryptoTools.a` — Pre-built (upstream version)
- `libmiracl.a` — Pre-built
- `libgazelle.so` — Pre-built (shared library)
- `libcryptoTools_ole.a` — Pre-built (libOLE version, renamed to avoid collision)

### Building pre-built libraries

Run the setup script to build from the experiments source tree:

```bash
bash service/protocols/yyh26/vendor/setup.sh [PREFIX]
```

Default prefix is `/usr/local`. Then configure CMake:

```bash
cmake .. -DMPSI_BUILD_YYH26=ON -DCMAKE_PREFIX_PATH=PREFIX
```

## Updating

To update vendored headers from experiments:

```bash
# From repo root
cp -r experiments/yyh26/libOPRF/{OPPRF,Hashing,yyh26_compat.h} service/protocols/yyh26/vendor/libOPRF/
# ... (similar for other trees)
```

## Note on dual cryptoTools versions

The project links against TWO different versions of cryptoTools simultaneously:
- **Upstream** (used by libOPRF, libOTe): Older, Bt* socket networking
- **libOLE** (used by Gazelle): Newer, async I/O, TLS support

These are intentionally separate and must remain so. The upstream version's `libcryptoTools.a` and libOLE's `libcryptoTools_ole.a` (renamed) are both linked into the final binary.
