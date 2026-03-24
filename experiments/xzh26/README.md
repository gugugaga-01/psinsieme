# XZH26 EC-ElGamal Bloom OPPRF MPSI

EC-ElGamal based multi-party private set intersection using Bloom filters and oblivious programmable pseudo-random functions (OPPRF).

## Dependencies

- Boost (system, thread)
- GMP
- NTL
- libsodium (Ristretto255 elliptic curve operations)
- cryptoTools (shared from `experiments/yyh26/upstream/`)

## Building

```bash
# Ensure yyh26 upstream submodule is initialized (provides cryptoTools)
git submodule update --init experiments/yyh26/upstream

cd experiments/xzh26
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## Running

Run each party in a separate terminal:

```bash
# 3 parties with set size 2^8 = 256
./bin/frontend.exe -n 3 -m 8 -p 0   # party 0 (client)
./bin/frontend.exe -n 3 -m 8 -p 1   # party 1 (client)
./bin/frontend.exe -n 3 -m 8 -p 2   # party 2 (leader)
```

**Flags:**

    -n    number of parties
    -m    log2 of set size
    -p    party ID (0 to n-2 are clients, n-1 is leader)
