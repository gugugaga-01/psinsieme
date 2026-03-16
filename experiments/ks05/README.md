# T-MPSI Implementation (KS05)

## Overview

This is a research implementation of threshold multi-party private set intersection (T-MPSI) using the Kissner-Song polynomial framework.

**Research Purpose**: For experimental and benchmarking purposes only.

## Getting Started

### 1. Install Dependencies

Required libraries:
- **cryptoTools** - Cryptographic primitives
- **coproto** - C++20 coroutine protocol framework
- **boost** - System and ASIO libraries
- **NTL** - Number Theory Library
- **GMP** - GNU Multiple Precision library
- **libvolePSI** - (headers only, for type definitions)
- **libOTe** - (headers only, for type definitions)

Build tools:
- C++20 compatible compiler (GCC 10+ or Clang 15+)
- CMake 3.16+

### 2. Build the Project

```bash
# From the experiments/ directory
mkdir -p build && cd build
cmake .. -DBUILD_KS05=ON -DBUILD_BEH21=OFF
make -j$(nproc)

# Binary will be at: build/ks05/ks05_t_mpsi
```

### 3. Run the Protocol

#### Command-Line Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-partyID` | Party identifier (0 to n-1, n-1 is leader) | **Required** |
| `-numParties` | Total number of parties | **Required** |
| `-threshold` | Minimum parties needed for intersection (1 < t < n) | **Required** |
| `-senderSize` | Member's input set size | 100 |
| `-receiverSize` | Leader's input set size | 100 |
| `-sharedSize` | Number of shared elements | auto (half of set size) |
| `-commonSeed` | Seed for generating shared elements | 0xDEADBEEFCAFEBABE |
| `-numRuns` | Number of benchmark runs | 1 |
| `-debug` | Enable debug logging | false |

#### Separate Terminal Usage

**Example: 3 parties with threshold 2**

Start the leader **first** (it acts as the server):

**Terminal 1 - Leader (Party 2)**:
```bash
./bin/t_mpsi -partyID 2 -numParties 3 -threshold 2 \
  -senderSize 8 -receiverSize 8 -debug
```

**Terminal 2 - Member 0**:
```bash
./bin/t_mpsi -partyID 0 -numParties 3 -threshold 2 \
  -senderSize 8 -receiverSize 8 -debug
```

**Terminal 3 - Member 1**:
```bash
./bin/t_mpsi -partyID 1 -numParties 3 -threshold 2 \
  -senderSize 8 -receiverSize 8 -debug
```

**Note**: When running the binary directly, use **actual set sizes** (e.g., 8, 100, 1024). For larger sets, use values like 1024 (2^10), 4096 (2^12), etc.

The leader will print:
- Intersection size found
- Average time (if multiple runs)
- Communication costs (sent/received MB)

## Automated Benchmarking

Two Python scripts are provided for automated benchmarking:

Benchmark scripts are in `experiments/tools/` (shared across protocols):

```bash
# Single benchmark
python3 ../tools/run_benchmark.py --protocol ks05 \
  --numParties 4 --threshold 3 --senderSize 10 --receiverSize 10

# Grid benchmarks
python3 ../tools/run_multiple_benchmarks.py --protocol ks05 \
  --numParties 5 --threshold 3 --sizes 4 6 8
```

---

**Disclaimer**: This is research code for experimental purposes.
