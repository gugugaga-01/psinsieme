# Threshold-MPSI Implementation (BEH21)

Research implementation of threshold multi-party private set intersection (T-MPSI) with Bloom filter optimizations.

## Prerequisites

See the [root README](../../README.md#prerequisites) for the full dependency list (Core + Experiments).

## Building

### From the repository root (recommended)

```bash
mkdir -p build && cd build
cmake .. -DBUILD_EXPERIMENTS=ON -DBUILD_BEH21=ON
make -j$(nproc)
```

Binary: `build/experiments/beh21/beh21_ot_mpsi`

### Standalone from experiments/

```bash
cd experiments
mkdir -p build && cd build
cmake .. -DBUILD_BEH21=ON -DBUILD_KS05=OFF
make -j$(nproc)
```

Binary: `build/beh21/beh21_ot_mpsi`

## Running

### Parameters

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

### Example: 3 parties, threshold 2

Start the leader **first** (it acts as the server):

**Terminal 1 — Leader (Party 2)**:
```bash
./beh21_ot_mpsi -partyID 2 -numParties 3 -threshold 2 -senderSize 1000 -receiverSize 1000 -debug
```

**Terminal 2 — Member 0**:
```bash
./beh21_ot_mpsi -partyID 0 -numParties 3 -threshold 2 -senderSize 1000 -receiverSize 1000 -debug
```

**Terminal 3 — Member 1**:
```bash
./beh21_ot_mpsi -partyID 1 -numParties 3 -threshold 2 -senderSize 1000 -receiverSize 1000 -debug
```

The leader prints the intersection size, average time, and communication costs.

## Benchmarking

Scripts are in `experiments/tools/` (shared across protocols):

```bash
# Single benchmark
python3 ../tools/run_benchmark.py --protocol beh21 \
  --numParties 4 --threshold 3 --senderSize 10 --receiverSize 10

# Grid benchmarks (multiple set sizes)
python3 ../tools/run_multiple_benchmarks.py --protocol beh21 \
  --numParties 5 --threshold 3 --sizes 4 6 8
```

---

**Disclaimer**: Research code for experimental purposes.
