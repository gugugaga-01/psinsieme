# Threshold-MPSI Implementation (beh21)

## Overview

This is a research implementation of threshold multi-party private set intersection (T-MPSI) with Bloom filter optimizations.

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
- Make

### 2. Build the Project

```bash
# Clean previous builds
make clean

# Build the executable
make

# Binary will be at: bin/t_mpsi
```

**Note**: Adjust `Makefile` if needed for your system's library paths.

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
  -senderSize 1000 -receiverSize 1000 -debug
```

**Terminal 2 - Member 0**:
```bash
./bin/t_mpsi -partyID 0 -numParties 3 -threshold 2 \
  -senderSize 1000 -receiverSize 1000 -debug
```

**Terminal 3 - Member 1**:
```bash
./bin/t_mpsi -partyID 1 -numParties 3 -threshold 2 \
  -senderSize 1000 -receiverSize 1000 -debug
```

The leader will print:
- Intersection size found
- Average time (if multiple runs)
- Communication costs (sent/received MB)

## Automated Benchmarking

Two Python scripts are provided for automated benchmarking:

### `tools/run_benchmark.py`

Runs a single benchmark configuration by automatically spawning all parties as subprocesses.

**Usage**:
```bash
python3 tools/run_benchmark.py \
  --numParties 4 \
  --threshold 3 \
  --senderSize 10 \
  --receiverSize 10 \
  --numRuns 5 \
  --debug
```

**Parameters**:
- `--binPath`: Path to binary (default: `bin/t_mpsi`)
- `--numParties`: Number of parties
- `--threshold`: Threshold value (default: ⌈n/2⌉)
- `--senderSize`: Exponent for sender size (set size = 2^senderSize)
- `--receiverSize`: Exponent for receiver size (set size = 2^receiverSize)
- `--numRuns`: Number of runs for averaging
- `--debug`: Enable debug output

**Example**: `--senderSize 12` means each sender has 2^12 = 4096 elements.

The script:
- Cleans up old key files
- Starts all parties concurrently
- Waits for completion
- Reports expected intersection size if debug enabled

### `tools/run_multiple_benchmarks.py`

Runs a grid of benchmark configurations for comprehensive performance evaluation.

**Usage**:
```bash
python3 tools/run_multiple_benchmarks.py
```

**Configuration** (edit the script to customize):
```python
numParties_list  = [4, 6, 8, 10]      # Test different party counts
threshold_list   = [2, 3, 4, 5]       # Corresponding thresholds (one-to-one)
size_list        = [10, 12, 14]       # Set sizes (as exponents: 2^10, 2^12, 2^14)
numRuns          = 10                 # Runs per configuration
```

The script:
- Tests all combinations of parameters
- Saves results to `tools/benchmark_result/` directory
- Each result file contains:
  - Command executed
  - Standard output (timing, communication stats)
  - Standard error (any errors/warnings)

**Output Files**: Named as `parties{n}_thr{t}_sender{s}_receiver{r}_runs{k}`

**Use Case**: Ideal for generating performance comparison data across different configurations for research papers.

---

**Disclaimer**: This is research code for experimental purposes. Not production-ready.
