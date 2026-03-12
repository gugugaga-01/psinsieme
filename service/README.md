# MPSI Service

gRPC-based multi-party PSI service with mTLS, threshold key distribution, and a Python client SDK.

## Building

```bash
mkdir -p build && cd build
cmake ../service
make -j$(nproc)
```

This produces two binaries: `psi_party` and `psi_dealer`.

Prerequisites: gRPC, protobuf, NTL, GMP.

## Quick Start

```bash
# Run a 3-party demo (insecure, localhost)
bash service/demos/ks05_t_mpsi/demo.sh

# 5-party with mTLS
bash service/demos/ks05_t_mpsi/demo.sh --parties 5 --tls

# Threshold mode (elements in >= 2 of 3 parties)
bash service/demos/ks05_t_mpsi/demo.sh --parties 3 --threshold 2
```

## Usage

### Step 1: Start the dealer

The dealer generates Paillier threshold keys and distributes shares to each party.
It only needs to run during startup — once all parties have their keys, the dealer can shut down.

```bash
./psi_dealer --parties 3 --listen 0.0.0.0:53050
```

### Step 2: Start party processes

Each data owner runs one `psi_party` process. No roles are assigned at startup — the party is generic.

- `--address` is this party's own inter-party address.
- `--addresses` lists the OTHER parties' addresses (not including self).
- Addresses are merged and sorted internally for consistent index assignment.

```bash
# On machine 10.0.0.1
./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090

# On machine 10.0.0.2
./psi_party --address 10.0.0.2:53000 \
            --addresses 10.0.0.1:53000,10.0.0.3:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090

# On machine 10.0.0.3
./psi_party --address 10.0.0.3:53000 \
            --addresses 10.0.0.1:53000,10.0.0.2:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090
```

Or use a config file instead of command-line flags:

```ini
# party1.conf
address = 10.0.0.1:53000
addresses = 10.0.0.2:53000,10.0.0.3:53000
dealer = 10.0.0.1:53050
listen = 0.0.0.0:50090
protocol = ks05_t_mpsi
```

```bash
./psi_party --config party1.conf
```

Command-line flags override config file values, so you can use a shared config and override per-party:

```bash
./psi_party --config base.conf --address 10.0.0.2:53000
```

The party topology is fixed at startup. To change who participates, restart all parties with new addresses and a new dealer.

### Step 3: Submit data (Python client)

Each client connects to their party's client-facing port and submits data with a **role** (`leader` or `member`) and the **leader's address**. The role is chosen per-request, not at startup — any party can be the leader.

```bash
pip install grpcio grpcio-tools
```

```python
from mpsi_client import PsiClient

# Leader client — receives the intersection result
with PsiClient("10.0.0.3:50090") as client:
    intersection, status = client.compute_intersection(
        elements=["alice", "bob", "charlie", "dave"],
        role="leader",
        leader_address="10.0.0.3:53000",
        num_parties=3,
        threshold=3,
    )
    print(intersection)

# Member client — learns nothing
with PsiClient("10.0.0.1:50090") as client:
    intersection, status = client.compute_intersection(
        elements=["alice", "bob", "eve"],
        role="member",
        leader_address="10.0.0.3:53000",
        num_parties=3,
        threshold=3,
    )
```

All parties must submit concurrently. Only the leader gets the intersection; members get an empty list.

You can also read elements from a file (one per line):

```python
with PsiClient("10.0.0.1:50090") as client:
    intersection, status = client.compute_intersection_from_file(
        "data.txt",
        role="member",
        leader_address="10.0.0.3:53000",
        num_parties=3, threshold=3,
    )
```

## mTLS

When TLS is enabled, all communication (inter-party, dealer, client-facing) uses mutual TLS.

### Generating certificates

The included `gen_certs.sh` script creates a self-signed CA and per-party/dealer certificates:

```bash
bash service/certs/gen_certs.sh 3 certs/my_certs
```

This generates the following files in `certs/my_certs/`:

```
ca.pem / ca-key.pem            # Certificate Authority
party0.pem / party0-key.pem    # Party 0 (CN=party0)
party1.pem / party1-key.pem    # Party 1 (CN=party1)
party2.pem / party2-key.pem    # Party 2 (CN=party2)
dealer.pem / dealer-key.pem    # Dealer  (CN=dealer)
```

Each certificate includes SANs for `localhost` and `127.0.0.1`, so they work out of the box on a single machine. For multi-machine deployments, edit the script to add the appropriate hostnames or IPs.

Certificate CN must match the party's index from sorted address order: `party0`, `party1`, etc. The dealer CN must be `dealer`.

### Starting services with TLS

Pass `--certs-dir` to both the dealer and party binaries. Each process loads `ca.pem` for verification, and its own cert/key pair based on its identity:

```bash
# Dealer with TLS
./psi_dealer --parties 3 --listen 0.0.0.0:53050 --certs-dir certs/my_certs

# Party with TLS
./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090 \
            --certs-dir certs/my_certs
```

```python
# Python client with mTLS
with PsiClient("10.0.0.1:50090", tls=True,
               ca_cert="ca.pem",
               client_cert="party0.pem",
               client_key="party0-key.pem") as client:
    intersection, status = client.compute_intersection(
        elements=["alice", "bob", "charlie"],
        role="member",
        leader_address="10.0.0.3:53000",
        num_parties=3, threshold=3,
    )
```

## Parameter Reference

### psi_party

| Flag | Required | Description |
|------|----------|-------------|
| `--address` | Yes | This party's own inter-party address |
| `--addresses` | Yes | Other parties' addresses (comma-separated) |
| `--dealer` | Yes | Dealer address for key distribution |
| `--listen` | No | Client-facing listen address (default: `0.0.0.0:50090`) |
| `--protocol` | No | Protocol to run (default: `ks05_t_mpsi`) |
| `--certs-dir` | No | Directory with `ca.pem`, `partyN.pem`, `partyN-key.pem` |
| `--config` | No | Config file (key = value format, CLI flags override) |

### psi_dealer

| Flag | Required | Description |
|------|----------|-------------|
| `--parties` | Yes | Number of parties expected |
| `--listen` | Yes | Listen address (e.g. `0.0.0.0:50051`) |
| `--certs-dir` | No | Directory with `ca.pem`, `dealer.pem`, `dealer-key.pem` |
| `--config` | No | Config file (key = value format, CLI flags override) |

### Python client (`compute_intersection`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `elements` | (required) | Input set (list of strings) |
| `role` | `"member"` | This party's role: `"leader"` or `"member"` |
| `leader_address` | `""` | Inter-party address of the leader (required) |
| `num_parties` | 3 | Number of participating parties |
| `threshold` | 3 | Elements in >= threshold parties appear in result |
| `protocol` | `"ks05_t_mpsi"` | Protocol identifier |
| `timeout` | None | RPC timeout in seconds |

## Tests

```bash
cd build
ctest --output-on-failure
```

For mTLS tests, generate certificates first:

```bash
bash service/certs/gen_certs.sh 3 service/certs/test
cd build && ctest --output-on-failure
```

## Security Notes

- **Semi-honest model**: The KS05 protocol assumes honest-but-curious adversaries. Parties follow the protocol correctly but may try to learn extra information.
- **Trusted dealer**: Key generation uses a trusted dealer — the dealer sees all secret key shares. It wipes secrets after distribution but must be trusted not to retain them.
- **CN verification**: When mTLS is enabled, the dealer and inter-party servers verify the peer's certificate CN matches the claimed party identity.
- **Key size**: Paillier modulus is 3072-bit (128-bit security per NIST SP 800-57).
