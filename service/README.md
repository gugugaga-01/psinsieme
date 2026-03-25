# MPSI Service

gRPC-based multi-party PSI service with mTLS, threshold key distribution, and a Python client SDK. Supports multiple protocols — each `psi_party` process can handle different protocols per-request.

For standalone experiment implementations (plaintext TCP, no gRPC), see `experiments/*/README.md`. For prerequisites and project overview, see the [root README](../README.md).

## Building

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

This produces two binaries under `build/service/`: `psi_party` and `psi_dealer`.

To enable YYH26 TT-MPSI protocol support:

```bash
cmake .. -DMPSI_BUILD_YYH26=ON
make -j$(nproc)
```

To enable BEH21 OT-MPSI protocol support:

```bash
cmake .. -DMPSI_BUILD_BEH21=ON
make -j$(nproc)
```

Prerequisites: gRPC, protobuf, NTL, GMP.

## Supported Protocols

| Protocol | Reference | Crypto Primitives | Dealer | Internal Transport |
|----------|-----------|-------------------|--------|--------------------|
| `ks05_t_mpsi` | Kissner & Song, CRYPTO 2005 | Paillier threshold encryption (3072-bit) | Required (trusted dealer) | gRPC (mTLS optional) |
| `beh21_ot_mpsi` | Bay et al., IEEE TIFS 2021 | Paillier threshold encryption + Bloom filters + SCP | Required (trusted dealer) | gRPC (mTLS optional) |
| `yyh26_tt_mpsi` | Yanai et al., NDSS 2026 | OPPRF + KKRT OT + BFV BOLE + Shamir SS | Not needed | Unencrypted TCP (BtEndpoint)* |

Both protocols operate under the **semi-honest** (honest-but-curious) threat model.

\* YYH26 internal crypto phases use unencrypted TCP via cryptoTools' BtEndpoint. This is inherited from the upstream library — cryptoTools' networking predates gRPC integration and uses its own socket layer. Protocol-level crypto (OT, BFV homomorphic encryption) already protects data confidentiality, so the lack of transport encryption does not leak plaintext inputs. However, traffic metadata is visible. Migrating these channels to gRPC with mTLS is tracked as future work.

## Architecture

Each data owner runs one `psi_party` process. The service supports **per-request protocol selection** — a single `psi_party` backend can handle both KS05 and YYH26 requests without restarting. The client specifies the protocol in each `ComputeIntersection` call.

```
                  ┌─────────────────────────┐
                  │       psi_dealer        │ (optional, KS05 only)
                  │  Paillier key distrib.  │
                  └────────┬────────────────┘
                           │ key shares
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                  ▼
  ┌─────────────┐  ┌─────────────┐   ┌─────────────┐
  │  psi_party  │  │  psi_party  │   │  psi_party  │
  │  Party 0    │  │  Party 1    │   │  Party 2    │
  │  :50090     │  │  :50091     │   │  :50092     │
  └──────┬──────┘  └──────┬──────┘   └──────┬──────┘
         │                │                  │
    Python/gRPC      Python/gRPC        Python/gRPC
     clients          clients            clients
```

## Quick Start

```bash
# KS05: 3-party with dealer (insecure, localhost)
bash service/demos/ks05/demo.sh

# BEH21: 3-party with dealer (requires -DMPSI_BUILD_BEH21=ON)
bash service/demos/beh21/demo.sh

# YYH26: 3-party without dealer
bash service/demos/yyh26/demo.sh
```

## Docker Quick-Start

Pull the pre-built image:

```bash
docker pull gugugaga001/psinsieme:latest
```

### Local 3-party demo (auto-generated TLS certs)

```bash
# Create a Docker network
docker network create psi-net

# Start the dealer (KS05 key distribution)
docker run -d --name dealer --network psi-net \
  gugugaga001/psinsieme \
  psi_dealer --parties 3 --listen 0.0.0.0:53050

# Start 3 parties
for i in 0 1 2; do
  docker run -d --name "party${i}" --network psi-net \
    gugugaga001/psinsieme \
    psi_party --address "party${i}:5300${i}" \
    --addresses "$(echo 0 1 2 | tr ' ' '\n' | grep -v $i | sed "s/\(.*\)/party\1:5300\1/" | paste -sd,)" \
    --dealer dealer:53050 --listen "0.0.0.0:5009${i}"
done
```

Each container auto-generates a self-signed certificate and runs in **TLS mode** (encrypted, no certificate verification). This is suitable for testing but not production.

### Running with your own certificates (mTLS)

Mount your certificate directory to `/app/certs/`:

```bash
docker run -d --name party0 --network psi-net \
  -v /path/to/certs:/app/certs:ro \
  gugugaga001/psinsieme \
  psi_party --address party0:53000 \
  --addresses party1:53001,party2:53002 \
  --dealer dealer:53050 --listen 0.0.0.0:50090
```

When certs are detected at `/app/certs/`, the entrypoint defaults to **mTLS mode** with `--certs-dir /app/certs`. The directory should contain `ca.pem`, `partyN.pem`, and `partyN-key.pem` (see [mTLS](#mtls) for details).

### TLS modes

| Mode | Flag | Description |
|------|------|-------------|
| `insecure` | `--tls-mode insecure` | No encryption (plaintext) |
| `tls` | `--tls-mode tls` | Encrypted channel, no certificate verification (default with auto-generated certs) |
| `mtls` | `--tls-mode mtls` | Full mutual TLS with certificate verification (default with mounted certs) |

Override the default mode with `--tls-mode`:

```bash
docker run -d --name party0 --network psi-net \
  gugugaga001/psinsieme \
  psi_party --address party0:53000 \
  --addresses party1:53001,party2:53002 \
  --tls-mode insecure --listen 0.0.0.0:50090
```

### Cleanup

```bash
docker stop dealer party0 party1 party2
docker rm dealer party0 party1 party2
docker network rm psi-net
```

## Usage

### Step 1: Start party processes

Each data owner runs one `psi_party` process:

- `--address` is this party's own inter-party address.
- `--addresses` lists the OTHER parties' addresses (not including self).
- `--dealer` fetches Paillier keys at startup (required for KS05, optional otherwise).
- Addresses are merged and sorted internally for consistent index assignment.

```bash
# With dealer
./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090

# Without dealer
./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --listen 0.0.0.0:50090
```

Or use a config file:

```ini
# party1.conf
address = 10.0.0.1:53000
addresses = 10.0.0.2:53000,10.0.0.3:53000
dealer = 10.0.0.1:53050
listen = 0.0.0.0:50090
```

```bash
./psi_party --config party1.conf
```

Command-line flags override config file values.

### Step 2: Submit data (Python client)

Each client connects to their party's client-facing port and submits data with a **role** (`leader` or `member`), the **leader's address**, and the **protocol** to use. The role and protocol are chosen per-request — any party can be the leader, and different requests can use different protocols.

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
        protocol="ks05_t_mpsi",  # or "yyh26_tt_mpsi"
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
        protocol="ks05_t_mpsi",
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

## KS05 T-MPSI Protocol

The KS05 protocol (Crypto 2005) uses Paillier threshold encryption for multi-party PSI. It requires a trusted dealer for key distribution.

### Dealer setup

The dealer generates Paillier threshold keys and distributes shares to each party. It only needs to run during startup — once all parties have their keys, the dealer can shut down.

```bash
./psi_dealer --parties 3 --listen 0.0.0.0:53050
```

Each party must include `--dealer` to fetch keys:

```bash
./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090
```

### Protocol details

- **Crypto**: Paillier threshold encryption (3072-bit modulus, 128-bit security)
- **Communication**: All inter-party communication uses gRPC (with optional mTLS)
- **Threat model**: Semi-honest (honest-but-curious) adversaries
- **Key distribution**: Trusted dealer model — the dealer sees all secret key shares

## YYH26 TT-MPSI Protocol

The YYH26 threshold TT-MPSI protocol (NDSS 2026) uses OPPRF, OT extensions (KKRT), and BFV-based BOLE for threshold secret sharing. It does **not** require a dealer.

### Building prerequisites

YYH26 requires upstream C++ libraries (libOTe, cryptoTools, miracl, gazelle). Use the vendor setup script to build and install them:

```bash
bash service/protocols/yyh26/vendor/setup.sh /usr/local
```

Then build the service with YYH26 enabled:

```bash
mkdir -p build && cd build
cmake .. -DMPSI_BUILD_YYH26=ON -DYYH26_DEPS_PREFIX=/usr/local
make -j$(nproc)
```

See [service/protocols/yyh26/vendor/README.md](protocols/yyh26/vendor/README.md) for details on what gets installed and custom prefix paths.

Prerequisites: Boost (system, thread), NTL, GMP, nasm, MPFR.

### Running YYH26

Start parties without `--dealer`:

```bash
./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --listen 0.0.0.0:50090
```

Python client usage specifies `protocol="yyh26_tt_mpsi"`:

```python
with PsiClient("10.0.0.1:50090") as client:
    intersection, status = client.compute_intersection(
        elements=["alice", "bob", "charlie"],
        role="member",
        leader_address="10.0.0.3:53000",
        num_parties=3, threshold=3,
        protocol="yyh26_tt_mpsi",
    )
```

### Protocol details

- **Crypto**: OPPRF + KKRT OT extensions + BFV homomorphic encryption (BOLE)
- **Secret sharing**: Shamir secret sharing over 4 CRT moduli
- **Communication**: gRPC for client API, unencrypted TCP (BtEndpoint) for internal crypto phases
- **Threat model**: Semi-honest (honest-but-curious) adversaries
- **Key distribution**: No dealer needed — keys are generated per-session

### Current limitations

- **Unencrypted TCP**: Internal crypto channels between parties use unencrypted TCP via cryptoTools' BtEndpoint (ports 11000+). Protocol-level crypto (OT, BFV) protects data confidentiality, but traffic is not transport-encrypted. Deploy on trusted networks or use external tunneling.
- **Localhost only**: TCP connections currently use `"localhost"`. Multi-machine deployments require configurable hostnames (tracked as future work).

## mTLS

When TLS is enabled, all gRPC communication (inter-party, dealer, client-facing) uses mutual TLS.

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

Pass `--certs-dir` to both the dealer and party binaries:

```bash
./psi_dealer --parties 3 --listen 0.0.0.0:53050 --certs-dir certs/my_certs

./psi_party --address 10.0.0.1:53000 \
            --addresses 10.0.0.2:53000,10.0.0.3:53000 \
            --dealer 10.0.0.1:53050 --listen 0.0.0.0:50090 \
            --certs-dir certs/my_certs
```

```python
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
| `--dealer` | No | Dealer address (enables KS05; omit for YYH26-only) |
| `--listen` | No | Client-facing listen address (default: `0.0.0.0:50090`) |
| `--protocol` | No | Default protocol (default: `ks05_t_mpsi`); clients can override per-request |
| `--certs-dir` | No | Directory with `ca.pem`, `partyN.pem`, `partyN-key.pem` |
| `--tls-mode` | No | TLS mode: `insecure`, `tls`, or `mtls` (default: `tls` with auto-cert, `mtls` with `--certs-dir`) |
| `--cert` | No | Path to this party's certificate file (overrides `--certs-dir`) |
| `--key` | No | Path to this party's private key file (overrides `--certs-dir`) |
| `--ca` | No | Path to CA certificate file (overrides `--certs-dir`) |
| `--config` | No | Config file (key = value format, CLI flags override) |

### psi_dealer

| Flag | Required | Description |
|------|----------|-------------|
| `--parties` | Yes | Number of parties expected |
| `--listen` | Yes | Listen address (e.g. `0.0.0.0:50051`) |
| `--certs-dir` | No | Directory with `ca.pem`, `dealer.pem`, `dealer-key.pem` |
| `--tls-mode` | No | TLS mode: `insecure`, `tls`, or `mtls` (default: `tls` with auto-cert, `mtls` with `--certs-dir`) |
| `--cert` | No | Path to the dealer's certificate file (overrides `--certs-dir`) |
| `--key` | No | Path to the dealer's private key file (overrides `--certs-dir`) |
| `--ca` | No | Path to CA certificate file (overrides `--certs-dir`) |
| `--config` | No | Config file (key = value format, CLI flags override) |

### Python client (`compute_intersection`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `elements` | (required) | Input set (list of strings) |
| `role` | `"member"` | This party's role: `"leader"` or `"member"` |
| `leader_address` | `""` | Inter-party address of the leader (required) |
| `num_parties` | 3 | Number of participating parties |
| `threshold` | 3 | Elements in >= threshold parties appear in result |
| `protocol` | `"ks05_t_mpsi"` | Protocol identifier (`ks05_t_mpsi`, `beh21_ot_mpsi`, or `yyh26_tt_mpsi`) |
| `timeout` | None | RPC timeout in seconds |

## Tests

```bash
cd build
ctest --output-on-failure --test-dir service
```

For mTLS tests, generate certificates first:

```bash
bash service/certs/gen_certs.sh 3 service/certs/test
cd build && ctest --output-on-failure --test-dir service
```

## Security Notes

- **Semi-honest model**: Both KS05 and YYH26 protocols assume honest-but-curious adversaries. Parties follow the protocol correctly but may try to learn extra information.
- **Trusted dealer (KS05 only)**: Key generation uses a trusted dealer — the dealer sees all secret key shares. It wipes secrets after distribution but must be trusted not to retain them.
- **CN verification**: When mTLS is enabled, the dealer and inter-party servers verify the peer's certificate CN matches the claimed party identity.
- **Key size**: Paillier modulus is 3072-bit (128-bit security per NIST SP 800-57).
- **Unencrypted TCP (YYH26)**: Internal crypto channels use unencrypted TCP. See [YYH26 Current limitations](#current-limitations) above.
