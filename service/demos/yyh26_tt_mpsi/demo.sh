#!/bin/bash
# Demo: run YYH26 TT-MPSI protocol via the gRPC service framework.
#
# Prerequisites:
#   1. Build the service with YYH26 support:
#      cd build && cmake ../service -DMPSI_BUILD_YYH26=ON && make -j$(nproc)
#   2. Build the experiments binary:
#      cd experiments/yyh26_ndss_tt-mpsi && mkdir -p build && cd build
#      cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
#   3. Set MPSI_YYH26_BINARY_PATH to the experiments binary path, or ensure
#      it's findable at ../experiments/yyh26_ndss_tt-mpsi/bin/frontend.exe
#
# Usage: bash demo.sh [--parties N] [--threshold T]
#
# NOTE: YYH26 does not use a dealer. Internal crypto channels use unencrypted
# TCP via BtEndpoint (ports 11000+). Deploy on trusted networks only.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"

NUM_PARTIES=3
THRESHOLD=3

while [[ $# -gt 0 ]]; do
    case $1 in
        --parties) NUM_PARTIES="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ! -f "$BUILD_DIR/psi_party" ]]; then
    echo "Build the project first:"
    echo "  cd build && cmake ../service -DMPSI_BUILD_YYH26=ON && make -j\$(nproc)"
    exit 1
fi

# Check for experiments binary
YYH26_BIN="${MPSI_YYH26_BINARY_PATH:-$REPO_ROOT/experiments/yyh26_ndss_tt-mpsi/bin/frontend.exe}"
if [[ ! -f "$YYH26_BIN" ]]; then
    echo "YYH26 experiments binary not found at: $YYH26_BIN"
    echo "Build it first:"
    echo "  cd experiments/yyh26_ndss_tt-mpsi && mkdir -p build && cd build"
    echo "  cmake .. -DCMAKE_BUILD_TYPE=Release && make -j\$(nproc)"
    exit 1
fi
export MPSI_YYH26_BINARY_PATH="$YYH26_BIN"
export MPSI_YYH26_LIB_PATH="$REPO_ROOT/experiments/yyh26_ndss_tt-mpsi/libOLE/bin/lib"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
}
trap cleanup EXIT

# Build address list (no dealer needed for yyh26)
PARTY_BASE_PORT=53000
CLIENT_BASE_PORT=50090

ADDRESSES=""
for i in $(seq 0 $((NUM_PARTIES - 1))); do
    [[ -n "$ADDRESSES" ]] && ADDRESSES+=","
    ADDRESSES+="localhost:$((PARTY_BASE_PORT + i))"
done

# Start parties (no dealer for yyh26)
for i in $(seq 0 $((NUM_PARTIES - 1))); do
    MY_ADDR="localhost:$((PARTY_BASE_PORT + i))"
    OTHER_ADDRS=$(echo "$ADDRESSES" | sed "s/${MY_ADDR}//;s/,,/,/;s/^,//;s/,$//" )
    CLIENT_PORT=$((CLIENT_BASE_PORT + i))

    echo "=== Starting party $i (inter=$MY_ADDR, client=0.0.0.0:$CLIENT_PORT) ==="
    "$BUILD_DIR/psi_party" \
        --address "$MY_ADDR" \
        --addresses "$OTHER_ADDRS" \
        --listen "0.0.0.0:${CLIENT_PORT}" \
        --protocol yyh26_tt_mpsi &
    PIDS+=($!)
done

echo "=== Waiting for parties to start... ==="
sleep 2

# Run Python clients
LEADER_IDX=$((NUM_PARTIES - 1))
LEADER_ADDR="localhost:$((PARTY_BASE_PORT + LEADER_IDX))"

echo "=== Submitting data via Python clients ==="
echo "  Leader: party $LEADER_IDX ($LEADER_ADDR)"
echo "  Protocol: yyh26_tt_mpsi"
echo "  Parties: $NUM_PARTIES, Threshold: $THRESHOLD"

cd "$REPO_ROOT"
python3 -c "
import sys
sys.path.insert(0, 'service/clients/python')
from mpsi_client import PsiClient
import threading

results = {}

def run_client(party_idx, role):
    port = ${CLIENT_BASE_PORT} + party_idx
    # Each party has a slightly different set; alice and bob are common
    if party_idx == 0:
        elements = ['alice', 'bob', 'charlie']
    elif party_idx == 1:
        elements = ['alice', 'bob', 'dave']
    else:
        elements = ['alice', 'bob', 'eve']

    with PsiClient('localhost:{}'.format(port)) as client:
        intersection, status = client.compute_intersection(
            elements=elements,
            role=role,
            leader_address='${LEADER_ADDR}',
            num_parties=${NUM_PARTIES},
            threshold=${THRESHOLD},
            protocol='yyh26_tt_mpsi',
        )
        results[party_idx] = (intersection, status)

threads = []
for i in range(${NUM_PARTIES}):
    role = 'leader' if i == ${LEADER_IDX} else 'member'
    t = threading.Thread(target=run_client, args=(i, role))
    threads.append(t)
    t.start()

for t in threads:
    t.join(timeout=120)

leader_result = results.get(${LEADER_IDX})
if leader_result:
    intersection, status = leader_result
    print(f'Status: {status}')
    print(f'Intersection ({len(intersection)} elements): {intersection}')
else:
    print('ERROR: No result from leader')
"

echo "=== Demo complete ==="
