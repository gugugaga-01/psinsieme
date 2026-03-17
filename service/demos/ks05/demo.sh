#!/bin/bash
# ============================================================================
# KS05 Threshold-MPSI Protocol Demo
# ============================================================================
# Demonstrates threshold multi-party private set intersection using the
# KS05 protocol with a trusted dealer for key distribution.
#
# Usage: ./demo.sh [--parties N] [--threshold T] [--tls]
#   --parties N     Number of parties (default: 3)
#   --threshold T   Intersection threshold (default: N, i.e. full intersection)
#                   Elements appearing in >= T parties are in the result.
#   --tls           Enable mTLS for inter-party communication
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_ROOT="$SCRIPT_DIR/../.."
PROJECT_ROOT="$SERVICE_ROOT/.."
BUILD_DIR="$PROJECT_ROOT/build"
PSI_PARTY="$BUILD_DIR/service/psi_party"
PSI_DEALER="$BUILD_DIR/service/psi_dealer"
PYTHON_CLIENT="$SERVICE_ROOT/clients/python"

NUM_PARTIES=3
THRESHOLD=""
USE_TLS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --parties) NUM_PARTIES="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --tls) USE_TLS="yes"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Default threshold = num_parties (full intersection)
if [ -z "$THRESHOLD" ]; then
    THRESHOLD="$NUM_PARTIES"
fi

if [ "$NUM_PARTIES" -lt 2 ]; then
    echo "ERROR: Need at least 2 parties"
    exit 1
fi

if [ "$THRESHOLD" -lt 2 ] || [ "$THRESHOLD" -gt "$NUM_PARTIES" ]; then
    echo "ERROR: Threshold must be between 2 and $NUM_PARTIES"
    exit 1
fi

# TLS setup
if [ -n "$USE_TLS" ]; then
    CERTS_DIR="$SERVICE_ROOT/certs/test"
    if [ ! -f "$CERTS_DIR/party$((NUM_PARTIES - 1)).pem" ]; then
        echo "Generating mTLS certificates for $NUM_PARTIES parties..."
        bash "$SERVICE_ROOT/certs/gen_certs.sh" "$NUM_PARTIES" "$CERTS_DIR"
    fi
fi

# Check prerequisites
if [ ! -f "$PSI_PARTY" ]; then
    echo "ERROR: psi_party binary not found. Build first:"
    echo "  mkdir -p build && cd build && cmake .. && make -j\$(nproc)"
    exit 1
fi

if [ ! -f "$PSI_DEALER" ]; then
    echo "ERROR: psi_dealer binary not found. Build first:"
    echo "  mkdir -p build && cd build && cmake .. && make -j\$(nproc)"
    exit 1
fi

python3 -c "import grpc" 2>/dev/null || {
    echo "ERROR: Python grpcio not installed. Run: pip3 install grpcio"
    exit 1
}

# Build addresses
DEALER_PORT=53050
DEALER_ADDR="127.0.0.1:$DEALER_PORT"
INTER_PARTY_ADDRS=()
CLIENT_PORTS=()
for i in $(seq 0 $((NUM_PARTIES - 1))); do
    INTER_PORT=$((53000 + i))
    CLIENT_PORT=$((53100 + i))
    INTER_PARTY_ADDRS+=("127.0.0.1:${INTER_PORT}")
    CLIENT_PORTS+=($CLIENT_PORT)
done
# Last party (sorted) is chosen as leader in the demo
LEADER_ADDR="${INTER_PARTY_ADDRS[$((NUM_PARTIES - 1))]}"

# ============================================================================
echo ""
echo "============================================================"
if [ "$THRESHOLD" -eq "$NUM_PARTIES" ]; then
    echo "  KS05 Threshold-MPSI Demo ($NUM_PARTIES parties, t=$THRESHOLD)"
else
    echo "  KS05 Threshold-MPSI Demo ($NUM_PARTIES parties, t=$THRESHOLD)"
fi
echo "============================================================"

PYTHONPATH="$PYTHON_CLIENT:$PYTHONPATH" python3 -c "
import json, os
from collections import Counter

n = $NUM_PARTIES
t = $THRESHOLD

# Name pools with controlled overlap:
#   - 'all_common'  elements appear in ALL n parties
#   - 'most_common' elements appear in all parties EXCEPT party 0
#   - 'pair_common' elements appear in party 0 and leader only
#   - rest are unique per party
all_common  = ['Alpha', 'Bravo', 'Charlie', 'Delta']
most_common = ['Echo', 'Foxtrot', 'Golf', 'Hotel']
pair_common = ['India', 'Juliet']

unique_pool = [
    'Kilo', 'Lima', 'Mike', 'November', 'Oscar', 'Papa',
    'Quebec', 'Romeo', 'Sierra', 'Tango', 'Uniform', 'Victor',
    'Whiskey', 'Xray', 'Yankee', 'Zulu',
    'Amber', 'Blake', 'Coral', 'Drake', 'Ember', 'Frost',
    'Garnet', 'Haven', 'Ivory', 'Jasper', 'Karma', 'Lotus',
    'Maple', 'Noble', 'Onyx', 'Pearl', 'Quartz', 'Raven',
    'Sage', 'Terra', 'Unity', 'Valor', 'Willow', 'Zenith',
    'Agate', 'Birch', 'Cedar', 'Dune', 'Elm', 'Flint',
    'Glen', 'Hawk', 'Isle', 'Jade', 'Knoll', 'Lark',
    'Moss', 'Nest', 'Opal', 'Pine', 'Ridge', 'Stone',
]

print()
if t == n:
    print(f'  {n}-party full intersection (threshold = {t})')
else:
    print(f'  {n}-party threshold intersection (threshold = {t})')
print(f'  Elements appearing in >= {t} parties will be output.')
print()

inputs = []
party_names = []
idx = 0
for i in range(n):
    party_set = list(all_common)

    # 'most_common' in all except party 0
    if i > 0:
        party_set += list(most_common)

    # 'pair_common' in party 0 and the leader only
    if i == 0 or i == n - 1:
        party_set += list(pair_common)

    # Different number of unique elements per party to show variable sizes
    if i == 0:
        num_unique = 6
    elif i == n - 1:
        num_unique = 10
    else:
        num_unique = 8

    party_set += unique_pool[idx:idx + num_unique]
    idx += num_unique
    inputs.append(party_set)

    name = f'Party {i}'
    party_names.append(name)
    role = ' (leader)' if i == n - 1 else ''
    print(f'  {name}{role}: {len(party_set)} elements')
    elems = ', '.join(sorted(party_set))
    print(f'    {{{elems}}}')

# Compute expected intersection for the leader
counter = Counter()
for party_set in inputs:
    for elem in party_set:
        counter[elem] += 1

leader_set = set(inputs[n - 1])
expected = set()
for elem in leader_set:
    if counter[elem] >= t:
        expected.add(elem)

print()
expected_str = ', '.join(sorted(expected))
print(f'  Expected result ({len(expected)} elements): {{{expected_str}}}')
explain_parts = []
for elem in sorted(expected):
    explain_parts.append(f'{elem} (in {counter[elem]}/{n})')
print(f'  Breakdown: {chr(10)}    ' + (chr(10) + '    ').join(explain_parts))

# Write inputs to temp file
data = {'inputs': inputs, 'names': party_names, 'expected': sorted(expected)}
tmp = os.path.join('$SCRIPT_DIR', '.demo_data.json')
with open(tmp, 'w') as f:
    json.dump(data, f)
"

echo ""
echo "============================================================"
echo ""

# Cleanup handler
PIDS=()
cleanup() {
    echo ""
    echo "[Demo] Shutting down..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -f "$SCRIPT_DIR/.demo_data.json"
    echo "[Demo] Done."
}
trap cleanup EXIT

# Start dealer first
DEALER_ARGS=(--parties "$NUM_PARTIES" --listen "$DEALER_ADDR")
if [ -n "$USE_TLS" ]; then
    DEALER_ARGS+=(--certs-dir "$CERTS_DIR")
    echo "[Demo] Starting dealer on $DEALER_ADDR (mTLS)..."
else
    echo "[Demo] Starting dealer on $DEALER_ADDR (insecure)..."
fi
no_proxy=127.0.0.1,localhost "$PSI_DEALER" "${DEALER_ARGS[@]}" > /dev/null 2>&1 &
PIDS+=($!)
sleep 1

# Start parties (they connect to dealer on startup to get keys)
for i in $(seq 0 $((NUM_PARTIES - 1))); do
    MY_ADDR="${INTER_PARTY_ADDRS[$i]}"
    # Build --addresses with all OTHER parties' addresses
    OTHERS=""
    for j in $(seq 0 $((NUM_PARTIES - 1))); do
        if [ "$j" -ne "$i" ]; then
            if [ -n "$OTHERS" ]; then OTHERS="$OTHERS,"; fi
            OTHERS="${OTHERS}${INTER_PARTY_ADDRS[$j]}"
        fi
    done

    PARTY_ARGS=(
        --address "$MY_ADDR"
        --addresses "$OTHERS"
        --listen "127.0.0.1:${CLIENT_PORTS[$i]}"
        --dealer "$DEALER_ADDR"
    )

    if [ -n "$USE_TLS" ]; then
        PARTY_ARGS+=(--certs-dir "$CERTS_DIR")
        echo "[Demo] Starting Party $i with mTLS on port ${CLIENT_PORTS[$i]}"
    else
        echo "[Demo] Starting Party $i on port ${CLIENT_PORTS[$i]}"
    fi

    no_proxy=127.0.0.1,localhost "$PSI_PARTY" "${PARTY_ARGS[@]}" > /dev/null 2>&1 &
    PIDS+=($!)
done

# Wait for parties to start and collect keys from dealer
echo "[Demo] Waiting for key distribution..."
sleep 5
echo ""
echo "[Demo] All $NUM_PARTIES parties running. Submitting inputs..."
echo ""

# Run Python clients in parallel
PYTHONPATH="$PYTHON_CLIENT:$PYTHONPATH" python3 -c "
import threading, sys, os, json

sys.path.insert(0, '$PYTHON_CLIENT')
os.environ['no_proxy'] = '127.0.0.1,localhost'

from mpsi_client import PsiClient

with open('$SCRIPT_DIR/.demo_data.json') as f:
    data = json.load(f)

inputs = data['inputs']
names = data['names']
expected = set(data['expected'])
n = len(inputs)
t = $THRESHOLD
ports = [53100 + i for i in range(n)]
leader_address = '$LEADER_ADDR'

results = {}
errors = {}

use_tls = '$USE_TLS' != ''
certs_dir = '$CERTS_DIR' if use_tls else ''

# Determine leader index: leader_address sorted among all inter-party addresses
inter_addrs = sorted([f'127.0.0.1:{53000+i}' for i in range(n)])
leader_idx = inter_addrs.index(leader_address)

def run(i):
    try:
        # Determine role: the party whose sorted index matches leader gets LEADER
        sorted_addr = f'127.0.0.1:{53000+i}'
        role = 'leader' if sorted_addr == leader_address else 'member'

        if use_tls:
            c = PsiClient(f'127.0.0.1:{ports[i]}', tls=True,
                ca_cert=f'{certs_dir}/ca.pem',
                client_cert=f'{certs_dir}/party{i}.pem',
                client_key=f'{certs_dir}/party{i}-key.pem')
        else:
            c = PsiClient(f'127.0.0.1:{ports[i]}')
        with c:
            intersection, status = c.compute_intersection(
                inputs[i], role=role, leader_address=leader_address,
                protocol='ks05_t_mpsi',
                num_parties=n, threshold=t, timeout=300)
            results[i] = (intersection, status)
    except Exception as e:
        errors[i] = str(e)

threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
for th in threads: th.start()
for th in threads: th.join(timeout=300)

if errors:
    for i, e in errors.items():
        print(f'  ERROR {names[i]}: {e}')
    sys.exit(1)

print('  Results:')
for i in range(n):
    intersection, status = results[i]
    sorted_addr = f'127.0.0.1:{53000+i}'
    if sorted_addr == leader_address and intersection:
        result_str = ', '.join(sorted(intersection))
        print(f'    {names[i]} (leader): {{{result_str}}}')
    else:
        print(f'    {names[i]}: protocol completed (no output)')

leader_result = set(results[leader_idx][0])

print()
if leader_result == expected:
    expected_str = ', '.join(sorted(expected))
    print(f'  SUCCESS: Threshold-{t} intersection = {{{expected_str}}}')
    member_count = n - 1
    print(f'  {member_count} members learned nothing about other parties' + \"'\" + ' data.')
else:
    print(f'  FAILED: Expected {sorted(expected)}, got {sorted(leader_result)}')
    sys.exit(1)
"

echo ""
echo "============================================================"
TLS_MSG=""
if [ -n "$USE_TLS" ]; then
    TLS_MSG=" with mTLS"
fi
echo "  Demo completed successfully${TLS_MSG}"
echo "============================================================"
echo ""
