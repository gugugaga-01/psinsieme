#!/usr/bin/env python3
"""End-to-end test: 1 psi_dealer + 3 psi_party processes + 3 Python clients."""

import os
import sys
import time
import signal
import subprocess
import threading

# Add Python client to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE_ROOT = os.path.join(SCRIPT_DIR, "..", "..")
PROJECT_ROOT = os.path.join(SERVICE_ROOT, "..")
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
sys.path.insert(0, os.path.join(SERVICE_ROOT, "clients", "python"))

from mpsi_client import PsiClient

PSI_PARTY_BIN = os.path.join(BUILD_DIR, "psi_party")
PSI_DEALER_BIN = os.path.join(BUILD_DIR, "psi_dealer")

# Party config
NUM_PARTIES = 3
THRESHOLD = 3

# Dealer address
DEALER_ADDR = "127.0.0.1:51050"

# Inter-party addresses (for protocol communication between parties)
INTER_PARTY_ADDRS = ["127.0.0.1:51000", "127.0.0.1:51001", "127.0.0.1:51002"]

# The last party (sorted) is the leader
LEADER_ADDR = INTER_PARTY_ADDRS[-1]
LEADER_IDX = INTER_PARTY_ADDRS.index(LEADER_ADDR)

# Client-facing addresses (for Python clients to connect to)
CLIENT_ADDRS = ["127.0.0.1:51010", "127.0.0.1:51011", "127.0.0.1:51012"]

# Input sets (intersection = {"apple", "banana"})
INPUTS = [
    ["apple", "banana", "cherry", "date"],        # Party 0
    ["banana", "apple", "elderberry", "fig"],      # Party 1
    ["grape", "apple", "banana", "honeydew"],      # Party 2 (leader)
]


def start_dealer() -> subprocess.Popen:
    """Start the psi_dealer process."""
    cmd = [
        PSI_DEALER_BIN,
        "--parties", str(NUM_PARTIES),
        "--listen", DEALER_ADDR,
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "no_proxy": "127.0.0.1,localhost"},
    )
    return proc


def start_party(party_id: int) -> subprocess.Popen:
    """Start a psi_party process."""
    # --addresses = other parties only (exclude self)
    others = [a for i, a in enumerate(INTER_PARTY_ADDRS) if i != party_id]
    cmd = [
        PSI_PARTY_BIN,
        "--address", INTER_PARTY_ADDRS[party_id],
        "--addresses", ",".join(others),
        "--dealer", DEALER_ADDR,
        "--listen", CLIENT_ADDRS[party_id],
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "no_proxy": "127.0.0.1,localhost"},
    )
    return proc


def run_client(party_id: int, results: dict, errors: dict):
    """Run a Python client against a party."""
    try:
        role = "leader" if party_id == LEADER_IDX else "member"
        with PsiClient(CLIENT_ADDRS[party_id]) as client:
            intersection, status = client.compute_intersection(
                INPUTS[party_id],
                role=role,
                leader_address=LEADER_ADDR,
                protocol="ks05_t_mpsi",
                num_parties=NUM_PARTIES,
                threshold=THRESHOLD,
                timeout=300,
            )
            results[party_id] = (intersection, status)
    except Exception as e:
        errors[party_id] = str(e)


def main():
    print("=== End-to-End Test: 1 dealer + 3 psi_party + 3 Python clients ===")

    for binary, name in [(PSI_DEALER_BIN, "psi_dealer"), (PSI_PARTY_BIN, "psi_party")]:
        if not os.path.exists(binary):
            print(f"ERROR: {name} binary not found at {binary}")
            sys.exit(1)

    procs = []

    try:
        # Start dealer first
        dealer = start_dealer()
        procs.append(dealer)
        print(f"Started dealer (PID {dealer.pid})")
        time.sleep(1)

        # Start all party processes
        for i in range(NUM_PARTIES):
            proc = start_party(i)
            procs.append(proc)
            print(f"Started party {i} (PID {proc.pid})")

        # Wait for key distribution and server startup
        print("Waiting for key distribution...")
        time.sleep(5)

        # Run clients in parallel (all must submit before protocol can complete)
        results = {}
        errors = {}
        threads = []
        for i in range(NUM_PARTIES):
            t = threading.Thread(target=run_client, args=(i, results, errors))
            threads.append(t)
            t.start()
            print(f"Client {i} submitted {len(INPUTS[i])} elements")

        # Wait for all clients
        for t in threads:
            t.join(timeout=300)

        # Check results
        print("\n=== Results ===")

        if errors:
            for pid, err in errors.items():
                print(f"Party {pid} ERROR: {err}")
            sys.exit(1)

        for pid in range(NUM_PARTIES):
            intersection, status = results.get(pid, ([], "missing"))
            print(f"Party {pid}: status='{status}', intersection={intersection}")

        # Leader should have the intersection
        leader_intersection = set(results[LEADER_IDX][0])
        expected = {"apple", "banana"}

        if leader_intersection == expected:
            print(f"\nTEST PASSED: Leader intersection = {leader_intersection}")
        else:
            print(f"\nTEST FAILED: Expected {expected}, got {leader_intersection}")
            sys.exit(1)

        # Members should have empty intersection
        for i in range(NUM_PARTIES):
            if i == LEADER_IDX:
                continue
            member_intersection = results[i][0]
            if member_intersection:
                print(f"WARNING: Member {i} returned non-empty intersection: {member_intersection}")

    finally:
        # Kill all processes
        for proc in procs:
            proc.send_signal(signal.SIGTERM)
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
