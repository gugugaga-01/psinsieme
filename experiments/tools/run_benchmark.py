#!/usr/bin/env python3

import argparse
import subprocess
import math
import os
import shutil

PROTOCOL_DEFAULTS = {
    "ks05": {"binPath": "bin/t_mpsi"},
    "beh21": {"binPath": "bin/t_mpsi"},
}


def main():
    parser = argparse.ArgumentParser(description="Run mp_psi parties for benchmarking.")
    parser.add_argument(
        "--protocol",
        choices=["ks05", "beh21"],
        required=True,
        help="Protocol to benchmark",
    )
    parser.add_argument("--binPath", default=None, help="Path to the binary (auto-detected from protocol if omitted)")
    parser.add_argument("--numParties", type=int, required=True, help="Number of parties")
    parser.add_argument("--threshold", type=int, help="Intersection threshold")
    parser.add_argument("--senderSize", type=int, required=True, help="Exponent to define 2^m for sender sizes")
    parser.add_argument("--receiverSize", type=int, required=True, help="Exponent to define 2^m for receiver sizes")
    parser.add_argument("--numRuns", type=int, default=1, help="Number of runs for benchmarking")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    bin_path = args.binPath or PROTOCOL_DEFAULTS[args.protocol]["binPath"]
    sender_size = 2 ** args.senderSize
    receiver_size = 2 ** args.receiverSize
    threshold = args.threshold if args.threshold is not None else (args.numParties // 2 + 1)

    processes = []

    keys_dir = "keys"
    if os.path.exists(keys_dir):
        shutil.rmtree(keys_dir)

    expect_size = 0
    for party_id in range(args.numParties):
        shared_size = math.floor((party_id + 1) / args.numParties * sender_size)

        if party_id == args.numParties - threshold:
            expect_size = shared_size
        cmd = [
            bin_path,
            "-partyID", str(party_id),
            "-numParties", str(args.numParties),
            "-threshold", str(threshold),
            "-senderSize", str(sender_size),
            "-receiverSize", str(receiver_size),
            "-sharedSize", str(shared_size),
            "-numRuns", str(args.numRuns),
        ]

        if args.debug:
            cmd.append("-debug")

        p = subprocess.Popen(cmd)
        processes.append(p)

    for p in processes:
        p.wait()

    if args.debug:
        print("Expect", expect_size, "intersection items.")

    print("All parties have finished running.")


if __name__ == "__main__":
    main()
