#!/usr/bin/env python3

import os
import subprocess
import argparse


def run_benchmarks(protocol, numParties_list, threshold_list, size_list, numRuns):
    assert len(numParties_list) == len(threshold_list), \
        "threshold_list must have the same length as numParties_list"

    script_path = os.path.join(os.path.dirname(__file__), "run_benchmark.py")
    result_dir = os.path.join("tools", "experiment_result")
    os.makedirs(result_dir, exist_ok=True)

    for (numParties, threshold) in zip(numParties_list, threshold_list):
        for size in size_list:
            run_single(protocol, numParties, threshold, size, numRuns,
                       script_path, result_dir)


def run_single(protocol, numParties, threshold, size, numRuns,
               script_path, result_dir):
    senderSize = size
    receiverSize = size

    out_filename = (
        f"{protocol}"
        f"_parties{numParties}"
        f"_thr{threshold}"
        f"_sender{senderSize}"
        f"_receiver{receiverSize}"
        f"_runs{numRuns}"
    )

    out_file_path = os.path.join(result_dir, out_filename)

    cmd = [
        "python3",
        script_path,
        "--protocol", protocol,
        "--numParties", str(numParties),
        "--threshold", str(threshold),
        "--senderSize", str(senderSize),
        "--receiverSize", str(receiverSize),
        "--numRuns", str(numRuns),
    ]

    print(f"Running: {cmd}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    with open(out_file_path, "w") as f:
        f.write("Command:\n")
        f.write(" ".join(cmd) + "\n\n")
        f.write("---- STDOUT ----\n")
        f.write(result.stdout + "\n")
        f.write("---- STDERR ----\n")
        f.write(result.stderr + "\n")

    print(f"Finished. Output saved to {out_file_path}")


def main():
    parser = argparse.ArgumentParser(description="Run multiple benchmarks over a parameter grid.")
    parser.add_argument("--protocol", choices=["ks05", "beh21"], required=True)
    parser.add_argument("--numParties", type=int, nargs="+", default=[5])
    parser.add_argument("--threshold", type=int, nargs="+", default=[3])
    parser.add_argument("--sizes", type=int, nargs="+", default=[4, 6])
    parser.add_argument("--numRuns", type=int, default=1)
    args = parser.parse_args()

    run_benchmarks(args.protocol, args.numParties, args.threshold,
                   args.sizes, args.numRuns)


if __name__ == "__main__":
    main()
