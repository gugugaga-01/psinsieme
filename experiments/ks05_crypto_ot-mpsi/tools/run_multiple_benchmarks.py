#!/usr/bin/env python3

import os
import subprocess

def run_benchmarks():
    # 1) Define the parameter space you want to explore
    numParties_list       = [5]      # e.g. test with 4, 10, 20, 40 parties
    threshold_list        = [3]       # one-to-one with numParties_list
    size_list             = [4, 6]       # exponent => 2^10, 2^12, 2^14
    numRuns               = 1        # number of runs (single value now)


    # Ensure one-to-one mapping
    assert len(numParties_list) == len(threshold_list), \
        "threshold_list must have the same length as numParties_list"

    script_path = "tools/run_benchmark.py"
    result_dir = "tools/experient_result"
    os.makedirs(result_dir, exist_ok=True)

    # Iterate over combinations; pair each numParties with its threshold
    for (numParties, threshold) in zip(numParties_list, threshold_list):
        for size in size_list:
            run_single(numParties, threshold, size, numRuns,
                           script_path, result_dir)

def run_single(numParties, threshold, size, numRuns,
               script_path, result_dir):
    senderSize = size
    receiverSize = size

    # Construct a meaningful filename
    out_filename = (
        f"parties{numParties}"
        f"_thr{threshold}"
        f"_sender{senderSize}"
        f"_receiver{receiverSize}"
        f"_runs{numRuns}"
    )

    out_file_path = os.path.join(result_dir, out_filename)

    # Build the command
    cmd = [
        "python3",
        script_path,
        "--numParties", str(numParties),
        "--threshold", str(threshold),
        "--senderSize", str(senderSize),
        "--receiverSize", str(receiverSize),
        "--numRuns", str(numRuns),
    ]

    print(f"Running: {cmd}")
    # Execute the command and capture its output
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Write the output (stdout and stderr) to the file
    with open(out_file_path, "w") as f:
        f.write("Command:\n")
        f.write(" ".join(cmd) + "\n\n")
        f.write("---- STDOUT ----\n")
        f.write(result.stdout + "\n")
        f.write("---- STDERR ----\n")
        f.write(result.stderr + "\n")

    print(f"Finished. Output saved to {out_file_path}")

def main():
    run_benchmarks()

if __name__ == "__main__":
    main()