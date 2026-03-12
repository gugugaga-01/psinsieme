#!/usr/bin/env python3

import argparse
import subprocess
import sys
import math
import os
import shutil

def main():
    parser = argparse.ArgumentParser(description="Run mp_psi parties for benchmarking.")
    parser.add_argument('--binPath', default='bin/t_mpsi', help='Path to the t_mpsi binary')
    parser.add_argument('--numParties', type=int, required=True, help='Number of parties')
    parser.add_argument('--threshold', type=int, help='Intersection threshold')
    parser.add_argument('--senderSize', type=int, required=True, help='Exponent to define 2^m for sender sizes')
    parser.add_argument('--receiverSize', type=int, required=True, help='Exponent to define 2^m for receiver sizes')
    parser.add_argument('--numRuns', type=int, default=1, help='Number of runs for benchmarking')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')


    args = parser.parse_args()

    sender_size   = 2 ** args.senderSize
    receiver_size = 2 ** args.receiverSize
    
    # Default threshold: ceiling of numParties/2 (e.g., 5->3, 6->3)
    threshold = args.threshold if args.threshold is not None else ((args.numParties + 1) // 2)


    processes = []
    
    keys_dir = "keys"

    # Remove the ../keys directory if it exists
    if os.path.exists(keys_dir):
        shutil.rmtree(keys_dir)

    # Start parties from the largest party_id down to 0
    # for party_id in reversed(range(args.numParties)):
    expect_size = 0
    for party_id in range(args.numParties):
        shared_size = math.floor((party_id+1)/args.numParties * sender_size)
        
        if(party_id == args.numParties -  threshold):
            expect_size = shared_size
        cmd = [
            args.binPath,
            "-partyID", str(party_id),
            "-numParties", str(args.numParties),
            "-threshold", str(threshold),
            "-senderSize", str(sender_size),
            "-receiverSize", str(receiver_size),
            "-sharedSize", str(shared_size),
            "-numRuns", str(args.numRuns)
        ]

        # If debug is enabled, add the -debug flag
        if args.debug:
            cmd.append("-debug")
        
            
        # Start the party in a subprocess
        p = subprocess.Popen(cmd)
        processes.append(p)

    # Wait for all parties to complete
    for p in processes:
        p.wait()
    
    if( args.debug ):
        print("Expect ", expect_size, " intersection items.")

    print("All parties have finished running.")
    

if __name__ == "__main__":
    main()