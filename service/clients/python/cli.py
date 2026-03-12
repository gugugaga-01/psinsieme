#!/usr/bin/env python3
"""CLI for submitting input sets to a PSI party."""

import argparse
import sys

from mpsi_client import PsiClient


def main():
    parser = argparse.ArgumentParser(description="MPSI Client CLI")
    parser.add_argument("--target", required=True,
                        help="Party gRPC address (e.g. localhost:50090)")
    parser.add_argument("--elements", nargs="*", default=None,
                        help="Input set elements")
    parser.add_argument("--input-file",
                        help="Read elements from file (one per line)")
    parser.add_argument("--role", choices=["leader", "member"], default="member",
                        help="Party role (default: member)")
    parser.add_argument("--leader-address", required=True,
                        help="Inter-party address of the leader")
    parser.add_argument("--protocol", default="ks05_t_mpsi",
                        help="Protocol to use (default: ks05_t_mpsi)")
    parser.add_argument("--num-parties", type=int, default=3,
                        help="Number of parties (default: 3)")
    parser.add_argument("--threshold", type=int, default=3,
                        help="Intersection threshold (default: 3)")
    parser.add_argument("--timeout", type=float, default=300,
                        help="Timeout in seconds (default: 300)")
    parser.add_argument("--tls", action="store_true",
                        help="Enable TLS")
    parser.add_argument("--ca-cert", help="CA certificate path")
    parser.add_argument("--client-cert", help="Client certificate path")
    parser.add_argument("--client-key", help="Client key path")

    args = parser.parse_args()

    # Resolve elements from --elements or --input-file
    if args.input_file:
        with open(args.input_file) as f:
            elements = [line.strip() for line in f if line.strip()]
    elif args.elements:
        elements = args.elements
    else:
        parser.error("one of --elements or --input-file is required")

    try:
        with PsiClient(
            args.target,
            tls=args.tls,
            ca_cert=args.ca_cert,
            client_cert=args.client_cert,
            client_key=args.client_key,
        ) as client:
            print(f"Submitting {len(elements)} elements to {args.target}...")

            intersection, status = client.compute_intersection(
                elements,
                role=args.role,
                leader_address=args.leader_address,
                protocol=args.protocol,
                num_parties=args.num_parties,
                threshold=args.threshold,
                timeout=args.timeout,
            )

            print(f"Status: {status}")
            if intersection:
                print(f"Intersection ({len(intersection)} elements):")
                for elem in intersection:
                    print(f"  {elem}")
            else:
                print("No intersection returned (member party or empty result)")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
