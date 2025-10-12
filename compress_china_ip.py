#!/usr/bin/env python3
"""
China IP Range Compressor

This script compresses China IPv4 ranges to a target count (e.g., 1200)
while maintaining high coverage (~94%+).

It uses a greedy algorithm to select the largest IP ranges that provide
the best coverage for iOS PacketTunnel memory constraints.

Usage:
    python3 compress_china_ip.py
    python3 compress_china_ip.py --input china_ipv4_ranges.txt --target 1200
    python3 compress_china_ip.py --targets 800,1000,1200,1500
"""

import os
import sys
import argparse
import ipaddress
from typing import List, Tuple
from datetime import datetime


class IPRange:
    """IP range with start, end, and CIDR notation"""

    def __init__(self, cidr: str):
        self.network = ipaddress.IPv4Network(cidr, strict=False)
        self.cidr = str(self.network)
        self.start = int(self.network.network_address)
        self.end = int(self.network.broadcast_address)
        self.num_addresses = self.network.num_addresses

    def __lt__(self, other):
        if self.start != other.start:
            return self.start < other.start
        return self.end < other.end

    def __repr__(self):
        return f"IPRange({self.cidr}, {self.num_addresses:,} IPs)"


class ChinaIPCompressor:
    """Compress China IP ranges to target count with high coverage"""

    def __init__(self, input_file: str):
        self.input_file = input_file
        self.ranges: List[IPRange] = []

    def load_ranges(self) -> None:
        """Load IP ranges from file"""
        print(f"Loading IP ranges from {self.input_file}...")

        with open(self.input_file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                ip_range = IPRange(line)
                self.ranges.append(ip_range)
            except Exception as e:
                print(f"Warning: Failed to parse line: {line} - {e}")

        print(f"Loaded {len(self.ranges):,} IP ranges")

    def compress(self, target_count: int) -> Tuple[List[IPRange], float]:
        """
        Compress ranges to target count using greedy algorithm

        Returns:
            (compressed_ranges, coverage_percentage)
        """
        print(f"\nCompressing to {target_count} ranges...")

        # Sort by size (largest first) for greedy selection
        sorted_ranges = sorted(self.ranges, key=lambda r: r.num_addresses, reverse=True)

        # Calculate total IPs in original ranges
        total_ips = sum(r.num_addresses for r in self.ranges)

        # Greedy selection: pick largest ranges until we hit target
        selected = sorted_ranges[:target_count]

        # Calculate coverage
        selected_ips = sum(r.num_addresses for r in selected)
        coverage = (selected_ips / total_ips) * 100.0

        # Sort by network address for output
        selected.sort()

        print(f"  Original: {len(self.ranges):,} ranges ({total_ips:,} IPs)")
        print(f"  Compressed: {len(selected):,} ranges ({selected_ips:,} IPs)")
        print(f"  Coverage: {coverage:.2f}%")
        print(f"  Compression ratio: {len(self.ranges) / len(selected):.2f}x")

        return selected, coverage

    def save_compressed(self, ranges: List[IPRange], output_file: str) -> None:
        """Save compressed ranges to file"""
        with open(output_file, 'w') as f:
            for r in ranges:
                f.write(f"{r.cidr}\n")
        print(f"  Saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Compress China IP ranges')
    parser.add_argument('--input', default='china_ipv4_ranges.txt',
                       help='Input IP ranges file')
    parser.add_argument('--target', type=int, default=1200,
                       help='Target number of ranges (default: 1200)')
    parser.add_argument('--targets', type=str, default=None,
                       help='Comma-separated list of targets (e.g., "800,1000,1200,1500")')
    parser.add_argument('--output-dir', default='.',
                       help='Output directory')

    args = parser.parse_args()

    # Check if input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize compressor
    compressor = ChinaIPCompressor(args.input)
    compressor.load_ranges()

    # Determine targets
    if args.targets:
        targets = [int(t.strip()) for t in args.targets.split(',')]
    else:
        targets = [args.target]

    print(f"\nTarget counts: {targets}")
    print("=" * 60)

    # Compress for each target
    results = []
    for target in targets:
        compressed, coverage = compressor.compress(target)

        # Generate output filename
        output_file = os.path.join(
            args.output_dir,
            f"china_ipv4_ranges_{target}.txt"
        )

        compressor.save_compressed(compressed, output_file)

        results.append({
            'target': target,
            'actual': len(compressed),
            'coverage': coverage,
            'file': output_file
        })

    # Summary
    print("\n" + "=" * 60)
    print("Compression Summary:")
    print("=" * 60)
    for result in results:
        print(f"Target: {result['target']:4d} | "
              f"Actual: {result['actual']:4d} | "
              f"Coverage: {result['coverage']:5.2f}%")

    print("\nAll compressed files generated successfully!")


if __name__ == '__main__':
    main()
