#!/usr/bin/env python3
"""
Test script to evaluate accuracy of compressed China IP ranges

This script generates random IPs from the full China IP list and tests
how many are correctly identified by the compressed 1200-range list.

Usage:
    python3 test_accuracy.py
    python3 test_accuracy.py --count 100000
    python3 test_accuracy.py --full china_ipv4_ranges.txt --compressed china_ipv4_ranges_1200.txt
"""

import argparse
import ipaddress
import random
from typing import List
from datetime import datetime


class IPRangeTester:
    """Test accuracy of compressed IP ranges"""

    def __init__(self, full_file: str, compressed_file: str):
        self.full_file = full_file
        self.compressed_file = compressed_file
        self.full_ranges: List[ipaddress.IPv4Network] = []
        self.compressed_ranges: List[ipaddress.IPv4Network] = []

    def load_ranges(self, filename: str) -> List[ipaddress.IPv4Network]:
        """Load IP ranges from file"""
        ranges = []
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        network = ipaddress.IPv4Network(line, strict=False)
                        ranges.append(network)
                    except Exception as e:
                        print(f"Warning: Failed to parse {line}: {e}")
        return ranges

    def ip_in_ranges(self, ip: ipaddress.IPv4Address, ranges: List[ipaddress.IPv4Network]) -> bool:
        """Check if IP is in any of the ranges"""
        for network in ranges:
            if ip in network:
                return True
        return False

    def generate_random_ips(self, count: int) -> List[ipaddress.IPv4Address]:
        """Generate random IPs from full China IP ranges"""
        print(f"\nGenerating {count:,} random IPs from China ranges...")

        # Calculate total IPs in each range for weighted selection
        ranges_with_weights = []
        total_ips = 0

        for network in self.full_ranges:
            num_ips = network.num_addresses
            ranges_with_weights.append((network, num_ips))
            total_ips += num_ips

        print(f"Total IPs in full ranges: {total_ips:,}")

        # Generate random IPs weighted by range size
        random_ips = []
        for i in range(count):
            # Select random range weighted by size
            rand_val = random.randint(0, total_ips - 1)
            cumulative = 0
            selected_range = None

            for network, num_ips in ranges_with_weights:
                cumulative += num_ips
                if rand_val < cumulative:
                    selected_range = network
                    break

            # Generate random IP within selected range
            if selected_range:
                # Get random offset within range
                offset = random.randint(0, selected_range.num_addresses - 1)
                random_ip = ipaddress.IPv4Address(int(selected_range.network_address) + offset)
                random_ips.append(random_ip)

            # Progress indicator
            if (i + 1) % 10000 == 0:
                print(f"  Generated {i + 1:,}/{count:,} IPs...")

        print(f"Generated {len(random_ips):,} random IPs")
        return random_ips

    def test_accuracy(self, test_ips: List[ipaddress.IPv4Address]) -> dict:
        """Test how many IPs are correctly identified by compressed ranges"""
        print(f"\nTesting accuracy with {len(test_ips):,} IPs...")

        matches = 0
        misses = 0
        missed_ips = []

        for i, ip in enumerate(test_ips):
            # All test IPs are from full China ranges, so they should be found
            if self.ip_in_ranges(ip, self.compressed_ranges):
                matches += 1
            else:
                misses += 1
                if len(missed_ips) < 10:  # Keep first 10 missed IPs
                    missed_ips.append(ip)

            # Progress indicator
            if (i + 1) % 10000 == 0:
                print(f"  Tested {i + 1:,}/{len(test_ips):,} IPs...")

        accuracy = (matches / len(test_ips)) * 100.0

        return {
            'total': len(test_ips),
            'matches': matches,
            'misses': misses,
            'accuracy': accuracy,
            'missed_ips': missed_ips
        }

    def run_test(self, count: int):
        """Run the complete test"""
        print("=" * 70)
        print("China IP Ranges Accuracy Test")
        print("=" * 70)
        print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Full ranges file: {self.full_file}")
        print(f"Compressed ranges file: {self.compressed_file}")

        # Load ranges
        print("\nLoading IP ranges...")
        self.full_ranges = self.load_ranges(self.full_file)
        print(f"Loaded {len(self.full_ranges):,} ranges from full list")

        self.compressed_ranges = self.load_ranges(self.compressed_file)
        print(f"Loaded {len(self.compressed_ranges):,} ranges from compressed list")

        # Calculate total IPs in each
        full_total = sum(r.num_addresses for r in self.full_ranges)
        compressed_total = sum(r.num_addresses for r in self.compressed_ranges)
        coverage = (compressed_total / full_total) * 100.0

        print(f"\nIP Coverage:")
        print(f"  Full ranges: {full_total:,} IPs")
        print(f"  Compressed ranges: {compressed_total:,} IPs")
        print(f"  Theoretical coverage: {coverage:.2f}%")

        # Generate random test IPs
        test_ips = self.generate_random_ips(count)

        # Test accuracy
        results = self.test_accuracy(test_ips)

        # Print results
        print("\n" + "=" * 70)
        print("Test Results")
        print("=" * 70)
        print(f"Total test IPs: {results['total']:,}")
        print(f"Correctly identified: {results['matches']:,}")
        print(f"Missed: {results['misses']:,}")
        print(f"Accuracy: {results['accuracy']:.2f}%")

        if results['missed_ips']:
            print(f"\nSample of missed IPs (first {len(results['missed_ips'])}):")
            for ip in results['missed_ips']:
                # Find which range it belongs to in full list
                for network in self.full_ranges:
                    if ip in network:
                        print(f"  {ip} (from range {network})")
                        break

        print("\n" + "=" * 70)
        print(f"Test completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        return results


def main():
    parser = argparse.ArgumentParser(description='Test accuracy of compressed China IP ranges')
    parser.add_argument('--count', type=int, default=100000,
                       help='Number of random IPs to test (default: 100000)')
    parser.add_argument('--full', default='china_ipv4_ranges.txt',
                       help='Full IP ranges file (default: china_ipv4_ranges.txt)')
    parser.add_argument('--compressed', default='china_ipv4_ranges_1200.txt',
                       help='Compressed IP ranges file (default: china_ipv4_ranges_1200.txt)')

    args = parser.parse_args()

    # Create tester and run
    tester = IPRangeTester(args.full, args.compressed)
    results = tester.run_test(args.count)

    # Exit with error code if accuracy is below threshold
    if results['accuracy'] < 90.0:
        print(f"\n⚠️  Warning: Accuracy {results['accuracy']:.2f}% is below 90% threshold!")
        return 1
    else:
        print(f"\n✅ Success: Accuracy {results['accuracy']:.2f}% meets quality standards!")
        return 0


if __name__ == '__main__':
    exit(main())