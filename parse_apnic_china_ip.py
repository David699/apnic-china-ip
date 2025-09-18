#!/usr/bin/env python3
"""
APNIC China IP Range Parser

This script downloads and parses China IP ranges from APNIC delegated statistics.
It generates IPv4 and IPv6 range files with checksums and compressed versions.

Usage:
    python3 parse_apnic_china_ip.py
    python3 parse_apnic_china_ip.py --output-dir ./ip-data
    python3 parse_apnic_china_ip.py --skip-download --input-file apnic-data.txt
"""

import os
import sys
import argparse
import ipaddress
import math
import hashlib
import subprocess
from datetime import datetime
from typing import List, Tuple
import urllib.request

class APNICParser:
    def __init__(self, output_dir: str = '.'):
        self.output_dir = output_dir
        self.apnic_url = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
        self.ipv4_ranges = []
        self.ipv6_ranges = []

    def download_apnic_data(self, output_file: str = 'apnic-data.txt') -> str:
        """Download APNIC delegated statistics file"""
        filepath = os.path.join(self.output_dir, output_file)
        print(f"Downloading APNIC data from {self.apnic_url}...")

        try:
            urllib.request.urlretrieve(self.apnic_url, filepath)
            print(f"Downloaded to {filepath}")
            return filepath
        except Exception as e:
            print(f"Error downloading APNIC data: {e}")
            sys.exit(1)

    def parse_apnic_file(self, filepath: str):
        """Parse APNIC delegated statistics file for China IP ranges"""
        print(f"Parsing {filepath} for China IP ranges...")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line in lines:
            # Skip comments and headers
            if line.startswith('#') or not line.strip():
                continue

            # Check if line contains China data
            if '|CN|' not in line:
                continue

            parts = line.strip().split('|')
            if len(parts) < 7:
                continue

            registry = parts[0]
            country = parts[1]
            ip_type = parts[2]
            start = parts[3]
            value = parts[4]
            date = parts[5]
            status = parts[6]

            if country != 'CN':
                continue

            try:
                if ip_type == 'ipv4':
                    # Value is the count of IPs
                    count = int(value)
                    # Calculate CIDR prefix length
                    prefix_len = 32 - int(math.log2(count))
                    cidr = f"{start}/{prefix_len}"

                    # Validate the network
                    network = ipaddress.IPv4Network(cidr, strict=False)
                    self.ipv4_ranges.append(str(network))

                elif ip_type == 'ipv6':
                    # Value is the prefix length
                    prefix_len = int(value)
                    cidr = f"{start}/{prefix_len}"

                    # Validate the network
                    network = ipaddress.IPv6Network(cidr, strict=False)
                    self.ipv6_ranges.append(str(network))

            except Exception as e:
                print(f"Warning: Error processing line: {line.strip()}")
                print(f"  Error: {e}")
                continue

        # Sort ranges
        self.ipv4_ranges.sort(key=lambda x: ipaddress.IPv4Network(x))
        self.ipv6_ranges.sort(key=lambda x: ipaddress.IPv6Network(x))

        print(f"Parsed {len(self.ipv4_ranges)} IPv4 ranges")
        print(f"Parsed {len(self.ipv6_ranges)} IPv6 ranges")

    def write_ranges(self):
        """Write IP ranges to files"""
        # Write IPv4 ranges
        ipv4_file = os.path.join(self.output_dir, 'china_ipv4_ranges.txt')
        with open(ipv4_file, 'w') as f:
            for cidr in self.ipv4_ranges:
                f.write(f"{cidr}\n")
        print(f"Wrote IPv4 ranges to {ipv4_file}")

        # Write IPv6 ranges
        ipv6_file = os.path.join(self.output_dir, 'china_ipv6_ranges.txt')
        with open(ipv6_file, 'w') as f:
            for cidr in self.ipv6_ranges:
                f.write(f"{cidr}\n")
        print(f"Wrote IPv6 ranges to {ipv6_file}")

    def generate_checksums(self):
        """Generate SHA256 checksums for files"""
        files = ['china_ipv4_ranges.txt', 'china_ipv6_ranges.txt']

        for filename in files:
            filepath = os.path.join(self.output_dir, filename)
            if not os.path.exists(filepath):
                continue

            # Calculate SHA256
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)

            checksum = sha256.hexdigest()

            # Write checksum file
            checksum_file = f"{filepath}.sha256sum"
            with open(checksum_file, 'w') as f:
                f.write(f"{checksum}  {filename}\n")
            print(f"Generated checksum: {checksum_file}")

    def create_compressed_files(self):
        """Create XZ compressed versions of IP range files"""
        files = ['china_ipv4_ranges.txt', 'china_ipv6_ranges.txt']

        for filename in files:
            filepath = os.path.join(self.output_dir, filename)
            if not os.path.exists(filepath):
                continue

            xz_file = f"{filepath}.xz"

            # Remove existing .xz file if it exists
            if os.path.exists(xz_file):
                os.remove(xz_file)

            try:
                # Create XZ compressed file
                result = subprocess.run(
                    ['xz', '-zk', filepath],
                    capture_output=True,
                    text=True,
                    check=True
                )
                print(f"Created compressed file: {xz_file}")

                # Generate checksum for compressed file
                sha256 = hashlib.sha256()
                with open(xz_file, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b''):
                        sha256.update(chunk)

                checksum = sha256.hexdigest()

                # Write checksum file for compressed version
                checksum_file = f"{xz_file}.sha256sum"
                with open(checksum_file, 'w') as f:
                    f.write(f"{checksum}  {filename}.xz\n")
                print(f"Generated compressed checksum: {checksum_file}")

            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to compress {filename}: {e}")
                print("Make sure 'xz' is installed (apt-get install xz-utils)")

    def generate_statistics(self):
        """Generate statistics file"""
        stats_file = os.path.join(self.output_dir, 'china_ip_stats.json')

        import json
        stats = {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'ipv4': {
                'total_ranges': len(self.ipv4_ranges),
                'first_range': self.ipv4_ranges[0] if self.ipv4_ranges else None,
                'last_range': self.ipv4_ranges[-1] if self.ipv4_ranges else None
            },
            'ipv6': {
                'total_ranges': len(self.ipv6_ranges),
                'first_range': self.ipv6_ranges[0] if self.ipv6_ranges else None,
                'last_range': self.ipv6_ranges[-1] if self.ipv6_ranges else None
            },
            'source': self.apnic_url
        }

        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Generated statistics: {stats_file}")

def main():
    parser = argparse.ArgumentParser(description='Parse APNIC data for China IP ranges')
    parser.add_argument('--output-dir', default='.', help='Output directory for files')
    parser.add_argument('--skip-download', action='store_true', help='Skip downloading APNIC data')
    parser.add_argument('--input-file', default='apnic-data.txt', help='Input APNIC data file')
    parser.add_argument('--no-compress', action='store_true', help='Skip creating compressed files')
    parser.add_argument('--no-checksum', action='store_true', help='Skip generating checksums')

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize parser
    apnic_parser = APNICParser(args.output_dir)

    # Download or use existing data
    if args.skip_download:
        apnic_file = os.path.join(args.output_dir, args.input_file)
        if not os.path.exists(apnic_file):
            print(f"Error: Input file {apnic_file} not found")
            sys.exit(1)
    else:
        apnic_file = apnic_parser.download_apnic_data(args.input_file)

    # Parse APNIC data
    apnic_parser.parse_apnic_file(apnic_file)

    # Write IP ranges
    apnic_parser.write_ranges()

    # Generate checksums
    if not args.no_checksum:
        apnic_parser.generate_checksums()

    # Create compressed files
    if not args.no_compress:
        apnic_parser.create_compressed_files()

    # Generate statistics
    apnic_parser.generate_statistics()

    print("\nAll files generated successfully!")

if __name__ == '__main__':
    main()