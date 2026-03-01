#!/usr/bin/env python3
"""
Converts GeoLite2 CSV data into a compact binary file for fast IP-to-country lookup.

Input:
    GeoLite2-Country-Blocks-IPv4.csv   (network, geoname_id, ...)
    GeoLite2-Country-Locations-en.csv  (geoname_id, ..., country_iso_code, ...)

Output:
    geoip.dat -- binary file in the following format:

    Header:  "GEO1" (4 bytes) + entryCount (UInt32 BE, 4 bytes)
    Entries: [startIP (UInt32 BE) + endIP (UInt32 BE) + countryCode (UInt16 BE)] x entryCount

    Entries are sorted by startIP for binary search.
    Country code is packed as UInt16: (ord(c1) << 8) | ord(c2), e.g. "CN" -> 0x434E.

Also prints a sorted list of unique country codes to stdout (for embedding in Swift).

Usage:
    python3 build_geoip.py [blocks_csv] [locations_csv] [output_path]

    Defaults:
        blocks_csv    = GeoLite2-Country-Blocks-IPv4.csv
        locations_csv = GeoLite2-Country-Locations-en.csv
        output_path   = "Anywhere Network Extension/geoip.dat"
"""

import csv
import ipaddress
import struct
import sys
import os

# Only include countries with serious internet censorship.
# Users in these countries want domestic traffic to bypass the VPN tunnel
# for better latency while international traffic goes through VLESS.
INCLUDED_COUNTRIES = {"CN", "RU", "IR", "TM", "MM", "BY", "SA", "AE", "VN", "CU"}


def load_locations(path: str) -> dict[int, str]:
    """Load geoname_id -> country_iso_code mapping from locations CSV."""
    mapping: dict[int, str] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            geoname_id = row.get("geoname_id", "").strip()
            country_code = row.get("country_iso_code", "").strip()
            if geoname_id and country_code and len(country_code) == 2:
                mapping[int(geoname_id)] = country_code.upper()
    return mapping


def pack_country(code: str) -> int:
    """Pack a 2-letter country code into a UInt16: (c1 << 8) | c2."""
    return (ord(code[0]) << 8) | ord(code[1])


def cidr_to_range(network_str: str) -> tuple[int, int]:
    """Convert CIDR notation to (start_ip, end_ip) as UInt32."""
    net = ipaddress.IPv4Network(network_str, strict=False)
    return int(net.network_address), int(net.broadcast_address)


def build(blocks_path: str, locations_path: str, output_path: str) -> None:
    locations = load_locations(locations_path)
    print(f"Loaded {len(locations)} country locations", file=sys.stderr)

    entries: list[tuple[int, int, int]] = []  # (startIP, endIP, packedCountry)
    country_codes: set[str] = set()
    skipped = 0

    with open(blocks_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            network = row.get("network", "").strip()
            geoname_id_str = row.get("geoname_id", "").strip()
            # Fall back to registered_country_geoname_id
            if not geoname_id_str:
                geoname_id_str = row.get("registered_country_geoname_id", "").strip()
            if not network or not geoname_id_str:
                skipped += 1
                continue

            geoname_id = int(geoname_id_str)
            country = locations.get(geoname_id)
            if not country or country not in INCLUDED_COUNTRIES:
                skipped += 1
                continue

            start_ip, end_ip = cidr_to_range(network)
            packed = pack_country(country)
            entries.append((start_ip, end_ip, packed))
            country_codes.add(country)

    # Sort by startIP
    entries.sort(key=lambda e: e[0])

    print(f"Processed {len(entries)} entries, skipped {skipped}", file=sys.stderr)
    print(f"Unique countries: {len(country_codes)}", file=sys.stderr)

    # Write binary file
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        # Header: magic "GEO1" + entry count (UInt32 BE)
        f.write(b"GEO1")
        f.write(struct.pack(">I", len(entries)))

        # Entries: startIP (UInt32 BE) + endIP (UInt32 BE) + countryCode (UInt16 BE)
        for start_ip, end_ip, packed_country in entries:
            f.write(struct.pack(">IIH", start_ip, end_ip, packed_country))

    file_size = os.path.getsize(output_path)
    print(f"Written {output_path} ({file_size:,} bytes, {len(entries):,} entries)", file=sys.stderr)

    # Print sorted country codes to stdout for embedding in Swift
    for code in sorted(country_codes):
        print(code)


if __name__ == "__main__":
    blocks = sys.argv[1] if len(sys.argv) > 1 else "GeoLite2-Country-Blocks-IPv4.csv"
    locs = sys.argv[2] if len(sys.argv) > 2 else "GeoLite2-Country-Locations-en.csv"
    output = sys.argv[3] if len(sys.argv) > 3 else "Anywhere Network Extension/geoip.dat"
    build(blocks, locs, output)
