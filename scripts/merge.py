#!/usr/bin/env python3
"""
Fetches OISD Big and HaGeZi Pro++ adblock lists,
merges them, removes duplicates, sorts, and writes a combined blocklist.
"""

import requests
import datetime
import sys
import os

SOURCES = {
    "OISD Big": "https://big.oisd.nl",
    "HaGeZi Pro++": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
}

OUTPUT_FILE = "blocklist.txt"
TITLE = "Combined OISD + HaGeZi Blocklist"
DESCRIPTION = (
    "Merged and deduplicated combination of OISD Big and HaGeZi Pro++ DNS blocklists. "
    "Blocks Ads, Tracking, Malware, Phishing, Scam, and more."
)
# Update this to your actual repo URL after creation
HOMEPAGE = "https://github.com/lakshits11/adblocklist"


def fetch_list(name: str, url: str) -> str:
    """Download a filter list with retries."""
    print(f"[*] Fetching {name} from {url} ...")
    for attempt in range(3):
        try:
            resp = requests.get(url, timeout=120)
            resp.raise_for_status()
            size_kb = len(resp.content) / 1024
            print(f"    Downloaded {size_kb:.0f} KB")
            return resp.text
        except requests.RequestException as e:
            print(f"    Attempt {attempt + 1} failed: {e}")
            if attempt == 2:
                print(f"[!] FATAL: Could not fetch {name}")
                sys.exit(1)


def parse_rules(raw_text: str) -> set:
    """
    Extract filter rules from raw list text.
    Skips blank lines, comments (!), and the [Adblock Plus] header.
    """
    rules = set()
    for line in raw_text.splitlines():
        line = line.strip()
        # Skip empty lines, comments, and header
        if not line or line.startswith("!") or line.startswith("["):
            continue
        rules.add(line)
    return rules


def build_header(entry_count: int, duplicates_removed: int, sources_info: dict) -> str:
    """Generate the Adblock Plus format header."""
    now = datetime.datetime.now(datetime.timezone.utc)

    source_lines = ""
    for name, info in sources_info.items():
        source_lines += f"!   - {name}: {info['count']} entries\n"

    header = (
        f"[Adblock Plus]\n"
        f"! Title: {TITLE}\n"
        f"! Description: {DESCRIPTION}\n"
        f"! Homepage: {HOMEPAGE}\n"
        f"! Expires: 12 hours\n"
        f"! Last modified: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"! Version: {now.strftime('%Y%m%d%H%M')}\n"
        f"! Entries: {entry_count}\n"
        f"! Duplicates removed: {duplicates_removed}\n"
        f"!\n"
        f"! Sources:\n"
        f"{source_lines}"
        f"!\n"
        f"! This list is auto-generated. Do not edit manually.\n"
        f"!"
    )
    return header


def main():
    all_rules = set()
    total_before_dedup = 0
    sources_info = {}

    # Fetch and parse each source
    for name, url in SOURCES.items():
        raw = fetch_list(name, url)
        rules = parse_rules(raw)
        count = len(rules)
        total_before_dedup += count
        sources_info[name] = {"url": url, "count": count}
        all_rules.update(rules)
        print(f"    Parsed {count} unique rules from {name}")

    duplicates_removed = total_before_dedup - len(all_rules)

    print(f"\n[*] Summary:")
    print(f"    Total rules (before dedup): {total_before_dedup}")
    print(f"    Duplicates removed:         {duplicates_removed}")
    print(f"    Final unique rules:         {len(all_rules)}")

    # Sort case-insensitively
    sorted_rules = sorted(all_rules, key=lambda r: r.lower())

    # Build output
    header = build_header(len(sorted_rules), duplicates_removed, sources_info)

    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), OUTPUT_FILE)
    # If run from repo root, just use OUTPUT_FILE directly
    if not os.path.isdir(os.path.dirname(output_path) or "."):
        output_path = OUTPUT_FILE

    with open(OUTPUT_FILE, "w", newline="\n", encoding="utf-8") as f:
        f.write(header + "\n")
        for rule in sorted_rules:
            f.write(rule + "\n")

    final_size = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"\n[✓] Written {len(sorted_rules)} rules to {OUTPUT_FILE} ({final_size:.1f} MB)")


if __name__ == "__main__":
    main()
