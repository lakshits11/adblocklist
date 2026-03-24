#!/usr/bin/env python3
"""
High-performance blocklist merger.

Architecture (before → after):
  BEFORE:  N sources → N strings → N lists → N sets → 1 merged set → sort → write
  NOW:     N sources (parallel stream) → 1 global set → write

Key improvements:
  • Streaming downloads (iter_lines — no full response in RAM)
  • Single shared set (no per-source copies, no double hashing)
  • Thread-safe batch inserts (lock per 50K lines, not per line)
  • Accurate duplicate count (tracks raw lines, not unique-per-source)
  • Configurable sorting (off by default — it's the #1 CPU cost)
  • Optional DNS-only filtering to cut junk
"""

import requests
import datetime
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────────────────────
#  SOURCES — just paste URLs. Titles are auto-detected from each list header.
# ─────────────────────────────────────────────────────────────────────────────

SOURCES = [
    "https://big.oisd.nl",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/piperun/iploggerfilter/refs/heads/master/filterlist",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt"
    # "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    # "https://example.com/another-list.txt",
]

# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_FILE = "blocklist.txt"
TITLE       = "Combined Blocklist"
DESCRIPTION = (
    "Auto-merged and deduplicated blocklist from multiple sources. "
    "Blocks Ads, Tracking, Malware, Phishing, Scam, and more."
)
HOMEPAGE = "https://github.com/lakshits11/adblocklist"

# ─────────────────────────────────────────────────────────────────────────────
#  PERFORMANCE TUNING  (defaults are safe for GitHub Actions — 7 GB RAM)
# ─────────────────────────────────────────────────────────────────────────────

MAX_WORKERS     = 6         # parallel downloads (keep ≤ 10)
CONNECT_TIMEOUT = 30        # seconds to establish TCP connection
READ_TIMEOUT    = 300       # seconds for entire download
RETRY_ATTEMPTS  = 3         # retries per source
WRITE_CHUNK     = 100_000   # lines per f.write() call
INSERT_BATCH    = 50_000    # rules per lock-acquire during parsing

# ─────────────────────────────────────────────────────────────────────────────
#  OPTIONS
# ─────────────────────────────────────────────────────────────────────────────

SORT_OUTPUT    = False   # sorting 3M rules ≈ 66M comparisons — skip for speed
DNS_RULES_ONLY = False   # True = keep only ||domain^ rules (cuts 20-40% junk)

# ─────────────────────────────────────────────────────────────────────────────
#  INTERNALS — nothing below needs editing
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT   = os.path.dirname(SCRIPT_DIR)
OUTPUT_PATH = os.path.join(REPO_ROOT, OUTPUT_FILE)

# single global set — the core of the new design
_rules = set()
_lock  = threading.Lock()


def _is_rule(line: str) -> bool:
    """
    Fast first-char check: is this a filter rule?
    Rejects blank lines, comments (!), headers ([), host comments (#).
    Optionally rejects non-DNS rules (cosmetic filters etc).
    """
    if not line:
        return False
    if line[0] in ("!", "[", "#"):
        return False
    if DNS_RULES_ONLY and not line.startswith("||"):
        return False
    return True


def fetch_and_parse(url: str) -> dict:
    """
    Stream-download one filter list.
    Rules go DIRECTLY into the global set — no intermediate storage.
    Returns metadata dict only (no rule data).
    """
    meta = {
        "url":       url,
        "title":     urlparse(url).netloc or url,
        "raw_count": 0,           # every line that passed _is_rule (incl dupes)
        "error":     None,
    }

    # ── download with retries ───────────────────────────────────
    resp = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            print(f"  ↓ {url}  (attempt {attempt}/{RETRY_ATTEMPTS})")
            resp = requests.get(
                url,
                stream=True,                            # ← no full body in RAM
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            resp.raise_for_status()
            resp.encoding = "utf-8"
            break
        except requests.RequestException as exc:
            print(f"    attempt {attempt} failed: {exc}")
            if attempt == RETRY_ATTEMPTS:
                meta["error"] = str(exc)
                print(f"    ✗ SKIPPING {url}")
                return meta

    # ── stream-parse into global set ────────────────────────────
    raw_count   = 0
    title_found = False
    batch       = []

    try:
        for raw_line in resp.iter_lines(decode_unicode=True):  # ← streaming
            if not raw_line:
                continue

            line = raw_line.strip()

            # auto-detect title from header (check only until found)
            if not title_found:
                if line.lower().startswith("! title:"):
                    meta["title"] = line.split(":", 1)[1].strip()
                    title_found = True
                    continue

            # fast rejection
            if not _is_rule(line):
                continue

            raw_count += 1
            batch.append(line)

            # batch insert: one lock acquire per INSERT_BATCH lines
            # vs one lock per line = orders of magnitude less contention
            if len(batch) >= INSERT_BATCH:
                with _lock:
                    _rules.update(batch)
                batch = []
    finally:
        resp.close()   # always close streamed response

    # flush remaining
    if batch:
        with _lock:
            _rules.update(batch)

    meta["raw_count"] = raw_count
    print(f"    ✓ {meta['title']} — {raw_count:,} rules streamed")
    return meta


def build_header(total: int, dupes: int, sources: list) -> str:
    """Adblock Plus format header with full provenance."""
    now = datetime.datetime.now(datetime.timezone.utc)

    src_lines = "\n".join(
        f"!   • {s['title']}: {s['raw_count']:,} raw rules"
        + (f"  [FAILED: {s['error']}]" if s["error"] else "")
        for s in sources
    )

    return (
        f"[Adblock Plus]\n"
        f"! Title: {TITLE}\n"
        f"! Description: {DESCRIPTION}\n"
        f"! Homepage: {HOMEPAGE}\n"
        f"! Expires: 12 hours\n"
        f"! Last modified: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"! Version: {now.strftime('%Y%m%d%H%M')}\n"
        f"! Total entries: {total:,}\n"
        f"! Duplicates removed: {dupes:,}\n"
        f"!\n"
        f"! --- Sources ({len(sources)}) ---\n"
        f"{src_lines}\n"
        f"!\n"
        f"! Auto-generated. Do not edit.\n"
        f"!\n"
    )


def write_sorted(path: str, header: str, rules: set):
    """Sort + chunked write. Frees the set before writing."""
    print(f"[*] Sorting {len(rules):,} rules ...")
    sorted_rules = sorted(rules, key=str.lower)
    rules.clear()  # free set memory before writing list

    print(f"[*] Writing {path} ...")
    with open(path, "w", newline="\n", encoding="utf-8") as f:
        f.write(header)
        for i in range(0, len(sorted_rules), WRITE_CHUNK):
            f.write("\n".join(sorted_rules[i : i + WRITE_CHUNK]))
            f.write("\n")

    return len(sorted_rules)


def write_unsorted(path: str, header: str, rules: set):
    """
    Stream directly from set → file. No intermediate list.
    Peak memory = just the set (no second copy).
    """
    total = len(rules)
    print(f"[*] Writing {path} (unsorted) ...")

    with open(path, "w", newline="\n", encoding="utf-8") as f:
        f.write(header)
        batch = []
        for rule in rules:
            batch.append(rule)
            if len(batch) >= WRITE_CHUNK:
                f.write("\n".join(batch))
                f.write("\n")
                batch.clear()
        if batch:
            f.write("\n".join(batch))
            f.write("\n")

    rules.clear()
    return total


def main():
    if not SOURCES:
        print("[!] No sources configured. Add URLs to the SOURCES list.")
        sys.exit(1)

    n = len(SOURCES)
    print(f"\n{'=' * 60}")
    print(f"  Blocklist Merger — {n} source{'s' if n != 1 else ''}")
    print(f"  Sort: {'ON' if SORT_OUTPUT else 'OFF'}  |  "
          f"DNS-only filter: {'ON' if DNS_RULES_ONLY else 'OFF'}")
    print(f"{'=' * 60}\n")

    # ── 1. Parallel streaming fetch + parse ─────────────────────
    metas = []
    workers = min(MAX_WORKERS, n)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_and_parse, url): url for url in SOURCES}
        for future in as_completed(futures):
            metas.append(future.result())

    metas.sort(key=lambda m: m["title"].lower())

    # ── 2. Stats (accurate: raw_count includes intra-source dupes) ──
    total_raw = sum(m["raw_count"] for m in metas)
    unique    = len(_rules)
    dupes     = total_raw - unique
    ok        = sum(1 for m in metas if not m["error"])

    print(f"\n{'─' * 60}")
    print(f"  Sources succeeded : {ok}/{n}")
    print(f"  Total raw rules   : {total_raw:,}")
    print(f"  Duplicates removed: {dupes:,}  (intra + inter source)")
    print(f"  Final unique rules: {unique:,}")
    print(f"{'─' * 60}\n")

    if not _rules:
        print("[!] No rules collected. Aborting.")
        sys.exit(1)

    # ── 3. Build header ─────────────────────────────────────────
    header = build_header(unique, dupes, metas)

    # ── 4. Write (sorted or streamed-unsorted) ──────────────────
    if SORT_OUTPUT:
        count = write_sorted(OUTPUT_PATH, header, _rules)
    else:
        count = write_unsorted(OUTPUT_PATH, header, _rules)

    size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)

    print(f"\n{'=' * 60}")
    print(f"  ✓ {count:,} rules → {OUTPUT_FILE} ({size_mb:.1f} MB)")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
