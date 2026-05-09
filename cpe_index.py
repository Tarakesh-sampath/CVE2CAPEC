"""
cpe_index.py
------------
Builds / updates a product-centric vulnerability history.

Modes:
  (no args)          Read from ALL database/CVE-*.jsonl  — full index rebuild
  2023 2024          Read from specific year files only
  --from-results     Read from results/new_cves.jsonl    — daily incremental update

Output : database/products/{vendor}/{product}.jsonl
         One line per CVE that affects that product, sorted chronologically.
         Existing files are merged (never overwritten from scratch) so the
         daily incremental mode is safe to run repeatedly.

Record format:
{
  "cve": "CVE-2024-1234",
  "version": "2.14.1",
  "published": "...",
  "lastModified": "...",
  "description": "...",
  "cvssScore": 9.8,
  "cvsseSeverity": "CRITICAL",
  "CWE": ["79"],
  "CAPEC": ["86"],
  "TECHNIQUES": [{"id": "T1059", "name": "...", "tactics": ["execution"]}],
  "DEFEND": [{"id": "D3-...", "tactic": "...", "technique": "...", "artifact": "..."}]
}
"""

import json
import os
import sys
import glob
from collections import defaultdict
from tqdm import tqdm


DATABASE_DIR = "database"
PRODUCTS_DIR = os.path.join(DATABASE_DIR, "products")
RESULTS_FILE = "results/new_cves.jsonl"


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------

def iter_results_file():
    """Yield (cve_id, data) from results/new_cves.jsonl."""
    if not os.path.exists(RESULTS_FILE):
        print(f"[-] Results file not found: {RESULTS_FILE}")
        return
    with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            for cve_id, data in entry.items():
                yield cve_id, data


def iter_cve_database(years: list[str] | None = None):
    """Yield (cve_id, data) from database/CVE-{year}.jsonl files."""
    pattern = os.path.join(DATABASE_DIR, "CVE-*.jsonl")
    files = sorted(glob.glob(pattern))

    if years:
        files = [f for f in files if any(f"CVE-{y}.jsonl" in f for y in years)]

    if not files:
        print(f"[-] No database files found matching {pattern}")
        return

    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                for cve_id, data in entry.items():
                    yield cve_id, data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_product_record(cve_id: str, version: str, data: dict) -> dict:
    return {
        "cve": cve_id,
        "version": version,
        "published": data.get("published", ""),
        "lastModified": data.get("lastModified", ""),
        "description": data.get("description", ""),
        "cvssScore": data.get("cvssScore"),
        "cvsseSeverity": data.get("cvsseSeverity"),
        "CWE": data.get("CWE", []),
        "CAPEC": data.get("CAPEC", []),
        "TECHNIQUES": data.get("TECHNIQUES", []),
        "DEFEND": data.get("DEFEND", []),
    }


def load_existing_product(vendor: str, product: str) -> dict[tuple, dict]:
    """
    Load an existing product JSONL into a dict keyed by (cve, version).
    Used to merge new records without creating duplicates.
    """
    filepath = os.path.join(PRODUCTS_DIR, vendor, f"{product}.jsonl")
    existing = {}
    if not os.path.exists(filepath):
        return existing
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            key = (record.get("cve"), record.get("version"))
            existing[key] = record
    return existing


def write_product_file(vendor: str, product: str, records: dict[tuple, dict]):
    """Write merged records for a vendor/product pair, sorted chronologically."""
    product_dir = os.path.join(PRODUCTS_DIR, vendor)
    os.makedirs(product_dir, exist_ok=True)
    filepath = os.path.join(product_dir, f"{product}.jsonl")

    sorted_records = sorted(
        records.values(),
        key=lambda r: r.get("published") or "9999"
    )

    with open(filepath, 'w', encoding='utf-8') as f:
        for record in sorted_records:
            f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Core indexer
# ---------------------------------------------------------------------------

def build_index(source_iter, label: str):
    """
    Consume an iterator of (cve_id, data), group by (vendor, product),
    merge with any existing product files, and write the result.
    """
    # Accumulate new records in memory: {(vendor, product): {(cve, version): record}}
    new_by_product: dict[tuple, dict[tuple, dict]] = defaultdict(dict)
    skipped = 0

    print(f"[!] Reading CVE data from {label}...")
    for cve_id, data in tqdm(source_iter, desc="Indexing CVEs", unit="CVE"):
        cpe_entries = data.get("CPE", [])
        if not cpe_entries:
            skipped += 1
            continue

        for cpe in cpe_entries:
            vendor = cpe.get("vendor", "").strip()
            product = cpe.get("product", "").strip()
            version = cpe.get("version", "N/A").strip()
            if not vendor or not product:
                continue
            record = build_product_record(cve_id, version, data)
            new_by_product[(vendor, product)][(cve_id, version)] = record

    if skipped:
        print(f"[!] Skipped {skipped} CVEs with no CPE data (run full rebuild to enrich these)")

    if not new_by_product:
        print("[-] No product data found — make sure the pipeline has run to completion.")
        return

    print(f"[!] Merging into product files for {len(new_by_product)} vendor/product pairs...")
    for (vendor, product), new_records in tqdm(new_by_product.items(), desc="Writing", unit="product"):
        existing = load_existing_product(vendor, product)
        existing.update(new_records)  # new data wins
        write_product_file(vendor, product, existing)

    print(f"[+] Product index updated under {PRODUCTS_DIR}/")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--from-results" in sys.argv:
        # Daily incremental: only process today's results/new_cves.jsonl
        build_index(iter_results_file(), label=RESULTS_FILE)
    else:
        # Full rebuild from database files, optionally filtered by year
        years = [a for a in sys.argv[1:] if a.isdigit()]
        label = f"database years: {', '.join(years)}" if years else "all database files"
        build_index(iter_cve_database(years or None), label=label)