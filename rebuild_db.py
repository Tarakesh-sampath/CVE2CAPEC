"""
rebuild_db.py
-------------
Full historical rebuild of the CVE database from scratch.

What it does:
  1. Fetches ALL CVEs from NVD since 1999-01-01 (when CVEs began) to today,
     automatically chunking into 119-day windows to respect the API limit.
  2. Processes each year's CVEs through the full pipeline:
       CVE → CWE hierarchy → CAPEC → ATT&CK Techniques (with tactics) → D3FEND
  3. Writes per-year database files:  database/CVE-{year}.jsonl
  4. Builds the product-centric index: database/products/{vendor}/{product}.jsonl
  5. Updates lastUpdate.txt to today so the daily job continues from here.

Usage:
    uv run python rebuild_db.py

    # Start from a specific year (useful to resume a failed run):
    uv run python rebuild_db.py --from 2010

    # Only rebuild specific years (does not re-fetch; reprocesses existing data):
    uv run python rebuild_db.py --years 2022 2023 2024

Notes:
  - The reference databases (CWE, CAPEC, ATT&CK, D3FEND) must already be
    up to date before running this. Run the update_* scripts first.
  - With an NVD API key (~50 req/30s) a full rebuild takes roughly 2-4 hours.
  - Without an API key (~5 req/30s) expect 10-20 hours.
  - The script is safe to interrupt and resume with --from <year>.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from tqdm import tqdm

# Reuse all logic from the existing pipeline scripts
from retrieve_cve import parse_cves, format_nvd_timestamp, MAX_WINDOW_DAYS
from cve2cwe import process_cve_to_cwe, load_db as load_cwe_db
from cwe2capec import process_cwe_to_capec, load_db as load_cwe_db_capec
from capec2technique import process_capec
from technique2defend import process_techniques

UPDATE_FILE = "lastUpdate.txt"
DATABASE_DIR = "database"
RESULTS_FILE = "results/new_cves.jsonl"
CAPEC_FILE = "resources/capec_db.json"
TECHNIQUES_FILE = "resources/techniques_db.json"
DEFEND_FILE = "resources/defend_db.jsonl"
PRODUCTS_DIR = os.path.join(DATABASE_DIR, "products")

# CVE programme started in 1999
CVE_EPOCH = datetime(1999, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_capec_db() -> dict:
    with open(CAPEC_FILE, 'r') as f:
        return json.load(f)


def load_techniques_db() -> dict:
    with open(TECHNIQUES_FILE, 'r') as f:
        return json.load(f)


def load_defend_db() -> dict:
    defend_list = {}
    with open(DEFEND_FILE, 'r') as f:
        for line in f:
            entry = json.loads(line.strip())
            defend_list.update(entry)
    return defend_list


def group_by_year(cve_data: dict) -> dict[str, dict]:
    """Split a flat {cve_id: data} dict into {year: {cve_id: data}}."""
    by_year = defaultdict(dict)
    for cve_id, data in cve_data.items():
        year = cve_id.split('-')[1]
        by_year[year][cve_id] = data
    return dict(by_year)


def save_year_jsonl(year: str, cve_data: dict):
    """Merge new CVE data into the existing per-year database file."""
    os.makedirs(DATABASE_DIR, exist_ok=True)
    filepath = os.path.join(DATABASE_DIR, f"CVE-{year}.jsonl")

    # Load existing records so we don't lose older entries
    existing = {}
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    existing.update(entry)

    existing.update(cve_data)  # new data wins (has CPE + full enrichment)

    with open(filepath, 'w') as f:
        for cve_id, data in existing.items():
            f.write(json.dumps({cve_id: data}) + "\n")

    return len(existing)


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


def build_cpe_index_from(cve_data: dict):
    """
    Incrementally update the product index from a dict of enriched CVE records.
    Loads existing product files, merges, and rewrites — so it's safe to call
    repeatedly without duplicating entries.
    """
    # Group new records by (vendor, product)
    new_by_product: dict[tuple, list] = defaultdict(list)

    for cve_id, data in cve_data.items():
        for cpe in data.get("CPE", []):
            vendor = cpe.get("vendor", "").strip()
            product = cpe.get("product", "").strip()
            version = cpe.get("version", "N/A").strip()
            if vendor and product:
                new_by_product[(vendor, product)].append(
                    build_product_record(cve_id, version, data)
                )

    for (vendor, product), new_records in new_by_product.items():
        product_dir = os.path.join(PRODUCTS_DIR, vendor)
        os.makedirs(product_dir, exist_ok=True)
        filepath = os.path.join(product_dir, f"{product}.jsonl")

        # Load existing records keyed by (cve, version)
        existing: dict[tuple, dict] = {}
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        existing[(rec["cve"], rec["version"])] = rec

        for rec in new_records:
            existing[(rec["cve"], rec["version"])] = rec  # new wins

        sorted_records = sorted(
            existing.values(),
            key=lambda r: r.get("published") or "9999"
        )
        with open(filepath, 'w') as f:
            for rec in sorted_records:
                f.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# Pipeline for a batch of CVEs
# ---------------------------------------------------------------------------

def run_pipeline(cve_data: dict, cwe_db: dict, capec_db: dict,
                 techniques_db: dict, defend_db: dict, year: str) -> dict:
    """
    Run the full enrichment pipeline on a dict of CVE records.
    Modifies cve_data in-place and returns it.
    """
    # Step 1: Walk CWE hierarchy
    print(f"  [2/5] Walking CWE hierarchy...")
    process_cve_to_cwe(cve_data, year, cwe_db)
    # reload — process_cve_to_cwe saves to JSONL and we need the updated dict
    with open(RESULTS_FILE, 'r') as f:
        cve_data = {}
        for line in f:
            entry = json.loads(line.strip())
            cve_data.update(entry)

    # Step 2: CWE → CAPEC
    print(f"  [3/5] Resolving CWEs to CAPEC...")
    for cve_id in tqdm(cve_data, desc="  CWE→CAPEC", unit="CVE", leave=False):
        cwe_list = cve_data[cve_id].get("CWE", [])
        cve_data[cve_id]["CAPEC"] = process_cwe_to_capec(cwe_list, cwe_db)

    # Step 3: CAPEC → ATT&CK Techniques (with tactics)
    print(f"  [4/5] Mapping CAPEC to ATT&CK techniques...")
    process_capec(cve_data, capec_db, techniques_db, year)

    # Step 4: Techniques → D3FEND
    print(f"  [5/5] Mapping techniques to D3FEND...")
    process_techniques(cve_data, defend_db, year)

    return cve_data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Full historical CVE database rebuild")
    parser.add_argument("--from", dest="from_year", type=int, default=None,
                        help="Start from this year (e.g. 2010). Skips earlier years.")
    parser.add_argument("--years", nargs="+", type=str, default=None,
                        help="Only process these specific years (space-separated). "
                             "Re-fetches and reprocesses from NVD.")
    args = parser.parse_args()

    today_dt = datetime.now(timezone.utc)

    # Determine the start date for fetching
    if args.from_year:
        start_dt = datetime(args.from_year, 1, 1, tzinfo=timezone.utc)
    else:
        start_dt = CVE_EPOCH

    print("=" * 60)
    print("  CVE2CAPEC — Full Database Rebuild")
    print("=" * 60)
    print(f"  Start : {format_nvd_timestamp(start_dt)}")
    print(f"  End   : {format_nvd_timestamp(today_dt)}")
    print()

    # Pre-load all reference databases once — they don't change during the run
    print("[!] Loading reference databases...")
    cwe_db = load_cwe_db()
    capec_db = load_capec_db()
    techniques_db = load_techniques_db()
    defend_db = load_defend_db()
    print(f"    CWE entries     : {len(cwe_db)}")
    print(f"    CAPEC entries   : {len(capec_db)}")
    print(f"    Technique entries: {len(techniques_db)}")
    print(f"    D3FEND entries  : {len(defend_db)}")
    print()

    # --- Fetch phase ---
    print("[!] Fetching CVEs from NVD (this will take a while)...")
    all_cve_data = parse_cves(start_dt, today_dt)
    print(f"\n[+] Total CVEs fetched: {len(all_cve_data)}")

    if not all_cve_data:
        print("[-] Nothing to process.")
        sys.exit(0)

    # Group by year so we can save incrementally
    by_year = group_by_year(all_cve_data)
    years_sorted = sorted(by_year.keys())

    if args.years:
        years_sorted = [y for y in years_sorted if y in args.years]

    print(f"\n[!] Processing {len(years_sorted)} year(s): {', '.join(years_sorted)}\n")

    os.makedirs("results", exist_ok=True)

    for year in years_sorted:
        cve_year_data = by_year[year]
        print(f"\n{'='*50}")
        print(f"  Year {year} — {len(cve_year_data)} CVEs")
        print(f"{'='*50}")

        # Write raw fetch output to results file (pipeline scripts read from here)
        print(f"  [1/5] Saving raw CVE data...")
        with open(RESULTS_FILE, 'w') as f:
            for cve_id, data in cve_year_data.items():
                f.write(json.dumps({cve_id: data}) + "\n")

        # Run full enrichment pipeline
        enriched = run_pipeline(
            cve_year_data, cwe_db, capec_db, techniques_db, defend_db, year
        )

        # Persist to per-year database file
        total = save_year_jsonl(year, enriched)
        print(f"  [+] database/CVE-{year}.jsonl — {total} total records")

        # Update product index incrementally
        print(f"  [+] Updating product index...")
        build_cpe_index_from(enriched)

    # Update the last-run timestamp so the daily job picks up from today
    with open(UPDATE_FILE, 'w') as f:
        f.write(today_dt.isoformat())

    print(f"\n{'='*60}")
    print(f"  Rebuild complete!")
    print(f"  lastUpdate.txt set to {today_dt.isoformat()}")
    print(f"  Daily runs will now continue from this point.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()