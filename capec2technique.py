import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


CAPEC_FILE = "resources/capec_db.json"
TECHNIQUES_FILE = "resources/techniques_db.json"
CVE_FILE = "results/new_cves.jsonl"


def save_jsonl(cve_capec_data: dict):
    """Write results to new_cves.jsonl and update per-year database files."""
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_capec_data.items():
            f.write(json.dumps({cve: data}) + "\n")

    new_cves = {}
    for cve, data in cve_capec_data.items():
        year = cve.split('-')[1]
        if year not in new_cves:
            new_cves[year] = {}
        new_cves[year][cve] = data

    for year, cves in new_cves.items():
        cve_db = load_db_jsonl(year)
        cve_db.update(cves)
        with open(f'database/CVE-{year}.jsonl', 'w') as f:
            for cve, data in cve_db.items():
                f.write(json.dumps({cve: data}) + "\n")


def load_db_jsonl(cve_year: str) -> dict:
    cve_db = {}
    try:
        with open(f'database/CVE-{cve_year}.jsonl', 'r') as f:
            for line in f:
                cve_entry = json.loads(line.strip())
                cve_db.update(cve_entry)
    except FileNotFoundError:
        cve_db = {}
    return cve_db


def process_single_cve(cve: str, capec_list: dict, techniques_db: dict, cve_capec_data: dict) -> list[dict]:
    """
    For a single CVE, resolve its CAPEC entries to ATT&CK techniques.
    Returns a list of dicts:
        [{"id": "T1059", "name": "...", "tactics": ["execution", ...]}, ...]
    Deduplicates by technique ID.
    """
    seen_ids = set()
    techniques = []

    for capec_id in cve_capec_data[cve].get("CAPEC", []):
        capec_entry = capec_list.get(capec_id, {})
        raw_mappings = capec_entry.get("techniques", "")
        if not raw_mappings:
            continue

        # The stored format is: "NAME:ATTACK:ENTRY <id>:<name>: ..."
        entries = raw_mappings.split("NAME:ATTACK:ENTRY ")[1:]
        for entry in entries:
            infos = entry.split(":")
            technique_id = infos[1] if len(infos) > 1 else ""
            technique_name = infos[2].strip() if len(infos) > 2 else ""

            if not technique_id or technique_id in seen_ids:
                continue
            seen_ids.add(technique_id)

            # Pull tactic(s) from the techniques_db
            tech_meta = techniques_db.get(technique_id, {})
            tactics = tech_meta.get("tactics", [])

            techniques.append({
                "id": technique_id,
                "name": technique_name,
                "tactics": tactics,
            })

    return sorted(techniques, key=lambda x: x["id"])


def process_capec(cve_capec_data: dict, capec_list: dict, techniques_db: dict, cve_year: str):
    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(process_single_cve, cve, capec_list, techniques_db, cve_capec_data): cve
            for cve in tqdm(cve_capec_data, desc=f"Processing CAPEC to TECHNIQUES for CVE-{cve_year}", unit="CVE")
        }
        for future in as_completed(futures):
            cve = futures[future]
            try:
                cve_capec_data[cve]["TECHNIQUES"] = future.result()
            except Exception as exc:
                print(f"CVE {cve} generated an exception: {exc}")
                cve_capec_data[cve]["TECHNIQUES"] = []


if __name__ == "__main__":
    file = sys.argv[1] if len(sys.argv) == 2 else CVE_FILE

    cve_capec_data = {}
    with open(file, 'r') as f:
        for line in f:
            cve_entry = json.loads(line.strip())
            cve_capec_data.update(cve_entry)

    if cve_capec_data:
        with open(CAPEC_FILE, 'r') as f:
            capec_list = json.load(f)

        with open(TECHNIQUES_FILE, 'r') as f:
            techniques_db = json.load(f)

        cve_year = list(cve_capec_data.keys())[0].split('-')[1]
        process_capec(cve_capec_data, capec_list, techniques_db, cve_year)
        save_jsonl(cve_capec_data)
    else:
        print("[-] No new vulnerabilities found")