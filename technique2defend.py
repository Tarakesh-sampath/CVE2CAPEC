import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


TECHNIQUES_FILE = "resources/techniques_db.json"
DEFEND_FILE = "resources/defend_db.jsonl"
CVE_FILE = "results/new_cves.jsonl"


def save_jsonl(cve_tech_data: dict):
    """Write results to new_cves.jsonl and update per-year database files."""
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_tech_data.items():
            f.write(json.dumps({cve: data}) + "\n")

    new_cves = {}
    for cve, data in cve_tech_data.items():
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


def process_single_cve(cve: str, defend_list: dict, cve_tech_data: dict) -> list[dict]:
    """
    Resolve D3FEND entries for each ATT&CK technique linked to a CVE.
    TECHNIQUES is now a list of dicts: [{id, name, tactics}, ...]
    Returns a deduplicated list of D3FEND dicts: [{id, tactic, technique, artifact}]
    """
    defends = []
    seen = set()

    for tech in cve_tech_data[cve].get("TECHNIQUES", []):
        # Support both old format (plain string) and new format (dict)
        technique_id = tech["id"] if isinstance(tech, dict) else tech
        defend_key = "T" + technique_id

        for entry in defend_list.get(defend_key, []):
            dedup_key = (entry.get("id"), entry.get("artifact"))
            if dedup_key not in seen:
                seen.add(dedup_key)
                defends.append(entry)

    return defends


def process_techniques(cve_tech_data: dict, defend_list: dict, cve_year: str):
    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(process_single_cve, cve, defend_list, cve_tech_data): cve
            for cve in tqdm(cve_tech_data, desc=f"Processing TECHNIQUES to DEFEND for CVE-{cve_year}", unit="CVE")
        }
        for future in as_completed(futures):
            cve = futures[future]
            try:
                cve_tech_data[cve]["DEFEND"] = future.result()
            except Exception as exc:
                print(f"CVE {cve} generated an exception: {exc}")
                cve_tech_data[cve]["DEFEND"] = []


if __name__ == "__main__":
    file = sys.argv[1] if len(sys.argv) == 2 else CVE_FILE

    cve_tech_data = {}
    with open(file, 'r') as f:
        for line in f:
            cve_entry = json.loads(line.strip())
            cve_tech_data.update(cve_entry)

    if cve_tech_data:
        defend_list = {}
        with open(DEFEND_FILE, 'r') as f:
            for line in f:
                defend_entry = json.loads(line.strip())
                defend_list.update(defend_entry)

        cve_year = list(cve_tech_data.keys())[0].split('-')[1]
        process_techniques(cve_tech_data, defend_list, cve_year)
        save_jsonl(cve_tech_data)
    else:
        print("[-] No new vulnerabilities found")