# Project Summary

## Directory Structure

```
/
    update_cwe_db.py
    _generate_project_summary.py
    cve2cwe.py
    update_defend_db.py
    README.md
    retrieve_cve.py
    update_technique_db.py
    cwe2capec.py
    capec2technique.py
    update_capec_db.py
    cpe_index.py
    rebuild_db.py
    technique2defend.py
docs/
    css/
    mitre/
        README.md
        layers/
            README.md
            samples/
                ATTACKcon 2018/
            spec/
                v4.1/
                v4.5/
                v1.3/
                v4.3/
                v1.0/
                v1.1/
                v2.1/
                v3.0/
                v1.2/
                v2.0/
                v4.0/
                v4.4/
                v4.2/
                v2.2/
        assets/
            icons/
    js/
```

## File: update_cwe_db.py

```py
import requests
import os
from zipfile import ZipFile
import re
from xml.dom import minidom
import json


CWE_FILE = "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_JSON_PATH = "resources/cwe_db.json"


# Download and extract CWE data
def download_cwe():
    response = requests.get(CWE_FILE)
    if response.status_code != 200:
        raise Exception("Failed to download CAPEC relation file")
    with open("cwec_latest.xml.zip", 'wb') as f:
        f.write(response.content)
    with ZipFile("cwec_latest.xml.zip", 'r') as zip_ref:
        zip_ref.extractall()
    os.remove("cwec_latest.xml.zip")
    file_name = re.search(r"cwec_v[\d\.]+\.xml", " ".join(os.listdir())).group()
    file = minidom.parse(file_name)
    os.remove(file_name)
    return file


# Format CWE data and save to JSON file
def format_cwe(cwe_list: minidom.Document):
    relations = cwe_list.getElementsByTagName("Weakness")
    results = {}
    for relation in relations:
        cwe_id = relation.getAttribute("ID")
        results[cwe_id] = {"ChildOf": set(), "RelatedAttackPatterns": set()}
        related_weaknesses = relation.getElementsByTagName("Related_Weaknesses")
        related_attack_patterns = relation.getElementsByTagName("Related_Attack_Patterns")
        
        if related_weaknesses:
            related_weaknesses = related_weaknesses[0].getElementsByTagName("Related_Weakness")
            for weakness in related_weaknesses:
                if weakness.getAttribute("Nature") == "ChildOf" and weakness.getAttribute("View_ID") == "1000":
                    results[cwe_id]["ChildOf"].add(weakness.getAttribute("CWE_ID"))
        else:
            results[cwe_id]["ChildOf"] = []

        if related_attack_patterns:
            related_attack_patterns = related_attack_patterns[0].getElementsByTagName("Related_Attack_Pattern")
            for attack_pattern in related_attack_patterns:
                results[cwe_id]["RelatedAttackPatterns"].add(attack_pattern.getAttribute("CAPEC_ID"))
        else:
            results[cwe_id]["RelatedAttackPatterns"] = []
    
    for cwe in results:
        results[cwe]["ChildOf"] = list(results[cwe]["ChildOf"])
        results[cwe]["RelatedAttackPatterns"] = list(results[cwe]["RelatedAttackPatterns"])
    
    with open(CWE_JSON_PATH, 'w') as f:
        f.write(json.dumps(results, indent=4))


if __name__ == "__main__":
    print("[!] Téléchargement des données CWE...")
    cwe_list = download_cwe()
    print("[!] Mise à jour des données CWE...")
    format_cwe(cwe_list)
```

## File: _generate_project_summary.py

```py
import os
from typing import Set

# ---------------- CONFIG ---------------- #

INCLUDE_DIRS: Set[str] = {
    "docs",
}

INCLUDE_EXTS: Set[str] = {
    ".py",
}

INCLUDE_FILES: Set[str] = {
    "README.md",
}

EXCLUDE_EXTS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".pyc",
    ".so",
    ".exe",
}

# ---------------- HELPERS ---------------- #

def is_allowed_file(filename: str) -> bool:
    if filename.startswith("."):
        return False

    ext = os.path.splitext(filename)[1].lower()

    if filename in INCLUDE_FILES:
        return True

    if ext in EXCLUDE_EXTS:
        return False

    return ext in INCLUDE_EXTS


# ---------------- DIRECTORY STRUCTURE ---------------- #

def get_directory_structure(root_dir: str) -> str:
    lines = []

    for root, dirs, files in os.walk(root_dir):
        rel_root = os.path.relpath(root, root_dir)

        if root != root_dir:
            path_parts = rel_root.split(os.sep)
            if path_parts[0] not in INCLUDE_DIRS:
                dirs[:] = []
                continue

        if root == root_dir:
            dirs[:] = [d for d in dirs if d in INCLUDE_DIRS]

        level = root.replace(root_dir, "").count(os.sep)
        indent = " " * 4 * level
        lines.append(f"{os.path.basename(root) if root == root_dir else indent + os.path.basename(root)}/")

        sub_indent = " " * 4 * (level + 1)

        for f in files:
            if is_allowed_file(f):
                lines.append(f"{sub_indent}{f}")

    return "\n".join(lines)


# ---------------- FILE CONTENTS ---------------- #

def get_file_contents(root_dir: str) -> str:
    content_blocks = []

    for root, dirs, files in os.walk(root_dir):
        rel_root = os.path.relpath(root, root_dir)

        if root != root_dir:
            path_parts = rel_root.split(os.sep)
            if path_parts[0] not in INCLUDE_DIRS:
                dirs[:] = []
                continue

        if root == root_dir:
            dirs[:] = [d for d in dirs if d in INCLUDE_DIRS]

        for f in files:
            if not is_allowed_file(f):
                continue

            file_path = os.path.join(root, f)
            rel_path = os.path.relpath(file_path, root_dir)

            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read()

                ext = os.path.splitext(f)[1].lstrip(".") or "text"

                content_blocks.append(
                    f"## File: {rel_path}\n\n```{ext}\n{content}\n```\n"
                )

            except (UnicodeDecodeError, PermissionError):
                continue

    return "\n".join(content_blocks)


# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    root = "./"
    output_file = "./project_summary.md"

    structure = get_directory_structure(root)
    contents = get_file_contents(root)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Project Summary\n\n")
        f.write("## Directory Structure\n\n```\n")
        f.write(structure)
        f.write("\n```\n\n")
        f.write(contents)

    print(f"Generated {output_file}")
```

## File: cve2cwe.py

```py
import json
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

session = requests.Session()
CWE_FILE = "resources/cwe_db.json"
CVE_FILE = "results/new_cves.jsonl"
RETRY_LIMIT = 3  # Retry limit for HTTP requests
MAX_THREADS = 10  # Maximum number of threads for concurrent processing

def get_parent_cwe(cwe: str, cwe_db: dict):
    cwe_list = set()
    try:
        result = cwe_db.get(cwe, {})
        if result.get("ChildOf", []):
            for related_cwe in result["ChildOf"]:
                cwe_list.add(related_cwe)
            return cwe_list
        else:
            return None
    except Exception as e:
        print(f"Exception occurred for CWE-{cwe}: {e}")
    return None

# Process each CVE to extract the related CWE entries
def process_cve_to_cwe(cve_cwe_data, cve_year, cwe_db):
    cwe_list = {}

    def process_single_cve(cve, cwe_db):
        cwe_set = set()  # Use a set to avoid duplicates
        for cwe in cve_cwe_data[cve]['CWE']:
            cwe_set.add(cwe)
            child_cwe = get_parent_cwe(cwe, cwe_db)
            
            # Use queue to process all parent CWEs
            queue = list(child_cwe) if child_cwe else []

            while queue:
                current_cwe = queue.pop(0)
                if current_cwe not in cwe_set: 
                    cwe_set.add(current_cwe)
                    new_children = get_parent_cwe(current_cwe, cwe_db)
                    if new_children:
                        # Add new children to the queue
                        queue.extend(new_children)

        return {cve: {"CWE": list(sorted(cwe_set))}}

    # Process each CVE concurrently
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(process_single_cve, cve, cwe_db): cve for cve in cve_cwe_data}
        for future in tqdm(as_completed(futures), total=len(futures), desc=f"Processing CVEs for CVE-{cve_year}", unit="CVE"):
            cve = futures[future]
            try:
                result = future.result()
                cwe_list.update(result)
            except Exception as exc:
                print(f"CVE {cve} generated an exception: {exc}")

    save_jsonl(cwe_list)


def load_db():
    with open(CWE_FILE, 'r') as f:
        cwe_db = json.load(f)
    return cwe_db


# Save the results to a JSONL file
def save_jsonl(cve_cwe_data):
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_cwe_data.items():
            f.write(json.dumps({cve: data}) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        file = sys.argv[1]
    else:
        file = CVE_FILE

    # Load the JSONL file
    with open(file, 'r') as f:
        cve_cwe_data = {}
        for line in f:
            cve = json.loads(line.strip())
            cve_cwe_data.update(cve)

    if cve_cwe_data:
        cwe_db = load_db()
        
        cve_year = list(cve_cwe_data.keys())[0].split('-')[1]

        process_cve_to_cwe(cve_cwe_data, cve_year, cwe_db)
    else:
        print("[-]No new vulnerabilities found")

```

## File: update_defend_db.py

```py
import json
from tqdm import tqdm
import requests
import os

TECHNIQUES_FILE = 'resources/techniques_db.json'
DEFENDE_SITE = 'https://d3fend.mitre.org/api/offensive-technique/attack/'

def load_techniques():
    try:
        with open(TECHNIQUES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading the data: {str(e)}")
        return None


def update_defend_techniques():
    techniques = load_techniques()
    if techniques:
        file_path = f"resources/defend_db.jsonl"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            for technique_id in tqdm(techniques, desc="Updating D3FEND techniques", unit="technique"):
                defend = {technique_id: []}
                response = requests.get(f"{DEFENDE_SITE}{technique_id}.json")
                if response.status_code == 200:
                    result = response.json()
                    for key in result.get("off_to_def").get("results").get("bindings"):
                        id = key.get("def_tech_id").get("value") if key.get("def_tech_id") else ""
                        tactic = key.get("def_tactic_label").get("value") if key.get("def_tactic_label") else ""
                        technique = key.get("def_tech_label").get("value") if key.get("def_tech_label") else ""
                        artifact = key.get("def_artifact_label").get("value") if key.get("def_artifact_label") else ""
                        entry = {"id": id, "tactic": tactic, "technique": technique, "artifact": artifact}
                        if id and tactic and technique and artifact and entry not in defend[technique_id]:
                            defend[technique_id].append(entry)
                f.write(json.dumps(defend) + '\n')
if __name__ == "__main__":
    update_defend_techniques()
    print("[+] D3FEND techniques updated successfully!")
```

## File: README.md

```md
<a name="readme-top"></a>
<div align="center">
  <h1 align="center">CVE2CAPEC</h1>
  <p align="center">
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-v3.11.9-blue?style=for-the-badge&logo=Python"></a>
    <a href="https://github.com/Galeax/CVE2CAPEC"><img src="https://img.shields.io/badge/Github-35495E?logo=GitHub&style=for-the-badge"></a>
    <a href="https://galeax.github.io/CVE2CAPEC/"><img src="https://img.shields.io/badge/github%20pages-121013?style=for-the-badge&logo=github&logoColor=white"></a>
    <br/><br/>
    Get CVE, CWE, CAPEC, MITRE ATT&CK and MITRE D3FEND Techniques data automatically.
    <br/>
    Try it online at <a href="https://galeax.github.io/CVE2CAPEC/">https://galeax.github.io/CVE2CAPEC/</a>.
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of contents</summary>
  <ol>
    <li><a href="#introduction">Introduction</a></li>
    <li>
      <a href="#installation">Installation</a>
    </li>
    <li><a href="#usage">Usage</a>
      <ul>
        <li><a href="#update-databases">Update databases</a></li>
        <li><a href="#get-new-cves">Get new CVEs</a></li>
        <li><a href="#license">License</a></li>
        <li><a href="#contact">Contact</a></li>
      </ul>
     </li>
  </ol>
</details>

## Explore this repo data with our MITRE ATT&CK and MITRE D3FEND generator

Data generated by this project also serve the interactive MITRE ATT&CK and MITRE D3FEND generator available at <a href="https://galeax.github.io/CVE2CAPEC/">https://galeax.github.io/CVE2CAPEC/</a>.

[<img src="docs/cve2capec-lowdef.gif">](https://galeax.github.io/CVE2CAPEC/)

<p style="text-align:center;"><a href="docs/cve2capec.gif" style="color:#aaaaaa;">click here for HD version</a></p>


## Introduction 

This project allows you to manage get all new CVE with their CWE, CAPEC, [MITRE ATT&CK](https://attack.mitre.org/) and [MITRE D3FEND](https://d3fend.mitre.org/) Techniques.
All CVE data are stored in `database` folder.

**CVE2CAPEC does not need to be run by yourself.**
In fact, github actions update the database every day at 00:05 UTC so you can get the new CVE with all their data in `results/new_cves.jsonl`.

However, if you want to run this project by your own : 

### Installation

```sh
git clone https://github.com/Galeax/CVE2CAPEC.git
cd CVE2CAPEC
pip install -r requirements.txt
```

### Update databases

```sh
python update_capec_db.py
python update_cwe_db.py
python update_technique_db.py
python update_defend_db.py
```

### Build the CVE - CWE - CAPEC - MITRE ATT&CK - MITRE D3FEND Techniques links

 **1. Get new CVEs**
```sh
python retrieve_cve.py
```
**2. Get CWEs from new CVEs**
```sh
python cve2cwe.py
```
**3. Get CAPECs from CWEs**
```sh
python cwe2capec.py
```
**4. Get MITRE ATT&CK Techniques from CAPECs**
```sh
python capec2technique.py
```

**4. Get MITRE D3FEND Techniques from MITRE ATT&CK Techniques**
```sh
python technique2defend.py
```

## License

This project is released under the GNU General Public License version 3 (the GPL).

For commercial use where you need to not be using the GPL, please contact us at `contact [AT] galeax.com` for additional options.

## Contact

Made with ❤️ in 🇫🇷 by <a href="https://galeax.com"><img src="https://galeax.com/wp-content/uploads/2024/01/logo_galeax_blue-e1705315482396.png" width=25%>

```

## File: retrieve_cve.py

```py
import requests
import json
from datetime import datetime, timezone, timedelta
from tqdm import tqdm
from re import match
import os
import time
from dotenv import load_dotenv

load_dotenv()

API_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
API_KEY = os.environ.get("NVD_API_KEY")
UPDATE_FILE = "lastUpdate.txt"
CVE_FILE = "results/new_cves.jsonl"

# NVD enforces a maximum 120-day window per request
MAX_WINDOW_DAYS = 119


def format_nvd_timestamp(dt: datetime) -> str:
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')


def fetch_data_with_retries(session, url, params=None, retries=3, delay=5):
    for attempt in range(1, retries + 1):
        response = session.get(url, params=params)
        if response.status_code == 200:
            return response
        elif 500 <= response.status_code < 600:
            print(f"[-] Failed to download CVE data (attempt {attempt}/{retries}) - Error:{response.status_code}. Retrying in {delay*attempt}s...")
            time.sleep(delay * attempt)
        else:
            raise Exception(f"Failed to download CVE data after {retries} attempts (status code: {response.status_code})")
    raise Exception(f"Failed to download CVE data after {retries} attempts (status code: {response.status_code})")


def parse_cpe_string(cpe: str) -> dict | None:
    """
    Parse a CPE 2.3 string into vendor, product, version components.
    Format: cpe:2.3:part:vendor:product:version:...
    Returns None if the string is not a valid CPE 2.3 entry.
    """
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    vendor = parts[3]
    product = parts[4]
    version = parts[5]
    if vendor == "*" or product == "*":
        return None
    return {
        "vendor": vendor,
        "product": product,
        "version": version if version not in ("*", "-", "") else "N/A"
    }


def extract_cpe_entries(configurations: list) -> list[dict]:
    """
    Walk the configurations block from NVD and collect unique
    vendor/product/version triples marked as vulnerable.
    """
    seen = set()
    results = []
    for node in configurations:
        nodes_to_visit = [node]
        while nodes_to_visit:
            current = nodes_to_visit.pop()
            for cpe_match in current.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                parsed = parse_cpe_string(cpe_match.get("criteria", ""))
                if parsed:
                    key = (parsed["vendor"], parsed["product"], parsed["version"])
                    if key not in seen:
                        seen.add(key)
                        results.append(parsed)
            for child in current.get("nodes", []):
                nodes_to_visit.append(child)
    return results


def build_date_chunks(start_dt: datetime, end_dt: datetime) -> list[tuple[datetime, datetime]]:
    """
    Split a date range into MAX_WINDOW_DAYS-day chunks.
    Returns a list of (chunk_start, chunk_end) datetime pairs.
    """
    chunks = []
    cursor = start_dt
    while cursor < end_dt:
        chunk_end = min(cursor + timedelta(days=MAX_WINDOW_DAYS), end_dt)
        chunks.append((cursor, chunk_end))
        cursor = chunk_end + timedelta(seconds=1)
    return chunks


def fetch_chunk(session, start_dt: datetime, end_dt: datetime) -> dict:
    """
    Fetch all CVEs within a single date window (<= 120 days).
    Returns a dict of {cve_id: data}.
    """
    cve_data = {}
    params = {
        "lastModStartDate": format_nvd_timestamp(start_dt),
        "lastModEndDate": format_nvd_timestamp(end_dt),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    response = fetch_data_with_retries(session, API_CVES, params)
    cves = response.json()
    results_per_page = cves.get("resultsPerPage", 0)
    total_results = cves.get("totalResults", 0)

    if results_per_page == 0 or total_results == 0:
        return cve_data

    nb_pages = (total_results + results_per_page - 1) // results_per_page

    for page in tqdm(range(nb_pages), desc="  Pages", unit="page", leave=False):
        if page > 0:
            params["startIndex"] = page * 2000
            response = fetch_data_with_retries(session, API_CVES, params)
            cves = response.json()
            time.sleep(1)  # be polite between paginated requests

        for cve in cves.get("vulnerabilities", []):
            cve_body = cve.get("cve", {})
            cve_id = cve_body.get("id", "")

            # --- CWE ---
            has_primary_cwe = False
            cwe_list = []
            infos = cve_body.get("weaknesses", [])
            if infos:
                for cwe in infos:
                    if cwe.get("type", "") == "Primary":
                        cwe_code = cwe.get("description", [])[0].get("value", "")
                        if match(r"CWE-\d{1,4}", cwe_code):
                            cwe_list.append(cwe_code.split("-")[1])
                            has_primary_cwe = True
                if not has_primary_cwe:
                    for cwe in infos:
                        if cwe.get("type", "") == "Secondary":
                            cwe_code = cwe.get("description", [])[0].get("value", "")
                            if match(r"CWE-\d{1,4}", cwe_code):
                                cwe_list.append(cwe_code.split("-")[1])

            # --- Metadata ---
            published = cve_body.get("published", "")
            last_modified = cve_body.get("lastModified", "")

            description = ""
            for desc in cve_body.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS: prefer v3.1, fall back to v3.0 then v2.0
            cvss_score = None
            cvss_severity = None
            metrics = cve_body.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = (
                        metric_list[0].get("baseSeverity")
                        or cvss_data.get("baseSeverity")
                    )
                    break

            # --- CPE ---
            configurations = cve_body.get("configurations", [])
            cpe_entries = extract_cpe_entries(configurations)

            cve_data[cve_id] = {
                "published": published,
                "lastModified": last_modified,
                "description": description,
                "cvssScore": cvss_score,
                "cvsseSeverity": cvss_severity,
                "CWE": cwe_list,
                "CPE": cpe_entries,
            }

    return cve_data


def parse_cves(start_dt: datetime, end_dt: datetime) -> dict:
    """
    Fetch all CVEs between start_dt and end_dt, automatically chunking
    into MAX_WINDOW_DAYS-day windows to satisfy the NVD API limit.
    """
    session = requests.Session()
    if API_KEY:
        session.headers.update({"apiKey": API_KEY})

    chunks = build_date_chunks(start_dt, end_dt)
    all_cve_data = {}

    print(f"[!] Fetching CVEs from {format_nvd_timestamp(start_dt)} → {format_nvd_timestamp(end_dt)}")
    print(f"[!] {len(chunks)} chunk(s) of up to {MAX_WINDOW_DAYS} days each\n")

    for i, (chunk_start, chunk_end) in enumerate(chunks, 1):
        print(f"[>] Chunk {i}/{len(chunks)}: {format_nvd_timestamp(chunk_start)} → {format_nvd_timestamp(chunk_end)}")
        try:
            chunk_data = fetch_chunk(session, chunk_start, chunk_end)
            all_cve_data.update(chunk_data)
            print(f"    +{len(chunk_data)} CVEs  |  running total: {len(all_cve_data)}")
        except Exception as e:
            print(f"[-] Chunk {i} failed: {e} — skipping")

        # Stay within NVD rate limits: 50 req/30s with key, 5 req/30s without
        if i < len(chunks):
            time.sleep(2 if API_KEY else 8)

    return all_cve_data


def save_jsonl(cve_data: dict, today_iso: str):
    os.makedirs(os.path.dirname(CVE_FILE), exist_ok=True)
    with open(CVE_FILE, 'w', encoding='utf-8') as f:
        for cve, data in cve_data.items():
            f.write(json.dumps({cve: data}) + "\n")

    with open(UPDATE_FILE, 'w', encoding='utf-8') as f:
        f.write(today_iso)


if __name__ == "__main__":
    today_dt = datetime.now(timezone.utc)

    try:
        with open(UPDATE_FILE, 'r') as f:
            last_update_raw = f.read().strip()
        last_update_dt = datetime.fromisoformat(last_update_raw)
    except Exception as e:
        print(f"[!] Failed to parse last update date: {e}. Using fallback date.")
        last_update_dt = datetime(2021, 1, 1, tzinfo=timezone.utc)

    cves_data = parse_cves(last_update_dt, today_dt)

    if cves_data:
        save_jsonl(cves_data, today_dt.isoformat())
        print(f"\n[+] Saved {len(cves_data)} CVEs to {CVE_FILE}")
    else:
        print("[-] No new vulnerabilities found")
```

## File: update_technique_db.py

```py
import json
import pandas as panda

TECHNIQUES_ENTERPRISE_FILE_URL = "https://attack.mitre.org/docs/attack-excel-files/v19.0/enterprise-attack/enterprise-attack-v19.0-techniques.xlsx"
TECHNIQUES_MOBILE_FILE_URL = "https://attack.mitre.org/docs/attack-excel-files/v19.0/mobile-attack/mobile-attack-v19.0-techniques.xlsx"
TECHNIQUES_ICS_FILE_URL = "https://attack.mitre.org/docs/attack-excel-files/v19.0/ics-attack/ics-attack-v19.0-techniques.xlsx"
TECHNIQUES_FILE = "resources/techniques_db.json"

# Column indices within each ATT&CK Excel file:
#   Enterprise : col 0 = ID,  col 9  = CAPEC mappings, col 4 = tactic
#   Mobile     : col 0 = ID,  col 10 = CAPEC mappings, col 4 = tactic
#   ICS        : col 0 = ID,  col 9  = CAPEC mappings, col 4 = tactic
#
# The tactic column contains a comma-separated list of tactic short-names
# (e.g. "execution, persistence").  We keep all of them.

DOMAIN_CONFIG = {
    "enterprise": {
        "url": TECHNIQUES_ENTERPRISE_FILE_URL,
        "capec_col": 9,
        "tactic_col": 4,
    },
    "mobile": {
        "url": TECHNIQUES_MOBILE_FILE_URL,
        "capec_col": 10,
        "tactic_col": 4,
    },
    "ics": {
        "url": TECHNIQUES_ICS_FILE_URL,
        "capec_col": 9,
        "tactic_col": 4,
    },
}


def download_techniques(url: str, capec_col: int, tactic_col: int) -> dict | None:
    """
    Download an ATT&CK techniques Excel file and return a dict keyed by
    technique ID.  Each value is:
        {
            "capec": ["CAPEC-ID", ...],   # split from the mapped column
            "tactics": ["tactic-name", ...]
        }
    Raw file is never written to disk.
    """
    try:
        data = panda.read_excel(url)
        result = {}
        for i in range(len(data)):
            technique_id = data.iloc[i, 0]

            # --- CAPEC mappings ---
            raw_capec = data.iloc[i, capec_col]
            if panda.isna(raw_capec) or str(raw_capec).strip() == "":
                capec_list = []
            else:
                capec_list = [c.strip() for c in str(raw_capec).split(",") if c.strip()]

            # --- Tactic(s) ---
            raw_tactic = data.iloc[i, tactic_col]
            if panda.isna(raw_tactic) or str(raw_tactic).strip() == "":
                tactic_list = []
            else:
                tactic_list = [t.strip() for t in str(raw_tactic).split(",") if t.strip()]

            result[technique_id] = {
                "capec": capec_list,
                "tactics": tactic_list,
            }
        return result
    except Exception as e:
        print(f"Error downloading the data from {url}: {str(e)}")
        return None


def save_json(data: dict):
    with open(TECHNIQUES_FILE, 'w') as f:
        json.dump(data, f, indent=4)


if __name__ == "__main__":
    combined = {}
    for domain, cfg in DOMAIN_CONFIG.items():
        print(f"[!] Downloading {domain} techniques...")
        result = download_techniques(cfg["url"], cfg["capec_col"], cfg["tactic_col"])
        if result:
            # Later domains overwrite earlier ones on ID clash — IDs are unique
            # across domains so this is safe.
            combined.update(result)

    if combined:
        print("[!] Saving techniques data...")
        save_json(combined)
        print(f"[+] {len(combined)} techniques saved to {TECHNIQUES_FILE}")
    else:
        print("[-] No technique data downloaded")
```

## File: cwe2capec.py

```py
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


CWE_FILE = "resources/cwe_db.json"
CVE_FILE = "results/new_cves.jsonl"

# Retrive the CAPEC entries related to a CWE
def fetch_capec_for_cwe(cwe: str, cwe_db: dict):
    try:
        result = cwe_db.get(cwe, {})
        capec_list = result.get("RelatedAttackPatterns", [])
        return capec_list if capec_list else []  
    except Exception as e:
        print(f"Exception for CWE-{cwe}: {str(e)}")
        return []


# Process each CWE to extract the related CAPEC entries
def process_cwe_to_capec(cwe_list, cwe_db):
    list_capec = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_capec_for_cwe, cwe, cwe_db): cwe for cwe in cwe_list}
        for future in as_completed(futures):
            cwe = futures[future]
            try:
                data = future.result()
                list_capec.update(data)
            except Exception as e:
                print(f"Error processing CWE-{cwe}: {str(e)}")
    return list(list_capec)


# Save the results to a JSONL file
def save_jsonl(cve_capec_data):
    with open(CVE_FILE, 'w') as f:
        for cve, data in cve_capec_data.items():
            f.write(json.dumps({cve: data}) + "\n")


# Load the CWE database
def load_db():
    with open(CWE_FILE, 'r') as f:
        cwe_db = json.load(f)
    return cwe_db


if __name__ == "__main__":
    if len(sys.argv) == 2:
        file = sys.argv[1]
    else:
        file = CVE_FILE
    
    # Load the JSONL file
    cve_cwe_data = {}
    with open(file, 'r') as f:
        for line in f:
            cve = json.loads(line.strip())
            cve_cwe_data.update(cve)
    
    if cve_cwe_data:
        cwe_db = load_db()
        
        # Get the year of the CVEs
        cve_year = list(cve_cwe_data.keys())[0].split('-')[1]

        # Process each CVE to extract the related CAPEC entries
        cve_capec_data = {}
        for cve in tqdm(cve_cwe_data, desc=f"Processing CWE to CAPEC for CVE-{cve_year}", unit="CVE"):
            cwe_list = cve_cwe_data[cve]["CWE"]
            cve_capec_data[cve] = {"CWE": cwe_list}
            cve_capec_data[cve]["CAPEC"] = process_cwe_to_capec(cwe_list, cwe_db)

        save_jsonl(cve_capec_data)
    else:
        print("[-]No new vulnerabilities found")

```

## File: capec2technique.py

```py
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
```

## File: update_capec_db.py

```py
import os
import requests
from zipfile import ZipFile
import csv
import json

CAPEC_FILE_URL = "https://capec.mitre.org/data/csv/1000.csv.zip"
CAPEC_FILE = "resources/capec_db.json"

# Download and extract CAPEC data
def download_capec():
    response = requests.get(CAPEC_FILE_URL)
    with open("1000.csv.zip", 'wb') as f:
        f.write(response.content)
    with ZipFile("1000.csv.zip", 'r') as zip_ref:
        zip_ref.extractall()
    os.remove("1000.csv.zip")
    with open("1000.csv", 'r') as f:
        reader = csv.DictReader(f)
        capec_list = [row for row in reader]
    os.remove("1000.csv")
    return capec_list


# Format CAPEC data and save to JSON file
def format_capec(capec_list):
    capec_data = {}
    for capec in capec_list:
        capec_data[capec["'ID"]] = {"name": capec["Name"], "techniques": capec["Taxonomy Mappings"]}

    with open(CAPEC_FILE, 'w') as f:
        json.dump(capec_data, f, indent=4)


if __name__ == "__main__":
    print("[!] Téléchargement des données CAPEC...")
    capec_list = download_capec()
    print("[!] Mise à jour des données CAPEC...")
    format_capec(capec_list)

```

## File: cpe_index.py

```py
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
```

## File: rebuild_db.py

```py
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
```

## File: technique2defend.py

```py
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
```

## File: docs/mitre/README.md

```md
# ATT&CK® Navigator

The ATT&CK Navigator is designed to provide basic navigation and annotation of [ATT&CK](https://attack.mitre.org) matrices, something that people are already doing today in tools like Excel.  We've designed it to be simple and generic - you can use the Navigator to visualize your defensive coverage, your red/blue team planning, the frequency of detected techniques or anything else you want to do.  The Navigator doesn't care - it just allows you to manipulate the cells in the matrix (color coding, adding a comment, assigning a numerical value, etc.).  We thought having a simple tool that everyone could use to visualize the matrix would help make it easy to use ATT&CK.

The principal feature of the Navigator is the ability for users to define layers - custom views of the ATT&CK knowledge base - e.g. showing just those techniques for a particular platform or highlighting techniques a specific adversary has been known to use. Layers can be created interactively within the Navigator or generated programmatically and then visualized via the Navigator.

## Usage

The ATT&CK Navigator is hosted live via GitHub Pages. [You can find a live instance of the current version of the Navigator here](https://mitre-attack.github.io/attack-navigator). You can read more about how to use the application itself in the [USAGE](/USAGE.md) document (which is mirrored in the in-app help page).

Version 4.0+ of the ATT&CK Navigator supports all ATT&CK domains in a single instance of the application instead of requiring a different instance for each domain. Additionally, older versions of ATT&CK can be loaded in the application. The ATT&CK Navigator supports ATT&CK versions 4+. Older versions do not work in the application since their data model is too outdated.

Previous versions of the Navigator application are also hosted via GitHub Pages for users who want a more classic experience:
| ATT&CK Version | Navigator Version | Domains | |
|:---------------|:------------------|:--------|-|
| [ATT&CK v7.2](https://attack.mitre.org/resources/versions/) | [Navigator v3.1](https://github.com/mitre-attack/attack-navigator/releases/tag/v3.1) | [Enterprise](https://mitre-attack.github.io/attack-navigator/v3/enterprise/) | [Mobile](https://mitre-attack.github.io/attack-navigator/v3/mobile/) |
| [ATT&CK v6.3](https://attack.mitre.org/resources/versions/) | [Navigator v2.3.2](https://github.com/mitre-attack/attack-navigator/releases/tag/v2.3.2) | [Enterprise](https://mitre-attack.github.io/attack-navigator/v2/enterprise/) | [Mobile](https://mitre-attack.github.io/attack-navigator/v2/mobile/) |

Please see [Install and Run](#Install-and-Run) for information on how to get the ATT&CK Navigator set up locally.

**Important Note:** Layer files uploaded when visiting our Navigator instance hosted on GitHub Pages are **NOT** being stored on the server side, as the Navigator is a client-side only application. However, we still recommend installing and running your own instance of the ATT&CK Navigator if your layer files contain any sensitive content.

Use our [GitHub Issue Tracker](https://github.com/mitre-attack/attack-navigator/issues) to let us know of any bugs or others issues that you encounter. We also encourage pull requests if you've extended the Navigator in a cool way and want to share back to the community!

*See [CONTRIBUTING.md](https://github.com/mitre-attack/attack-navigator/blob/master/CONTRIBUTING.md) for more information on making contributions to the ATT&CK Navigator.*

## Requirements

* [Node.js v18](https://nodejs.org)
* [AngularCLI v17](https://cli.angular.io)

## Supported Browsers

* Chrome
* Firefox
* Internet Explorer 11<sup>[1]</sup>
* Edge
* Opera
* Safari<sup>[2]</sup>

**[1]** There is a recorded issue with the SVG export feature on Internet Explorer. Because of a [missing functionality on SVGElements](https://developer.mozilla.org/en-US/docs/Web/API/ParentNode/children) in that browser, text will not be properly vertically centered in SVGs exported in that browser. We recommend switching to a more modern browser for optimal results.

**[2]** ATT&CK Navigator only supports Safari versions 14 and above because older versions of the browser can exhibit an unfixable freeze when selecting a layer tab. Users on unsupported versions of the browser will be warned of this possibility when opening the application.

## Install and Run

### First time

1. Navigate to the **nav-app** directory
2. Run `npm install`

### Serve application on local machine

1. Run `ng serve` within the **nav-app** directory
2. Navigate to `localhost:4200` in browser

### Compile for use elsewhere

1. Run `ng build` within the **nav-app** directory
2. Copy files from `nav-app/dist/` directory

_Note: `ng build --configuration production` does not currently work for ATT&CK Navigator without additional flags. To build the production environment instead use `ng build --configuration production --aot=false --build-optimizer=false`._

### Running the Navigator offline

1. Install the Navigator as per instructions above.
2. Follow instructions under [loading content from local files](#Loading-content-from-local-files) to configure the Navigator to populate the matrix without an internet connection. The latest MITRE ATT&CK data files can be found here:
	- [Enterprise ATT&CK](https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json).
	- [Mobile ATT&CK](https://github.com/mitre-attack/attack-stix-data/raw/master/mobile-attack/mobile-attack.json).
	- [ICS ATT&CK](https://github.com/mitre-attack/attack-stix-data/raw/master/ics-attack/ics-attack.json).

## Documentation

When viewing the Navigator in a browser, click on the **?** icon in the upper right corner to view the in-app documentation.

## Layers Folder

The **layers** folder contains specifications for the layer format as well as example layers and a script demonstrating programatic layer generation. We will continue to add content to this repository as new scripts are implemented. Also, feel free to create pull requests if you want to add new capabilities here!

More information on how layers are used and developed can be found in the ATT&CK Navigator documentation that can be viewed by clicking **?** when running the app in a browser, and in the README in the **layers** folder.

## Adding Custom Context Menu Options

To create custom options to the **ATT&CK® Navigator** context menu using data in the Navigator, objects must be added to the array labeled `custom_context_menu_options` in `nav-app/src/assets/config.json`. Each object must have a property **label**, which is the text displayed in the context menu, and a property **url**, which is where the user is navigated.

To utilize data on right-clicked technique in the url, parameters surrounded by double curly brackets can be added to the string. For example: using `http://www.someurl.com/{{technique_attackID}}}` as the url in the custom option would lead to `http://www.someurl.com/T1098`, if the right-clicked technique's attackID was T1098.

The following data substitutions will be parsed:

* `{{technique_attackID}}` will be substituted with the ATT&CK ID of the technique, e.g `T1234`
* `{{technique_stixID}}` will be substituted with the STIX ID of the technique, e.g `attack-pattern--12345678-1234-1234-1234-123456789123`
* `{{technique_name}}` will be substituted with the technique name in lower case and with spaces replaced with hyphens, e.g `example-technique-name`
* `{{tactic_attackID}}` will be substituted with the ATT&CK ID of the tactic, e.g `TA1234`
* `{{tactic_stixID}}` will be substituted with the STIX ID of the tactic, e.g `x-mitre-tactic--12345678-1234-1234-1234-123456789123`
* `{{tactic_name}}` will be substituted with the tactic name in lower case and with spaces replaced with hyphens, e.g `example-tactic`. This is also equivalent to the x_mitre_shortname property of the tactic.

Optionally, a `subtechnique_url` field may be added to a custom option. This field will be parsed when the option is used on a sub-technique instead of the normal URL, which will be used for techniques. If `subtechnique_url` is not used, the `technique_` substitutions defined above will refer to the sub-technique object itself.

The following substitutions will be parsed for sub-techniques:

* `{{parent_technique_attackID}}` will be substituted with the ATT&CK ID of the sub-technique's parent, e.g `T1234`
* `{{parent_technique_stixID}}` will be substituted with the STIX ID of the sub-technique's parent, e.g `attack-pattern--12345678-1234-1234-1234-123456789123`
* `{{parent_technique_name}}` will be substituted with the name of the sub-technique's parent in lower case and with spaces replaced with hyphens, e.g `example-technique-name`
* `{{subtechnique_attackID}}` will be substituted with the ATT&CK ID of the sub-technique, e.g `T1234.001`
* `{{subtechnique_attackID_suffix}}` will be substituted with the portion of the ATT&CK ID of the sub-technique after the delimiting period, e.g `001`
* `{{subtechnique_stixID}}` will be substituted with the STIX ID of the sub-technique, e.g `attack-pattern--98765432-9876-9876-9876-987654321987`
* `{{subtechnique_name}}` will be substituted with the sub-technique name in lower case and with spaces replaced with hyphens, e.g `example-subtechnique-name`
* `{{tactic_attackID}}` will be substituted with the ATT&CK ID of the tactic, e.g `TA1234`
* `{{tactic_stixID}}` will be substituted with the STIX ID of the tactic, e.g `x-mitre-tactic--12345678-1234-1234-1234-123456789123`
* `{{tactic_name}}` will be substituted with the tactic name in lower case and with spaces replaced with hyphens, e.g `example-tactic`. This is also equivalent to the x_mitre_shortname property of the tactic.

Example custom context menu objects:

```json
{
    "label": "view technique on ATT&CK website",
    "url": "https://attack.mitre.org/techniques/{{technique_attackID}}",
    "subtechnique_url": "https://attack.mitre.org/techniques/{{parent_technique_attackID}}/{{subtechnique_attackID_suffix}}"
}
```

```json
{
    "label": "view tactic on ATT&CK website",
    "url": "https://attack.mitre.org/tactics/{{tactic_attackID}}"
}
```

## Methods for loading content

### Loading content from a Collection Index

By default, the Navigator loads content from the ATT&CK Collection Index hosted on the [ATT&CK STIX Data repository](#related-mitre-work). More information about Collection Indexes can be found [here](https://github.com/mitre-attack/attack-stix-data?tab=readme-ov-file#collection-indexes).

1. Modify the `config.json` file located in the `src/assets` directory.
2. Set the `collection_index_url` property to the URL of your Collection Index (for example, `"collection_index_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"`)

*Note: For the Navigator to load successfully, either the `collection_index_url` property, the `versions` property, or both must be defined. If both the `collection_index_url` and `versions` properties are defined, the Navigator will display the union of the versions under the "More Options" dropdown in the "Create New Layer" interface. If neither are defined, an alert will be triggered indicating that the Navigator failed to load.*

### Loading content from a TAXII server

Both TAXII 2.0 and TAXII 2.1 are currently supported. Support for TAXII 2.0 will be deprecated in December 2024. More information about the TAXII 2.1 Server can be found [here](https://github.com/mitre-attack/attack-workbench-taxii-server/tree/main).

1. Modify the `config.json` file located in the `src/assets` directory.
2. In the `versions` section, set the `enabled` property to `true`.
3. Define the `taxii_url` property in the list of domains, in place of the domain `data` property, and set its value to the TAXII server URL.
4. Define the `taxii_collection` property and set its value to the collection UUID as determined by the TAXII server.

#### Example loading content from a TAXII 2.0 server:

```json
"versions": {
	"enabled": true,
	"entries": [
		{
			"name": "Enterprise TAXII 2.0 Data",
			"version": "14",
			"domains": [
				{
					"name": "Enterprise",
					"taxii_url": "https://cti-taxii.mitre.org/",
					"taxii_collection": "95ecc380-afe9-11e4-9b6c-751b66dd541e"
				}
			]
		}
	]
},
```

#### Example loading content from a TAXII 2.1 server:

```json
"versions": {
	"enabled": true,
	"entries": [
		{
			"name": "Enterprise TAXII 2.1 Data",
			"version": "14",
			"domains": [
				{
					"name": "Enterprise",
					"taxii_url": "https://attack-taxii.mitre.org/",
					"taxii_collection": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
				}
			]
		}
	]
},
```

### Loading content from local files

Navigator can be populated using files that consist of bundles of STIX objects, similar to the format found in [this example](https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json). Both STIX 2.0 and STIX 2.1 bundles are supported.

1. Place the STIX bundle(s) in the `src/assets` directory. This allows the server hosting the Navigator to also host the data.
2. Modify the `config.json` file located in the `src/assets` directory.
3. In the `versions` section, set the `enabled` property to `true`.
4. Update the URL specified in the `data` array to the path to the STIX bundle (for example, `assets/enterprise-attack.json`). Multiple paths may be added to the `data` array to display multiple STIX bundles in a single instance.

#### Example loading content from local files:

```json
"versions": {
    "enabled": true,
    "entries": [
        {
            "name": "Local Enterprise STIX Data",
            "version": "14",
            "domains": [
                {
                    "name": "Enterprise",
                    "identifier": "enterprise-attack",
                    "data": ["assets/enterprise-attack.json"]
                }
            ]
        }
    ]
},
```

## Running the Docker File

1. Navigate to the directory where you checked out the git repository
2. Run `docker build -t yourcustomname .`
3. Run `docker run -p 4200:4200 yourcustomname`
4. Navigate to `localhost:4200` in browser

## Loading Default Layers Upon Initialization

The Navigator can be configured so as to load a set of layers upon initialization. These layers can be from the web and/or from local files.
Local files to load should be placed in the `nav-app/src/assets/` directory.

1. Set the `enabled` property in `default_layers` in `src/assets/config.json` to `true`
2. Add the paths to your desired default layers to the `urls` array in `default_layers`. For example,

   ```JSON
   "default_layers": {
        "enabled": true,
        "urls": [
            "assets/example.json", 
            "https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/layers/samples/Bear_APT.json"
        ]
    }
   ```

   would load `example.json` from the local assets directory, and `Bear_APT.json` from this repo's sample layer folder on Github.
3. Load/reload the Navigator

Default layers from the web can also be set using a query string in the Navigator URL. Refer to the in-application help page section "Customizing the Navigator" for more details.

Users will not be prompted to upgrade default layers to the current version of ATT&CK if they are outdated.

## Enabling Banner in Navigator

The `banner` setting in `nav-app/src/assets/config.json` by default is an empty string `"""` (and not visible), and can be set to whatever content you wish to display inside a banner at the top of the Navigator webpage. The banner supports HTML and hyperlinks in the content.

## Disabling Navigator Features

The `features` array in `nav-app/src/assets/config.json` lists Navigator features you may want to disable. Setting the `enabled` field on a feature in the configuration file will hide all control
elements related to that feature.

However, if a layer is uploaded with an annotation or configuration
relating to that feature it will not be hidden. For example, if `comments` are disabled the
ability to add a new comment annotation will be removed, however if a layer is uploaded with
comments present they will still be displayed in tooltips and and marked with an underline.

Features can also be disabled using the _create customized Navigator_ feature. Refer to the in-application help page section "Customizing the Navigator" for more details.

## Embedding the Navigator in a Webpage

If you want to embed the Navigator in a webpage, use an iframe:

```HTML
<iframe src="https://mitre-attack.github.io/attack-navigator/enterprise/" width="1000" height="500"></iframe>
```

If you want to embed a version of the Navigator with specific features removed (e.g tabs, adding annotations), or with a default layer, we recommend using the _create customized Navigator_ feature. We highly recommend disabling the "leave site dialog" via this means when embedding the Navigator since otherwise you will be warned whenever you try to leave the embedding page. Refer to the in-application help page section "Customizing the Navigator" for more details.

The following is an example iframe which embeds our [*Bear APTs](layers/samples/Bear_APT.json) layer with tabs and the ability to add annotations removed:

```HTML
<iframe src="https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fmitre%2Fattack-navigator%2Fmaster%2Flayers%2Fdata%2Fsamples%2FBear_APT.json&tabs=false&selecting_techniques=false" width="1000" height="500"></iframe>
```

## Related MITRE Work

### CTI

[Cyber Threat Intelligence repository](https://github.com/mitre/cti) of the ATT&CK catalog expressed in STIX 2.0 JSON.

### ATT&CK STIX Data

[ATT&CK STIX Data repository](https://github.com/mitre-attack/attack-stix-data) of the ATT&CK catalog expressed in STIX 2.1 JSON.

### ATT&CK

ATT&CK® is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target. ATT&CK is useful for understanding security risk against known adversary behavior, for planning security improvements, and verifying defenses work as expected.

<https://attack.mitre.org>

### STIX

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

<https://oasis-open.github.io/cti-documentation/>

## Notice

Copyright 2024 The MITRE Corporation

Approved for Public Release; Distribution Unlimited. Case Number 18-0128.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project makes use of ATT&CK®

[ATT&CK® Terms of Use](https://attack.mitre.org/resources/terms-of-use/)

```

## File: docs/mitre/layers/README.md

```md
# ATT&CK Navigator Layers

A layer constitutes a set of annotations on the ATT&CK matrix for a specific technology domain. Layers can also store a default configuration of the view such as sorting, visible platforms, and more. The ATT&CK Navigator includes functionalities for exporting annotations into layer files, as well as the ability to import layer files for viewing.

See the latest [layer format specification](spec/v4.5/layerformat.md) for more information about Layer files.

## Sample Layers

This repository includes a couple of [sample layers](samples/) demonstrating example use cases of layers and the ATT&CK Navigator. The scripts used to generate these layer files can be found in the [mitreattack-python repository](https://github.com/mitre-attack/attack-scripts/tree/master/scripts/layers/samples). These scripts may serve as examples on how to access and work with [ATT&CK data](https://github.com/mitre/cti).

```
