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