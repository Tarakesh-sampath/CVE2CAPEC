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