#!/usr/bin/env python3
import subprocess
import sys
import time
from datetime import datetime

def run_script(script_name, description):
    print(f"\n{'='*60}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {description}")
    print(f"{'='*60}")
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            check=True,
            capture_output=False,
            text=True
        )
        elapsed = time.time() - start_time
        print(f"[SUCCESS] {script_name} completed in {elapsed:.2f}s")
        return True
    except subprocess.CalledProcessError as e:
        elapsed = time.time() - start_time
        print(f"[ERROR] {script_name} failed after {elapsed:.2f}s")
        print(f"Exit code: {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"[ERROR] {script_name} not found")
        return False

def main():
    print(f"\n{'#'*60}")
    print(f"# CVE2CAPEC Full Update Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}")
    
    total_start = time.time()
    
    # Phase 1: Update databases
    databases = [
        ("update_capec_db.py", "Updating CAPEC database"),
        ("update_cwe_db.py", "Updating CWE database"),
        ("update_technique_db.py", "Updating MITRE ATT&CK techniques"),
        ("update_defend_db.py", "Updating MITRE D3FEND techniques"),
    ]
    
    # Phase 2: Build CVE mappings
    mappings = [
        ("retrieve_cve.py", "Retrieving new CVEs"),
        ("cve2cwe.py", "Extracting CWEs from CVEs"),
        ("cwe2capec.py", "Extracting CAPECs from CWEs"),
        ("capec2technique.py", "Getting MITRE ATT&CK Techniques from CAPECs"),
        ("technique2defend.py", "Getting MITRE D3FEND Techniques from ATT&CK"),
    ]
    
    all_tasks = databases + mappings
    
    success_count = 0
    failed_tasks = []
    
    for script, description in all_tasks:
        if run_script(script, description):
            success_count += 1
        else:
            failed_tasks.append(script)
            print(f"\nStopping execution due to failure in {script}")
            break
    
    total_elapsed = time.time() - total_start
    
    print(f"\n{'#'*60}")
    print(f"# Update Complete")
    print(f"# Total time: {total_elapsed:.2f}s")
    print(f"# Completed: {success_count}/{len(all_tasks)}")
    
    if failed_tasks:
        print(f"# Failed: {', '.join(failed_tasks)}")
        print(f"{'#'*60}")
        sys.exit(1)
    else:
        print(f"# All tasks completed successfully!")
        print(f"{'#'*60}")
        sys.exit(0)

if __name__ == "__main__":
    main()
