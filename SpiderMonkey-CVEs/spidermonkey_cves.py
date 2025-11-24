import nvdlib
import requests
import time
import re
import csv
from typing import List, Dict
from datetime import datetime, timedelta, MINYEAR, MAXYEAR

BUGZILLA_PATTERN = r'https?://bugzilla\.mozilla\.org/show_bug\.cgi\?id=(\d+)'

OUTPUT_FILE = 'spidermonkey_jit_cves.csv'

def generate_date_ranges(start_year: int, end_year: int) -> List[tuple]:
  """Generate date ranges in 120-day chunks to query NVD"""
  ranges = []
  start_date = datetime(start_year, 1, 1)
  end_date = datetime(end_year, 12, 31)
  
  current_start = start_date
  while current_start < end_date:
    current_end = min(current_start + timedelta(days=119), end_date)
    ranges.append((
      current_start.strftime('%Y-%m-%d %H:%M'),
      current_end.strftime('%Y-%m-%d %H:%M')
    ))
    current_start = current_end + timedelta(days=1)
  
  return ranges

def query_nvd_mozilla_cves(start_year: int = 2020, end_year: int = 2025) -> List:
  """Query NVD API for Mozilla Corporation CVEs"""
  all_cves = []
  date_ranges = generate_date_ranges(start_year, end_year)
  
  print(f"Querying NVD for Mozilla Corporation CVEs")
  
  for i, (pub_start, pub_end) in enumerate(date_ranges, 1):
    print(f"Range {i}/{len(date_ranges)}: {pub_start[:10]} to {pub_end[:10]}", end='')
    
    try:
      cves = nvdlib.searchCVE(
        pubStartDate=pub_start,
        pubEndDate=pub_end,
        sourceIdentifier='security@mozilla.org',
      )
      
      cve_list = list(cves)
      all_cves.extend(cve_list)
      print(f" - Found {len(cve_list)} CVEs")
        
    except Exception as e:
      print(f" - Error: {e}")
      continue
  
  return all_cves

def extract_bugzilla_urls(cve) -> List[str]:
  """Extract Bugzilla URLs from CVE references."""
  bugzilla_urls = []
  
  if hasattr(cve, 'references'):
    for ref in cve.references:
      url = ref.url if hasattr(ref, 'url') else str(ref)
      if 'bugzilla.mozilla.org' in url:
        bugzilla_urls.append(url)
  
  return bugzilla_urls

def query_bugzilla_component(bug_id: str) -> tuple:
  """Query Bugzilla API to get the product and component of a bug."""
  bugzilla_api = f"https://bugzilla.mozilla.org/rest/bug/{bug_id}"
  
  try:
    response = requests.get(bugzilla_api, timeout=10)
    response.raise_for_status()
    data = response.json()
    
    if 'bugs' in data and len(data['bugs']) > 0:
      bug = data['bugs'][0]
      product = bug.get('product', '')
      component = bug.get('component', '')
      return product, component
      
  except requests.exceptions.RequestException:
    pass
  
  return "", ""

def extract_cwe(cve) -> str:
    """Extract CWE(s) from CVE"""
    cwe_ids = []
    if hasattr(cve, 'weaknesses'):
      for weakness in cve.weaknesses:
        if hasattr(weakness, 'description'):
          for desc in weakness.description:
            if hasattr(desc, 'value'):
              cwe_ids.append(desc.value)
    
    return ', '.join(cwe_ids) if cwe_ids else "N/A"  

def find_jit_cves(mozilla_cves: List) -> List[Dict]:
  """Check if component is JavaScript Engine: JIT in Bugzilla"""
  jit_cves = []
  
  print(f"\nChecking {len(mozilla_cves)} Mozilla CVEs for JIT vulnerability")
  
  checked = 0
  found = 0
  
  for cve in mozilla_cves:
    cve_id = cve.id
    bugzilla_urls = extract_bugzilla_urls(cve)
    
    if not bugzilla_urls:
      continue
    
    checked += 1
    if checked % 50 == 0:
      print(f"Checked {checked}/{len(mozilla_cves)} CVEs, found {found} JIT vulnerabilities")
      found = 0
    
    for url in bugzilla_urls:
      match = re.search(BUGZILLA_PATTERN, url)
      if match:
        bug_id = match.group(1)
        product, component = query_bugzilla_component(bug_id)
        
        if product == "Core" and component == "JavaScript Engine: JIT":
          cwe_ids = extract_cwe(cve)
          jit_cves.append({
            'cve_id': cve_id,
            'cwes': cwe_ids,
            'bugzilla_id': bug_id
          })
          found += 1
        
        time.sleep(1)
        break
  
  print(f"Checked {checked}/{len(mozilla_cves)} CVEs, found {found} JIT vulnerabilities...")
          
  return jit_cves

def save_to_csv(jit_cves: List[Dict]):
  """Save JIT CVEs to CSV file."""
  with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    fieldnames = ['CVE ID', 'CWE IDs', 'Bugzilla ID']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for cve in sorted(jit_cves, key=lambda x: x['cve_id']):
      writer.writerow({
        'CVE ID': cve['cve_id'],
        'CWE IDs': cve['cwes'],
        'Bugzilla ID': cve['bugzilla_id']
      })

def main():
  start_input= input("Start year (2020): ")
  end_input = input("End year (2025): ")

  if len(start_input) > 0 and start_input.isnumeric() and MINYEAR <= int(start_input) <= MAXYEAR:
    start_year = int(start_input)
  else:
    start_year = 2020
  if len(end_input) > 0 and end_input.isnumeric() and MINYEAR <= int(end_input) <= MAXYEAR:
    end_year = int(end_input)
  else:
    end_year = 2025
  
  print(f"Checking for Mozilla Corporation JIT vulnerabilities from {start_year} to {end_year}\n")

  # Query NVD for Mozilla Corporation CVEs
  mozilla_cves = query_nvd_mozilla_cves(start_year, end_year)
  
  if not mozilla_cves:
    print("\nNo Mozilla Corporation CVEs found")
    return
  
  # Check Bugzilla to find JIT vulnerabilities
  jit_cves = find_jit_cves(mozilla_cves)
  
  if jit_cves:
    save_to_csv(jit_cves)
  else:
    print("\nNo CVEs found with JavaScript Engine: JIT component")

if __name__ == "__main__":
    main()