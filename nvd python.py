import requests
import csv
import json
from datetime import datetime, timedelta

# Calculate date for 3 months ago
current_date = datetime.now()
three_months_ago = current_date - timedelta(days=90)

# Format dates for NVD API
start_date = three_months_ago.strftime("%Y-%m-%dT00:00:00.000")
end_date = current_date.strftime("%Y-%m-%dT23:59:59.999")

# Set up API request parameters
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "pubStartDate": start_date,
    "pubEndDate": end_date,
    "keywordSearch": "GitHub",
    "resultsPerPage": 2000  # Adjust based on expected results
}

# Make the API request
print("Fetching vulnerability data from NVD...")
response = requests.get(api_url, params=params)

if response.status_code != 200:
    print(f"Error: Received status code {response.status_code}")
    print(response.text)
    exit(1)

# Parse the JSON response
data = response.json()
vulnerabilities = data.get('vulnerabilities', [])

print(f"Found {len(vulnerabilities)} vulnerabilities")

# Prepare CSV file
csv_filename = "github_vulnerabilities_last_3_months.csv"
with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['Vulnerability ID', 'Summary', 'CVSS Severity']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    
    # Process each vulnerability
    for vuln in vulnerabilities:
        cve = vuln.get('cve', {})
        
        # Get CVE ID
        cve_id = cve.get('id', 'N/A')
        
        # Get summary
        descriptions = cve.get('descriptions', [])
        summary = "N/A"
        for desc in descriptions:
            if desc.get('lang') == 'en':
                summary = desc.get('value', 'N/A')
                break
        
        # Get CVSS severity
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
        
        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            base_score = cvss_data.get('baseScore', 'N/A')
            severity = cvss_v3[0].get('baseSeverity', 'N/A')
            cvss_severity = f"{base_score} {severity}"
        else:
            # Fall back to CVSS v2 if v3 is not available
            cvss_v2 = metrics.get('cvssMetricV2', [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_v2[0].get('baseSeverity', 'N/A')
                cvss_severity = f"{base_score} {severity}"
            else:
                cvss_severity = "N/A"
        
        # Write to CSV
        writer.writerow({
            'Vulnerability ID': cve_id,
            'Summary': summary,
            'CVSS Severity': cvss_severity
        })

print(f"Export complete. Data saved to {csv_filename}")