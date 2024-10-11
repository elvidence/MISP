#!/var/www/MISP/venv/bin/python
"""
Script Name: cps_ioc_feed.py
Version: 2.2
Date: 11/10/2024
Author: A.R.
Purpose: Fetch and process IOCs from CriticalPathSecurity's GitHub, deduplicate, and output to CSV files.
         It filters IP addresses through the zero_noise_ips.py script to exclude non-public, non-routable, and irrelevant IPs.

Details:
- This script is designed to fetch indicators of compromise (IOCs) from CriticalPathSecurity GitHub URLs.
- It processes IOCs by removing duplicates and filtering out non-public or irrelevant IP addresses using functions from zero_noise_ips.py.
- IOCs are then saved into separate CSV files based on their type (IPs or domains).
- The zero_noise_ips.py script must be located in the same directory as this script for proper IP validation.

Setup:
- Logging is configured to save activity logs to '/var/log/local_feeds.log'.
- The script requires an API token for GitHub (your GitHub account) to fetch IOCs from private or rate-limited repositories.
"""

import requests
import csv
import os
import logging
import json
from zero_noise_ips import is_non_public_ip, update_consolidated_ips  # Import necessary functions

# Setup logging
logging.basicConfig(filename='/var/log/local_feeds.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - cps_ioc_feed.py: %(message)s')

# Directory and file setup
BASE_URL = "/var/www/MISP/app/files/feeds/GitHub"
if not os.path.exists(BASE_URL):
    os.makedirs(BASE_URL)

cobalt_strike_file = os.path.join(BASE_URL, 'cobalt_strike.csv')
cobalt_strike_domains_file = os.path.join(BASE_URL, 'cobalt_strike_domains.csv')
log4j_file = os.path.join(BASE_URL, 'log4j.csv')
etag_file = os.path.join(BASE_URL, 'etags.json')

# API and authentication (Credentials directly in the script)
TOKEN = 'XXXXX'  # Replace with your actual GitHub API token
headers = {'Authorization': f'token {TOKEN}'}
# Avoid hardcoding sensitive information like API tokens directly in the scripts.
# Suggested use for production systems below:

#import os
#TOKEN = os.environ.get('GITHUB_TOKEN')
#if not TOKEN:
#    logging.error("GitHub token not found. Please set the GITHUB_TOKEN environment variable.")
#    exit(1)
#headers = {'Authorization': f'token {TOKEN}'}


# Define URLs for IOCs
urls = {
    'cobalt_strike': [
        'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cobaltstrike_ips.txt',
        'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cps_cobaltstrike_ip.txt'
    ],
    'cobalt_strike_domains': [
        'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cps_cobaltstrike_domain.txt'
    ],
    'log4j': [
        'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/log4j.txt'
    ]
}

# Load previous ETags
etags = {}
if os.path.exists(etag_file):
    with open(etag_file, 'r') as ef:
        etags = json.load(ef)

def fetch_iocs(url_list):
    """
    Fetches IOCs from provided URLs with ETag handling to minimize redundant data transfer.
    """
    iocs = set()
    updated = False
    for url in url_list:
        current_headers = headers.copy()
        if url in etags:
            current_headers['If-None-Match'] = etags.get(url, '')
        response = requests.get(url, headers=current_headers)
        if response.status_code == 200:
            iocs.update(response.text.strip().splitlines())
            etags[url] = response.headers.get('ETag')
            updated = True
        elif response.status_code == 304:
            logging.info(f"No update needed for {url}")
        else:
            logging.error(f"Failed to fetch {url}: {response.status_code}")
    return iocs, updated

def write_to_csv(filename, iocs):
    """
    Writes IOCs to a CSV file, sorted alphabetically.
    """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for ioc in sorted(iocs):
            writer.writerow([ioc])

# Update the consolidated IPs and load them into a set
logging.info("Updating consolidated IPs from zero_noise_ips.py...")
consolidated_ips_set = update_consolidated_ips()
if not consolidated_ips_set:
    with open('consolidated_ips.json', 'r') as file:
        consolidated_ips_set = set(json.load(file))
logging.info("Consolidated IPs have been updated.")

# Process and write IOCs to CSV files if updated
cobalt_strike_iocs, cobalt_strike_updated = fetch_iocs(urls['cobalt_strike'])
# Filter out non-public IPs and IPs in consolidated_ips_set
cobalt_strike_iocs = {
    ioc for ioc in cobalt_strike_iocs
    if not is_non_public_ip(ioc) and ioc not in consolidated_ips_set
}
logging.info("Applied filtering to cobalt_strike IOCs.")

cobalt_strike_domains_iocs, cobalt_strike_domains_updated = fetch_iocs(urls['cobalt_strike_domains'])
# No filtering applied to domain IOCs

log4j_iocs, log4j_updated = fetch_iocs(urls['log4j'])
# Filter out non-public IPs and IPs in consolidated_ips_set
log4j_iocs = {
    ioc for ioc in log4j_iocs
    if not is_non_public_ip(ioc) and ioc not in consolidated_ips_set
}
logging.info("Applied filtering to log4j IOCs.")

if cobalt_strike_updated:
    write_to_csv(cobalt_strike_file, cobalt_strike_iocs)
    logging.info("cobalt_strike.csv has been created and populated correctly.")

if cobalt_strike_domains_updated:
    write_to_csv(cobalt_strike_domains_file, cobalt_strike_domains_iocs)
    logging.info("cobalt_strike_domains.csv has been created and populated correctly.")

if log4j_updated:
    write_to_csv(log4j_file, log4j_iocs)
    logging.info("log4j.csv has been created and populated correctly.")

# Save updated ETags
with open(etag_file, 'w') as ef:
    json.dump(etags, ef)
logging.info("ETags have been updated.")
