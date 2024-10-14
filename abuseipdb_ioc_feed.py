#!/var/www/MISP/venv/bin/python

# AbuseIPDB Blacklist Fetcher and Filter
# Version: 2.0
# Date: 11 October 2024
# Author: A.R.
# License: MIT

"""
This script automates the process of fetching IP addresses from the AbuseIPDB's blacklist API,
filters out non-public and special-use IP addresses as defined by RFCs, and excludes IPs present
in the consolidated_ips.json file. It then saves only new and public IPs to a specified file.
This ensures that the blacklist only contains IPs that are routable on the public internet and
not known benign or irrelevant IPs. The script is designed to work with large datasets efficiently.
"""

import requests
import logging
import ipaddress
import json
import os
from zero_noise_ips import is_non_public_ip, update_consolidated_ips  # Import necessary functions

# Logging setup
logging.basicConfig(filename='/var/log/local_feeds.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - abuseipdb_blacklist_fetcher.py: %(message)s')

# Global configuration
global_config = {
    # Avoid hardcoding sensitive information like API tokens directly in the scripts.
    'api_key': 'REPLACE WITH ABUSEIPDB API KEY',
    'file_path': '/var/www/MISP/app/files/feeds/AbuseIPDB/blacklist.txt',
    'limit': 500000,
    'confidence_minimum': 100
}

def fetch_blacklist(configuration):
    """Fetches the blacklist data from AbuseIPDB using the provided configuration."""
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    querystring = {
        'limit': configuration['limit'],
        'confidenceMinimum': configuration['confidence_minimum']
    }
    headers = {
        'Accept': 'text/plain',
        'Key': configuration['api_key']
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching blacklist: {e}")
        return None

def save_blacklist(data, file_path, consolidated_ips_set):
    """Overwrites the blacklist file with new IPs, filtered to exclude non-public IPs and IPs in consolidated_ips.json."""
    try:
        total_ips = data.strip().splitlines()
        filtered_ips = {
            ip for ip in total_ips
            if not is_non_public_ip(ip) and ip not in consolidated_ips_set
        }
        private_or_consolidated_count = len(total_ips) - len(filtered_ips)  # Count of filtered out IPs

        # Overwrite the existing file with the new IPs
        with open(file_path, 'w') as file:
            file.write('\n'.join(filtered_ips) + '\n')

        logging.info(f"Blacklist updated with {len(filtered_ips)} IPs at {file_path}")
        logging.info(f"{private_or_consolidated_count} non-public or consolidated IPs filtered out.")
    except Exception as e:
        logging.error(f"Error saving blacklist: {e}")

if __name__ == '__main__':
    # Update the consolidated IPs and load them into a set
    logging.info("Updating consolidated IPs from zero_noise_ips.py...")
    consolidated_ips_set = update_consolidated_ips()
    if not consolidated_ips_set:
        with open('consolidated_ips.json', 'r') as file:
            consolidated_ips_set = set(json.load(file))
    logging.info("Consolidated IPs have been updated.")

    content = fetch_blacklist(global_config)
    if content:
        save_blacklist(content, global_config['file_path'], consolidated_ips_set)
