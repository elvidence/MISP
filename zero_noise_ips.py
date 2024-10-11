#!/usr/bin/env python3

"""
Author: A.R.
Version: 0.2b
Date: 11 October 2024
License: MIT

Description: This script automates the integration of a large IP address feed(s) into OpenCTI (Open Cyber Threat Intelligence) 
or MISP (Malware Information Sharing Platform). It reduces false positives by validating incoming IPs against multiple criteria, 
including non-routable IPs, special-use ranges, and data from MISP warning lists. The goal is to ensure only relevant IPs are flagged for ingestion.

The script efficiently handles large datasets and allows users to configure the source feed and validation criteria to meet specific needs.

Example Adaptation:
Users can modify the validation criteria or integrate different IP feeds to suit their environment. 
Considerations for false positives include non-routable or specially designated IP addresses, 
IPs associated with security sensors, public DNS resolvers, CDN ranges, or known SMTP mailer IPs that are not exclusively used by threat actors. 
Blocking these could inadvertently impact legitimate users.

Please note: This is a beta release and may be subject to further updates and improvements.

Ensure the 'requests' module is installed before running the script.
You can install it by running: pip install requests
"""
import os
import sys
import json
import ipaddress
import requests
from typing import Set, Dict
from datetime import datetime
import concurrent.futures

# Base URL for all the MISP warning lists
BASE_URL = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/"

# List of file names to be appended to the base URL
FILE_NAMES = [
    'censys-scanning', 'microsoft-office365-ip', 'zscaler', 'wikimedia',
    'umbrella-blockpage-v4', 'umbrella-blockpage-v6', 'tenable-cloud-ipv4',
    'tenable-cloud-ipv6', 'stackpath', 'smtp-sending-ips', 'smtp-receiving-ips',
    'sinkholes', 'openai-gptbot', 'microsoft-office365-cn', 'microsoft-azure-us-gov',
    'googlebot', 'google-gmail-sending-ips', 'fastly', 'crl-ip', 'check-host-net',
    'akamai', 'public-dns-v4'
]

def get_etag_data() -> Dict[str, Dict]:
    if os.path.exists('etag_data.json'):
        with open('etag_data.json', 'r') as file:
            return json.load(file)
    return {}

def save_etag_data(data: Dict) -> None:
    with open('etag_data.json', 'w') as file:
        json.dump(data, file, indent=4)

def fetch_and_extract_ips(url: str, etag_data: Dict, ip_set: Set[str]) -> bool:
    headers = {}
    if url in etag_data:
        headers['If-None-Match'] = etag_data[url]['etag']

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 304:
            print(f"No update needed for {url}")
            return False
        elif response.status_code == 200:
            data = response.json()
            ip_set.update(data['list'])  # Extract IPs from the 'list' field
            etag_data[url] = {
                'etag': response.headers.get('ETag'),
                'last_checked': datetime.now().isoformat()
            }
            save_etag_data(etag_data)
            return True
    except requests.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return False

def save_all_ips(ip_set: Set[str]) -> None:
    with open('consolidated_ips.json', 'w') as file:
        json.dump(list(ip_set), file, indent=4)

def is_non_public_ip(ip_address: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return False  # Return False if the input is not a valid IP address

    non_public_ranges = [
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('100.64.0.0/10'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.0.0.0/24'),
        ipaddress.ip_network('192.0.2.0/24'),
        ipaddress.ip_network('192.52.193.0/24'),
        ipaddress.ip_network('192.88.99.0/24'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('198.18.0.0/15'),
        ipaddress.ip_network('198.51.100.0/24'),
        ipaddress.ip_network('203.0.113.0/24'),
        ipaddress.ip_network('224.0.0.0/4'),
        ipaddress.ip_network('240.0.0.0/4'),
        ipaddress.ip_network('255.255.255.255/32'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
        ipaddress.ip_network('2001:DB8::/32')
    ]

    return any(ip_obj in network for network in non_public_ranges)

def clean_ip_list(filename: str, consolidated_ips: Set[str]) -> None:
    cleaned_ips = []
    with open(filename, 'r') as file:
        for line in file:
            ip = line.strip()
            if ip not in consolidated_ips and not is_non_public_ip(ip):
                cleaned_ips.append(ip)

    # Generate the new file name
    base, ext = os.path.splitext(filename)
    new_filename = f"inspected_{os.path.basename(base)}{ext}"

    with open(new_filename, 'w') as file:
        for ip in cleaned_ips:
            file.write(ip + "\n")

    print(f"Cleaned IP list saved to {new_filename}")

def update_consolidated_ips() -> Set[str]:
    # Build full URLs from the base URL and file names
    urls = [f"{BASE_URL}{name}/list.json" for name in FILE_NAMES]

    etag_data = get_etag_data()
    ip_set = set()  # Set to store all unique IPs

    # Check if consolidated_ips.json exists and is not empty
    consolidated_exists = os.path.exists('consolidated_ips.json') and os.path.getsize('consolidated_ips.json') > 0

    # Determine if any updates are required by checking ETags
    updates_required = False
    for url in urls:
        headers = {}
        if url in etag_data:
            headers['If-None-Match'] = etag_data[url]['etag']
        try:
            response = requests.head(url, headers=headers, timeout=10)
            if response.status_code == 200:
                updates_required = True
                break
        except requests.RequestException as e:
            print(f"Failed to check {url}: {e}")

    if not consolidated_exists or updates_required:
        print("Fetching updates and updating consolidated_ips.json...")
        ip_set.clear()  # Clear old data before overwriting
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(fetch_and_extract_ips, url, etag_data, ip_set): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    print(f"Update status for {url}: {result}")
                except Exception as exc:
                    print(f"{url} generated an exception: {exc}")
        save_all_ips(ip_set)
    else:
        print("No updates required. Using existing consolidated_ips.json")
        with open('consolidated_ips.json', 'r') as file:
            ip_set = set(json.load(file))

    return ip_set

def main() -> None:
    # Check the number of command-line arguments
    if len(sys.argv) == 1:
        print("No input file provided. Updating consolidated_ips.json only.")
        update_consolidated_ips()
    elif len(sys.argv) == 2:
        input_filename = sys.argv[1]
        if not os.path.isfile(input_filename):
            print(f"Error: The file '{input_filename}' does not exist.")
            sys.exit(1)
        # Update the consolidated IPs and clean the input file
        ip_set = update_consolidated_ips()
        clean_ip_list(input_filename, ip_set)
    else:
        print("Usage: python script.py [<filename>]")
        sys.exit(1)

if __name__ == '__main__':
    main()

