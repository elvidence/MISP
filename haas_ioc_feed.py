#!/var/www/MISP/venv/bin/python
# HaaS Feed Fetcher and Filter
# Version: 4.0
# Date: 15 October 2024
# Author: A.R.
# License: MIT

"""
This script automates the process of fetching IP addresses from the HaaS (Honeypot as a Service) feed provided by
haas.nic.cz. It downloads the latest feed, extracts unique IP addresses, filters out non-public and special-use IP
addresses as defined by RFCs, and excludes IPs present in the `consolidated_ips.json` file.

By utilising functions from `zero_noise_ips.py`, specifically `is_non_public_ip` and `update_consolidated_ips`,
the script ensures that only public, routable IP addresses that are not known benign or irrelevant are retained.
The cleaned list of IPs is then saved to a specified CSV file.

This process reduces false positives and enhances the relevance of the data when integrating with security platforms
like MISP or OpenCTI. The script is designed to handle large datasets efficiently, including mechanisms to check for
data changes and avoid unnecessary processing.
"""

import requests
import os
import gzip
import hashlib
import logging
import json
import csv
from datetime import datetime, timedelta
import re
from zero_noise_ips import is_non_public_ip, update_consolidated_ips  # Import necessary functions

def get_hash_of_file(file_content):
    """Calculates the MD5 hash of the file content."""
    return hashlib.md5(file_content).hexdigest()

def process_json_to_csv(gz_path, csv_path, consolidated_ips):
    """
    Processes a gzipped JSON file, extracts unique public IPs not in consolidated_ips,
    and writes them to a CSV, checking for changes.
    """
    with gzip.open(gz_path, 'rt', encoding='utf-8') as f_in:
        data = json.load(f_in)  # Parse JSON directly from the file object
        current_hash = get_hash_of_file(json.dumps(data).encode('utf-8'))  # Hash the parsed data

        # Check if the CSV file exists and if the hash matches
        if os.path.exists(csv_path):
            with open(csv_path, 'r') as f:
                existing_hash = f.readline().strip()
            if existing_hash == current_hash:
                logging.info("No changes in data. Existing data is up-to-date.")
                return False

        unique_ips = set()
        rows = []
        for entry in data:
            ip = entry.get('ip')
            if ip and not is_non_public_ip(ip) and ip not in consolidated_ips and ip not in unique_ips:
                unique_ips.add(ip)
                rows.append({'dst-ip': ip})

        if not rows:
            logging.info("No new IPs to write after filtering.")
            return False

        with open(csv_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['dst-ip'])
            writer.writeheader()
            writer.writerows(rows)

        # Store hash at the beginning of the file
        with open(csv_path, 'r+') as f:
            content = f.read()
            f.seek(0, 0)
            f.write(current_hash + '\n' + content)

        logging.info(f"Processed JSON data and written to CSV at {csv_path}")
        return True

def download_latest_file(_base_url, _download_dir, _extract_dir, consolidated_ips, days_delay=1):
    """Downloads the latest HaaS feed file, processes it, and cleans up."""

    def clean_directory(directory, pattern):
        for filename in os.listdir(directory):
            if re.match(pattern, filename):
                filepath = os.path.join(directory, filename)
                os.remove(filepath)

    clean_directory(_download_dir, r'\d{4}-\d{2}-\d{2}\.json\.gz')  # Clean directory of old files
    os.makedirs(_extract_dir, exist_ok=True)

    target_date = datetime.now() - timedelta(days=days_delay)
    file_date = target_date.strftime("%Y-%m-%d")
    year = target_date.strftime("%Y")
    month = target_date.strftime("%m")
    file_name = f"{file_date}.json.gz"
    gz_path = os.path.join(_download_dir, file_name)
    csv_path = os.path.join(_extract_dir, "haas_feed.csv")
    url = f"{_base_url}/{year}/{month}/{file_name}"

    logging.info(f"Attempting to download file from {url}")
    try:
        response = requests.get(url)
        if response.status_code == 200 and response.content:
            with open(gz_path, 'wb') as f:
                f.write(response.content)
            logging.info(f"Downloaded {file_name} to {gz_path}")

            if process_json_to_csv(gz_path, csv_path, consolidated_ips):
                os.remove(gz_path)  # Delete the gzip file only if CSV was updated
            else:
                os.remove(gz_path)
        else:
            logging.error(f"Failed to download or empty content: {url}, Status Code: {response.status_code}, Content-Length: {response.headers.get('Content-Length', 'Unknown')}")
    except Exception as e:
        logging.error(f"Error downloading or processing file: {e}")
        raise

# Logging configuration
logging.basicConfig(
    filename='/var/log/local_feeds.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - haas_feed_fetcher.py: %(message)s'
)

# Main execution (if run as a script)
if __name__ == "__main__":
    # Update the consolidated IPs and load them into a set
    logging.info("Updating consolidated IPs from zero_noise_ips.py...")
    consolidated_ips_set = update_consolidated_ips()
    if not consolidated_ips_set:
        with open('consolidated_ips.json', 'r') as file:
            consolidated_ips_set = set(json.load(file))
    logging.info("Consolidated IPs have been updated.")

    base_url = "https://haas.nic.cz/stats/export"
    download_dir = "/var/www/MISP/app/files/feeds"
    extract_dir = "/var/www/MISP/app/files/feeds/HaaS"
    download_latest_file(base_url, download_dir, extract_dir, consolidated_ips_set, days_delay=1)
