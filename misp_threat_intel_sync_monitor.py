#!/var/www/MISP/venv/bin/python

"""
Version: 0.9
Author: A. R.
License: MIT
Date: 18 May 2024

Description:
This script monitors the status and connectivity of both local and network-based cyber threat intelligence 
(CTI) feeds configured in a MISP instance. It uses threading to make the monitoring process efficient. 

The script also checks the connectivity with other MISP instances for CTI and Indicators of Compromise (IOCs) sharing purposes. 
Results are categorised and presented in a structured format to aid in quick assessment.

Inspired by a presentation from the MISP team.

Future updates will include the implementation of logging functionality.

Ensure the 'requests' module is installed before running the script.
You can install it by running: pip install requests
"""

import os
import warnings
from pymisp import PyMISP
import requests
from datetime import datetime
from threading import Thread, Lock

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# MISP configuration
misp_url = "https://localhost"  # Use localhost to avoid load balancer
misp_key = 'ENTER VALID MISP IP KEY'
misp_verifycert = False

# Initialise the MISP connector
misp_connector = PyMISP(misp_url, misp_key, ssl=misp_verifycert, debug=False)

# Fetch the list of feeds and filter out enabled ones
all_feeds = misp_connector.feeds()
enabled_feeds = [feed for feed in all_feeds if "Feed" in feed and feed["Feed"]["enabled"]]


def check_local_feed(feed_name, feed_url, results_dict, results_lock):
    """
    Checks the status of a local feed file.

    Parameters:
    feed_name (str): The name of the feed.
    feed_url (str): The local file path of the feed.
    results_dict (dict): Dictionary to store results.
    results_lock (Lock): A lock for thread-safe operations.
    """
    if os.path.isfile(feed_url):
        file_timestamp = os.path.getmtime(feed_url)
        file_age = datetime.now() - datetime.fromtimestamp(file_timestamp)
        result = (file_age.days, f"OK {feed_name} - Local feed file {feed_url} is {file_age.days} days old")
    else:
        result = (float('inf'), f"FAIL {feed_name} - Local feed file {feed_url} does not exist")

    with results_lock:
        if "FAIL" in result[1]:
            results_dict['problematic_results'].append(result[1])
        else:
            results_dict['local_feed_results'].append(result)


def get_auth_header(feed):
    """
    Retrieves the authorisation header from the feed.

    Parameters:
    feed (dict): The feed dictionary.

    Returns:
    dict: A dictionary containing the authorisation header if present, else an empty dictionary.
    """
    if "headers" in feed["Feed"] and isinstance(feed["Feed"]["headers"], str):
        auth_header = feed["Feed"]["headers"]
        if auth_header.startswith("Authorization: Basic "):
            return {"Authorization": auth_header.split("Authorization: ", 1)[1].strip()}
    return {}


def check_network_feed(feed, results_dict, results_lock):
    """
    Checks the connectivity of a network feed.

    Parameters:
    feed (dict): The feed dictionary.
    results_dict (dict): Dictionary to store results.
    results_lock (Lock): A lock for thread-safe operations.
    """
    feed_name = feed["Feed"]["name"]
    feed_url = feed["Feed"]["url"]

    headers = get_auth_header(feed)

    try:
        response = requests.get(feed_url, headers=headers, verify=misp_verifycert)
        if response.status_code in [200, 301]:
            result = f"OK {feed_name} - Connectivity check returned {response.status_code}"
            with results_lock:
                results_dict['network_feed_results'].append(result)
        else:
            result = f"FAIL {feed_name} - Connectivity check returned {response.status_code}"
            with results_lock:
                results_dict['problematic_results'].append(result)
    except Exception as e:
        result = f"FAIL {feed_name} - Connectivity check returned exception error: {str(e)}"
        with results_lock:
            results_dict['problematic_results'].append(result)


def process_feeds(feeds_list):
    """
    Processes all enabled feeds in parallel using threading.

    Parameters:
    feeds_list (list): List of enabled feeds.

    Returns:
    dict: A dictionary containing results for local feeds, network feeds, and problematic connections.
    """
    threads = []
    results_dict = {
        'local_feed_results': [],
        'network_feed_results': [],
        'problematic_results': []
    }
    results_lock = Lock()

    for feed in feeds_list:
        feed_url = feed["Feed"]["url"]
        feed_name = feed["Feed"]["name"]
        if feed_url.startswith('/'):
            thread = Thread(target=check_local_feed, args=(feed_name, feed_url, results_dict, results_lock))
        else:
            thread = Thread(target=check_network_feed, args=(feed, results_dict, results_lock))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results_dict


def check_sync_servers(servers_list, results_dict, results_lock):
    """
    Checks the connectivity of sync servers.

    Parameters:
    servers_list (list): List of sync servers.
    results_dict (dict): Dictionary to store results.
    results_lock (Lock): A lock for thread-safe operations.
    """
    for server in servers_list:
        if "Server" in server:
            server_id = server["Server"]["id"]
            server_name = server["Server"]["name"]
            sync_test = misp_connector.test_server(server_id)
            sync_mechanism = ""
            if server["Server"]["pull"]:
                sync_mechanism = "Pull"
            if server["Server"]["push"]:
                sync_mechanism = "{}Push".format(sync_mechanism)
            if "status" in sync_test and sync_test["status"] == 1:
                result = f"OK {server_name} - Sync test with {server_name} successful. {sync_mechanism}"
                with results_lock:
                    results_dict['sync_server_results'].append(result)
            else:
                result = f"FAIL {server_name} - Sync test with {server_name} failed. {sync_mechanism}"
                with results_lock:
                    results_dict['problematic_results'].append(result)


def sort_local_feeds(results_dict):
    """
    Sorts local feeds by file age (oldest first).

    Parameters:
    results_dict (dict): Dictionary containing results to be sorted.
    """
    results_dict['local_feed_results'].sort(reverse=True, key=lambda x: x[0])


def print_results(results_dict):
    """
    Prints the results of the connectivity checks.

    Parameters:
    results_dict (dict): Dictionary containing results to be printed.
    """
    print("\nProblematic Connections")
    print("——————")
    for result in results_dict['problematic_results']:
        print(result)

    print("\nLocal Feeds")
    print("——————")
    for _, result in results_dict['local_feed_results']:
        print(result)

    print("\nNetwork Feeds")
    print("——————")
    for result in results_dict['network_feed_results']:
        print(result)

    print("\nSync Servers")
    print("——————")
    for result in results_dict['sync_server_results']:
        print(result)


# Main processing
final_results = process_feeds(enabled_feeds)
sort_local_feeds(final_results)

# Check sync servers
sync_servers_list = misp_connector.servers()
sync_lock = Lock()
final_results['sync_server_results'] = []
check_sync_servers(sync_servers_list, final_results, sync_lock)

# Print final results
print_results(final_results)
