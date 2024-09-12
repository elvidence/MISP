#!/usr/bin/env python3

"""
Author: A.R.
Version: 1.0
Date: 12 Sep 2024
License: MIT

Description: This script interacts with a MISP (Malware Information Sharing Platform) to concurrently search and
retrieve details on cybersecurity events based on specific attributes, such as destination IP addresses ('ip-dst').
It efficiently manages multiple network requests to enhance performance. Users can dynamically configure the MISP URL
and API key, adapting to various operational environments. The script is developed in Python 3, ensuring compatibility
with contemporary libraries and systems. 

The script is highly adaptable, easily extended to handle other attribute types such as URLs, email addresses or hashes.

Example Adaptation:
To search for URLs instead of IP addresses, change the attribute type in the `misp_search` call from 'ip-dst' to 'url'.
"""

import os
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Constants
MISP_URL = os.getenv('MISP_URL') or input("Enter MISP URL (e.g., https://misp.example.com): ")
API_KEY = os.getenv('MISP_API_KEY') or input("Enter MISP API Key: ")
HEADERS = {
    'Authorization': API_KEY,
    'Accept': 'application/json',
    'Content-type': 'application/json'
}


def fetch_event_details(event_id):
    """Fetch detailed information for a given MISP event ID."""
    url = f"{MISP_URL}/events/view/{event_id}"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        event_data = response.json().get('Event', {})
        info = event_data.get('info', "No event info available")
        tags = [tag['name'] for tag in event_data.get('Tag', [])]
        return event_id, info, tags
    except requests.HTTPError as e:
        print(f"Failed to retrieve event details for Event ID {event_id}: {str(e)}")
        return event_id, "No event info available", []


def misp_search(keyword, attribute_type):
    """Search MISP for attributes based on a keyword and attribute type, handling concurrency."""
    payload = {
        'returnFormat': 'json',
        'category': ["Network activity", "Payload delivery", "External analysis"],
        'type': attribute_type,
        'value': keyword,
        'includeDecayScore': True
    }

    search_url = f'{MISP_URL}/attributes/restSearch/json'
    try:
        response = requests.post(search_url, headers=HEADERS, json=payload)
        response.raise_for_status()
        attributes = response.json().get('response', {}).get('Attribute', [])

        with ThreadPoolExecutor() as executor:
            event_details = {executor.submit(fetch_event_details, attr['event_id']): attr for attr in attributes if
                             'event_id' in attr}
            unique_events = set()
            for future in event_details:
                event_id, info, tags = future.result()
                if event_id not in unique_events:
                    unique_events.add(event_id)
                    attribute = event_details[future]
                    process_event(attribute, event_id, info, tags)
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {str(e)}")


def process_event(attribute, event_id, info, tags):
    """Process and display details of an event."""
    timestamp = attribute.get('timestamp')
    human_readable_timestamp = datetime.fromtimestamp(int(timestamp)).strftime(
        "%Y-%m-%d") if timestamp else "No valid timestamp available."
    decay_scores = attribute.get('decay_score', [])
    print_event_details(event_id, info, decay_scores, human_readable_timestamp, tags)


def print_event_details(event_id, info, decay_scores, timestamp, tags):
    """Print details of an event in a structured format."""
    print(f"Event ID: {event_id}")
    print(f"Incident: {info}")
    print_decay_scores(decay_scores)
    print(f"Last Updated: {timestamp}")
    print("Event Tags:")
    for tag in tags:
        tag_type, _, tag_value = tag.partition(':')
        print(f"• {tag_type.capitalize()}: {tag_value}")
    print("-" * 40)


def print_decay_scores(decay_scores):
    """Print decay scores if available."""
    if decay_scores:
        decayed = decay_scores[0]['decayed']
        score = decay_scores[0]['score']
        model_name = decay_scores[0]['DecayingModel']['name']
        decay_output = "Decay Scores: DECAYED - " + model_name if decayed else f"{score:.1f} - {model_name}"
        print(decay_output)


# Main execution
if __name__ == "__main__":
    ip_to_search = input("Enter IP: ")
    misp_search(ip_to_search, "ip-dst")
