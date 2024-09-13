#!/var/www/MISP/venv/bin/python
"""
MISP Event Review Notifier
Version: 1.1
Date: 30 July 2024
Author: A.R.

Description:
This script fetches events tagged with the specified tag from a MISP instance and sends an email notification for each
event requiring review. The script uses concurrency to enhance efficiency and includes dynamic email subject line
adjustments based on the number of events requiring review.

License: MIT License
"""

# Imports
import requests
import logging
from datetime import datetime, timedelta
import os
import pickle
from email.message import EmailMessage
import smtplib
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
misp_url = "https://localhost"  # Use localhost to avoid load balancer issues
misp_key = 'ENTER VALID MISP API KEY'
misp_verifycert = False
headers = {
    'Authorization': misp_key,
    'Accept': 'application/json',
    'Content-type': 'application/json'
}
receiver_emails = ['email1@example.com', 'email2@example.com']
tag_name = "workflow:pending_review"
email_enabled = True  # Set to False to disable email notifications
logging_enabled = False  # Set to True to enable logging
log_file = '/var/log/local_management.log'
track_file = 'event_tracking.pkl'
default_interval_days = 30

# Logging setup
if logging_enabled:
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def load_tracking():
    if os.path.exists(track_file):
        with open(track_file, 'rb') as f:
            return pickle.load(f)
    return {}

def save_tracking(tracking):
    with open(track_file, 'wb') as f:
        pickle.dump(tracking, f)

def fetch_tagged_events(interval_days):
    since_date = (datetime.now() - timedelta(days=interval_days)).strftime('%Y-%m-%d')
    search_url = f"{misp_url}/events/restSearch"
    search_payload = {
        "returnFormat": "json",
        "tag": tag_name,
        "date_from": since_date
    }
    response = requests.post(search_url, headers=headers, json=search_payload, verify=misp_verifycert)
    return response.json().get('response', []) if response.status_code == 200 else []

def fetch_event_details(event_id):
    event_url = f"{misp_url}/events/view/{event_id}"
    response = requests.get(event_url, headers=headers, verify=misp_verifycert)
    if response.status_code == 200:
        event_data = response.json()
        return {
            'id': event_id,
            'info': event_data['Event'].get('info', "No event info available"),
            'timestamp': event_data['Event'].get('timestamp')
        }
    else:
        if logging_enabled:
            logging.error(f"Failed to fetch details for Event ID {event_id}. HTTP Status: {response.status_code}")
        return None

def send_email(subject, body, recipients):
    if email_enabled:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = 'misp@example.com'
        msg['To'] = ', '.join(recipients)
        with smtplib.SMTP('localhost') as s:
            s.send_message(msg)
        if logging_enabled:
            logging.info(f"Email sent regarding event IDs: {body}")

def cleanup_tracking(tracking, interval_days):
    cutoff = (datetime.now() - timedelta(days=interval_days)).timestamp()
    return {event_id: ts for event_id, ts in tracking.items() if ts >= cutoff}

def main():
    tracking = load_tracking()
    events = fetch_tagged_events(default_interval_days)
    events_to_notify = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_event = {executor.submit(fetch_event_details, event['Event']['id']): event for event in events}
        for future in as_completed(future_to_event):
            event_details = future.result()
            if event_details and (event_details['id'] not in tracking or tracking[event_details['id']] < int(event_details['timestamp'])):
                events_to_notify.append(f"Event ID {event_details['id']} requires review.")
                tracking[event_details['id']] = int(event_details['timestamp'])
    if events_to_notify:
        number_of_events = len(events_to_notify)
        subject_suffix = "Event Requires Review" if number_of_events == 1 else "Events Require Review"
        email_body = "\n".join(events_to_notify)
        email_subject = f"{number_of_events} MISP {subject_suffix}"
        send_email(email_subject, email_body, receiver_emails)
    tracking = cleanup_tracking(tracking, default_interval_days)
    save_tracking(tracking)

if __name__ == '__main__':
    main()
