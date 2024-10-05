#!/usr/bin/env python3

"""
Author: A.R.
Version: 1.1
Date: 05 October 2024
License: MIT

Description:
This script monitors the status of MISP workers and attempts to restart them if they are down.
It logs the worker status and sends email notifications if a worker fails to start after (set number of) repeated attempts.
The script is intended to be added to the crontab for the same user as MISP (typically www-data on Ubuntu installations).
Please note that MISP 2.5, released in October 2024, now uses a Supervisor-based implementation. It is the default option 
for new installations and for instances upgraded via the upgrade script. Therefore, this script is only relevant to MISP 
versions below 2.5 that use workers.

"""

import subprocess
import time
import logging
import smtplib
import json
from datetime import datetime
from email.message import EmailMessage

# Configuration
workers = ['cache', 'default', 'email', 'prio', 'update', 'scheduler']
email_enabled = True  # Set based on your need False/True
log_file = '/var/log/misp_workers.log' # Set the log destination
receiver_email = 'admin@yourorg.com.au', 'admin1@yourorg.com.au'  # Define the email address for notifications

# Setup logging
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')


def check_worker_status(worker):
    """Check the status of a worker."""
    command = ['/var/www/MISP/app/Console/cake', 'Admin', 'getWorkers']
    result = subprocess.run(command, capture_output=True, text=True)
    try:
        workers_status = json.loads(result.stdout)
        worker_status = workers_status.get(worker, {}).get('ok', False)
        return worker_status
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON from worker status command.")
        return False


def start_worker(worker):
    """Start a specific worker."""
    command = ['/var/www/MISP/app/Console/cake', 'CakeResque.CakeResque', 'start', '--interval', '5', '--queue', worker]
    subprocess.run(command)
    logging.info(f"{worker} worker start command issued.")


def send_email(subject, body):
    """Send an email notification."""
    if not email_enabled:
        return
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = 'misp@yourorg.gov.au'
    msg['To'] = receiver_email

    # Set up the SMTP server (modify as needed for your configuration)
    with smtplib.SMTP('localhost') as s:
        s.send_message(msg)


def manage_workers():
    for worker in workers:
        if not check_worker_status(worker):
            logging.info(f"[{datetime.now()}] {worker} worker is down, attempting to start.")
            start_worker(worker)
            time.sleep(180)  # Wait for 3 minutes before checking again
            if not check_worker_status(worker):
                logging.info(f"[{datetime.now()}] {worker} worker failed to start on first attempt, retrying.")
                time.sleep(1800)  # Wait for 30 minutes before retrying
                start_worker(worker)
                if not check_worker_status(worker):
                    logging.error(f"[{datetime.now()}] {worker} worker failed to start after second attempt.")
                    if email_enabled:
                        send_email(f"{worker} Worker Failed", f"The {worker} worker failed to start after "
                                                              f"repeated attempts.")
                else:
                    logging.info(f"[{datetime.now()}] {worker} worker started on second attempt.")
            else:
                logging.info(f"[{datetime.now()}] {worker} worker started successfully on first attempt.")


if __name__ == "__main__":
    manage_workers()
