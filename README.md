# MISP Administration Tools

Welcome to the repository for enhancing MISP (Malware Information Sharing Platform & Threat Sharing). This collection of tools aims to simplify the administration and improve the stability of MISP instances. These utilities are designed to streamline processes and ensure a more robust platform, making it easier for administrators to manage MISP.

## misp_attr_async_get.py 
Interacts with a MISP (Malware Information Sharing Platform) to concurrently search and
retrieve details on cybersecurity events based on specific attributes, such as destination IP addresses ('ip-dst').
It efficiently manages multiple network requests to enhance performance. Users can dynamically configure the MISP URL
and API key, adapting to various operational environments. The script is developed in Python 3, ensuring compatibility
with contemporary libraries and systems. 

The script is highly adaptable, easily extended to handle other attribute types such as URLs, email addresses or hashes.

Example Adaptation:
To search for URLs instead of IP addresses, change the attribute type in the `misp_search` call from `ip-dst` to `url`.

## misp_review_alert.py
This script fetches events tagged with the specified tag from a MISP instance and sends an email notification for each
event requiring review. The script uses concurrency to enhance efficiency and includes dynamic email subject line
adjustments based on the number of events requiring review.

## misp_tag_cleaner.py
This script connects to a MISP instance, retrieves all tags, and allows the user to delete tags based on a keyword match. It first displays matched tags with pagination for easier review, then prompts the user for confirmation before proceeding with deletion. This method enhances user control and prevents accidental deletion of unintended tags.

## misp_threat_intel_sync_monitor.py
Inspired by a presentation from the MISP team.

This script monitors the status and connectivity of both local and network-based cyber threat intelligence 
(CTI) feeds configured in a MISP instance. It uses threading to make the monitoring process efficient. 

The script also checks the connectivity with other MISP instances for CTI and Indicators of Compromise (IOCs) sharing purposes. Results are categorised and presented in a structured format to aid in quick assessment.

Future updates will include the implementation of logging functionality.

## misp_worker_monitor.py
This script monitors the status of MISP workers and attempts to restart them if they are down. This should greatly improve MISPs stabailiy. It logs the worker status and sends email notifications if a worker fails to start after repeated attempts. For the email functionality to operate, the SMTP service must be configured and functioning properly. However, the script can operate without the email and logging features if necessary; these can be enabled or disabled as needed with the `email_enabled` and `log_file` settings. The `email_enabled` setting allows for turning off email notifications, while the `log_file` specifies the destination for log entries. The script is intended to be added to the crontab for the same user as MISP (typically `www-data` on Ubuntu installations).



