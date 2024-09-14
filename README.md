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



