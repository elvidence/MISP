# MISP Administration and Threat Intel Tools

Welcome to the repository for enhancing [MISP](https://github.com/MISP/MISP/) (Malware Information Sharing Platform & Threat Sharing). This collection of tools is designed to simplify administration, improve stability, and support Cyber Threat Intelligence (CTI) management. By streamlining processes and reinforcing platform reliability, these utilities make MISP easier to manage for administrators.

To maintain efficiency and reduce dependencies, the tools are built with minimal reliance on third-party Python modules, with the only exception being the requests library.


## misp_attr_async_get.py 
Interacts with a MISP (Malware Information Sharing Platform) to concurrently search and
retrieve details on cybersecurity events based on specific attributes, such as destination IP addresses ('ip-dst').
It efficiently manages multiple network requests to enhance performance. Users can dynamically configure the MISP URL
and API key, adapting to various operational environments. The script is developed in Python 3, ensuring compatibility
with contemporary libraries and systems. 

The script is highly adaptable, easily extended to handle other attribute types such as URLs, domains, email addresses or hashes.

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
>Please note that MISP 2.5, released in October 2024, now uses a Supervisor-based implementation. It is the default option for new installations and for instances upgraded via the upgrade script. Therefore, this script is only relevant to MISP versions below 2.5 that use workers.

This script monitors the status of MISP workers and attempts to restart them if they are down. This should greatly improve MISPs stabailiy. It logs the worker status and sends email notifications if a worker fails to start after repeated attempts. For the email functionality to operate, the SMTP service must be configured and functioning properly. However, the script can operate without the email and logging features if necessary; these can be enabled or disabled as needed with the `email_enabled` and `log_file` settings. The `email_enabled` setting allows for turning off email notifications, while the `log_file` specifies the destination for log entries. The script is intended to be added to the crontab for the same user as MISP (typically `www-data` on Ubuntu installations).

## ip_spec_ranges.py
This mudule provides a function that determines if the given IP address is part of designated non-public network ranges that include private networks, documentation, special protocols, and other non-routable uses. It handles both IPv4 and IPv6 addresses. This implementation provides a more comprehensive list of non-public IP ranges compared to commonly used libraries like netaddr, making it particularly suited for applications in threat intelligence cleaning and filtering. It ensures that all relevant special-use ranges are considered, minimising the risk of inadvertently processing or exposing these IPs in threat analysis environments.
> **Note**: The IPv6 address ranges `64:ff9b::/96` and `FF00::/8` are not included in the non-routable checks. `64:ff9b::/96` is used for IPv6 transition mechanisms (IPv4-IPv6 Network Prefix Translation), and while it is used for facilitating communication between IPv4 and IPv6 networks, it can be involved in specific security scenarios like address spoofing or obfuscation. `FF00::/8`, designated for IPv6 multicast. It is used for efficient data distribution, but it can be exploited in amplification or DoS attacks. Monitoring and special handling of these ranges can be important when addressing potential security threats.

## zero_noise_ips.py
This script helps to automate the integration of a large IP address feed(s) into OpenCTI (Open Cyber Threat Intelligence) or MISP (Malware Information Sharing Platform). It reduces false positives by validating IPs against benign lists derived from MISP warnings, focusing on IPs that warrant further investigation.
Usage: `python3 zero_noise_ips.py feed_to_clean.txt`. To update the consolidated json file `consolidated_ips.json` only, simply run `python3 zero_noise_ips.py`.

## cps_ioc_feed.py
This script is designed to fetch indicators of compromise (IOCs) from CriticalPathSecurity Public-Intelligence-Feeds at GitHub, specifically related to log4j, and cobaltstrike IPs as well as cobaltstrike domains. It processes IOCs by removing duplicates and filtering out non-public, non-routable (RFC) or irrelevant (CDN etc) IP addresses using functions from zero_noise_ips.py. IOCs are then saved into separate CSV files based on their type (IPs or domains). The zero_noise_ips.py script must be located in the same directory as this script for proper IP validation. These CSV files are ready for ingestion by threat intelligence tools such as MISP (as local feeds), OpenCTI, or other Threat Intelligence platforms, ensuring clean and relaible Iindicators of Compromise. 

## abuseipdb_ioc_feed.py
This script, similar to cps_ioc_feed.py, fetches indicators of compromise (IOCs) from AbuseIPDB (API key required) and processes them by removing duplicates and filtering out non-public, non-routable IP addresses (per RFC standards), as well as irrelevant IPs (e.g., from CDNs). It leverages functions from zero_noise_ips.py, which must be in the same directory for accurate IP validation.

## haas_ioc_feed.py
This script, similar to cps_ioc_feed.py and abuseipdb_ioc_feed.py, fetches indicators of compromise (IOCs) from the Honeypot as a Service (HaaS) feed provided by haas.nic.cz. It processes the data by unpacking, removing duplicates and filtering out non-public, non-routable IP addresses (per RFC standards), as well as excluding irrelevant IPs, such as those from content delivery networks (CDNs). The script relies on functions from zero_noise_ips.py, which should be in the same directory for accurate IP validation.

The data is provided by haas.nic.cz in a daily YYYY-MM-DD.json.gz format (e.g., 2024-10-01.json.gz published on 02-Oct-2024 around 01:01 AM) and is updated daily at about the same time. To ensure timely processing, it is essential to use cron to schedule the script's execution to match the data publication times.

## malwarepatrol_ioc_feed.py

This script, similar to cps_ioc_feed.py, haas_ioc_feed.py and abuseipdb_ioc_feed.py, fetches indicators of compromise (IOCs) from the MalwarePatrol feed. It processes the data by downloading a gzipped file, unpacking it, removing duplicates, and filtering out non-public, non-routable IP addresses (per RFC standards), as well as excluding irrelevant IPs, such as those from content delivery networks (CDNs). The script relies on functions from zero_noise_ips.py, which should be in the same directory for accurate IP validation.

Important Notes:
Ensure that the directories specified in the script (download_directory and extract_directory) exist or can be created by the script. The script will attempt to create these directories if they do not exist. Verify that the script has the necessary execution permissions. You may need to adjust file permissions using chmod if required. On MISP it typically runs as www-data.

The script requires the requests library. Install it using pip install requests.
The script logs all activities and any issues encountered to /var/log/local_feeds.log. 
To ensure timely processing, it is essential to use cron to schedule the script's execution to match the data publication times.

Example cron Entry:
To run the script every day at 2:00 AM, add the following line to your crontab:
```bash
0 2 * * * /var/www/MISP/venv/bin/python /path/to/malwarepatrol_feed_fetcher.py
```












    




