#!/usr/bin/env python3

"""
Author: A.R.
Version: 1.0
Date: 03 Aug 2024
License: MIT

Description:
This script connects to a MISP (Malware Information Sharing Platform) instance, retrieves all tags,
and allows the user to delete tags based on a keyword match. It first displays matched tags with pagination
for easier review, then prompts the user for confirmation before proceeding with deletion. This method enhances
user control and prevents accidental deletion of unintended tags.

Ensure the 'requests' module is installed before running the script.
You can install it by running: pip install requests
"""

import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MISP configuration
misp_url = 'https://127.0.0.1'
misp_key = 'ENTER_MISP_KEY'
misp_verifycert = False
headers = {
    'Authorization': misp_key,
    'Accept': 'application/json',
    'Content-type': 'application/json'
}

def paginate_tags(tags, page_size=10):
    """Utility function to paginate tags for easy viewing."""
    for i in range(0, len(tags), page_size):
        current_page = tags[i:i + page_size]
        for tag in current_page:
            print(f"ID: {tag['id']} - Tag: {tag['name']}")
        if i + page_size < len(tags):
            input("Press enter to see more tags...")
        else:
            print("End of list.")

def delete_tags_by_keyword(keyword):
    """
    Retrieves all tags from MISP, filters by a user-specified keyword,
    displays matched tags with pagination, and prompts for user confirmation
    before deleting the tags.
    """
    try:
        # Retrieve all tags
        response = requests.get(f"{misp_url}/tags/index", headers=headers, verify=misp_verifycert)
        tags = response.json()

        # Assume tags are directly the JSON response; handle differently if necessary
        tag_list = tags if isinstance(tags, list) else tags.get('Tag', [])

        # Filter tags containing the specified keyword
        matched_tags = [tag for tag in tag_list if keyword in tag['name']]
        if matched_tags:
            print("Matching tags found:")
            paginate_tags(matched_tags)

            # Ask user if they want to proceed with deletion
            confirm = input("Do you want to delete these matching tags? (yes/no): ")
            if confirm.lower() == 'yes':
                for tag in matched_tags:
                    print(f"Attempting to delete tag: {tag['name']} with ID: {tag['id']}")
                    delete_response = requests.post(f"{misp_url}/tags/delete/{tag['id']}", headers=headers, verify=misp_verifycert)
                    if delete_response.status_code == 200:
                        print(f"Deleted tag: {tag['name']} with ID: {tag['id']}")
                    else:
                        print(f"Failed to delete tag: {tag['name']} with response: {delete_response.text}")
            else:
                print("Deletion cancelled by user.")
        else:
            print("No matching tags found.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Request user input for tag keyword
    keyword = input("Enter the keyword for the tags you wish to check: ")
    delete_tags_by_keyword(keyword)
