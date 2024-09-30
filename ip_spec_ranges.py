# ip_spec_ranges.py
# ------------------------------------------------------------------------------
# Module Name: IP Special Ranges Checker
# Author: A.R.
# Version: 1.1
# Last Modified: 20 Sep 2024
# Description: This module provides a function to check if an IP address
#              belongs to non-public (special and private) IP ranges. It is
#              designed to be used in environments where accurate identification
#              of such IPs is crucial for security and network management.
# ------------------------------------------------------------------------------
import ipaddress


def is_non_public_ip(ip_address):
    """
    Check if an IP address is non-public (non-routable) as defined by various RFCs.

    This function determines if the given IP address is part of designated non-public
    network ranges that include private networks, documentation, special protocols,
    and other non-routable uses. It handles both IPv4 and IPv6 addresses.

    This implementation provides a more comprehensive list of non-public IP ranges
    compared to commonly used libraries like netaddr, making it particularly suited
    for applications in threat intelligence cleaning and filtering. It ensures
    that all relevant special-use ranges are considered, minimising the risk of
    inadvertently processing or exposing these IPs in threat analysis environments.

    Args:
    ip_address (str): The IP address to check.

    Returns:
    bool: True if the IP address is non-public, False otherwise or if the IP is invalid.

    Examples:
    >>> is_non_public_ip('192.168.1.1')
    True
    >>> is_non_public_ip('8.8.8.8')
    False
    """
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return False  # Return False if the input is not a valid IP address

    # List of non-public (non-routable) IP ranges, more comprehensive than what netaddr provides.
    non_public_ranges = [
        ipaddress.ip_network('0.0.0.0/8'),  # Current network (RFC 5735)
        ipaddress.ip_network('10.0.0.0/8'),  # Private network - RFC 1918
        ipaddress.ip_network('100.64.0.0/10'),  # Carrier-grade NAT (RFC 6598)
        ipaddress.ip_network('127.0.0.0/8'),  # Loopback (RFC 5735)
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local (RFC 3927)
        ipaddress.ip_network('172.16.0.0/12'),  # Private network - RFC 1918
        ipaddress.ip_network('192.0.0.0/24'),  # IETF Protocol Assignments (RFC 6890)
        ipaddress.ip_network('192.0.2.0/24'),  # TEST-NET-1 (RFC 5737)
        ipaddress.ip_network('192.52.193.0/24'),  # AMT (RFC 7450)
        ipaddress.ip_network('192.88.99.0/24'),  # IPv6 to IPv4 relay anycast (RFC 3068)
        ipaddress.ip_network('192.168.0.0/16'),  # Private network - RFC 1918
        ipaddress.ip_network('198.18.0.0/15'),  # Network benchmark tests (RFC 2544)
        ipaddress.ip_network('198.51.100.0/24'),  # TEST-NET-2 (RFC 5737)
        ipaddress.ip_network('203.0.113.0/24'),  # TEST-NET-3 (RFC 5737)
        ipaddress.ip_network('224.0.0.0/4'),  # Multicast (RFC 5771)
        ipaddress.ip_network('240.0.0.0/4'),  # Reserved for future use (RFC 1112)
        ipaddress.ip_network('255.255.255.255/32'),  # Limited broadcast (RFC 919)
        ipaddress.ip_network('::1/128'),  # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),  # IPv6 Unique local address
        ipaddress.ip_network('fe80::/10')  # IPv6 link-local
        ipaddress.ip_network('2001:DB8::/32')  # Documentation (RFC 3849)
    ]

    # Check if the IP address belongs to any of the non-public ranges
    return any(ip_obj in network for network in non_public_ranges)


if __name__ == '__main__':
    # Test cases to demonstrate the use of the function
    # Delete this section when using in production env

    test_ips = ['192.168.1.1', '8.8.8.8', '10.0.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '192.0.2.1',
                '224.0.0.1']
    for ip in test_ips:
        print(f"{ip}: {is_non_public_ip(ip)}")
