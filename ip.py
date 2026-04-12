import ipaddress
from typing import List, Generator, Tuple, Optional, Dict
import sys

def classify_ip(ip_str: str) -> str:
    """
    Classify an IP address as Private or Public.
    """
    try:
        # Strip whitespace and handle empty strings
        ip_str = ip_str.strip()
        if not ip_str:
            return "Invalid (Empty)"
        
        ip = ipaddress.ip_address(ip_str)
        return "Private" if ip.is_private else "Public"
    except ValueError:
        return "Invalid"
    except Exception as e:
        return f"Error: {str(e)}"

def classify_ips_batch(ip_list: List[str]) -> List[str]:
    """Process IPs and return formatted results."""
    results = []
    for ip_str in ip_list:
        result = classify_ip(ip_str)
        results.append(f"{ip_str} -> {result}")
    return results

def normalize_cidr(cidr_str: str) -> str:
    """Handle CIDR strings with host bits set."""
    try:
        cidr_str = cidr_str.strip()
        # strict=False allows host bits to be zeroed out automatically
        network = ipaddress.ip_network(cidr_str, strict=False)
        return str(network)
    except ValueError:
        return f"Invalid CIDR: {cidr_str}"
    except Exception as e:
        return f"Error: {str(e)}"

# Simple test without classes or logging (to avoid compatibility issues)
def main():
    # Test cases including valid and invalid IPs
    ips = [
        "10.0.0.1",           # Valid private
        "8.8.8.8",            # Valid public
        "192.168.1.1",        # Valid private
        "invalid_ip",         # Invalid
        "999.999.999.999",    # Invalid
        " 172.16.0.1 ",       # Valid private with whitespace
        "",                   # Empty string
        "2001:db8::1"         # Valid IPv6 private (unique local)
    ]
    
    print("IP Classification Results:")
    print("-" * 40)
    results = classify_ips_batch(ips)
    for result in results:
        print(result)
    
    # CIDR normalization examples
    print("\n" + "=" * 40)
    print("CIDR Normalization Examples:")
    print("-" * 40)
    test_cidrs = [
        "192.168.1.5/24",     # Has host bits
        "10.0.0.100/8",       # Has host bits
        "invalid/cidr",       # Invalid format
        "192.168.1.0/24",     # Already normalized
        "192.168.1.0/24",     
    ]
    for cidr in test_cidrs:
        normalized = normalize_cidr(cidr)
        print(f"{cidr:20} -> {normalized}")
    
    # Statistics
    print("\n" + "=" * 40)
    print("Statistics:")
    print("-" * 40)
    valid_count = sum(1 for r in results if "-> Public" in r or "-> Private" in r)
    invalid_count = len(results) - valid_count
    print(f"Total IPs: {len(results)}")
    print(f"Valid: {valid_count}")
    print(f"Invalid: {invalid_count}")

# Run the main function
main()
