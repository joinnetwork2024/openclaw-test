import ipaddress
from typing import Iterator, Dict, Any

def audit_security_groups(groups: Iterator[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    """
    Streams findings using a generator to handle large-scale SG data efficiently.
    Addresses IPv4, IPv6, and Protocol -1 (All Traffic) risks.
    """
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unknown")
        
        for rule in sg.get("IpPermissions", []):
            # AWS uses -1 to represent 'All Protocols'
            ip_protocol = rule.get("IpProtocol")
            from_port = rule.get("FromPort")
            is_all_traffic = (ip_protocol == "-1") or (from_port is None)
            
            # Helper to check both IPv4 and IPv6
            ip_sources = [
                (r.get("CidrIp"), "IPv4") for r in rule.get("IpRanges", [])
            ] + [
                (r.get("CidrIpv6"), "IPv6") for r in rule.get("Ipv6Ranges", [])
            ]

            for cidr, ip_type in ip_sources:
                if not cidr:
                    continue

                network = ipaddress.ip_network(cidr)
                
                if network.is_global and not network.is_private:
                    yield {
                        "GroupId": sg_id,
                        "GroupName": sg_name,
                        "Type": ip_type,
                        "Port": "ALL" if is_all_traffic else from_port,
                        "Source": cidr,
                        "Risk": "CRITICAL" if is_all_traffic else "HIGH"
                    }

# Execution with Paginator (Mocked for context)
if __name__ == "__main__":
    security_groups_data = [
        {"GroupName": "web-sg", "GroupId": "sg-0a1b2c", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}  # Dangerous IPv6 All Traffic
        ]}
    ]

    # audit_security_groups is now a generator, so we iterate over it
    for finding in audit_security_groups(security_groups_data):
        print(f"[{finding['Risk']}] {finding['GroupName']}: Port {finding['Port']} open to {finding['Source']} ({finding['Type']})")
