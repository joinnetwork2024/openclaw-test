import ipaddress
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, Dict, List, Tuple
from collections import defaultdict

class InvalidFirewallRuleError(Exception):
    """Custom exception for invalid firewall rule parameters."""
    pass

class Action(Enum):
    """Firewall action types."""
    ALLOW = 'allow'
    DENY = 'deny'

@dataclass(frozen=True, slots=True)  # Make immutable and hashable
class FirewallRule:
    """Individual firewall rule - lightweight, immutable data container."""
    src: str
    dst: str
    port: int
    action: Action = Action.ALLOW
    priority: int = 0  # Lower number = higher priority
    
    # These will be set in __post_init__ but excluded from comparison
    _src_net: Optional[ipaddress.IPv4Network] = None
    _dst_net: Optional[ipaddress.IPv4Network] = None
    
    def __post_init__(self):
        """Validate and normalize - called after init for frozen dataclass."""
        # Use object.__setattr__ because dataclass is frozen
        object.__setattr__(self, '_src_net', self._normalize_to_network(self.src, "src"))
        object.__setattr__(self, '_dst_net', self._normalize_to_network(self.dst, "dst"))
        self._validate_port()
        self._validate_action()
    
    def _normalize_to_network(self, ip_string: str, field_name: str):
        try:
            if '/' in ip_string:
                network = ipaddress.ip_network(ip_string, strict=False)
            else:
                ip_obj = ipaddress.ip_address(ip_string)
                prefix = 32 if ip_obj.version == 4 else 128
                network = ipaddress.ip_network(f"{ip_string}/{prefix}", strict=False)
            return network
        except ValueError as e:
            raise InvalidFirewallRuleError(f"Invalid {field_name}: {e}")
    
    def _validate_port(self):
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise InvalidFirewallRuleError(f"Invalid port: {self.port}")
    
    def _validate_action(self):
        if not isinstance(self.action, Action):
            raise InvalidFirewallRuleError(f"Invalid action: {self.action}")


class RadixTrieNode:
    """Node in a radix tree for IP prefix matching."""
    
    __slots__ = ('children', 'rule', 'prefix')
    
    def __init__(self):
        self.children: Dict[int, RadixTrieNode] = {}
        self.rule: Optional[FirewallRule] = None
        self.prefix: Optional[ipaddress.IPv4Network] = None


class FirewallEngine:
    """
    High-performance firewall engine using Radix Tree for O(log n) lookups.
    """
    
    def __init__(self):
        self.src_trie = RadixTrieNode()
        self.dst_trie = RadixTrieNode()
        self.port_map: Dict[int, List[FirewallRule]] = defaultdict(list)
        self.rules: List[FirewallRule] = []
    
    def add_rule(self, rule: FirewallRule):
        """Add a rule to the engine with optimized indexing."""
        self.rules.append(rule)
        self._insert_into_trie(self.src_trie, rule._src_net, rule)
        self._insert_into_trie(self.dst_trie, rule._dst_net, rule)
        self.port_map[rule.port].append(rule)
    
    def _insert_into_trie(self, root: RadixTrieNode, network: ipaddress.IPv4Network, rule: FirewallRule):
        """Insert a network prefix into the radix tree."""
        current = root
        bits = self._network_to_bits(network)
        prefix_len = network.prefixlen
        
        for pos in range(prefix_len):
            bit = bits[pos]
            
            if bit not in current.children:
                current.children[bit] = RadixTrieNode()
            
            current = current.children[bit]
            
            # Store rule at the most specific node
            if pos == prefix_len - 1:
                if current.rule is None or rule.priority < current.rule.priority:
                    current.rule = rule
                    current.prefix = network
    
    def _network_to_bits(self, network: ipaddress.IPv4Network) -> List[int]:
        """Convert IP network to list of bits for trie traversal."""
        addr_int = int(network.network_address)
        bit_length = 32 if network.version == 4 else 128
        binary_str = bin(addr_int)[2:].zfill(bit_length)
        return [int(bit) for bit in binary_str]
    
    def _longest_prefix_match(self, trie: RadixTrieNode, ip: ipaddress.IPv4Address) -> Optional[FirewallRule]:
        """Find the longest prefix match for an IP address."""
        if not trie.children:
            return None
        
        current = trie
        best_match = None
        bits = self._ip_to_bits(ip)
        
        for bit in bits:
            if bit in current.children:
                current = current.children[bit]
                if current.rule is not None:
                    best_match = current.rule
            else:
                break
        
        return best_match
    
    def _ip_to_bits(self, ip: ipaddress.IPv4Address) -> List[int]:
        """Convert IP address to list of bits."""
        addr_int = int(ip)
        bit_length = 32 if ip.version == 4 else 128
        binary_str = bin(addr_int)[2:].zfill(bit_length)
        return [int(bit) for bit in binary_str]
    
    def match_flow(self, src_ip: str, dst_ip: str, port: int) -> Optional[Action]:
        """
        Match a flow against all rules using optimized trie lookups.
        Fixed: Now uses list instead of set to avoid hashing issues.
        """
        try:
            src_obj = ipaddress.ip_address(src_ip)
            dst_obj = ipaddress.ip_address(dst_ip)
            
            # Get best matching rules for source and destination
            src_rule = self._longest_prefix_match(self.src_trie, src_obj)
            dst_rule = self._longest_prefix_match(self.dst_trie, dst_obj)
            
            # Port-specific rules (usually small set)
            port_rules = self.port_map.get(port, [])
            
            # Combine candidates using list (avoiding set hashing issues)
            candidates = []
            if src_rule:
                candidates.append(src_rule)
            if dst_rule:
                candidates.append(dst_rule)
            candidates.extend(port_rules)
            
            # Remove duplicates while preserving order (using dict from Python 3.7+)
            seen = {}
            candidates = [seen.setdefault(id(rule), rule) for rule in candidates if id(rule) not in seen]
            
            # Find the best matching rule
            best_rule = None
            best_score = -1
            
            for rule in candidates:
                # Verify full match
                if (src_obj in rule._src_net and 
                    dst_obj in rule._dst_net and 
                    rule.port == port):
                    
                    # Score: lower priority is better, then longer prefix length
                    score = (rule.priority, 
                            rule._src_net.prefixlen + rule._dst_net.prefixlen)
                    
                    if best_rule is None or score < best_score:
                        best_rule = rule
                        best_score = score
            
            return best_rule.action if best_rule else None
            
        except (ValueError, ipaddress.AddressValueError):
            return None
    
    def add_rules_batch(self, rules: List[FirewallRule]):
        """Add multiple rules efficiently."""
        for rule in rules:
            self.add_rule(rule)


# Simplified test
if __name__ == "__main__":
    print("🔍 Firewall Engine Test Results:")
    print("=" * 50)
    
    engine = FirewallEngine()
    
    # Add rules with different priorities
    engine.add_rule(FirewallRule("192.168.1.0/24", "10.0.0.0/8", 80, Action.ALLOW, priority=10))
    engine.add_rule(FirewallRule("192.168.1.100/32", "10.1.1.0/24", 80, Action.DENY, priority=5))
    engine.add_rule(FirewallRule("0.0.0.0/0", "0.0.0.0/0", 443, Action.DENY, priority=100))
    
    # Test flows
    test_cases = [
        ("192.168.1.50", "10.0.1.10", 80, "Should ALLOW"),
        ("192.168.1.100", "10.1.1.5", 80, "Should DENY (specific rule)"),
        ("8.8.8.8", "1.1.1.1", 443, "Should DENY (default)"),
        ("192.168.2.1", "10.2.2.2", 22, "Should NO MATCH"),
    ]
    
    for src, dst, port, description in test_cases:
        action = engine.match_flow(src, dst, port)
        action_str = action.value if action else "NO MATCH"
        print(f"{src:20} -> {dst:20}:{port:<5} => {action_str:10} ({description})")
    
    # Performance test with more rules
    print("\n" + "=" * 50)
    print("⚡ Performance Test with 1,000 rules")
    print("=" * 50)
    
    import random
    import time
    
    # Add 1000 random rules
    for i in range(1000):
        src_network = f"{random.randint(1, 223)}.{random.randint(0, 255)}.0.0/{random.choice([8, 16, 24, 32])}"
        dst_network = f"10.{random.randint(0, 255)}.0.0/{random.choice([8, 16, 24, 32])}"
        port = random.randint(1, 65535)
        engine.add_rule(FirewallRule(src_network, dst_network, port, 
                                    action=random.choice([Action.ALLOW, Action.DENY]),
                                    priority=i))
    
    # Test 10,000 flows
    test_flows = []
    for _ in range(10000):
        src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        port = random.randint(1, 65535)
        test_flows.append((src_ip, dst_ip, port))
    
    start = time.perf_counter()
    for src, dst, port in test_flows:
        engine.match_flow(src, dst, port)
    elapsed = time.perf_counter() - start
    
    print(f"Processed {len(test_flows):,} flows in {elapsed:.3f} seconds")
    print(f"Throughput: {len(test_flows)/elapsed:,.0f} flows/second")
    print(f"Average latency: {elapsed/len(test_flows)*1000:.3f} ms/flow")
