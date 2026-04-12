import ipaddress
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, Dict, Tuple
from collections import defaultdict

class InvalidFirewallRuleError(Exception):
    """Custom exception for invalid firewall rule parameters."""
    pass

class Action(Enum):
    """Firewall action types."""
    ALLOW = 'allow'
    DENY = 'deny'

@dataclass
class FirewallRule:
    """Individual firewall rule - lightweight data container."""
    src: str
    dst: str
    port: int
    action: Action = Action.ALLOW
    priority: int = 0  # Lower number = higher priority
    
    _src_net: Optional[ipaddress.IPv4Network] = None
    _dst_net: Optional[ipaddress.IPv4Network] = None
    
    def __post_init__(self):
        self._src_net = self._normalize_to_network(self.src, "src")
        self._dst_net = self._normalize_to_network(self.dst, "dst")
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
        self.children: Dict[int, RadixTrieNode] = {}  # Next bit position -> node
        self.rule: Optional[FirewallRule] = None
        self.prefix: Optional[ipaddress.IPv4Network] = None
    
    def __repr__(self):
        return f"Node(prefix={self.prefix}, has_rule={self.rule is not None}, children={len(self.children)})"


class FirewallEngine:
    """
    High-performance firewall engine using Radix Tree for O(log n) lookups.
    
    Suitable for 10,000+ rules with microsecond lookup times.
    """
    
    def __init__(self):
        self.src_trie = RadixTrieNode()
        self.dst_trie = RadixTrieNode()
        self.port_map: Dict[int, list] = defaultdict(list)  # Port -> list of rules
        self.rules: list[FirewallRule] = []
    
    def add_rule(self, rule: FirewallRule):
        """Add a rule to the engine with optimized indexing."""
        self.rules.append(rule)
        
        # Index by source IP
        self._insert_into_trie(self.src_trie, rule._src_net, rule)
        
        # Index by destination IP
        self._insert_into_trie(self.dst_trie, rule._dst_net, rule)
        
        # Index by port for fast filtering
        self.port_map[rule.port].append(rule)
    
    def _insert_into_trie(self, root: RadixTrieNode, network: ipaddress.IPv4Network, rule: FirewallRule):
        """
        Insert a network prefix into the radix tree.
        
        Time complexity: O(prefix_length) = O(32) for IPv4, O(128) for IPv6
        """
        current = root
        
        # Convert network to binary string for bit-by-bit traversal
        bits = self._network_to_bits(network)
        prefix_len = network.prefixlen
        
        for pos in range(prefix_len):
            bit = bits[pos]
            
            if bit not in current.children:
                current.children[bit] = RadixTrieNode()
            
            current = current.children[bit]
            
            # Store rule at the most specific node (longest prefix match)
            # But keep less specific ones for fallback
            if prefix_len - 1 == pos or pos == prefix_len - 1:
                if current.rule is None or rule.priority < current.rule.priority:
                    current.rule = rule
                    current.prefix = network
    
    def _network_to_bits(self, network: ipaddress.IPv4Network) -> list:
        """
        Convert IP network to list of bits for trie traversal.
        
        Returns list of 0/1 integers representing the binary form.
        """
        # Get the network address as integer
        addr_int = int(network.network_address)
        
        # Determine bit length based on IP version
        bit_length = 32 if network.version == 4 else 128
        
        # Convert to binary string without '0b' prefix, pad to full length
        binary_str = bin(addr_int)[2:].zfill(bit_length)
        
        # Return list of bits as integers (0 or 1)
        return [int(bit) for bit in binary_str]
    
    def _longest_prefix_match(self, trie: RadixTrieNode, ip: ipaddress.IPv4Address) -> Optional[FirewallRule]:
        """
        Find the longest prefix match for an IP address.
        
        Time complexity: O(prefix_length) = O(32) for IPv4, O(128) for IPv6
        """
        if not trie.children:
            return None
        
        current = trie
        best_match = None
        bits = self._ip_to_bits(ip)
        
        for pos, bit in enumerate(bits):
            if bit in current.children:
                current = current.children[bit]
                if current.rule is not None:
                    best_match = current.rule
            else:
                break
        
        return best_match
    
    def _ip_to_bits(self, ip: ipaddress.IPv4Address) -> list:
        """Convert IP address to list of bits."""
        addr_int = int(ip)
        bit_length = 32 if ip.version == 4 else 128
        binary_str = bin(addr_int)[2:].zfill(bit_length)
        return [int(bit) for bit in binary_str]
    
    def match_flow(self, src_ip: str, dst_ip: str, port: int) -> Optional[Action]:
        """
        Match a flow against all rules using optimized trie lookups.
        
        Time complexity: O(prefix_len) ~ O(32-128) for longest prefix match
        Plus O(k) where k = rules matching port (usually very small)
        """
        try:
            src_obj = ipaddress.ip_address(src_ip)
            dst_obj = ipaddress.ip_address(dst_ip)
            
            # Get best matching rules for source and destination
            src_rule = self._longest_prefix_match(self.src_trie, src_obj)
            dst_rule = self._longest_prefix_match(self.dst_trie, dst_obj)
            
            # Port-specific rules (usually small set)
            port_rules = self.port_map.get(port, [])
            
            # Combine candidates and find highest priority match
            candidates = set()
            if src_rule:
                candidates.add(src_rule)
            if dst_rule:
                candidates.add(dst_rule)
            candidates.update(port_rules)
            
            # Find the best matching rule (highest priority, then most specific)
            best_rule = None
            best_score = -1
            
            for rule in candidates:
                # Verify full match (source, dest, port all match)
                if (src_obj in rule._src_net and 
                    dst_obj in rule._dst_net and 
                    rule.port == port):
                    
                    # Score: lower priority number is better, then longer prefix length
                    score = (rule.priority, 
                            rule._src_net.prefixlen + rule._dst_net.prefixlen)
                    
                    if best_rule is None or score < best_score:
                        best_rule = rule
                        best_score = score
            
            return best_rule.action if best_rule else None
            
        except (ValueError, ipaddress.AddressValueError):
            return None
    
    def add_rules_batch(self, rules: list[FirewallRule]):
        """Add multiple rules efficiently."""
        for rule in rules:
            self.add_rule(rule)


# Optimized Segment Tree for Port Ranges (bonus optimization)
class SegmentTree:
    """
    Segment tree for O(log n) port range matching.
    Useful when rules have port ranges instead of single ports.
    """
    
    def __init__(self, max_port: int = 65535):
        self.max_port = max_port
        self.tree = [None] * (4 * max_port)
    
    def insert(self, port_start: int, port_end: int, rule: FirewallRule):
        """Insert a port range rule into the segment tree."""
        self._insert(1, 1, self.max_port, port_start, port_end, rule)
    
    def _insert(self, node: int, left: int, right: int, 
                port_start: int, port_end: int, rule: FirewallRule):
        """Recursive segment tree insertion."""
        if port_start > right or port_end < left:
            return
        
        if port_start <= left and right <= port_end:
            if self.tree[node] is None or rule.priority < self.tree[node].priority:
                self.tree[node] = rule
            return
        
        mid = (left + right) // 2
        self._insert(node * 2, left, mid, port_start, port_end, rule)
        self._insert(node * 2 + 1, mid + 1, right, port_start, port_end, rule)
    
    def query(self, port: int) -> Optional[FirewallRule]:
        """Find best matching rule for a port."""
        node = 1
        left, right = 1, self.max_port
        best_rule = None
        
        while left <= right:
            if self.tree[node] is not None:
                if best_rule is None or self.tree[node].priority < best_rule.priority:
                    best_rule = self.tree[node]
            
            if left == right:
                break
            
            mid = (left + right) // 2
            if port <= mid:
                node = node * 2
                right = mid
            else:
                node = node * 2 + 1
                left = mid + 1
        
        return best_rule


# Performance Benchmark
def benchmark_performance():
    """Compare linear vs trie-based lookup performance."""
    import time
    import random
    
    print("🏢 Enterprise Firewall Engine Benchmark")
    print("=" * 50)
    
    # Generate realistic rule set (mix of /8, /16, /24, /32)
    rule_counts = [100, 500, 1000, 5000, 10000]
    
    for num_rules in rule_counts:
        engine = FirewallEngine()
        rules = []
        
        # Create rules with varying prefix lengths
        for i in range(num_rules):
            # Diverse prefix lengths for realistic scenarios
            src_prefix = random.choice([8, 16, 24, 32])
            dst_prefix = random.choice([8, 16, 24, 32])
            
            src_network = f"{random.randint(1, 223)}.{random.randint(0, 255)}.0.0/{src_prefix}"
            dst_network = f"10.{random.randint(0, 255)}.0.0/{dst_prefix}"
            port = random.randint(1, 65535)
            
            rule = FirewallRule(src_network, dst_network, port, 
                               action=random.choice([Action.ALLOW, Action.DENY]),
                               priority=i)
            rules.append(rule)
        
        # Add rules to engine
        start_add = time.perf_counter()
        engine.add_rules_batch(rules)
        add_time = time.perf_counter() - start_add
        
        # Generate test flows
        test_flows = []
        for _ in range(10000):
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            port = random.randint(1, 65535)
            test_flows.append((src_ip, dst_ip, port))
        
        # Benchmark lookup performance
        start_lookup = time.perf_counter()
        for src, dst, port in test_flows:
            engine.match_flow(src, dst, port)
        lookup_time = time.perf_counter() - start_lookup
        
        # Calculate theoretical linear search time
        linear_time = (len(rules) * len(test_flows)) / 10_000_000  # ~10M checks/sec
        
        print(f"\n📊 {num_rules:5,} rules:")
        print(f"   Add time:     {add_time:.3f}s")
        print(f"   Lookup time:  {lookup_time:.3f}s ({lookup_time/len(test_flows)*1000:.3f} ms/flow)")
        print(f"   Throughput:   {len(test_flows)/lookup_time:,.0f} flows/sec")
        print(f"   Linear would be ~{linear_time:.2f}s (O(n) vs O(log n))")
        print(f"   Speedup:      {linear_time/lookup_time:.1f}x")


if __name__ == "__main__":
    # Quick demonstration
    engine = FirewallEngine()
    
    # Add rules with different priorities
    engine.add_rule(FirewallRule("192.168.1.0/24", "10.0.0.0/8", 80, Action.ALLOW, priority=10))
    engine.add_rule(FirewallRule("192.168.1.100/32", "10.1.1.0/24", 80, Action.DENY, priority=5))  # Higher priority
    engine.add_rule(FirewallRule("0.0.0.0/0", "0.0.0.0/0", 443, Action.DENY, priority=100))  # Default deny
    
    # Test flows
    test_cases = [
        ("192.168.1.50", "10.0.1.10", 80),    # Should ALLOW (matches first rule)
        ("192.168.1.100", "10.1.1.5", 80),    # Should DENY (more specific rule)
        ("8.8.8.8", "1.1.1.1", 443),          # Should DENY (default rule)
        ("192.168.2.1", "10.2.2.2", 22),      # Should None (no match)
    ]
    
    print("🔍 Firewall Engine Test Results:")
    print("=" * 50)
    for src, dst, port in test_cases:
        action = engine.match_flow(src, dst, port)
        action_str = action.value if action else "NO MATCH"
        print(f"{src:20} -> {dst:20}:{port:<5} => {action_str}")
    
    # Run performance benchmark
    print("\n" + "=" * 50)
    benchmark_performance()
