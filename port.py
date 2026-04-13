import asyncio
import aiodns
import socket
import random
from typing import Optional

# True non-blocking resolver
resolver = aiodns.DNSResolver()
MAX_CONCURRENT_TASKS = asyncio.Semaphore(100)

async def resolve_host(host: str) -> Optional[str]:
    """True async DNS resolution using aiodns (c-ares)."""
    # If it's already an IP, return it directly
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        pass

    try:
        # query() is truly non-blocking and doesn't use threads
        result = await resolver.query(host, 'A')
        return result[0].host
    except Exception as e:
        # Handles DNS timeouts or NXDOMAIN
        return None

async def check_port(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Standard async TCP handshake with jitter."""
    async with MAX_CONCURRENT_TASKS:
        try:
            await asyncio.sleep(random.uniform(0.1, 0.5))
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

async def main():
    targets = ["google.com", "8.8.8.8", "github.com", "not-a-real-site.xyz"]
    port = 443

    # Phase 1: True Async Resolution
    print("Resolving...")
    ips = await asyncio.gather(*(resolve_host(t) for t in targets))
    
    valid_scans = [(targets[i], ip) for i, ip in enumerate(ips) if ip]

    # Phase 2: Port Scanning
    print("Scanning...")
    results = await asyncio.gather(*(check_port(ip, port) for _, ip in valid_scans))

    for (host, ip), is_open in zip(valid_scans, results):
        status = "✓ Open" if is_open else "✗ Closed"
        print(f"{host} ({ip}) — {status}")

await main()
