import asyncio
import httpx
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Callable
from enum import Enum
import time
from collections import defaultdict


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests allowed
    OPEN = "open"          # Failure threshold reached, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent cascading failures.
    Stops calling failing providers temporarily to allow recovery.
    """
    
    def __init__(
        self, 
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: int = 60,
        half_open_max_calls: int = 1
    ):
        """
        Initialize circuit breaker.
        
        Args:
            name: Provider name for logging
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            half_open_max_calls: Max calls in half-open state
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.half_open_calls = 0
        self.success_count = 0
        
    def can_call(self) -> bool:
        """Check if calls are allowed to this provider."""
        if self.state == CircuitState.CLOSED:
            return True
            
        elif self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if self.last_failure_time and \
               datetime.now() - self.last_failure_time > timedelta(seconds=self.recovery_timeout):
                print(f"  🔄 Circuit {self.name} moving from OPEN to HALF-OPEN")
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
                return True
            return False
            
        elif self.state == CircuitState.HALF_OPEN:
            # Allow limited calls for testing
            if self.half_open_calls < self.half_open_max_calls:
                self.half_open_calls += 1
                return True
            return False
            
        return False
    
    def record_success(self):
        """Record a successful call."""
        self.success_count += 1
        
        if self.state == CircuitState.HALF_OPEN:
            print(f"  ✅ Circuit {self.name} recovered! Moving to CLOSED")
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.half_open_calls = 0
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0
            
    def record_failure(self):
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.state == CircuitState.CLOSED and self.failure_count >= self.failure_threshold:
            print(f"  🔴 Circuit {self.name} moving from CLOSED to OPEN (after {self.failure_count} failures)")
            self.state = CircuitState.OPEN
        elif self.state == CircuitState.HALF_OPEN:
            print(f"  ❌ Circuit {self.name} test failed! Moving back to OPEN")
            self.state = CircuitState.OPEN
            
    def get_state(self) -> str:
        """Get current circuit state."""
        return self.state.value


class AsyncClientWrapper:
    """
    Wrapper for httpx.AsyncClient with enhanced features:
    - Automatic retries
    - Timeout management
    - Request/response logging
    - Metrics collection
    """
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 2,
        retry_delay: float = 1.0,
        follow_redirects: bool = True
    ):
        """
        Initialize the async client wrapper.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            follow_redirects: Whether to follow redirects
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.follow_redirects = follow_redirects
        self.metrics = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0, "total_time": 0})
        
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """
        Make an HTTP request with retries and timeout.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional arguments to pass to httpx
            
        Returns:
            httpx.Response object
            
        Raises:
            Exception: If all retries fail
        """
        start_time = time.time()
        
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=self.follow_redirects
                ) as client:
                    response = await client.request(method, url, **kwargs)
                    
                    # Update metrics
                    elapsed = time.time() - start_time
                    self.metrics[url]["total"] += 1
                    self.metrics[url]["success"] += 1
                    self.metrics[url]["total_time"] += elapsed
                    
                    return response
                    
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                elapsed = time.time() - start_time
                self.metrics[url]["total"] += 1
                self.metrics[url]["failed"] += 1
                
                if attempt < self.max_retries:
                    print(f"  ⚠️ Retry {attempt + 1}/{self.max_retries} for {url}: {str(e)}")
                    await asyncio.sleep(self.retry_delay * (attempt + 1))  # Exponential backoff
                else:
                    raise Exception(f"Failed after {self.max_retries} retries: {str(e)}")
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make GET request."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make POST request."""
        return await self.request("POST", url, **kwargs)
    
    def get_metrics(self, url: str = None) -> Dict:
        """Get metrics for a specific URL or all URLs."""
        if url:
            return self.metrics.get(url, {})
        return dict(self.metrics)
    
    def get_success_rate(self, url: str) -> float:
        """Get success rate for a specific URL."""
        metrics = self.metrics.get(url, {})
        total = metrics.get("total", 0)
        if total == 0:
            return 1.0
        return metrics.get("success", 0) / total


class AIClient:
    """
    AI Client with circuit breaker and fastest response logic.
    """
    
    def __init__(
        self,
        providers: List[str],
        timeout: int = 30,
        failure_threshold: int = 3,
        recovery_timeout: int = 60
    ):
        """
        Initialize AI client.
        
        Args:
            providers: List of provider URLs
            timeout: Request timeout in seconds
            failure_threshold: Failures before opening circuit
            recovery_timeout: Seconds before attempting recovery
        """
        self.providers = providers
        self.http_client = AsyncClientWrapper(timeout=timeout)
        
        # Circuit breakers for each provider
        self.circuit_breakers = {
            provider: CircuitBreaker(
                name=provider,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout
            )
            for provider in providers
        }
        
    async def call_provider(self, provider: str, prompt: str) -> tuple[Optional[str], str, float]:
        """
        Call a single provider with circuit breaker protection.
        
        Returns:
            Tuple of (response_text, provider_url, response_time)
        """
        start_time = time.time()
        
        # Check circuit breaker
        if not self.circuit_breakers[provider].can_call():
            print(f"  🔒 Circuit OPEN for {provider} - skipping")
            return None, provider, 0
        
        try:
            # Simulate AI API call (replace with actual API call)
            print(f"  📡 Calling {provider}...")
            
            # Mock different response times for demonstration
            if "slow" in provider.lower():
                await asyncio.sleep(2.0)
            elif "google" in provider.lower():
                await asyncio.sleep(0.3)
            elif "yahoo" in provider.lower():
                await asyncio.sleep(0.5)
            else:
                await asyncio.sleep(0.4)
            
            # Simulate random failures (10% chance) for testing
            import random
            if random.random() < 0.1:  # 10% failure rate
                raise Exception("Simulated random failure")
            
            # Mock successful response
            response_text = f"AI response from {provider} to: '{prompt[:50]}...' (in {time.time() - start_time:.2f}s)"
            
            # Record success in circuit breaker
            self.circuit_breakers[provider].record_success()
            
            response_time = time.time() - start_time
            print(f"  ✅ Success from {provider} ({response_time:.2f}s)")
            
            return response_text, provider, response_time
            
        except Exception as e:
            # Record failure in circuit breaker
            self.circuit_breakers[provider].record_failure()
            response_time = time.time() - start_time
            print(f"  ❌ Error from {provider}: {str(e)}")
            return None, provider, response_time
    
    async def get_fastest_successful_response(self, prompt: str) -> str:
        """
        Call all providers concurrently and return the fastest successful response.
        Implements circuit breaker and returns the response with lowest latency.
        """
        async with httpx.AsyncClient() as client:
            # Create tasks for all providers that are allowed by circuit breaker
            tasks = []
            for provider in self.providers:
                if self.circuit_breakers[provider].can_call():
                    task = asyncio.create_task(self.call_provider(provider, prompt))
                    tasks.append(task)
            
            if not tasks:
                raise Exception("All circuit breakers are OPEN. No providers available.")
            
            # Store results as they complete
            results = []
            pending = set(tasks)
            
            # Wait for all tasks to complete or timeout
            try:
                # Wait for all tasks with timeout
                done, pending = await asyncio.wait(
                    pending,
                    timeout=self.http_client.timeout,
                    return_when=asyncio.ALL_COMPLETED
                )
                
                # Collect results
                for task in done:
                    try:
                        result, provider, response_time = task.result()
                        if result:
                            results.append((result, provider, response_time))
                    except Exception:
                        pass
                
                # Cancel any pending tasks
                for task in pending:
                    task.cancel()
                
            except Exception as e:
                print(f"⚠️ Error during concurrent calls: {e}")
            
            if not results:
                raise Exception("No successful responses from any provider")
            
            # Return the fastest response (lowest response time)
            fastest = min(results, key=lambda x: x[2])
            print(f"\n🏆 Fastest response: {fastest[1]} ({fastest[2]:.2f}s)")
            return fastest[0]
    
    async def call_with_circuit_breaker(self, prompt: str) -> str:
        """
        Call providers with circuit breaker and fastest response logic.
        This is the main method that implements all three requirements.
        """
        print(f"\n{'='*60}")
        print(f"🚀 Calling AI with Circuit Breaker + Fastest Response")
        print(f"{'='*60}")
        print(f"📝 Prompt: {prompt[:100]}...")
        print(f"🔌 Providers: {', '.join(self.providers)}")
        print(f"{'-'*60}")
        
        # Display initial circuit states
        print("\n🔌 Initial Circuit States:")
        for provider, cb in self.circuit_breakers.items():
            print(f"  {provider}: {cb.get_state().upper()} (failures: {cb.failure_count})")
        
        print(f"\n{'='*60}")
        print("🔄 Starting concurrent calls with fastest response...")
        print(f"{'='*60}")
        
        # Get fastest successful response
        response = await self.get_fastest_successful_response(prompt)
        
        # Display final circuit states
        print(f"\n{'='*60}")
        print("📊 Final Circuit States:")
        for provider, cb in self.circuit_breakers.items():
            success_rate = self.http_client.get_success_rate(provider)
            print(f"  {provider}: {cb.get_state().upper()} (success rate: {success_rate:.1%})")
        
        return response
    
    async def call(self, prompt: str) -> str:
        """
        Main method to call AI providers.
        """
        return await self.call_with_circuit_breaker(prompt)
    
    def get_circuit_status(self) -> Dict[str, str]:
        """Get current status of all circuit breakers."""
        return {
            provider: cb.get_state()
            for provider, cb in self.circuit_breakers.items()
        }
    
    def reset_circuit(self, provider: str = None):
        """Reset circuit breaker for a specific provider or all providers."""
        if provider:
            self.circuit_breakers[provider].__init__(
                name=provider,
                failure_threshold=self.circuit_breakers[provider].failure_threshold,
                recovery_timeout=self.circuit_breakers[provider].recovery_timeout
            )
        else:
            for provider in self.providers:
                self.reset_circuit(provider)


# Extended test scenarios
async def test_circuit_breaker_functionality():
    """Test circuit breaker functionality."""
    print("\n" + "🎯"*30)
    print("TEST 1: Circuit Breaker Functionality")
    print("🎯"*30)
    
    # Create client with low failure threshold for testing
    client = AIClient(
        providers=["http://failing-provider.com", "http://google.com"],
        failure_threshold=2,  # Open after 2 failures
        recovery_timeout=10    # Try recovery after 10 seconds
    )
    
    # Simulate multiple failures
    for i in range(3):
        print(f"\n--- Attempt {i+1} ---")
        try:
            result = await client.call("Test prompt")
            print(f"Result: {result[:100]}...")
        except Exception as e:
            print(f"Error: {e}")
    
    # Check circuit status
    status = client.get_circuit_status()
    print(f"\nFinal circuit status: {status}")


async def test_fastest_response():
    """Test fastest response logic."""
    print("\n" + "⚡"*30)
    print("TEST 2: Fastest Response Logic")
    print("⚡"*30)
    
    # Providers with different speeds
    client = AIClient([
        "http://slow-provider.com",
        "http://medium-provider.com", 
        "http://fast-provider.com",
        "http://google.com"
    ])
    
    result = await client.call("What is the fastest way to learn Python?")
    print(f"\n✅ Fastest response received!")


async def test_concurrent_requests():
    """Test multiple concurrent requests."""
    print("\n" + "🔄"*30)
    print("TEST 3: Concurrent Requests")
    print("🔄"*30)
    
    client = AIClient([
        "http://google.com",
        "http://yahoo.com",
        "http://openai.com"
    ])
    
    # Make multiple concurrent requests
    prompts = [
        "What is AI?",
        "Explain machine learning",
        "What is deep learning?",
        "Explain neural networks"
    ]
    
    tasks = [client.call(prompt) for prompt in prompts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"Request {i+1}: FAILED - {result}")
        else:
            print(f"Request {i+1}: SUCCESS - {result[:80]}...")


async def test_circuit_recovery():
    """Test circuit breaker recovery."""
    print("\n" + "🔄"*30)
    print("TEST 4: Circuit Breaker Recovery")
    print("🔄"*30)
    
    client = AIClient(
        providers=["http://unstable-provider.com"],
        failure_threshold=2,
        recovery_timeout=3  # Quick recovery for testing
    )
    
    # First few calls will fail and open circuit
    for i in range(3):
        print(f"\n--- Call {i+1} ---")
        try:
            result = await client.call(f"Test {i+1}")
            print(f"Success: {result[:50]}")
        except Exception as e:
            print(f"Failed: {e}")
        
        await asyncio.sleep(1)
    
    # Wait for recovery timeout
    print("\n⏰ Waiting for recovery timeout...")
    await asyncio.sleep(4)
    
    # This call should succeed after recovery
    print("\n--- Recovery Call ---")
    try:
        result = await client.call("Recovery test")
        print(f"✅ Recovery successful: {result[:50]}")
    except Exception as e:
        print(f"❌ Recovery failed: {e}")


async def demo_with_realistic_scenario():
    """Demonstrate realistic usage scenario."""
    print("\n" + "🚀"*30)
    print("DEMO: Realistic Production Scenario")
    print("🚀"*30)
    
    # Initialize client with multiple providers
    client = AIClient(
        providers=[
            "https://api.openai.com/v1/chat/completions",
            "https://api.anthropic.com/v1/messages",
            "https://api.cohere.ai/v1/generate",
            "https://api.google.com/ai/v1/chat"
        ],
        timeout=10,
        failure_threshold=2,
        recovery_timeout=30
    )
    
    # Simulate production load
    queries = [
        "What is the capital of France?",
        "Explain quantum computing simply",
        "Write a haiku about coding",
        "What's the weather like today?",
        "Tell me a fun fact about space"
    ]
    
    print("\n📊 Processing multiple queries with circuit protection...")
    print("="*60)
    
    for i, query in enumerate(queries, 1):
        print(f"\n📝 Query {i}/{len(queries)}")
        try:
            result = await client.call(query)
            print(f"✅ Response received in <1s")
        except Exception as e:
            print(f"❌ All providers failed: {e}")
        
        # Small delay between requests
        await asyncio.sleep(0.5)
    
    # Display final metrics
    print("\n" + "="*60)
    print("📊 Final Metrics")
    print("="*60)
    
    for provider in client.providers:
        metrics = client.http_client.get_metrics(provider)
        success_rate = client.http_client.get_success_rate(provider)
        print(f"\n{provider}:")
        print(f"  State: {client.circuit_breakers[provider].get_state().upper()}")
        print(f"  Success Rate: {success_rate:.1%}")
        print(f"  Total Calls: {metrics.get('total', 0)}")
        print(f"  Avg Time: {metrics.get('total_time', 0) / max(metrics.get('total', 1), 1):.2f}s")


# Run all tests
async def main():
    """Run all test scenarios."""
    
    # Test 1: Basic functionality with fastest response
    print("\n" + "="*60)
    print("BASIC FUNCTIONALITY TEST")
    print("="*60)
    client = AIClient(["http://google.com", "http://yahoo.com", "http://slow.com"])
    result = await client.call("What is the meaning of life?")
    print(f"\n🎯 Final result: {result}")
    
    # Uncomment to run additional tests
    # await test_circuit_breaker_functionality()
    # await test_fastest_response()
    # await test_concurrent_requests()
    # await test_circuit_recovery()
    # await demo_with_realistic_scenario()


if __name__ == "__main__":
    # Run the main test
    asyncio.run(main())
    
    # To run specific tests:
    # asyncio.run(test_fastest_response())
    # asyncio.run(test_circuit_breaker_functionality())
