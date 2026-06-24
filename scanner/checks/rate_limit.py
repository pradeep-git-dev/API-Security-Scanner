import asyncio
import aiohttp
import time
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def rate_limit_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    seen_429 = False
    connector = aiohttp.TCPConnector(ssl=False)
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            for second in range(3):
                # Formulate 10 concurrent requests
                tasks = []
                for _ in range(10):
                    tasks.append(session.get(url, timeout=5))
                
                start_time = time.time()
                # Run the batch concurrently
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for resp in responses:
                    if isinstance(resp, aiohttp.ClientResponse):
                        if resp.status == 429:
                            seen_429 = True
                            break
                
                if seen_429:
                    break
                
                # Maintain the rate limit of 10 requests per second
                elapsed = time.time() - start_time
                wait_time = 1.0 - elapsed
                if wait_time > 0 and second < 2:
                    await asyncio.sleep(wait_time)
                    
    except Exception as e:
        print(f"Rate limit check error scanning {url}: {e}")
        
    if not seen_429:
        return [
            Vulnerability(
                endpoint=endpoint,
                method="GET",
                issue="Missing Rate Limiting",
                severity="MEDIUM",
                confidence="HIGH",
                description="The API endpoint does not enforce rate limiting. The scanner sent 30 requests in 3 seconds without receiving a 429 Too Many Requests status code.",
                recommendation="Implement rate limiting using a middleware, token bucket algorithm, or API gateway to prevent brute-force and DoS attacks."
            )
        ]
        
    return []
