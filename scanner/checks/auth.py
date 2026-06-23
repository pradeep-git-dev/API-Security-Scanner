import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def auth_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=5) as response:
                if response.status < 400:
                    return [
                        Vulnerability(
                            endpoint=endpoint,
                            method="GET",
                            issue="Potential Public Endpoint",
                            severity="LOW",
                            confidence="LOW",
                            description=(
                                f"The endpoint responded with HTTP status {response.status} when accessed "
                                "without authentication credentials (e.g. tokens or cookies)."
                            ),
                            recommendation=(
                                "Verify if this endpoint is intended to be publicly accessible. "
                                "If it requires restriction, implement proper authentication and authorization checks."
                            )
                        )
                    ]
    except Exception as e:
        print(f"Auth check error scanning {url}: {e}")
        
    return []
