import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def auth_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    captured_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=5) as response:
                captured_headers = {k: v for k, v in response.headers.items()}
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
                            ),
                            category="Security Findings",
                            evidence={
                                "headers": captured_headers,
                                "details": [f"HTTP Status: {response.status}", "No authorization headers required."],
                                "bodyPreview": "",
                                "truncated": False
                            },
                            impact="Exposes resources to anonymous requests. If the endpoint exposes user-specific data, this can lead to data leaks.",
                            owasp="API1:2023 – Broken Object Level Authorization",
                            cwe="CWE-285: Improper Authorization"
                        )
                    ]
                else:
                    return [
                        Vulnerability(
                            endpoint=endpoint,
                            method="GET",
                            issue="Authentication Required",
                            severity="INFO",
                            confidence="HIGH",
                            description="The endpoint correctly requires authentication credentials (responded with non-success status).",
                            recommendation="Ensure all restricted endpoints enforce similar validation.",
                            category="Passed Checks",
                            evidence={
                                "headers": captured_headers,
                                "details": [f"HTTP Status: {response.status}", "Unauthenticated request was rejected."],
                                "bodyPreview": "",
                                "truncated": False
                            },
                            impact="None",
                            owasp="API2:2023 – Broken Authentication",
                            cwe="CWE-287: Improper Authentication"
                        )
                    ]
    except Exception as e:
        print(f"Auth check error scanning {url}: {e}")
        
    return []
