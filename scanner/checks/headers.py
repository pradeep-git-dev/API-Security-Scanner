import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def header_check(url: str) -> List[Vulnerability]:
    target_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    
    header_mapping = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy"
    }
    
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    missing = []
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=5) as response:
                # response.headers is case-insensitive
                for h in target_headers:
                    if h not in response.headers:
                        missing.append(header_mapping[h])
    except Exception as e:
        print(f"Header check error scanning {url}: {e}")
        return []
        
    if missing:
        missing_list_str = "\n".join([f"- {m}" for m in missing])
        description = f"The following security headers are missing from the response:\n{missing_list_str}"
        return [
            Vulnerability(
                endpoint=endpoint,
                method="GET",
                issue="Missing Security Headers",
                severity="MEDIUM",
                confidence="HIGH",
                description=description,
                recommendation="Configure the missing HTTP security headers on your web server or application framework."
            )
        ]
    return []
