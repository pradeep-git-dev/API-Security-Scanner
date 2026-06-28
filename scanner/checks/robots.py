import aiohttp
from typing import List
from models.vulnerability import Vulnerability
from urllib.parse import urlparse

async def robots_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    root_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(root_url, timeout=5) as response:
                if response.status == 200:
                    text = await response.text()
                    lines = [line.strip() for line in text.split("\n") if line.strip()][:10]
                    headers = {k: v for k, v in response.headers.items()}
                    
                    return [
                        Vulnerability(
                            endpoint="/robots.txt",
                            method="GET",
                            issue="robots.txt Discovered",
                            severity="INFO",
                            confidence="HIGH",
                            description="A robots.txt file was discovered on the server.",
                            recommendation="Review the contents of robots.txt to ensure it does not disclose sensitive directories or paths (e.g. admin panels, staging sites) that you want to keep hidden.",
                            category="Observations",
                            evidence={
                                "headers": headers,
                                "details": lines if lines else ["Robots.txt exists but is empty."],
                                "bodyPreview": text[:500],
                                "truncated": len(text) > 500
                            },
                            impact="Public crawlers can read robots.txt. If private endpoints are disallowed there, malicious actors can use them for target discovery.",
                            owasp="A05:2021 – Security Misconfiguration",
                            cwe="CWE-16: Configuration"
                        )
                    ]
    except Exception as e:
        print(f"Robots check error: {e}")
        
    return []
