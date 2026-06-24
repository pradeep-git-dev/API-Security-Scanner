import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def exposure_check(url: str) -> List[Vulnerability]:
    findings = []
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    keywords = [
        "password", "secret", "apikey", "token",
        "privatekey", "accesskey", "email"
    ]
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=5) as response:
                text = await response.text()
                lower_text = text.lower()
                
                detected = []
                for kw in keywords:
                    if kw in lower_text:
                        # Find the actual original casing keyword name for reporting
                        original_name = next(x for x in [
                            "password", "secret", "apikey", "token",
                            "privateKey", "accessKey", "email"
                        ] if x.lower() == kw)
                        detected.append(original_name)
                
                if detected:
                    findings.append(
                        Vulnerability(
                            endpoint=endpoint,
                            method="GET",
                            issue="Potential Sensitive Data Exposure",
                            severity="HIGH",
                            confidence="HIGH",
                            description=f"The response body contains potential sensitive data keywords: {', '.join(detected)}.",
                            recommendation="Ensure that sensitive information such as credentials, secrets, keys, or emails is not leaked in API responses. Implement proper serialization and filtering."
                        )
                    )
    except Exception as e:
        print(f"Exposure check error scanning {url}: {e}")
        
    return findings
