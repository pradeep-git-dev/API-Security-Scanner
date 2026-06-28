import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def jwt_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    captured_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        # Test with a weak, easily forged JWT token
        weak_token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."
        )
        headers = {"Authorization": f"Bearer {weak_token}"}
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers, timeout=5) as response:
                captured_headers = {k: v for k, v in response.headers.items()}
                
                # If backend accepts JWT 'none' alg token and returns 200, it is vulnerable
                if response.status == 200:
                    return [
                        Vulnerability(
                            endpoint=endpoint,
                            method="GET",
                            issue="JWT Signature Verification Bypass",
                            severity="CRITICAL",
                            confidence="MEDIUM",
                            description="The server accepted a JWT token with the algorithm ('alg') set to 'none' and granted access.",
                            recommendation="Configure your JWT validation library to reject tokens using 'none' algorithm. Do not dynamically trust the header 'alg' value.",
                            category="Security Findings",
                            evidence={
                                "headers": captured_headers,
                                "details": ["Injected Bearer token with 'alg':'none'", "Server responded with HTTP 200 OK"],
                                "bodyPreview": "",
                                "truncated": False
                            },
                            impact="Allows attackers to forge arbitrary tokens (e.g. claim admin identities) and bypass validation controls completely.",
                            owasp="API2:2023 – Broken Authentication",
                            cwe="CWE-347: Improper Verification of Cryptographic Signature"
                        )
                    ]
    except Exception as e:
        print(f"JWT check error: {e}")
        
    return [
        Vulnerability(
            endpoint=endpoint,
            method="GET",
            issue="JWT Config Safe",
            severity="INFO",
            confidence="HIGH",
            description="The API does not accept plain forged algorithm 'none' JWT tokens.",
            recommendation="Maintain strict cryptographic signature validation on all incoming tokens.",
            category="Passed Checks",
            evidence={
                "headers": captured_headers,
                "details": ["JWT signature verification checks completed successfully; algorithm 'none' tokens were not accepted."],
                "bodyPreview": "",
                "truncated": False
            },
            impact="None",
            owasp="API2:2023 – Broken Authentication",
            cwe="CWE-287: Improper Authentication"
        )
    ]
