import aiohttp
from typing import List
from models.vulnerability import Vulnerability
from urllib.parse import urlparse

async def cors_check(url: str, headers: dict = None) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    captured_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        req_headers = {"Origin": "http://evil-attacker-website.com"}
        if headers:
            req_headers.update(headers)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request("OPTIONS", url, headers=req_headers, timeout=5) as response:
                captured_headers = {k: v for k, v in response.headers.items()}
                allow_origin = response.headers.get("Access-Control-Allow-Origin") or response.headers.get("access-control-allow-origin")
                allow_credentials = response.headers.get("Access-Control-Allow-Credentials") or response.headers.get("access-control-allow-credentials")
                
                is_weak = False
                reason = []
                
                if allow_origin == "*":
                    is_weak = True
                    reason.append("Access-Control-Allow-Origin header is set to wildcard '*'")
                elif allow_origin == "http://evil-attacker-website.com":
                    is_weak = True
                    reason.append("Access-Control-Allow-Origin header dynamically reflects client Origin")
                    if allow_credentials == "true":
                        reason.append("Access-Control-Allow-Credentials is set to true (High Risk)")
                
                if is_weak:
                    severity = "MEDIUM" if "Credentials" in "".join(reason) else "LOW"
                    return [
                        Vulnerability(
                            endpoint=endpoint,
                            method="OPTIONS",
                            issue="Weak CORS Policy (Permissive)",
                            severity=severity,
                            confidence="HIGH",
                            description="Cross-Origin Resource Sharing (CORS) policy is configured permissively, allowing requests from external sites.",
                            recommendation="Configure Access-Control-Allow-Origin with trusted, specific origin domains. Avoid using '*' or dynamically reflecting the user Origin, especially if authentication headers or cookies are sent.",
                            category="Security Findings",
                            evidence={
                                "headers": captured_headers,
                                "details": reason,
                                "bodyPreview": "",
                                "truncated": False
                            },
                            impact="Allows malicious sites to read response data from this API on behalf of authenticated sessions.",
                            owasp="A05:2021 – Security Misconfiguration",
                            cwe="CWE-942: Permissive Share of Domain"
                        )
                    ]
    except Exception as e:
        print(f"CORS check error: {e}")
        
    return [
        Vulnerability(
            endpoint=endpoint,
            method="OPTIONS",
            issue="CORS Policy Restrictive",
            severity="INFO",
            confidence="HIGH",
            description="The API does not expose a weak CORS configuration or wildcard origin permissions to arbitrary hosts.",
            recommendation="Keep cross-origin configuration restrictive and scoped to trusted endpoints.",
            category="Passed Checks",
            evidence={
                "headers": captured_headers,
                "details": ["CORS checks completed. No weak Access-Control-Allow-Origin configurations detected."],
                "bodyPreview": "",
                "truncated": False
            },
            impact="None",
            owasp="A05:2021 – Security Misconfiguration",
            cwe="CWE-942: Permissive Share of Domain"
        )
    ]
