import aiohttp
from typing import List
from models.vulnerability import Vulnerability
from urllib.parse import urlparse

async def security_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    well_known_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
    root_url = f"{parsed.scheme}://{parsed.netloc}/security.txt"
    
    found = False
    details_found = []
    captured_headers = {}
    body_text = ""
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Check /.well-known/security.txt
            async with session.get(well_known_url, timeout=5) as response:
                if response.status == 200:
                    found = True
                    details_found.append("Found at /.well-known/security.txt")
                    captured_headers = {k: v for k, v in response.headers.items()}
                    body_text = await response.text()
            
            # Check /security.txt if not found yet
            if not found:
                async with session.get(root_url, timeout=5) as response:
                    if response.status == 200:
                        found = True
                        details_found.append("Found at /security.txt")
                        captured_headers = {k: v for k, v in response.headers.items()}
                        body_text = await response.text()
    except Exception as e:
        print(f"Security.txt check error: {e}")
        
    if found:
        return [
            Vulnerability(
                endpoint="/.well-known/security.txt",
                method="GET",
                issue="security.txt Discovered",
                severity="INFO",
                confidence="HIGH",
                description="A security.txt file was found on the server.",
                recommendation="Ensure contact details, policy, and public keys in security.txt are accurate and updated regularly.",
                category="Observations",
                evidence={
                    "headers": captured_headers,
                    "details": details_found,
                    "bodyPreview": body_text[:500],
                    "truncated": len(body_text) > 500
                },
                impact="Enables structured and responsible disclosure of security issues by external researchers.",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-16: Configuration"
            )
        ]
    else:
        return [
            Vulnerability(
                endpoint="/.well-known/security.txt",
                method="GET",
                issue="security.txt Missing",
                severity="INFO",
                confidence="HIGH",
                description="The target site does not publish a security.txt file.",
                recommendation="Deploy a security.txt file under /.well-known/security.txt defining security reporting channels and responsible disclosure policies.",
                category="Observations",
                evidence={
                    "headers": {},
                    "details": ["Checked /.well-known/security.txt", "Checked /security.txt"],
                    "bodyPreview": "",
                    "truncated": False
                },
                impact="Limits standard channels for security researchers to responsibly report vulnerabilities.",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-16: Configuration"
            )
        ]
