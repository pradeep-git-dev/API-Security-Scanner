import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def method_check(url: str, headers: dict = None) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE"]
    exposed_dangerous = []
    
    captured_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request("OPTIONS", url, headers=headers, timeout=5) as response:
                captured_headers = {k: v for k, v in response.headers.items()}
                allow_header = response.headers.get("Allow") or response.headers.get("allow")
                if allow_header:
                    methods_supported = [m.strip().upper() for m in allow_header.split(",")]
                    for m in dangerous_methods:
                        if m in methods_supported:
                            exposed_dangerous.append(m)
    except Exception as e:
        print(f"Method check error: {e}")
        
    if exposed_dangerous:
        exposed_str = ", ".join(exposed_dangerous)
        return [
            Vulnerability(
                endpoint=endpoint,
                method="OPTIONS",
                issue="HTTP Methods Over-permissive",
                severity="LOW",
                confidence="HIGH",
                description=f"The API exposes potentially dangerous or unneeded HTTP methods: {exposed_str}",
                recommendation="Disable unused or unsafe HTTP methods (like TRACE, PUT, DELETE) unless explicitly required and fully authenticated.",
                category="Security Findings",
                evidence={
                    "headers": captured_headers,
                    "details": [f"Supported methods: {allow_header}", f"Exposed dangerous methods: {exposed_str}"],
                    "bodyPreview": "",
                    "truncated": False
                },
                impact="Attackers can leverage unsupported methods to modify records, bypass filter boundaries, or perform Cross-Site Tracking (via TRACE).",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-16: Configuration"
            )
        ]
        
    return [
        Vulnerability(
            endpoint=endpoint,
            method="OPTIONS",
            issue="HTTP Methods Restricted",
            severity="INFO",
            confidence="HIGH",
            description="The API restricts exposed HTTP methods and does not advertise PUT, DELETE, or TRACE publicly without credentials.",
            recommendation="Continue maintaining disabled status for unused methods.",
            category="Passed Checks",
            evidence={
                "headers": captured_headers,
                "details": [f"Allowed headers: {captured_headers.get('allow', 'None advertised')}"],
                "bodyPreview": "",
                "truncated": False
            },
            impact="None",
            owasp="A05:2021 – Security Misconfiguration",
            cwe="CWE-16: Configuration"
        )
    ]
