import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def header_check(url: str, headers: dict = None) -> List[Vulnerability]:
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
    headers_found = []
    captured_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers, timeout=5) as response:
                captured_headers = {k: v for k, v in response.headers.items()}
                for h in target_headers:
                    if h in response.headers:
                        headers_found.append(header_mapping[h])
                    else:
                        missing.append(header_mapping[h])
    except Exception as e:
        print(f"Header check error scanning {url}: {e}")
        return []
        
    if missing:
        missing_list_str = ", ".join(missing)
        description = f"The following security headers are missing from the response: {missing_list_str}"
        return [
            Vulnerability(
                endpoint=endpoint,
                method="GET",
                issue="Missing Security Headers",
                severity="MEDIUM",
                confidence="HIGH",
                description=description,
                recommendation="Configure the missing HTTP security headers on your web server or application framework.",
                category="Security Findings",
                evidence={
                    "headers": captured_headers,
                    "details": [f"Missing header: {h}" for h in missing],
                    "bodyPreview": "",
                    "truncated": False
                },
                impact="Increases vulnerability to common web attacks such as Cross-Site Scripting (XSS), clickjacking, and MIME sniffing.",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-693: Protection Mechanism Failure"
            )
        ]
    
    return [
        Vulnerability(
            endpoint=endpoint,
            method="GET",
            issue="Security Headers Configured",
            severity="INFO",
            confidence="HIGH",
            description="All monitored security headers are present in the response.",
            recommendation="Continue maintaining restrictive security headers.",
            category="Passed Checks",
            evidence={
                "headers": captured_headers,
                "details": [f"Present header: {h}" for h in headers_found],
                "bodyPreview": "",
                "truncated": False
            },
            impact="None",
            owasp="A05:2021 – Security Misconfiguration",
            cwe="CWE-693: Protection Mechanism Failure"
        )
    ]
