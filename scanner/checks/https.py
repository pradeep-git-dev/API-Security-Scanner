from typing import List
from models.vulnerability import Vulnerability

async def https_check(url: str) -> List[Vulnerability]:
    findings = []
    if not url.startswith("https://"):
        findings.append(
            Vulnerability(
                endpoint="/",
                method="GET",
                issue="Missing HTTPS",
                severity="HIGH",
                confidence="HIGH",
                description="The target URL does not enforce HTTPS, allowing sensitive data to be intercepted in transit.",
                recommendation="Redirect HTTP traffic to HTTPS and use TLS certificates.",
                category="Security Findings",
                evidence={
                    "headers": {},
                    "details": ["Target URL scheme is HTTP."],
                    "bodyPreview": "",
                    "truncated": False
                },
                impact="Credentials, session keys, and sensitive API payloads can be intercepted by an attacker via a Man-in-the-Middle (MitM) attack.",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
        )
    else:
        findings.append(
            Vulnerability(
                endpoint="/",
                method="GET",
                issue="HTTPS Enforced",
                severity="INFO",
                confidence="HIGH",
                description="The target URL enforces HTTPS.",
                recommendation="Ensure security protocols and TLS ciphers are kept up to date.",
                category="Passed Checks",
                evidence={
                    "headers": {},
                    "details": ["Target URL scheme is HTTPS."],
                    "bodyPreview": "",
                    "truncated": False
                },
                impact="None",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
        )
    return findings
