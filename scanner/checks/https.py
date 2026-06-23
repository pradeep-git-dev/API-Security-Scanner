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
                recommendation="Redirect HTTP traffic to HTTPS and use TLS certificates."
            )
        )
    return findings
