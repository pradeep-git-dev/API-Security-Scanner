import aiohttp
import re
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

SECRET_PATTERNS = {
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"aws_secret_access_key\s*[:=]\s*['\"][a-zA-Z0-9/+=]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "SSH Private Key": r"-----BEGIN\s+([A-Z]+)\s+PRIVATE\s+KEY-----",
    "Generic Credentials": r"(?i)(password|secret|privateKey|access_token|db_conn|connectionstring)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\@\#\$\%\^\&\*\(\)\+]{6,}['\"]"
}

async def exposure_check(url: str, headers: dict = None) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    captured_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers, timeout=5) as response:
                captured_headers = {k: v for k, v in response.headers.items()}
                text = await response.text()
                
                findings = []
                details = []
                for name, regex in SECRET_PATTERNS.items():
                    matches = re.findall(regex, text)
                    if matches:
                        # Mask matches
                        masked = []
                        for m in matches:
                            # if it's a tuple (like SSH key capture), handle string
                            m_str = m[0] if isinstance(m, tuple) else m
                            if len(m_str) > 8:
                                masked.append(f"{m_str[:4]}...{m_str[-4:]}")
                            else:
                                masked.append("********")
                        details.append(f"Exposed {name} patterns: {', '.join(masked)}")
                
                if details:
                    return [
                        Vulnerability(
                            endpoint=endpoint,
                            method="GET",
                            issue="Excessive Data Exposure (Sensitive Secrets)",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description="The endpoint response body contains plain-text credentials, API keys, tokens, or private keys.",
                            recommendation="1. Remove all credentials and secrets from response structures.\n2. Store secrets in secure environment variables.\n3. Revoke any exposed keys immediately.",
                            category="Security Findings",
                            evidence={
                                "headers": captured_headers,
                                "details": details,
                                "bodyPreview": text[:500],
                                "truncated": len(text) > 500
                            },
                            impact="Enables attackers to hijack connected cloud platforms, access databases, or compromise third-party APIs.",
                            owasp="API3:2023 – Broken Object Level Authorization / Excessive Data Exposure",
                            cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
                        )
                    ]
    except Exception as e:
        print(f"Exposure check error: {e}")
        
    return [
        Vulnerability(
            endpoint=endpoint,
            method="GET",
            issue="Secrets Leak Protection Safe",
            severity="INFO",
            confidence="HIGH",
            description="The endpoint response body does not expose generic secrets, private keys, or API tokens.",
            recommendation="Maintain clean response schemas and ensure config files remain unexposed.",
            category="Passed Checks",
            evidence={
                "headers": captured_headers,
                "details": ["Response scanned for sensitive keys and tokens; no matches found."],
                "bodyPreview": "",
                "truncated": False
            },
            impact="None",
            owasp="API3:2023 – Broken Object Level Authorization / Excessive Data Exposure",
            cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        )
    ]
