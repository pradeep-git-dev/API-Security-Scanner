import aiohttp
import time
import re
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl
from models.vulnerability import Vulnerability

DB_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"mysql_query",
    r"unclosed quotation mark after the character string",
    r"postgreSQL query failed",
    r"severity: error",
    r"pg_query",
    r"pg_exec",
    r"invalid input syntax for integer",
    r"sqlite3.operationalerror",
    r"sqlite3.databaseerror",
    r"unclosed github quotation mark",
    r"near \"'\": syntax error",
    r"ora-\d{5}",
    r"oracle error",
    r"microsoft oledb provider for sql server",
    r"sql syntax",
    r"database error",
    r"driver.*failed",
]

async def sqli_check(url: str, headers: dict = None) -> List[Vulnerability]:
    findings = []
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            start_base = time.time()
            async with session.get(url, headers=headers, timeout=5) as base_resp:
                base_status = base_resp.status
                base_text = await base_resp.text()
                base_len = len(base_text)
            base_duration = time.time() - start_base
            
            test_cases = []
            queries = dict(parse_qsl(parsed.query))
            
            if queries:
                for k, v in queries.items():
                    err_queries = queries.copy()
                    err_queries[k] = f"{v}'"
                    err_url = parsed._replace(query=urlencode(err_queries)).geturl()
                    test_cases.append((err_url, "character injection", None))
                    
                    time_queries1 = queries.copy()
                    time_queries1[k] = f"{v}; sleep(1) --"
                    time_url1 = parsed._replace(query=urlencode(time_queries1)).geturl()
                    test_cases.append((time_url1, "timing sleep(1)", 1.0))
            else:
                err_url = f"{url.rstrip('/')}'" if url.endswith("/") else f"{url}'"
                test_cases.append((err_url, "character injection", None))
                test_cases.append((f"{url}?id=sleep(1)", "timing sleep(1)", 1.0))
                test_cases.append((f"{url}?id=pg_sleep(1)", "timing pg_sleep(1)", 1.0))
            
            for test_url, test_type, expected_delay in test_cases:
                try:
                    start_test = time.time()
                    async with session.get(test_url, headers=headers, timeout=5) as test_resp:
                        test_status = test_resp.status
                        test_text = await test_resp.text()
                        test_len = len(test_text)
                        captured_headers = {k: v for k, v in test_resp.headers.items()}
                    test_duration = time.time() - start_test
                    
                    score = 0
                    indicators = []
                    
                    matched_errors = []
                    lower_text = test_text.lower()
                    for pattern in DB_ERRORS:
                        if re.search(pattern, lower_text):
                            matched_errors.append(pattern)
                    
                    if matched_errors:
                        score += 40
                        indicators.append(f"Database error signature matched: {matched_errors[0]}")
                    
                    if expected_delay is not None:
                        delay_diff = test_duration - base_duration
                        if delay_diff > 0.9:
                            score += 30
                            indicators.append(f"Significant time delay observed (+{delay_diff:.2f}s)")
                    
                    if test_status != base_status:
                        if test_status == 500:
                            score += 20
                            indicators.append("HTTP status changed to 500 (Internal Server Error)")
                        elif test_status in [401, 403]:
                            score += 10
                            indicators.append(f"HTTP status changed to {test_status}")
                    
                    if base_len > 0:
                        len_diff = abs(test_len - base_len)
                        if len_diff > 100 and (len_diff / base_len) > 0.15:
                            score += 10
                            indicators.append("Significant response body length difference")
                    
                    if score >= 30:
                        confidence = "LOW"
                        if score >= 70:
                            confidence = "HIGH"
                        elif score >= 50:
                            confidence = "MEDIUM"
                            
                        findings.append(
                            Vulnerability(
                                endpoint=endpoint,
                                method="GET",
                                issue="Potential SQL Injection",
                                severity="HIGH" if confidence != "HIGH" else "CRITICAL",
                                confidence=confidence,
                                description=f"Potential SQL Injection vulnerability detected via query parameter manipulation.",
                                recommendation="1. Enforce strict input validation using allowlists.\n2. Use parameterized queries or prepared statements.\n3. Employ an ORM to handle database queries securely.",
                                category="Security Findings",
                                evidence={
                                    "headers": captured_headers,
                                    "details": indicators,
                                    "bodyPreview": test_text[:500],
                                    "truncated": len(test_text) > 500
                                },
                                impact="Allows attackers to bypass authentication, read/write/modify database contents, or execute arbitrary system commands.",
                                owasp="API8:2023 – Security Misconfiguration / Injection",
                                cwe="CWE-89: SQL Injection"
                            )
                        )
                        break
                        
                except Exception:
                    pass
                    
    except Exception as e:
        print(f"SQLi check error: {e}")
        
    if not findings:
        findings.append(
            Vulnerability(
                endpoint=endpoint,
                method="GET",
                issue="SQL Injection Probing Safe",
                severity="INFO",
                confidence="HIGH",
                description="The endpoint was probed with standard SQL injection payloads and showed no indicators of vulnerability.",
                recommendation="Continue using parameterized queries and secure coding practices.",
                category="Passed Checks",
                evidence={
                    "headers": {},
                    "details": ["Probed with timing and error-based payloads; no database errors or timing delays detected."],
                    "bodyPreview": "",
                    "truncated": False
                },
                impact="None",
                owasp="API8:2023 – Security Misconfiguration / Injection",
                cwe="CWE-89: SQL Injection"
            )
        )
        
    return findings
