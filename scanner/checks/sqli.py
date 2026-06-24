import aiohttp
import time
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl
from models.vulnerability import Vulnerability

async def sqli_check(url: str) -> List[Vulnerability]:
    findings = []
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    db_keywords = ["mysql", "postgres", "sqlite", "syntax error"]
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Baseline Request
            start_base = time.time()
            async with session.get(url, timeout=5) as base_resp:
                base_status = base_resp.status
                base_text = await base_resp.text()
                base_len = len(base_text)
            base_duration = time.time() - start_base
            
            # Check database keywords in baseline response
            found_base_keywords = [kw for kw in db_keywords if kw in base_text.lower()]
            if found_base_keywords:
                findings.append(
                    Vulnerability(
                        endpoint=endpoint,
                        method="GET",
                        issue="Possible SQL Injection Indicator",
                        severity="HIGH",
                        confidence="LOW",
                        description=f"Database-specific keywords ({', '.join(found_base_keywords)}) were found in the baseline response.",
                        recommendation="Enforce strict input validation, use parameterized queries, and disable verbose database error messages in production."
                    )
                )
                return findings
            
            # Prepare test cases
            test_cases = []
            queries = dict(parse_qsl(parsed.query))
            
            if queries:
                for k, v in queries.items():
                    # Error / Character Injection payload
                    err_queries = queries.copy()
                    err_queries[k] = f"{v}'"
                    err_url = parsed._replace(query=urlencode(err_queries)).geturl()
                    test_cases.append((err_url, "character injection", None))
                    
                    # Timing payload 1
                    time_queries1 = queries.copy()
                    time_queries1[k] = f"{v}; sleep(1) --"
                    time_url1 = parsed._replace(query=urlencode(time_queries1)).geturl()
                    test_cases.append((time_url1, "timing sleep(1)", 1.0))
                    
                    # Timing payload 2
                    time_queries2 = queries.copy()
                    time_queries2[k] = f"{v}; pg_sleep(1) --"
                    time_url2 = parsed._replace(query=urlencode(time_queries2)).geturl()
                    test_cases.append((time_url2, "timing pg_sleep(1)", 1.0))
            else:
                # Path / Direct URL injection
                err_url = f"{url.rstrip('/')}'" if url.endswith("/") else f"{url}'"
                test_cases.append((err_url, "character injection", None))
                
                # Timing payloads via query parameters
                test_cases.append((f"{url}?id=sleep(1)", "timing sleep(1)", 1.0))
                test_cases.append((f"{url}?id=pg_sleep(1)", "timing pg_sleep(1)", 1.0))
            
            for test_url, test_type, expected_delay in test_cases:
                try:
                    start_test = time.time()
                    async with session.get(test_url, timeout=5) as test_resp:
                        test_status = test_resp.status
                        test_text = await test_resp.text()
                        test_len = len(test_text)
                    test_duration = time.time() - start_test
                    
                    # A. Check for Status Change
                    if test_status != base_status:
                        findings.append(
                            Vulnerability(
                                endpoint=endpoint,
                                method="GET",
                                issue="Possible SQL Injection Indicator",
                                severity="HIGH",
                                confidence="LOW",
                                description=f"HTTP status changed from {base_status} to {test_status} when sending SQL payload: {test_type}.",
                                recommendation="Use prepared statements and parameterized queries. Validate and sanitize all user input."
                            )
                        )
                        break
                    
                    # B. Check for Database Keywords in response
                    found_test_keywords = [kw for kw in db_keywords if kw in test_text.lower()]
                    if found_test_keywords:
                        findings.append(
                            Vulnerability(
                                endpoint=endpoint,
                                method="GET",
                                issue="Possible SQL Injection Indicator",
                                severity="HIGH",
                                confidence="LOW",
                                description=f"Database-specific keywords ({', '.join(found_test_keywords)}) were found in response to SQL payload: {test_type}.",
                                recommendation="Ensure database errors are handled gracefully and not leaked in HTTP responses."
                            )
                        )
                        break
                    
                    # C. Check for Response Length Change
                    # Trigger if length changes by > 20 characters AND by > 10% of baseline length
                    if abs(test_len - base_len) > 20 and (abs(test_len - base_len) / (base_len or 1)) > 0.1:
                        findings.append(
                            Vulnerability(
                                endpoint=endpoint,
                                method="GET",
                                issue="Possible SQL Injection Indicator",
                                severity="HIGH",
                                confidence="LOW",
                                description=f"Response body length changed significantly (from {base_len} to {test_len} characters) when sending SQL payload: {test_type}.",
                                recommendation="Use parameterized APIs or ORMs to ensure user inputs are not interpreted as SQL commands."
                            )
                        )
                        break
                    
                    # D. Check for Timing Delays
                    if expected_delay is not None:
                        delay_diff = test_duration - base_duration
                        if delay_diff > 0.8:
                            findings.append(
                                Vulnerability(
                                    endpoint=endpoint,
                                    method="GET",
                                    issue="Possible SQL Injection Indicator",
                                    severity="HIGH",
                                    confidence="LOW",
                                    description=f"Response time increased significantly by {delay_diff:.2f} seconds (baseline: {base_duration:.2f}s, test: {test_duration:.2f}s) when sending timing payload: {test_type}.",
                                    recommendation="Use parameterized queries and ensure that database queries are execute-bound with strict timeouts."
                                )
                            )
                            break
                            
                except Exception as test_err:
                    # Proceed to next test case if one fails
                    pass
                    
    except Exception as e:
        print(f"SQLi check error scanning {url}: {e}")
        
    return findings
