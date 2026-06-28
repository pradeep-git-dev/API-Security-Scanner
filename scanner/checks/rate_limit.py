import asyncio
import aiohttp
import time
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def rate_limit_check(url: str, headers: dict = None) -> List[Vulnerability]:
    parsed = urlparse(url)
    endpoint = parsed.path if parsed.path else "/"
    
    requests_sent = 0
    responses_429 = 0
    retry_after_header = "Not Present"
    rate_limit_headers_found = []
    response_times = []
    
    connector = aiohttp.TCPConnector(ssl=False)
    captured_headers = {}
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            for second in range(3):
                tasks = []
                for _ in range(10):
                    tasks.append(session.get(url, headers=headers, timeout=5))
                    requests_sent += 1
                
                start_time = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start_time
                
                for resp in responses:
                    if isinstance(resp, aiohttp.ClientResponse):
                        response_times.append(elapsed)
                        captured_headers = {k: v for k, v in resp.headers.items()}
                        
                        if resp.status == 429:
                            responses_429 += 1
                            
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        if "retry-after" in headers:
                            retry_after_header = headers["retry-after"]
                            
                        rl_headers = [
                            "x-ratelimit-limit", 
                            "x-ratelimit-remaining", 
                            "ratelimit-limit", 
                            "ratelimit-remaining",
                            "retry-after",
                            "x-rate-limit-limit",
                            "x-rate-limit-remaining"
                        ]
                        for rlh in rl_headers:
                            if rlh in headers and rlh not in rate_limit_headers_found:
                                rate_limit_headers_found.append(rlh)
                
                wait_time = 1.0 - elapsed
                if wait_time > 0 and second < 2:
                    await asyncio.sleep(wait_time)
                    
    except Exception as e:
        print(f"Rate limit check error: {e}")
        
    seen_429 = responses_429 > 0
    has_headers = len(rate_limit_headers_found) > 0
    throttled = False
    
    if len(response_times) >= 10:
        first_avg = sum(response_times[:5]) / 5
        last_avg = sum(response_times[-5:]) / 5
        if last_avg > (first_avg * 2.5) and (last_avg - first_avg) > 0.4:
            throttled = True

    conclusion = "Unable to verify rate limiting."
    is_safe = False
    
    if seen_429:
        conclusion = "Rate limiting is active and enforced."
        is_safe = True
    elif throttled:
        conclusion = "API shows active response throttling. Rate limiting is configured."
        is_safe = True
    elif has_headers:
        conclusion = "Rate limit headers present. Rate limiting is configured."
        is_safe = True
        
    evidence_data = {
        "headers": captured_headers,
        "details": [
            f"Requests Sent: {requests_sent}",
            f"429 Responses: {responses_429}",
            f"Retry-After Header: {retry_after_header}",
            f"Conclusion: {conclusion}"
        ],
        "bodyPreview": "",
        "truncated": False
    }
    
    if is_safe:
        return [
            Vulnerability(
                endpoint=endpoint,
                method="GET",
                issue="Rate Limiting Configured",
                severity="INFO",
                confidence="HIGH",
                description="The API implements active rate limiting or throttling controls.",
                recommendation="Maintain current rate limiting policies to prevent resource exhaustion.",
                category="Passed Checks",
                evidence=evidence_data,
                impact="None",
                owasp="API4:2023 – Unrestricted Resource Consumption",
                cwe="CWE-770: Allocation of Resources Without Limits or Throttling"
            )
        ]
    else:
        return [
            Vulnerability(
                endpoint=endpoint,
                method="GET",
                issue="Rate Limiting Not Observed",
                severity="LOW",
                confidence="LOW",
                description="No rate-limiting headers or 429 Too Many Requests status codes were observed during a concurrent burst of requests.",
                recommendation="Implement rate limiting at the API gateway, load balancer, or application level.",
                category="Security Findings",
                evidence=evidence_data,
                impact="Exposes the API to Denial of Service (DoS) attacks, brute-forcing, and resource exhaustion.",
                owasp="API4:2023 – Unrestricted Resource Consumption",
                cwe="CWE-770: Allocation of Resources Without Limits or Throttling"
            )
        ]
