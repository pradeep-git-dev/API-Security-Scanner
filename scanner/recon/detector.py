from urllib.parse import urlparse

async def detect_target_type(url: str, headers: dict) -> str:
    """
    Probes the target URL headers and returns: 'WEBSITE' | 'REST_API' | 'UNKNOWN'
    """
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    
    # Content-Type header analysis
    ct_header = str(headers.get("content-type", "")).lower()
    if "application/json" in ct_header or "application/xml" in ct_header or "application/ld+json" in ct_header:
        return "REST_API"
    elif "text/html" in ct_header:
        return "WEBSITE"
        
    # Check common path keywords
    if any(p in path for p in ["/api", "/v1", "/v2", "/graphql"]):
        return "REST_API"
        
    return "UNKNOWN"
