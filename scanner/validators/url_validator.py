from urllib.parse import urlparse

def validate_url(url: str):
    """
    Checks if a URL is valid and uses http/https.
    Returns: (is_valid: bool, error_message: str | None)
    """
    if not url:
        return False, "Target URL cannot be empty."
    
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False, "Target URL must start with http:// or https://."
        
        if not parsed.netloc:
            return False, "Invalid target URL syntax."
            
        return True, None
    except Exception as e:
        return False, f"URL validation failed: {str(e)}"
