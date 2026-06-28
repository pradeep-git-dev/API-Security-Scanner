import re
from typing import Dict

def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Sanitizes HTTP header keys and values to prevent injection of CRLF or control characters.
    """
    sanitized = {}
    if not headers or not isinstance(headers, dict):
        return sanitized
        
    for k, v in headers.items():
        clean_k = str(k).strip()
        clean_v = str(v).strip()
        
        # Ensure header name is not empty and has no carriage return / newline / control characters
        if clean_k and not re.search(r"[\r\n\x00-\x1f\x7f]", clean_k):
            # Strip control chars from value too
            clean_v_sanitized = re.sub(r"[\r\n\x00-\x1f\x7f]", "", clean_v)
            sanitized[clean_k] = clean_v_sanitized
            
    return sanitized
