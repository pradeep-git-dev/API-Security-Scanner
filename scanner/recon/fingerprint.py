import socket
import ssl
import time
import aiohttp
from urllib.parse import urlparse
from fingerprint.technologies import fingerprint_tech

def get_tls_version(url: str) -> str:
    """
    Connects to the HTTPS server and retrieves the active TLS protocol version.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "N/A"
    
    host = parsed.hostname
    port = parsed.port or 443
    
    try:
        context = ssl.create_default_context()
        # Create connection with a short timeout to prevent blocking
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                # e.g. TLSv1.3 -> 1.3
                if version.startswith("TLSv"):
                    return version.replace("TLSv", "")
                return version
    except Exception as e:
        print(f"Error getting TLS version for {host}: {e}")
        return "Unknown"

async def fingerprint_target(url: str):
    """
    Fingerprints the target URL.
    Returns: (content_type, tls_version, response_time_ms, tech_info)
    """
    content_type = "Unknown"
    tls_version = "N/A"
    response_time_ms = 0
    tech_info = {
        "server": {"name": "Unknown", "confidence": "LOW"},
        "framework": {"name": "Unknown", "confidence": "LOW"},
        "hosting": {"name": "Unknown", "confidence": "LOW"}
    }
    
    start_time = time.time()
    raw_headers = {}
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=5) as response:
                elapsed = time.time() - start_time
                response_time_ms = int(elapsed * 1000)
                
                raw_headers = {k: v for k, v in response.headers.items()}
                ct = response.headers.get("Content-Type", "Unknown")
                content_type = ct.split(";")[0].strip()
    except Exception as e:
        print(f"Error fingerprinting target {url}: {e}")
        elapsed = time.time() - start_time
        response_time_ms = int(elapsed * 1000)
        
    tls_version = get_tls_version(url)
    tech_info = fingerprint_tech(raw_headers)
    
    return content_type, tls_version, response_time_ms, tech_info
