from typing import Dict, Any

def fingerprint_tech(headers: Dict[str, str], response_body: str = "") -> Dict[str, Any]:
    """
    Analyzes response headers to detect backend technologies, servers, and hosting providers.
    Returns structured name and confidence levels for: 'server', 'framework', 'hosting'.
    """
    server = {"name": "Unknown", "confidence": "LOW"}
    framework = {"name": "Unknown", "confidence": "LOW"}
    hosting = {"name": "Unknown", "confidence": "LOW"}
    
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    
    # 1. Server Fingerprinting
    srv_header = headers_lower.get("server", "")
    if "nginx" in srv_header:
        server = {"name": "Nginx", "confidence": "HIGH"}
    elif "apache" in srv_header or "httpd" in srv_header:
        server = {"name": "Apache", "confidence": "HIGH"}
    elif "microsoft-iis" in srv_header or "iis" in srv_header:
        server = {"name": "IIS", "confidence": "HIGH"}
    elif "uvicorn" in srv_header:
        server = {"name": "Uvicorn", "confidence": "HIGH"}
    elif "cloudflare" in srv_header:
        server = {"name": "Cloudflare-Proxy", "confidence": "HIGH"}
        hosting = {"name": "Cloudflare", "confidence": "HIGH"}
    elif srv_header:
        # Format neatly (e.g. gunicorn -> Gunicorn)
        server = {"name": srv_header.split('/')[0].strip().title(), "confidence": "MEDIUM"}
        
    # 2. Framework Fingerprinting
    x_pb = headers_lower.get("x-powered-by", "")
    if "express" in x_pb or "express" in srv_header:
        framework = {"name": "Express", "confidence": "HIGH"}
    elif "next.js" in x_pb or "nextjs" in x_pb:
        framework = {"name": "Next.js", "confidence": "HIGH"}
    elif "fastapi" in x_pb or "fastapi" in srv_header or "uvicorn" in srv_header:
        framework = {"name": "FastAPI", "confidence": "HIGH" if "fastapi" in x_pb else "MEDIUM"}
    elif "django" in x_pb or "django" in srv_header or "csrftoken" in headers_lower or "sessionid" in headers_lower:
        framework = {"name": "Django", "confidence": "HIGH" if "django" in x_pb else "MEDIUM"}
    elif "flask" in x_pb or "flask" in srv_header:
        framework = {"name": "Flask", "confidence": "HIGH"}
    elif "laravel" in x_pb or "php" in x_pb:
        framework = {"name": "Laravel/PHP", "confidence": "HIGH"}
    elif "spring" in x_pb or "spring" in srv_header:
        framework = {"name": "Spring Boot", "confidence": "HIGH"}
        
    # 3. Hosting Platform Fingerprinting
    if "x-vercel-id" in headers_lower or "x-vercel-cache" in headers_lower or "vercel" in srv_header:
        hosting = {"name": "Vercel", "confidence": "HIGH"}
        if framework["name"] == "Unknown":
            framework = {"name": "Next.js", "confidence": "MEDIUM"}
    elif "x-nf-request-id" in headers_lower or "netlify" in srv_header:
        hosting = {"name": "Netlify", "confidence": "HIGH"}
    elif "cf-ray" in headers_lower or "cf-cache-status" in headers_lower:
        hosting = {"name": "Cloudflare", "confidence": "HIGH"}
    elif srv_header == "github.com" or "github-pages" in srv_header or "x-github-request-id" in headers_lower:
        hosting = {"name": "GitHub Pages", "confidence": "HIGH"}
        
    return {
        "server": server,
        "framework": framework,
        "hosting": hosting
    }
