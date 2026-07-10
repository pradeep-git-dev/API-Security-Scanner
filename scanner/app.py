import asyncio
from fastapi import FastAPI, Response, Query, HTTPException
from typing import List, Dict, Any

from models.scan_request import ScanRequest
from models.vulnerability import Vulnerability

# Recon & Fingerprint Modules
from recon.detector import detect_target_type
from recon.fingerprint import fingerprint_target

# Validators
from validators.url_validator import validate_url
from validators.header_validator import sanitize_headers
from validators.openapi_validator import validate_openapi

# OpenAPI Parser
from openapi.parser import parse_endpoints
from openapi.endpoint_builder import build_endpoint_tree

# Check Modules
from checks.https import https_check
from checks.headers import header_check
from checks.methods import method_check
from checks.auth import auth_check
from checks.sqli import sqli_check
from checks.jwt import jwt_check
from checks.exposure import exposure_check
from checks.rate_limit import rate_limit_check
from checks.robots import robots_check
from checks.security import security_check
from checks.cors import cors_check

# Report Modules
from report.builder import build_scan_report

app = FastAPI(title="API Auditor Scanner Service")

@app.get("/")
def read_root():
    return {"message": "Scanner running"}

@app.get("/health")
def health_check():
    return {"status": "scanner running"}

@app.post("/scan")
async def scan(req: ScanRequest):
    url = req.targetUrl
    
    # 1. URL Validation
    is_valid_url, url_error = validate_url(url)
    if not is_valid_url:
        raise HTTPException(status_code=400, detail=url_error)
        
    # 2. Inject and Sanitize authentication headers if configured
    auth_headers = {}
    if req.authConfig:
        auth_type = req.authConfig.get("authType")
        header_name = req.authConfig.get("headerName")
        token_val = req.authConfig.get("tokenValue")
        
        if auth_type and token_val:
            if auth_type == "Bearer":
                auth_headers["Authorization"] = f"Bearer {token_val}"
            elif auth_type == "Basic":
                auth_headers["Authorization"] = f"Basic {token_val}"
            elif auth_type == "API Key" and header_name:
                auth_headers[header_name] = token_val
            elif auth_type == "Custom Header" and header_name:
                auth_headers[header_name] = token_val
                
    sanitized_auth_headers = sanitize_headers(auth_headers)
    
    # 3. OpenAPI discovery processing
    endpoint_tree = {}
    discovery_metadata = {
        "source": "Recon Probing",
        "endpointCount": 1,
        "version": "N/A",
        "parsedSuccessfully": False
    }
    
    # Target endpoints list to scan
    scan_targets = [url]
    
    if req.openApiSpec:
        is_valid_spec, spec_data, spec_error = validate_openapi(req.openApiSpec)
        if not is_valid_spec:
            raise HTTPException(status_code=400, detail=f"OpenAPI Validation Error: {spec_error}")
            
        parsed_eps = parse_endpoints(spec_data)
        endpoint_tree = build_endpoint_tree(parsed_eps)
        
        # Populate discovery metadata
        version_val = spec_data.get("openapi") or spec_data.get("swagger") or "Unknown"
        discovery_metadata = {
            "source": "OpenAPI",
            "endpointCount": len(parsed_eps),
            "version": str(version_val),
            "parsedSuccessfully": True
        }
        
        # Resolve target endpoints list
        base_url = url.rstrip("/")
        for ep in parsed_eps:
            path = ep["path"]
            # Ensure path starts with a slash
            if not path.startswith("/"):
                path = f"/{path}"
            scan_targets.append(f"{base_url}{path}")
            
    # 4. Fingerprint target (always using primary root url)
    content_type, tls_version, response_time_ms, tech_info = await fingerprint_target(url)
    target_type = await detect_target_type(url, sanitized_auth_headers)
    
    fingerprint = {
        "server": tech_info.get("server", {"name": "Unknown", "confidence": "LOW"}),
        "framework": tech_info.get("framework", {"name": "Unknown", "confidence": "LOW"}),
        "hosting": tech_info.get("hosting", {"name": "Unknown", "confidence": "LOW"}),
        "tls": tls_version,
        "responseTime": response_time_ms
    }
    
    metadata = {
        "targetType": target_type,
        "framework": fingerprint["framework"]["name"],
        "hosting": fingerprint["hosting"]["name"],
        "contentType": content_type,
        "server": fingerprint["server"]["name"],
        "tlsVersion": tls_version,
        "responseTimeMs": response_time_ms,
        "authConfigured": req.authConfig is not None and req.authConfig.get("authType") != "None"
    }
    
    # 5. Execute Scan Suite
    findings = []
    
    # We will iterate over resolved target URLs
    # For optimization, we only run intensive path vulnerability scans on unique endpoints
    unique_targets = list(dict.fromkeys(scan_targets))[:10] # limit to max 10 to keep scans fast
    
    # HTTPS and root checks only need to run once against primary target
    primary_https = await https_check(url)
    primary_headers = await header_check(url, sanitized_auth_headers)
    findings.extend(primary_https)
    findings.extend(primary_headers)
    
    for t_url in unique_targets:
        t_findings = []
        
        # Auth check always unauthenticated to test restrictions
        auth_res = await auth_check(t_url)
        t_findings.extend(auth_res)
        
        # Run rest of checking modules with authenticated headers
        sqli_res = await sqli_check(t_url, sanitized_auth_headers)
        rate_res = await rate_limit_check(t_url, sanitized_auth_headers)
        jwt_res = await jwt_check(t_url)
        method_res = await method_check(t_url, sanitized_auth_headers)
        cors_res = await cors_check(t_url, sanitized_auth_headers)
        exposure_res = await exposure_check(t_url, sanitized_auth_headers)
        
        t_findings.extend(sqli_res)
        t_findings.extend(rate_res)
        t_findings.extend(jwt_res)
        t_findings.extend(method_res)
        t_findings.extend(cors_res)
        t_findings.extend(exposure_res)
        
        # Filter target findings
        for f in t_findings:
            # Avoid repeating base scans
            if f.issue in ["Missing HTTPS", "HTTPS Enforced", "Missing Security Headers", "Security Headers Configured"]:
                continue
            findings.append(f)
            
    # Run passive observations once
    obs_robots = await robots_check(url)
    obs_security = await security_check(url)
    findings.extend(obs_robots)
    findings.extend(obs_security)
    
    # 6. Build scan report
    report_data = build_scan_report(findings, metadata)
    
    # 7. Add transient discovery metrics, fingerprint attributes, and endpoint trees to return payload
    report_data["fingerprint"] = fingerprint
    report_data["discoveryMetadata"] = discovery_metadata
    
    # Convert tree dictionary map to schema list representation
    report_data["endpointTree"] = [{"path": k, "methods": v} for k, v in endpoint_tree.items()]
    
    return report_data

# Tiny temporary endpoint for verification of security checks
@app.get("/test-vulnerabilities")
async def test_vulnerabilities(response: Response, id: str = Query(None)):
    if id and ("sleep(1)" in id or "pg_sleep(1)" in id):
        await asyncio.sleep(1.2)
        return {"status": "success", "message": "query processed after delay"}
        
    if id and "'" in id:
        response.status_code = 500
        return {
            "error": "Internal Server Error",
            "details": "sqlite3.OperationalError: syntax error near \"'\"",
            "driver": "postgres",
            "sql_state": "42601"
        }
        
    return {
        "status": "success",
        "email": "admin@sentinel.local",
        "password": "supersecretpassword123",
        "secret": "key_amFzb25fdG9rZW5fc2VjcmV0X2tleV9leG1wbGU=",
        "token": "ey12345.token.value",
        "privateKey": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...",
        "accessKey": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
