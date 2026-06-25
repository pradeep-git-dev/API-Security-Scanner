import asyncio
from fastapi import FastAPI, Response, Query
from typing import List
from models.scan_request import ScanRequest
from models.vulnerability import Vulnerability
from checks.https import https_check
from checks.headers import header_check
from checks.methods import method_check
from checks.auth import auth_check
from checks.sqli import sqli_check
from checks.jwt import jwt_check
from checks.exposure import exposure_check
from checks.rate_limit import rate_limit_check

app = FastAPI(title="API Sentinel Scanner Service")

@app.get("/")
def read_root():
    return {"message": "Scanner running"}

@app.get("/health")
def health_check():
    return {"status": "scanner running"}

@app.post("/scan", response_model=List[Vulnerability])
async def scan(req: ScanRequest):
    results = await asyncio.gather(
        https_check(req.targetUrl),
        header_check(req.targetUrl),
        method_check(req.targetUrl),
        auth_check(req.targetUrl),
        sqli_check(req.targetUrl),
        jwt_check(req.targetUrl),
        exposure_check(req.targetUrl),
        rate_limit_check(req.targetUrl)
    )
    # Flatten findings from all checks
    findings = [finding for sublist in results for finding in sublist]
    return findings

# Tiny temporary endpoint for verification of security checks
@app.get("/test-vulnerabilities")
async def test_vulnerabilities(response: Response, id: str = Query(None)):
    # 1. Missing Security Headers (we explicitly remove them, though FastAPI doesn't add them by default)
    # 2. Missing HTTPS (endpoint is accessed via http://localhost:8000/test-vulnerabilities)
    # 3. Potential Public Endpoint (responds 200 without auth)
    # 4. Missing Rate Limiting (we don't rate limit or return 429)
    
    # Check for SQL injection timing indicators
    if id and ("sleep(1)" in id or "pg_sleep(1)" in id):
        await asyncio.sleep(1.2)  # Delay response by 1.2 seconds (triggers delay difference > 0.8 sec)
        return {"status": "success", "message": "query processed after delay"}
        
    # Check for SQL injection error/keyword indicators
    if id and "'" in id:
        response.status_code = 500
        return {
            "error": "Internal Server Error",
            "details": "sqlite3.OperationalError: syntax error near \"'\"",
            "driver": "postgres",
            "sql_state": "42601"
        }
        
    # Default response containing sensitive data keywords (triggers Excessive Data Exposure)
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
