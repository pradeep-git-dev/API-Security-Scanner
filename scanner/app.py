import asyncio
from fastapi import FastAPI
from typing import List
from models.scan_request import ScanRequest
from models.vulnerability import Vulnerability
from checks.https import https_check
from checks.headers import header_check
from checks.methods import method_check
from checks.auth import auth_check

app = FastAPI(title="API Sentinel Scanner Service")

@app.get("/")
def read_root():
    return {"message": "Scanner running"}

@app.post("/scan", response_model=List[Vulnerability])
async def scan(req: ScanRequest):
    results = await asyncio.gather(
        https_check(req.targetUrl),
        header_check(req.targetUrl),
        method_check(req.targetUrl),
        auth_check(req.targetUrl)
    )
    # Flatten findings from all checks
    findings = [finding for sublist in results for finding in sublist]
    return findings

