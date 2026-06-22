from fastapi import FastAPI
from typing import List
from models.scan_request import ScanRequest
from models.vulnerability import Vulnerability

app = FastAPI(title="API Sentinel Scanner Service")

@app.get("/")
def read_root():
    return {"message": "Scanner running"}

@app.post("/scan", response_model=List[Vulnerability])
def scan(req: ScanRequest):
    # Dummy findings
    dummy_findings = [
        Vulnerability(
            endpoint="/",
            method="GET",
            issue="Missing HTTPS",
            severity="HIGH",
            confidence="HIGH",
            description="Dummy result: The target URL does not enforce HTTPS.",
            recommendation="Redirect HTTP traffic to HTTPS and use TLS certificates."
        )
    ]
    return dummy_findings
