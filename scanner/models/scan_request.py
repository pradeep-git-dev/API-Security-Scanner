from pydantic import BaseModel

class ScanRequest(BaseModel):
    targetUrl: str
