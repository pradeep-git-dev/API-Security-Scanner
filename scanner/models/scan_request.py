from pydantic import BaseModel
from typing import Optional, Dict

class ScanRequest(BaseModel):
    targetUrl: str
    openApiSpec: Optional[str] = None
    authConfig: Optional[Dict[str, str]] = None
