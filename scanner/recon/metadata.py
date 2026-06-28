from pydantic import BaseModel

class TargetMetadata(BaseModel):
    targetType: str
    framework: str
    contentType: str
    server: str
    tlsVersion: str
    responseTimeMs: int
