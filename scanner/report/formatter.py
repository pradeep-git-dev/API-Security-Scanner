import hashlib
from typing import List, Dict, Any

def calculate_finding_id(endpoint: str, method: str, issue: str) -> str:
    """
    Generates a deterministic finding ID via SHA256(endpoint + method + issue).
    """
    norm_ep = str(endpoint).strip()
    norm_method = str(method).strip().upper()
    norm_issue = str(issue).strip()
    
    hash_input = f"{norm_ep}{norm_method}{norm_issue}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

def format_scan_result(
    findings: List[Any],
    score: int,
    score_breakdown: List[Dict[str, Any]],
    categories: List[Dict[str, Any]],
    confidence: Dict[str, Any],
    metadata: Dict[str, Any],
    headers_status: List[Dict[str, Any]],
    rate_limit_report: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Formats the scanner response into a clean JSON structure for the Node backend.
    """
    formatted_findings = []
    for f in findings:
        f_dict = f.dict() if hasattr(f, "dict") else dict(f)
        
        # Calculate dynamic finding ID
        f_dict["findingId"] = calculate_finding_id(
            f_dict.get("endpoint", "/"),
            f_dict.get("method", "GET"),
            f_dict.get("issue", "")
        )
        formatted_findings.append(f_dict)
        
    return {
        "score": score,
        "scoreBreakdown": score_breakdown,
        "categories": categories,
        "confidence": confidence,
        "targetType": metadata.get("targetType", "UNKNOWN"),
        "framework": metadata.get("framework", "Unknown"),
        "hosting": metadata.get("hosting", "Unknown"),
        "contentType": metadata.get("contentType", "Unknown"),
        "server": metadata.get("server", "Unknown"),
        "tlsVersion": metadata.get("tlsVersion", "N/A"),
        "responseTimeMs": metadata.get("responseTimeMs", 0),
        "headersStatus": headers_status,
        "rateLimitReport": rate_limit_report,
        "findings": formatted_findings
    }
