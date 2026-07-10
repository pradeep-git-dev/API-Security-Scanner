from typing import List, Dict, Any
from report.scoring import compute_score
from report.categorizer import generate_informational_findings
from report.formatter import format_scan_result

def build_scan_report(findings: List[Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for report generation. Computes score, extracts headers status
    and rate limit stats, builds informational findings, and formats the response.
    """
    # 1. Compute Score, Categories, Breakdown and Confidence based on original findings & metadata
    score, categories, score_breakdown, confidence = compute_score(findings, metadata)
    
    # 2. Extract Header Analysis status
    headers_to_check = {
        "CSP": "Content-Security-Policy",
        "HSTS": "Strict-Transport-Security",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy"
    }
    
    # We want to return a list of headers status
    headers_status = []
    header_finding = next((f for f in findings if f.issue in ["Missing Security Headers", "Security Headers Configured"]), None)
    
    if header_finding:
        f_issue = header_finding.issue if hasattr(header_finding, "issue") else header_finding.get("issue", "")
        if f_issue == "Security Headers Configured":
            for clean_name in headers_to_check.keys():
                headers_status.append({"header": clean_name, "status": True})
        else:
            evidence = getattr(header_finding, "evidence", {}) or {}
            evidence_dict = evidence if isinstance(evidence, dict) else (evidence.dict() if hasattr(evidence, "dict") else {})
            missing_list = evidence_dict.get("details", [])
            
            # Clean descriptive detail strings to extract raw header names (e.g. "Missing header: HSTS" -> "HSTS")
            missing_cleaned = []
            for item in missing_list:
                parts = item.split(": ")
                h_name = parts[1] if len(parts) > 1 else item
                missing_cleaned.append(h_name)
                
            for clean_name in headers_to_check.keys():
                headers_status.append({"header": clean_name, "status": clean_name not in missing_cleaned})
    else:
        # No header finding means the check did not complete; avoid reporting
        # verified missing headers without evidence from the header checker.
        for clean_name in headers_to_check.keys():
            headers_status.append({"header": clean_name, "status": None})
            
    # 3. Extract Rate Limit Report
    rate_limit_report = {
        "requestsSent": 30,
        "responses429": 0,
        "retryAfter": "Missing",
        "conclusion": "Unable to verify rate limiting."
    }
    rl_finding = next((f for f in findings if f.issue in ["Rate Limiting Configured", "Rate Limiting Not Observed"]), None)
    if rl_finding:
        evidence = getattr(rl_finding, "evidence", {}) or {}
        evidence_dict = evidence if isinstance(evidence, dict) else (evidence.dict() if hasattr(evidence, "dict") else {})
        retry_val = evidence_dict.get("retryAfter", "Not Present")
        retry_status = "Missing" if retry_val in ["Not Present", "Missing"] else "Present"
        
        rate_limit_report = {
            "requestsSent": evidence_dict.get("requestsSent", 30),
            "responses429": evidence_dict.get("responses429", 0),
            "retryAfter": retry_status,
            "conclusion": evidence_dict.get("conclusion", "Unable to verify rate limiting.")
        }
        
    # 4. Generate Informational findings based on metadata
    info_findings = generate_informational_findings(metadata)
    
    # Combine original findings with the new Informational findings
    all_findings = findings + info_findings
    
    # 5. Format scan result
    return format_scan_result(
        findings=all_findings,
        score=score,
        score_breakdown=score_breakdown,
        categories=categories,
        confidence=confidence,
        metadata=metadata,
        headers_status=headers_status,
        rate_limit_report=rate_limit_report
    )
