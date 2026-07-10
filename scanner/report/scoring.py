import json
import os
from typing import List, Tuple, Dict, Any

SYSTEMIC_FINDINGS = {
    "Missing HTTPS",
    "Missing CSP",
    "Missing HSTS",
    "Missing X-Frame-Options",
    "Missing X-Content-Type-Options",
    "Missing Referrer-Policy",
    "Missing Permissions-Policy",
    "HTTP Methods Over-permissive",
    "Weak CORS Policy (Permissive)",
    "Rate Limiting Not Observed",
    "JWT Signature Verification Bypass",
}

INCONCLUSIVE_PHRASES = (
    "unable to verify",
    "could not verify",
    "not enough evidence",
    "inconclusive",
)

def compute_score(findings: List[Any], metadata: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Computes category-based weighted security scores and overall test confidence.
    Returns:
        - final_score: int (overall score)
        - categories_breakdown: List[Dict] (scores per category)
        - deductions: List[Dict] (reasons, category, and penalty)
        - confidence: Dict (score and label)
    """
    # 1. Load scoring configuration
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(current_dir, '..', 'config', 'scoring.json')
    
    try:
        with open(config_path, 'r') as f:
            scoring_config = json.load(f)
    except Exception as e:
        print(f"Error loading scoring.json: {e}")
        # Robust fallback config in case of read errors
        scoring_config = {
            "categories": {
                "Header Security": 30,
                "Transport Security": 15,
                "Server Security": 15,
                "API Security": 25,
                "Data Protection": 15
            },
            "findings": {
                "Missing HTTPS": { "category": "Transport Security", "penalty": 15 },
                "Missing CSP": { "category": "Header Security", "penalty": 5 },
                "Missing HSTS": { "category": "Header Security", "penalty": 5 },
                "Missing X-Frame-Options": { "category": "Header Security", "penalty": 5 },
                "Missing X-Content-Type-Options": { "category": "Header Security", "penalty": 5 },
                "Missing Referrer-Policy": { "category": "Header Security", "penalty": 5 },
                "Missing Permissions-Policy": { "category": "Header Security", "penalty": 5 },
                "HTTP Methods Over-permissive": { "category": "Server Security", "penalty": 5 },
                "Excessive Data Exposure (Sensitive Secrets)": { "category": "Data Protection", "penalty": 15 },
                "Weak CORS Policy (Permissive)": { "category": "API Security", "penalty": 12 },
                "Rate Limiting Not Observed": { "category": "API Security", "penalty": 10 },
                "Potential Public Endpoint": { "category": "API Security", "penalty": 8 },
                "JWT Signature Verification Bypass": { "category": "API Security", "penalty": 15 },
                "Potential SQL Injection": { "category": "Data Protection", "penalty": 15 }
            }
        }

    categories_config = scoring_config.get("categories", {})
    findings_config = scoring_config.get("findings", {})

    category_penalties = {cat_name: 0 for cat_name in categories_config.keys()}
    deductions = []
    applied_deductions = set()

    def get_attr(finding: Any, key: str, default: Any = "") -> Any:
        return getattr(finding, key, default) if hasattr(finding, key) else finding.get(key, default)

    def evidence_dict_for(finding: Any) -> Dict[str, Any]:
        evidence = get_attr(finding, "evidence", {}) or {}
        if isinstance(evidence, dict):
            return evidence
        if hasattr(evidence, "dict"):
            return evidence.dict()
        return {}

    def is_inconclusive(finding: Any) -> bool:
        evidence = evidence_dict_for(finding)
        searchable = [str(evidence.get("conclusion", ""))]
        searchable.extend(str(item) for item in evidence.get("details", []) if item is not None)
        return any(phrase in " ".join(searchable).lower() for phrase in INCONCLUSIVE_PHRASES)

    def add_penalty(issue: str, finding: Any, override_penalty: int = None) -> None:
        if issue not in findings_config:
            return

        rule = findings_config[issue]
        cat = rule["category"]
        base_penalty = rule["penalty"]
        penalty = override_penalty if override_penalty is not None else base_penalty

        if penalty <= 0:
            return

        endpoint = get_attr(finding, "endpoint", "")
        dedupe_key = (cat, issue) if issue in SYSTEMIC_FINDINGS else (cat, issue, endpoint)
        if dedupe_key in applied_deductions:
            return

        applied_deductions.add(dedupe_key)
        category_penalties[cat] = category_penalties.get(cat, 0) + penalty
        deductions.append({
            "category": cat,
            "reason": issue,
            "penalty": penalty
        })

    # 2. Map findings and compute penalties
    for finding in findings:
        issue = get_attr(finding, "issue", "")
        
        # Special handling for composite check "Missing Security Headers"
        if issue == "Missing Security Headers":
            evidence_dict = evidence_dict_for(finding)
            details = evidence_dict.get("details", [])
            for missing_header in details:
                # Extract header name from detail string (e.g. "Missing header: HSTS")
                parts = missing_header.split(": ")
                h_name = parts[1] if len(parts) > 1 else missing_header
                header_key = f"Missing {h_name}"
                add_penalty(header_key, finding)
        else:
            if issue in findings_config:
                penalty_override = None
                if issue == "Rate Limiting Not Observed" and is_inconclusive(finding):
                    penalty_override = scoring_config.get("inconclusivePenalties", {}).get(issue, 5)
                add_penalty(issue, finding, penalty_override)

    # 3. Calculate category breakdown and overall score
    categories_breakdown = []
    overall_score = 0

    for cat_name, max_score in categories_config.items():
        penalties_sum = category_penalties.get(cat_name, 0)
        cat_score = max(0, max_score - penalties_sum)
        overall_score += cat_score
        
        percentage = int(round((cat_score / max_score) * 100)) if max_score > 0 else 100
        categories_breakdown.append({
            "name": cat_name,
            "score": cat_score,
            "max": max_score,
            "percentage": percentage
        })

    # 4. Multi-factor Confidence Calculation
    count_completed = 0
    
    # Factor A: Checks Completed (40%)
    tls_version = metadata.get("tlsVersion", "N/A")
    if tls_version and tls_version != "N/A" and tls_version != "None":
        count_completed += 1
        
    has_rl_check = False
    for f in findings:
        f_issue = f.issue if hasattr(f, "issue") else f.get("issue", "")
        if f_issue in ["Rate Limiting Configured", "Rate Limiting Not Observed"]:
            evidence = getattr(f, "evidence", {}) or {}
            evidence_dict = evidence if isinstance(evidence, dict) else (evidence.dict() if hasattr(evidence, "dict") else {})
            conclusion = evidence_dict.get("conclusion", "")
            if conclusion and "Unable to verify" not in conclusion:
                has_rl_check = True
                break
    if has_rl_check:
        count_completed += 1
        
    has_header_check = False
    has_sqli_check = False
    has_cors_check = False
    for f in findings:
        f_issue = f.issue if hasattr(f, "issue") else f.get("issue", "")
        if f_issue in ["Missing Security Headers", "Security Headers Configured"]:
            has_header_check = True
        elif f_issue in ["Potential SQL Injection", "SQL Injection Probing Safe"]:
            has_sqli_check = True
        elif f_issue in ["Weak CORS Policy (Permissive)", "CORS Policy Restrictive"]:
            has_cors_check = True

    if has_header_check:
        count_completed += 1
    if has_sqli_check:
        count_completed += 1
    if has_cors_check:
        count_completed += 1
        
    checks_completed_ratio = count_completed / 5.0
    checks_score = checks_completed_ratio * 40.0
    
    # Factor B: Endpoint Coverage (30%)
    unique_endpoints = set()
    for f in findings:
        ep = f.endpoint if hasattr(f, "endpoint") else f.get("endpoint", "")
        if ep:
            unique_endpoints.add(ep)
            
    num_endpoints = len(unique_endpoints)
    coverage_ratio = 1.0 if num_endpoints > 1 else 0.5
    coverage_score = coverage_ratio * 30.0
    
    # Factor C: Target Detection Confidence (20%)
    detection_ratio = 0.0
    framework = metadata.get("framework", "Unknown")
    server = metadata.get("server", "Unknown")
    if framework and framework != "Unknown":
        detection_ratio += 0.5
    if server and server != "Unknown":
        detection_ratio += 0.5
    detection_score = detection_ratio * 20.0
    
    # Factor D: Authentication Coverage (10%)
    auth_configured = metadata.get("authConfigured", False)
    auth_ratio = 1.0 if auth_configured else 0.0
    auth_score = auth_ratio * 10.0
    
    total_confidence_score = int(round(checks_score + coverage_score + detection_score + auth_score))
    
    if total_confidence_score > 90:
        confidence_label = "HIGH"
    elif total_confidence_score >= 70:
        confidence_label = "MEDIUM"
    else:
        confidence_label = "LOW"
        
    confidence = {
        "score": total_confidence_score,
        "label": confidence_label
    }

    confidence_caps = scoring_config.get("confidenceScoreCaps", {
        "LOW": 70,
        "MEDIUM": 85,
        "HIGH": 100
    })
    score_cap = confidence_caps.get(confidence_label, 100)
    if overall_score > score_cap:
        confidence_penalty = overall_score - score_cap
        deductions.append({
            "category": "Assessment Confidence",
            "reason": f"{confidence_label.title()} Scan Confidence Cap",
            "penalty": confidence_penalty
        })

        scale = score_cap / overall_score if overall_score else 0
        scaled_categories = []
        for idx, category in enumerate(categories_breakdown):
            exact_score = category["score"] * scale
            floor_score = int(exact_score)
            scaled_categories.append({
                "idx": idx,
                "floor": floor_score,
                "fraction": exact_score - floor_score
            })

        remainder = score_cap - sum(item["floor"] for item in scaled_categories)
        for item in sorted(scaled_categories, key=lambda row: row["fraction"], reverse=True):
            if remainder <= 0:
                break
            item["floor"] += 1
            remainder -= 1

        by_index = {item["idx"]: item["floor"] for item in scaled_categories}
        for idx, category in enumerate(categories_breakdown):
            category["score"] = by_index[idx]
            max_score = category["max"]
            category["percentage"] = int(round((category["score"] / max_score) * 100)) if max_score > 0 else 100

        overall_score = score_cap

    return overall_score, categories_breakdown, deductions, confidence
