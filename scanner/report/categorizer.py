from typing import List, Dict, Any
from models.vulnerability import Vulnerability

def generate_informational_findings(metadata: Dict[str, Any]) -> List[Vulnerability]:
    """
    Constructs Informational findings from the recon metadata so they can be
    stored and rendered like other findings.
    """
    info_findings = []
    
    # 1. Target Type
    target_type = metadata.get("targetType", "Unknown")
    info_findings.append(
        Vulnerability(
            endpoint="/",
            method="GET",
            issue="Target Type",
            severity="INFO",
            confidence="HIGH",
            description=f"Target classification: {target_type}",
            recommendation="Informational only.",
            category="Informational",
            evidence={
                "type": "info_target",
                "details": [f"Type: {target_type}"]
            },
            impact="None",
            owasp="N/A",
            cwe="CWE-16"
        )
    )
    
    # 2. Framework
    framework = metadata.get("framework", "Unknown")
    info_findings.append(
        Vulnerability(
            endpoint="/",
            method="GET",
            issue="Framework",
            severity="INFO",
            confidence="HIGH",
            description=f"Inferred backend framework: {framework}",
            recommendation="Informational only.",
            category="Informational",
            evidence={
                "type": "info_framework",
                "details": [f"Framework: {framework}"]
            },
            impact="None",
            owasp="N/A",
            cwe="CWE-16"
        )
    )
    
    # 3. Server
    server = metadata.get("server", "Unknown")
    info_findings.append(
        Vulnerability(
            endpoint="/",
            method="GET",
            issue="Server Banner",
            severity="INFO",
            confidence="HIGH",
            description=f"Server header: {server}",
            recommendation="Informational only.",
            category="Informational",
            evidence={
                "type": "info_server",
                "details": [f"Server: {server}"]
            },
            impact="None",
            owasp="N/A",
            cwe="CWE-16"
        )
    )
    
    # 4. TLS Version
    tls = metadata.get("tlsVersion", "N/A")
    info_findings.append(
        Vulnerability(
            endpoint="/",
            method="GET",
            issue="TLS Version",
            severity="INFO",
            confidence="HIGH",
            description=f"TLS Connection protocol: {tls}",
            recommendation="Informational only.",
            category="Informational",
            evidence={
                "type": "info_tls",
                "details": [f"TLS Version: {tls}"]
            },
            impact="None",
            owasp="N/A",
            cwe="CWE-319"
        )
    )
    
    # 5. Response Time
    resp_time = metadata.get("responseTimeMs", 0)
    info_findings.append(
        Vulnerability(
            endpoint="/",
            method="GET",
            issue="Response Time",
            severity="INFO",
            confidence="HIGH",
            description=f"Initial response time: {resp_time} ms",
            recommendation="Informational only.",
            category="Informational",
            evidence={
                "type": "info_time",
                "details": [f"Response Time: {resp_time} ms"]
            },
            impact="None",
            owasp="N/A",
            cwe="CWE-16"
        )
    )
    
    return info_findings

def categorize_findings(findings: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
    """
    Groups findings into: 'Security Findings', 'Observations', 'Passed Checks', 'Informational'.
    """
    categorized = {
        "Security Findings": [],
        "Observations": [],
        "Passed Checks": [],
        "Informational": []
    }
    
    for f in findings:
        cat = f.category
        if cat in categorized:
            categorized[cat].append(f)
        else:
            # Fallback
            categorized["Security Findings"].append(f)
            
    return categorized
