from typing import Dict, List, Any

def parse_endpoints(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Given a parsed OpenAPI dict, extracts all endpoint paths and their allowed methods.
    Returns: List of {"path": "/users", "methods": ["GET", "POST"]}
    """
    endpoints = []
    paths = data.get("paths", {})
    
    for path, path_obj in paths.items():
        if not isinstance(path_obj, dict):
            continue
            
        methods = []
        for method in ["get", "post", "put", "delete", "options", "head", "patch", "trace"]:
            if method in path_obj:
                methods.append(method.upper())
                
        if methods:
            endpoints.append({
                "path": path,
                "methods": sorted(methods)
            })
            
    return endpoints
