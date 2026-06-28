from typing import List, Dict, Any

def build_endpoint_tree(endpoints: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Transforms list of parsed endpoints into a simple path-to-methods dictionary:
    {"/users": ["GET", "POST"], "/products": ["GET"]}
    """
    tree = {}
    for ep in endpoints:
        path = ep.get("path")
        methods = ep.get("methods", [])
        if path:
            tree[path] = methods
    return tree
