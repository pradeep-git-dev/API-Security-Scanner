import json
try:
    import yaml
except ImportError:
    yaml = None

def dict_raise_on_duplicates(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            raise ValueError(f"Duplicate key detected: '{k}'")
        d[k] = v
    return d

def validate_openapi(spec_content: str):
    """
    Parses and validates an OpenAPI/Swagger spec string.
    Checks:
    - Malformed JSON/YAML syntax
    - OpenAPI version (supports Swagger 2.0, OpenAPI 3.0, OpenAPI 3.1)
    - Duplicate paths/keys
    Returns: (is_valid: bool, data: dict | None, error_message: str | None)
    """
    if not spec_content or not spec_content.strip():
        return False, None, "Specification content is empty."
        
    data = None
    is_json = False
    
    # 1. Try parsing as JSON first
    try:
        content_stripped = spec_content.strip()
        if content_stripped.startswith("{") or content_stripped.startswith("["):
            data = json.loads(spec_content, object_pairs_hook=dict_raise_on_duplicates)
            is_json = True
    except ValueError as val_err:
        return False, None, f"Malformed JSON: {str(val_err)}"
    except Exception as e:
        return False, None, f"JSON Parse error: {str(e)}"
        
    # 2. If not JSON, parse as YAML
    if not is_json:
        if yaml is None:
            return False, None, "YAML parser dependency is not installed."
        
        try:
            class UniqueKeyLoader(yaml.SafeLoader):
                def construct_mapping(self, node, deep=False):
                    mapping = set()
                    for key_node, value_node in node.value:
                        key = self.construct_object(key_node, deep=deep)
                        if key in mapping:
                            raise ValueError(f"Duplicate key detected: '{key}'")
                        mapping.add(key)
                    return super().construct_mapping(node, deep)
                    
            data = yaml.load(spec_content, Loader=UniqueKeyLoader)
        except yaml.YAMLError as yaml_err:
            return False, None, f"Malformed YAML: {str(yaml_err)}"
        except ValueError as val_err:
            return False, None, f"YAML Validation: {str(val_err)}"
        except Exception as e:
            return False, None, f"YAML Parse error: {str(e)}"
            
    # 3. Check OpenAPI / Swagger version
    if not isinstance(data, dict):
        return False, None, "Invalid specification schema: root must be a JSON object."
        
    version = data.get("openapi") or data.get("swagger")
    if not version:
        return False, None, "Missing specification version identifier. Root must contain 'openapi' or 'swagger' fields."
        
    version_str = str(version).strip()
    if not (version_str.startswith("2.0") or version_str.startswith("3.0") or version_str.startswith("3.1")):
        return False, None, f"Unsupported specification version '{version_str}'. Supported versions: Swagger 2.0, OpenAPI 3.0, OpenAPI 3.1."
        
    # 4. Check for paths
    if "paths" not in data or not isinstance(data["paths"], dict):
        return False, None, "Specification must contain a valid 'paths' object mapping endpoints."
        
    return True, data, None
