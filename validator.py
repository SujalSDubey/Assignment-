def validate_spec(spec: dict):
    if not isinstance(spec, dict):
        raise ValueError("Invalid OpenAPI structure")

    if "paths" not in spec:
        raise ValueError("Missing 'paths' in OpenAPI spec")

    if not (spec.get("openapi") or spec.get("swagger") == "2.0"):
        raise ValueError("Unsupported OpenAPI version")
