from app.rules.base import create_finding

# SEC001: No Global Security Defined (Critical)
def check_sec001_no_global_security(spec):
    findings = []

    is_v2 = spec.get("swagger") == "2.0"
    is_v3 = "openapi" in spec

    has_global_security = "security" in spec

    if is_v2:
        has_definitions = "securityDefinitions" in spec
    else:
        has_definitions = "components" in spec and "securitySchemes" in spec.get("components", {})

    if not has_global_security and not has_definitions:
        findings.append(
            create_finding(
                rule_id="SEC001",
                severity="Critical",
                description="No global security definition found in OpenAPI specification",
                location="root",
                recommendation="Define global security schemes and apply them at the root level"
            )
        )

    return findings


# SEC002: Unprotected Endpoint (High)
def check_sec002_unprotected_endpoints(spec):
    findings = []

    global_security = spec.get("security")

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.startswith("x-"):
                continue

            has_operation_security = "security" in details

            if not global_security and not has_operation_security:
                findings.append(
                    create_finding(
                        rule_id="SEC002",
                        severity="High",
                        description="Endpoint has no security requirements defined",
                        location=f"paths.{path}.{method}.security",
                        recommendation="Apply authentication using global or operation-level security"
                    )
                )

    return findings
# SEC003: HTTP Allowed (High)
def check_sec003_http_allowed(spec):
    findings = []

    # OpenAPI v3
    if "openapi" in spec:
        for idx, server in enumerate(spec.get("servers", [])):
            url = server.get("url", "")
            if url.startswith("http://"):
                findings.append(
                    create_finding(
                        rule_id="SEC003",
                        severity="High",
                        description="Insecure HTTP protocol allowed in server URL",
                        location=f"servers[{idx}].url",
                        recommendation="Use HTTPS instead of HTTP for all server URLs"
                    )
                )

    # OpenAPI v2 (Swagger)
    if spec.get("swagger") == "2.0":
        schemes = spec.get("schemes", [])
        if "http" in schemes:
            findings.append(
                create_finding(
                    rule_id="SEC003",
                    severity="High",
                    description="Insecure HTTP protocol allowed in schemes",
                    location="schemes",
                    recommendation="Remove HTTP and enforce HTTPS only"
                )
            )

    return findings
# SEC004: No Rate Limiting Headers (Medium)
def check_sec004_no_rate_limit_headers(spec):
    findings = []

    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.startswith("x-"):
                continue

            responses = details.get("responses", {})
            rate_limit_found = False

            for response in responses.values():
                headers = response.get("headers", {})
                for header_name in headers.keys():
                    if header_name.lower().startswith("x-ratelimit"):
                        rate_limit_found = True
                        break

            if not rate_limit_found:
                findings.append(
                    create_finding(
                        rule_id="SEC004",
                        severity="Medium",
                        description="No rate limiting headers defined in responses",
                        location=f"paths.{path}.{method}.responses",
                        recommendation="Include X-RateLimit-* headers to indicate API rate limits"
                    )
                )

    return findings
# SEC005: Sensitive Data in Query Parameters (Medium)
def check_sec005_sensitive_query_params(spec):
    findings = []

    sensitive_keywords = [
        "password",
        "token",
        "secret",
        "api_key",
        "apikey",
        "auth"
    ]

    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.startswith("x-"):
                continue

            parameters = details.get("parameters", [])

            for param in parameters:
                if param.get("in") == "query":
                    param_name = param.get("name", "").lower()

                    if any(keyword in param_name for keyword in sensitive_keywords):
                        findings.append(
                            create_finding(
                                rule_id="SEC005",
                                severity="Medium",
                                description="Sensitive data exposed in query parameter",
                                location=f"paths.{path}.{method}.parameters.{param_name}",
                                recommendation="Avoid using sensitive data in query parameters; use headers or request body instead"
                            )
                        )

    return findings
# SEC006: Missing Error Response Definitions (Medium)
def check_sec006_missing_error_responses(spec):
    findings = []

    required_errors = {"401", "403", "429"}

    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.startswith("x-"):
                continue

            responses = details.get("responses", {})
            defined_responses = set(responses.keys())

            missing_errors = required_errors - defined_responses

            if missing_errors:
                findings.append(
                    create_finding(
                        rule_id="SEC006",
                        severity="Medium",
                        description="Missing standard error response definitions (401, 403, 429)",
                        location=f"paths.{path}.{method}.responses",
                        recommendation="Define 401, 403, and 429 error responses for better security and API resilience"
                    )
                )

    return findings
# SEC007: No Contact / Security Contact (Low)
def check_sec007_missing_security_contact(spec):
    findings = []

    info = spec.get("info", {})

    has_contact = "contact" in info
    has_security_contact = "x-security-contact" in info

    if not has_contact and not has_security_contact:
        findings.append(
            create_finding(
                rule_id="SEC007",
                severity="Low",
                description="No contact or security contact information provided",
                location="info",
                recommendation="Add info.contact or x-security-contact for vulnerability reporting"
            )
        )

    return findings
# SEC008: Deprecated Endpoint Without Sunset Information (Low)
def check_sec008_deprecated_without_sunset(spec):
    findings = []

    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.startswith("x-"):
                continue

            if details.get("deprecated") is True:
                has_sunset = (
                    "sunset" in details or
                    "x-sunset" in details or
                    "x-deprecation-date" in details
                )

                if not has_sunset:
                    findings.append(
                        create_finding(
                            rule_id="SEC008",
                            severity="Low",
                            description="Deprecated endpoint does not specify sunset or removal information",
                            location=f"paths.{path}.{method}",
                            recommendation="Add sunset or deprecation timeline information for deprecated endpoints"
                        )
                    )

    return findings
# SEC009: Wildcard or Unconstrained Server URL (High)
def check_sec009_wildcard_server_url(spec):
    findings = []

    if "openapi" not in spec:
        return findings

    servers = spec.get("servers", [])

    for idx, server in enumerate(servers):
        url = server.get("url", "")
        variables = server.get("variables")

        has_wildcard = "*" in url
        has_template = "{" in url and "}" in url

        # CASE 1: Template or wildcard exists but variables are missing
        if (has_wildcard or has_template) and not variables:
            findings.append(
                create_finding(
                    rule_id="SEC009",
                    severity="High",
                    description="Server URL contains wildcard or templated host without variable constraints",
                    location=f"servers[{idx}].url",
                    recommendation="Avoid wildcards or define server variables with enum constraints"
                )
            )
            continue

        # CASE 2: Variables exist but lack enum constraints
        if has_template and variables:
            for var_name, var_details in variables.items():
                if "enum" not in var_details:
                    findings.append(
                        create_finding(
                            rule_id="SEC009",
                            severity="High",
                            description="Server URL contains templated host without enum constraints",
                            location=f"servers[{idx}].variables.{var_name}",
                            recommendation="Constrain server variables using enum values"
                        )
                    )
                    break

    return findings
# SEC010: No Input Validation (Medium)
def check_sec010_no_input_validation(spec):
    findings = []

    paths = spec.get("paths", {})

    validation_keys = {
        "minLength", "maxLength",
        "minimum", "maximum",
        "pattern", "enum"
    }

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.startswith("x-"):
                continue

            # Check parameters
            parameters = details.get("parameters", [])
            for param in parameters:
                schema = param.get("schema", {})
                if schema and not validation_keys.intersection(schema.keys()):
                    findings.append(
                        create_finding(
                            rule_id="SEC010",
                            severity="Medium",
                            description="Input parameter lacks validation constraints",
                            location=f"paths.{path}.{method}.parameters.{param.get('name')}",
                            recommendation="Define input validation such as min/max, pattern, or enum"
                        )
                    )

            # Check request body (OpenAPI v3)
            request_body = details.get("requestBody", {})
            content = request_body.get("content", {})

            for media in content.values():
                schema = media.get("schema", {})
                if schema and not validation_keys.intersection(schema.keys()):
                    findings.append(
                        create_finding(
                            rule_id="SEC010",
                            severity="Medium",
                            description="Request body schema lacks validation constraints",
                            location=f"paths.{path}.{method}.requestBody",
                            recommendation="Add validation constraints to request body schema"
                        )
                    )

    return findings
