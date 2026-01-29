from app.rules.sec_rules import (
    check_sec001_no_global_security,
    check_sec002_unprotected_endpoints,
    check_sec003_http_allowed,
    check_sec004_no_rate_limit_headers,
    check_sec005_sensitive_query_params,
    check_sec006_missing_error_responses,
    check_sec007_missing_security_contact,
    check_sec008_deprecated_without_sunset,
    check_sec009_wildcard_server_url,
    check_sec010_no_input_validation
)





def run_security_checks(spec):
    findings = []

    findings.extend(check_sec001_no_global_security(spec))
    findings.extend(check_sec002_unprotected_endpoints(spec))
    findings.extend(check_sec003_http_allowed(spec))

    return findings
def calculate_security_score(findings):
    score = 100

    for finding in findings:
        severity = finding["severity"]

        if severity == "Critical":
            score -= 20
        elif severity == "High":
            score -= 10
        elif severity == "Medium":
            score -= 5
        elif severity == "Low":
            score -= 2

    return max(score, 0)
def run_security_checks(spec):
    findings = []

    findings.extend(check_sec001_no_global_security(spec))
    findings.extend(check_sec002_unprotected_endpoints(spec))
    findings.extend(check_sec003_http_allowed(spec))
    findings.extend(check_sec004_no_rate_limit_headers(spec))
    findings.extend(check_sec005_sensitive_query_params(spec))
    findings.extend(check_sec006_missing_error_responses(spec))
    findings.extend(check_sec007_missing_security_contact(spec))
    findings.extend(check_sec008_deprecated_without_sunset(spec))
    findings.extend(check_sec009_wildcard_server_url(spec))
    findings.extend(check_sec010_no_input_validation(spec))

    return findings






