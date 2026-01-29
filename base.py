def create_finding(rule_id, severity, description, location, recommendation):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "description": description,
        "location": location,
        "recommendation": recommendation
    }
