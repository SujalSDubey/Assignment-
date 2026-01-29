from collections import defaultdict

def group_findings(findings):
    grouped = defaultdict(list)

    for f in findings:
        key = f["rule_id"]
        grouped[key].append(f)

    return [
        {
            "rule_id": rule_id,
            "severity": items[0]["severity"],
            "count": len(items),
            "locations": [i["location"] for i in items],
            "description": items[0]["description"],
            "recommendation": items[0]["recommendation"]
        }
        for rule_id, items in grouped.items()
    ]
