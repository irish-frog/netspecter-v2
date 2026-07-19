def build_rule_based_findings(overview, ids_rows=None):
    findings = []
    recommendations = []

    internet_issues = int(overview.get("internet_issues") or 0)
    uploaded_mb = float(overview.get("uploaded_mb") or 0)

    score = 0
    reasons = []
    if uploaded_mb >= 10240:
        score += 10
        reasons.append("high upload volume")
        findings.append("Upload volume was high during the reporting period.")
        recommendations.append("Confirm whether the highest-uploading users or devices were performing expected business activity.")
    if internet_issues:
        score += min(10, internet_issues * 2)
        reasons.append(f"{internet_issues} internet-quality issue(s)")
        findings.append("Internet-quality degradation was recorded during the reporting period.")
        recommendations.append("Escalate recurring connectivity degradation to the internet service provider.")

    if score >= 20:
        rating = "Needs Review"
    elif score >= 10:
        rating = "Watch"
    else:
        rating = "Normal"

    if not findings:
        findings.append("No major usage or internet-quality concerns were detected in the selected period.")
        recommendations.append("Review the top users, applications, and destinations for client context.")

    return {
        "rating": rating,
        "score": score,
        "reasons": reasons or ["No weighted risk triggers exceeded their thresholds."],
        "findings": findings,
        "recommendations": list(dict.fromkeys(recommendations)),
    }
