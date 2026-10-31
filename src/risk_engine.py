from datetime import datetime, timezone

def calculate_risk(ioc, ioc_type, intelligence):
    """Transparent heuristic score; not a calibrated probability."""
    score = 0
    reasons = []
    evidence_sources = 0
    vt = intelligence.get("virustotal", {})
    abuse = intelligence.get("abuseipdb", {})

    if vt.get("available"):
        evidence_sources += 1
        malicious = int(vt.get("malicious", 0))
        suspicious = int(vt.get("suspicious", 0))
        if malicious:
            points = min(55, malicious * 8)
            score += points
            reasons.append(f"VirusTotal reported {malicious} malicious detection(s) (+{points}).")
        if suspicious:
            points = min(20, suspicious * 4)
            score += points
            reasons.append(f"VirusTotal reported {suspicious} suspicious detection(s) (+{points}).")
        rep = vt.get("reputation")
        if isinstance(rep, (int, float)) and rep < 0:
            points = min(10, max(0, abs(int(rep)) // 5))
            score += points
            if points:
                reasons.append(f"Negative VirusTotal community reputation contributed +{points}.")
        categories = vt.get("categories") or {}
        if isinstance(categories, dict):
            category_text = " ".join(str(v).lower() for v in categories.values())
            suspicious_terms = ("phishing", "malware", "malicious", "botnet", "command-and-control", "c2")
            if any(term in category_text for term in suspicious_terms):
                score += 10
                reasons.append("A threat-related category was present (+10).")

    if abuse.get("available"):
        evidence_sources += 1
        abuse_score = int(abuse.get("abuse_confidence_score", 0))
        if abuse_score:
            points = round(abuse_score * 0.35)
            score += points
            reasons.append(f"AbuseIPDB abuse-confidence score was {abuse_score}/100 (+{points}).")
        reports = int(abuse.get("total_reports", 0))
        if reports >= 10:
            score += 5
            reasons.append(f"AbuseIPDB showed {reports} reports (+5).")

    score = min(100, max(0, score))
    if score >= 70:
        severity = "High"
    elif score >= 35:
        severity = "Medium"
    elif score >= 1:
        severity = "Low"
    else:
        severity = "No positive signals"

    if evidence_sources >= 2:
        confidence = "Higher"
    elif evidence_sources == 1:
        confidence = "Moderate"
    else:
        confidence = "Low"

    if score >= 70:
        assessment = "Prioritize for investigation. Review the contributing evidence and validate it in context."
    elif score >= 35:
        assessment = "Investigate further. Some risk signals were returned, but context is still required."
    elif score > 0:
        assessment = "Limited risk signals were returned. Review the evidence before making a decision."
    else:
        assessment = "No positive risk signals were available from configured sources. This does not mean the IOC is safe."

    if not reasons:
        reasons.append("No positive risk signals were returned by the available sources.")
    if evidence_sources == 0:
        reasons.append("No live source returned usable evidence; this score is evidence-limited.")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": score,
        "severity": severity,
        "confidence": confidence,
        "assessment": assessment,
        "reasons": reasons,
        "intelligence": intelligence,
    }
