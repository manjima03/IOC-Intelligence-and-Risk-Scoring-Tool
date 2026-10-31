import json
import pandas as pd

def result_to_csv(results):
    rows = []
    for r in results:
        intel = r.get("intelligence", {})
        rows.append({
            "timestamp": r.get("timestamp", ""),
            "ioc": r.get("ioc", ""),
            "ioc_type": r.get("ioc_type", ""),
            "risk_score": r.get("risk_score", 0),
            "severity": r.get("severity", ""),
            "confidence": r.get("confidence", ""),
            "assessment": r.get("assessment", ""),
            "reasons": " | ".join(r.get("reasons", [])),
            "intelligence_json": json.dumps(intel, ensure_ascii=False),
        })
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")
