import pandas as pd
import streamlit as st
from src.validator import validate_and_normalize
from src.enrichment import enrich_ioc
from src.risk_engine import calculate_risk
from src.database import init_db, save_result, get_history
from src.report import result_to_csv

st.set_page_config(page_title="IOC Intelligence & Risk Scoring Tool", page_icon="🛡️", layout="wide")
init_db()

st.title("IOC Intelligence & Risk Scoring Tool")
st.caption("A small IOC triage aid for IP addresses, domains, URLs, and file hashes.")
st.warning(
    "This tool supports analyst triage; it does not prove that an indicator is safe or malicious. "
    "Do not submit confidential or internal indicators to third-party services unless you are authorized to do so."
)

with st.sidebar:
    st.header("Configuration")
    st.write("Add API keys to `.env` to enable live enrichment.")
    st.write("- VirusTotal: IPs, domains, URLs, file hashes")
    st.write("- AbuseIPDB: IP addresses")
    st.divider()
    st.write("Without keys, the app validates indicators and shows a limited-evidence assessment.")

tab_single, tab_batch, tab_history = st.tabs(["Single IOC", "Batch CSV", "History"])

with tab_single:
    ioc = st.text_input("Enter an IP, domain, URL, or file hash", placeholder="e.g. 8.8.8.8")
    if st.button("Analyse IOC", type="primary"):
        valid, normalized, ioc_type, message = validate_and_normalize(ioc)
        if not valid:
            st.error(message)
        else:
            with st.spinner("Checking available intelligence sources..."):
                intel = enrich_ioc(normalized, ioc_type)
                result = calculate_risk(normalized, ioc_type, intel)
                save_result(result)
            c1, c2, c3 = st.columns(3)
            c1.metric("Risk score", f"{result['risk_score']}/100")
            c2.metric("Severity", result["severity"])
            c3.metric("Confidence", result["confidence"])
            st.subheader("Assessment")
            st.write(result["assessment"])
            st.subheader("Why this score?")
            if result["reasons"]:
                for reason in result["reasons"]:
                    st.write(f"- {reason}")
            else:
                st.write("No positive risk signals were returned. This is not proof that the IOC is benign.")
            st.subheader("Intelligence details")
            st.json(result["intelligence"])
            st.download_button(
                "Download result as CSV",
                data=result_to_csv([result]),
                file_name="ioc_analysis.csv",
                mime="text/csv",
            )

with tab_batch:
    st.write("Upload a CSV containing a column named `ioc`, or choose the column below.")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded:
        try:
            df = pd.read_csv(uploaded)
            if df.empty:
                st.info("The CSV has no rows.")
            else:
                col = st.selectbox("IOC column", options=list(df.columns), index=(
                    list(df.columns).index("ioc") if "ioc" in df.columns else 0
                ))
                if st.button("Analyse batch"):
                    results = []
                    progress = st.progress(0)
                    for i, raw in enumerate(df[col].fillna("").astype(str).tolist()):
                        valid, normalized, ioc_type, message = validate_and_normalize(raw)
                        if valid:
                            intel = enrich_ioc(normalized, ioc_type)
                            result = calculate_risk(normalized, ioc_type, intel)
                            save_result(result)
                        else:
                            result = {
                                "timestamp": "", "ioc": raw, "ioc_type": "unknown",
                                "risk_score": 0, "severity": "Invalid", "confidence": "None",
                                "assessment": message, "reasons": [message], "intelligence": {}
                            }
                        results.append(result)
                        progress.progress((i + 1) / len(df))
                    st.dataframe(pd.DataFrame([{
                        "IOC": r["ioc"], "Type": r["ioc_type"], "Risk": r["risk_score"],
                        "Severity": r["severity"], "Confidence": r["confidence"],
                        "Assessment": r["assessment"]
                    } for r in results]), use_container_width=True)
                    st.download_button(
                        "Download batch results",
                        data=result_to_csv(results),
                        file_name="ioc_batch_results.csv",
                        mime="text/csv",
                    )
        except Exception as exc:
            st.error(f"Could not read this CSV: {exc}")

with tab_history:
    history = get_history()
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True)
        st.download_button(
            "Download history",
            data=pd.DataFrame(history).to_csv(index=False).encode("utf-8"),
            file_name="ioc_history.csv",
            mime="text/csv",
        )
    else:
        st.info("No analyses saved yet.")
