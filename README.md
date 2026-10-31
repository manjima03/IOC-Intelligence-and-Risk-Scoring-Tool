# IOC Intelligence & Risk Scoring Tool

A lightweight Python/Streamlit project for initial triage of Indicators of Compromise (IOCs): IP addresses, domains, URLs, and file hashes.

The app validates and normalizes an IOC, optionally retrieves reputation data from VirusTotal and AbuseIPDB, calculates a transparent heuristic risk score, explains the score, saves analysis history locally, and supports CSV batch analysis/export.

## Features

- IOC validation and normalization
- Optional VirusTotal enrichment for IPs, domains, URLs, and hashes
- Optional AbuseIPDB enrichment for public IP addresses
- Explainable risk score from 0–100, severity, confidence, and contributing factors
- CSV batch analysis and export
- Local SQLite analysis history
- Unit tests for core IOC validation

## Important limitations

- The score is a **heuristic triage aid**, not a probability of compromise or a definitive malicious/benign verdict.
- No live evidence is available unless API keys are configured and the sources return usable data.
- A score of zero does not prove that an IOC is safe. New, rare, private, or unreported indicators may have little or no reputation data.
- Public threat-intelligence services may have rate limits, coverage gaps, and terms governing use. Do not submit confidential/internal indicators unless permitted by your organization and the service terms.
- API responses can be incomplete or stale. Confirm findings using context, logs, and additional evidence.
- The current implementation does not automatically block indicators or integrate with a SIEM.

## Setup

Use Python 3.10 or newer.

### 1. Create and activate a virtual environment

Windows PowerShell:
```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API keys (optional)

Create `.env` and add your API keys:
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Keep `.env` private. It is excluded by `.gitignore`. Never commit real API keys.

### 4. Run the app
```bash
streamlit run app.py
```

Open the local URL printed by Streamlit in your browser.

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Risk scoring logic

The initial heuristic combines selected source signals:
- VirusTotal malicious detections: up to 55 points
- VirusTotal suspicious detections: up to 20 points
- Negative VirusTotal community reputation: up to 10 points
- Threat-related categories: 10 points
- AbuseIPDB abuse-confidence score: scaled contribution up to 35 points
- Higher AbuseIPDB report volume: 5 points

The total is capped at 100. Severity bands are Low (1–34), Medium (35–69), and High (70–100). A score of zero is shown as “No positive signals,” not “Safe.”

These weights are starter values for an MVP, not scientifically validated weights. Document the rationale, test them against a labeled sample, and revise them based on evaluation. Confidence currently reflects the number of sources that returned usable data; it is not a statistical confidence interval.

## Suggested evaluation

Create a small, documented test set containing benign, known-malicious, and ambiguous indicators. Record source results and expected behavior. Review:
- Whether malicious indicators tend to rank above benign indicators
- False positives and conflicting source results
- Results when one or both APIs are unavailable
- Rate limiting and malformed input
- Whether the explanation matches the signals returned

Avoid claiming precision, recall, or accuracy unless you have a clearly labeled test set and calculate those metrics correctly.

## Project structure

```text
ioc-intelligence-risk-tool/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── src/
│   ├── validator.py
│   ├── enrichment.py
│   ├── risk_engine.py
│   ├── database.py
│   └── report.py
└── tests/
    └── test_validator.py
```

## Future improvements

- Add more sources with clear provenance and caching
- Add configurable weights and version the scoring model
- Track IOC first-seen/last-seen timestamps and source freshness
- Add unit tests for scoring and API failure handling
- Add a JSON report and analyst notes
- Integrate with Wazuh or Microsoft Sentinel after the core tool is evaluated

## Responsible use

Use only indicators you are authorized to investigate. Keep API keys out of source control. This project is for defensive analysis and educational use.
