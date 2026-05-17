# Phishing Link Threat Analysis Dashboard

This project is a Python-based cybersecurity dashboard designed to simulate how a SOC analyst may triage suspicious URLs from phishing alerts. The tool uses the VirusTotal API to retrieve URL reputation data, calculates a custom phishing risk score, identifies suspicious URL patterns, stores investigation history, and generates analyst-style notes for escalation decisions.

## Why This Project Matters

Phishing links are one of the most common alerts that SOC teams investigate. This dashboard acts as a decision-support tool by helping an analyst quickly enrich a suspicious URL, review detection results, assign a risk level, and document the investigation.

## Features

- Single URL scanning
- Bulk CSV URL scanning
- VirusTotal API enrichment
- Custom phishing risk scoring
- Malicious, suspicious, harmless, undetected, and timeout verdict tracking
- URL parsing for domain, subdomain, scheme, and path
- Phishing keyword detection
- Brand impersonation indicators
- SOC-style analyst notes
- Recommended action logic
- SQLite scan history
- CSV report export

## Tools Used

- Python
- Streamlit
- VirusTotal API v3
- SQLite
- Pandas
- Requests
- python-dotenv
- tldextract

## Project Structure

```text
phishing-virustotal-url-risk-dashboard/
│
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── test_urls.csv
└── README.md
```

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Preet36/virustotal-url-risk-dashboard.git
cd virustotal-url-risk-dashboard

```

### 2. Create a virtual environment

```bash
python -m venv .venv

If that does not work use this command instead:
py -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

Activate it on Mac/Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Copy .env.example to .env
run these commands in order to change the API key to your own
```bash
copy .env.example .env
```
check if the .env is inside of your directory 
```bash
dir 
```
Then use this command to open the file and change the API key
```bash
code .env
```

```env
VT_API_KEY=your_virustotal_api_key_here
```
Make sure to save your file (Ctrl + S)

### 5. Run the dashboard

```bash
streamlit run app.py
```

## Example Workflow

1. A suspicious URL is reported from a phishing email.
2. The analyst submits the URL into the dashboard.
3. The dashboard sends the URL to VirusTotal for reputation analysis.
4. The tool parses the URL for domain, subdomain, and path indicators.
5. The scoring engine calculates a risk score using VirusTotal detections and phishing indicators.
6. The dashboard displays a risk level, detection counts, and recommended action.
7. The analyst copies the generated SOC notes or exports the report.

## Risk Scoring Logic

The custom risk score is calculated using:

- Malicious VirusTotal detections
- Suspicious VirusTotal detections
- Undetected and timeout verdicts
- Phishing-related keywords
- Brand impersonation indicators
- Suspicious subdomains

Risk levels:

```text
0-24    = Low
25-54   = Medium
55-79   = High
80-100  = Critical
```

## Example Analyst Note

```text
The URL https://paypal-account-verification-alert.com was triaged as High risk with a score of 72/100. VirusTotal returned malicious and suspicious detections. The extracted domain contains phishing-related keywords and possible brand impersonation. Recommended action: escalate for SOC review, consider blocking the domain, and search logs for related activity.
```


