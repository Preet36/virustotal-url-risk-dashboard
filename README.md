# Phishing Link Threat Analysis Dashboard

This project is a Python-based cybersecurity dashboard designed to simulate how a SOC analyst may triage suspicious URLs from phishing alerts. The tool uses the VirusTotal API, redirect-chain analysis, URL parsing, custom phishing risk scoring, SQLite scan history, and exportable reports to support phishing investigation and escalation decisions.

## Why This Project Matters

Phishing links are one of the most common alerts that SOC teams investigate. In real investigations, analysts often need to determine not only whether a URL is malicious, but also where the link redirects, what final domain it reaches, whether it uses a URL shortener, and whether it contains suspicious phishing or brand impersonation indicators.

This dashboard acts as a decision-support tool by helping an analyst enrich a suspicious URL, inspect its final destination, review detection results, assign a risk level, and document the investigation with SOC-style analyst notes.

## Features

- Single URL investigation
- Bulk CSV URL scanning
- VirusTotal API enrichment
- Redirect-chain analysis
- Final URL and final domain inspection
- Cross-domain redirect detection
- URL shortener detection
- Custom phishing risk scoring
- Malicious, suspicious, harmless, undetected, and timeout verdict tracking
- URL parsing for domain, subdomain, scheme, and path
- Phishing keyword detection
- Brand impersonation indicators
- Suspicious subdomain detection
- SOC-style analyst notes
- Recommended action logic
- SQLite scan history
- CSV report export for single scans, bulk scans, and full scan history
- API key support through the Streamlit sidebar or a local `.env` file

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
├── Screenshots.md
├── .env.example
├── .gitignore
├── test_urls.csv
└── README.md
```

## Setup Instructions
### Pre Requisite
You need an API key from Virus Total

You can do this by going to the VirusTotal Website and Signing up on https://www.virustotal.com/gui/join-us

Check your email and activate your account 

After successfully signing in go into your profile and you should be able to access your API Key

### 1. Clone the repository

```bash
git clone https://github.com/Preet36/virustotal-url-risk-dashboard.git
cd virustotal-url-risk-dashboard

```

### 2. Create a virtual environment

```bash
python -m venv .venv

If that does not work use this instead:
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

### 4.Run the dashboard

```bash
streamlit run app.py
```

### 5.  Manually Add your VirusTotal API key to .env (only do this if the API key in the sidebar is not working)
Copy .env.example to .env
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

## Example Workflow
1. A suspicious URL is reported from a phishing email.
2. The analyst submits the URL into the dashboard.
3. The dashboard expands the URL and analyzes the redirect chain.
4. The tool identifies the final destination, final domain, redirect count, URL shortener usage, and cross-domain redirects.
5. The final URL is submitted to VirusTotal for reputation analysis.
6. The dashboard parses the URL for domain, subdomain, scheme, and path indicators.
7. The scoring engine calculates a risk score using VirusTotal detections, phishing indicators, suspicious subdomains, and redirect behavior.
8. The dashboard displays the risk score, risk level, detection counts, redirect-chain details, and recommended action.
9. The analyst copies the generated SOC notes or exports the report as a CSV file.

## Redirect Chain Analysis

The dashboard follows redirects before submitting the final destination to VirusTotal. This helps reveal where shortened links, tracking links, or suspicious URLs actually lead.

For each scanned URL, the dashboard displays:

- Original URL
- Final URL
- Final domain
- Redirect count
- Full redirect chain
- HTTP status code for each redirect hop
- Cross-domain redirect status
- URL shortener detection status

This makes the project more realistic for SOC-style phishing triage because analysts often need to investigate where a suspicious link redirects before deciding whether it should be blocked or escalated
## 
Bulk CSV Scanning

The dashboard supports bulk URL analysis through CSV upload.

The uploaded CSV file must contain a column named:
```bash
url
```
```bash
Example:

url
https://example.com
https://bit.ly/example
https://suspicious-login-example.com
```
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
The URL http://malware.wicar.org was triaged as Critical risk with a score of 100/100.
VirusTotal returned 16 malicious, 1 suspicious, 46 harmless, and 30 undetected verdicts.
The original URL was expanded through redirect analysis. The final destination is http://malware.wicar.org/ with final domain wicar.org.
Redirect count: 0. Cross-domain redirect detected: False. URL shortener detected: False.
The extracted final-domain details are domain wicar.org, subdomain malware, and path /.
Phishing keywords found: none detected. Brand-related indicators found: none detected.
Recommended action: Escalate immediately, block the URL/domain, preserve evidence, and check for user clicks.
```


