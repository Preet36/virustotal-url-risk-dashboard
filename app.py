import os
import time
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st
import tldextract
from dotenv import load_dotenv

# ------------------------------------------------------
# Streamlit Page Configuration
# ------------------------------------------------------
st.set_page_config(
    page_title="Phishing Link Threat Analysis Dashboard",
    layout="wide",
)

# ------------------------------------------------------
# Configuration
# ------------------------------------------------------
load_dotenv()

DB_NAME = "scan_history.db"

env_api_key = os.getenv("VT_API_KEY")

st.sidebar.header("API Configuration")
user_api_key = st.sidebar.text_input(
    "Enter your VirusTotal API Key",
    type="password",
    help="Your key is only used during this session and is not saved."
)

VT_API_KEY = user_api_key if user_api_key else env_api_key

if not VT_API_KEY:
    st.error("Please enter your VirusTotal API key in the sidebar or add it to the .env file.")
    st.stop()

VT_HEADERS = {
    "x-apikey": VT_API_KEY
}

PHISHING_KEYWORDS = [
    "login", "verify", "account", "secure", "password", "mfa",
    "update", "bank", "invoice", "payment", "paypal", "apple",
    "microsoft", "office365", "security", "confirm", "signin",
    "wallet", "reset", "unlock", "support", "alert"
]

BRAND_KEYWORDS = [
    "microsoft", "office365", "paypal", "apple", "google", "amazon",
    "chase", "bankofamerica", "wellsfargo", "netflix", "facebook"
]

# ------------------------------------------------------
# Database Functions
# ------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            subdomain TEXT,
            path TEXT,
            scan_time TEXT,
            malicious INTEGER,
            suspicious INTEGER,
            harmless INTEGER,
            undetected INTEGER,
            timeout INTEGER,
            phishing_keywords TEXT,
            brand_indicators TEXT,
            suspicious_subdomain TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            recommendation TEXT,
            analyst_notes TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def save_scan(result):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans (
            url, domain, subdomain, path, scan_time, malicious, suspicious,
            harmless, undetected, timeout, phishing_keywords, brand_indicators,
            suspicious_subdomain, risk_score, risk_level, recommendation, analyst_notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result["url"],
            result["domain"],
            result["subdomain"],
            result["path"],
            result["scan_time"],
            result["malicious"],
            result["suspicious"],
            result["harmless"],
            result["undetected"],
            result["timeout"],
            ", ".join(result["keywords"]),
            ", ".join(result["brand_indicators"]),
            str(result["suspicious_subdomain"]),
            result["risk_score"],
            result["risk_level"],
            result["recommendation"],
            result["analyst_notes"]
        ),
    )

    conn.commit()
    conn.close()


def load_history():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM scans ORDER BY id DESC", conn)
    conn.close()
    return df


# ------------------------------------------------------
# URL Parsing and Risk Indicators
# ------------------------------------------------------
def normalize_url(url):
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def parse_url_details(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain if extracted.subdomain else "None"
    path = parsed.path if parsed.path else "/"

    return {
        "scheme": parsed.scheme,
        "domain": domain,
        "subdomain": subdomain,
        "path": path,
        "full_url": url,
    }


def detect_keywords(url):
    lower_url = url.lower()
    return [keyword for keyword in PHISHING_KEYWORDS if keyword in lower_url]


def detect_brand_impersonation(url):
    lower_url = url.lower()
    return [brand for brand in BRAND_KEYWORDS if brand in lower_url]


def calculate_risk_score(
    malicious,
    suspicious,
    undetected,
    timeout,
    keyword_count,
    brand_count,
    has_suspicious_subdomain
):
    score = 0

    score += malicious * 22
    score += suspicious * 12
    score += timeout * 2
    score += min(undetected, 20) * 1
    score += keyword_count * 5
    score += brand_count * 8

    if has_suspicious_subdomain:
        score += 8

    return min(score, 100)


def assign_risk_level(score):
    if score >= 80:
        return "Critical"
    elif score >= 55:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"


def create_recommendation(risk_level):
    if risk_level == "Critical":
        return "Escalate immediately, block the URL/domain, preserve evidence, and check for user clicks."
    elif risk_level == "High":
        return "Escalate for SOC review, consider blocking the domain, and search logs for related activity."
    elif risk_level == "Medium":
        return "Investigate further, validate the source, and monitor for related alerts."
    else:
        return "Document the result and close if no other suspicious evidence is present."


def generate_analyst_notes(result):
    keyword_text = ", ".join(result["keywords"]) if result["keywords"] else "none detected"
    brand_text = ", ".join(result["brand_indicators"]) if result["brand_indicators"] else "none detected"

    return (
        f"The URL {result['url']} was triaged as {result['risk_level']} risk with a score of "
        f"{result['risk_score']}/100. VirusTotal returned {result['malicious']} malicious, "
        f"{result['suspicious']} suspicious, {result['harmless']} harmless, and "
        f"{result['undetected']} undetected verdicts. The extracted domain is {result['domain']} "
        f"with subdomain {result['subdomain']} and path {result['path']}. Phishing keywords found: "
        f"{keyword_text}. Brand-related indicators found: {brand_text}. Recommended action: "
        f"{result['recommendation']}"
    )


# ------------------------------------------------------
# VirusTotal API Functions
# ------------------------------------------------------
def submit_url_to_virustotal(url):
    endpoint = "https://www.virustotal.com/api/v3/urls"

    response = requests.post(
        endpoint,
        headers=VT_HEADERS,
        data={"url": url},
        timeout=20
    )

    if response.status_code not in [200, 201]:
        raise RuntimeError(
            f"VirusTotal URL submission failed: {response.status_code} - {response.text}"
        )

    return response.json()["data"]["id"]


def get_analysis_results(analysis_id):
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for _ in range(12):
        response = requests.get(
            endpoint,
            headers=VT_HEADERS,
            timeout=20
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"VirusTotal analysis lookup failed: {response.status_code} - {response.text}"
            )

        data = response.json()
        status = data["data"]["attributes"].get("status")

        if status == "completed":
            return data

        time.sleep(3)

    raise TimeoutError("VirusTotal analysis did not finish in time. Try again in a few minutes.")


# ------------------------------------------------------
# Main Analysis Function
# ------------------------------------------------------
def analyze_url(url):
    url = normalize_url(url)
    parsed_details = parse_url_details(url)

    keywords = detect_keywords(url)
    brand_indicators = detect_brand_impersonation(url)

    has_suspicious_subdomain = (
        parsed_details["subdomain"] != "None"
        and any(
            word in parsed_details["subdomain"].lower()
            for word in ["login", "secure", "verify", "account", "update"]
        )
    )

    analysis_id = submit_url_to_virustotal(url)
    vt_data = get_analysis_results(analysis_id)

    stats = vt_data["data"]["attributes"].get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    risk_score = calculate_risk_score(
        malicious=malicious,
        suspicious=suspicious,
        undetected=undetected,
        timeout=timeout,
        keyword_count=len(keywords),
        brand_count=len(brand_indicators),
        has_suspicious_subdomain=has_suspicious_subdomain,
    )

    risk_level = assign_risk_level(risk_score)
    recommendation = create_recommendation(risk_level)

    result = {
        "url": url,
        "domain": parsed_details["domain"],
        "subdomain": parsed_details["subdomain"],
        "path": parsed_details["path"],
        "scheme": parsed_details["scheme"],
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "keywords": keywords,
        "brand_indicators": brand_indicators,
        "suspicious_subdomain": has_suspicious_subdomain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendation": recommendation,
    }

    result["analyst_notes"] = generate_analyst_notes(result)

    save_scan(result)

    return result


# ------------------------------------------------------
# Streamlit Dashboard
# ------------------------------------------------------
init_db()

st.title("Phishing Link Threat Analysis Dashboard")

st.write(
    "A SOC-style dashboard that uses VirusTotal threat intelligence, custom risk scoring, "
    "URL parsing, scan history, and exportable reports to support phishing alert triage."
)

with st.sidebar:
    st.header("Project Features")
    st.write("• Single URL investigation")
    st.write("• Bulk CSV scanning")
    st.write("• Custom risk scoring")
    st.write("• Phishing keyword detection")
    st.write("• SQLite scan history")
    st.write("• Exportable CSV reports")

tab1, tab2, tab3 = st.tabs([
    "Single URL Scan",
    "Bulk CSV Scan",
    "Scan History",
])


# ------------------------------------------------------
# Single Scan Tab
# ------------------------------------------------------
with tab1:
    st.subheader("Single URL Investigation")

    input_url = st.text_input("Enter a suspicious URL")

    if st.button("Analyze URL", type="primary"):
        if not input_url:
            st.warning("Enter a URL first.")
        else:
            with st.spinner("Submitting URL to VirusTotal and analyzing results..."):
                try:
                    result = analyze_url(input_url)

                    col1, col2, col3, col4 = st.columns(4)

                    col1.metric("Risk Score", f"{result['risk_score']}/100")
                    col2.metric("Risk Level", result["risk_level"])
                    col3.metric("Malicious", result["malicious"])
                    col4.metric("Suspicious", result["suspicious"])

                    st.subheader("URL Breakdown")

                    breakdown = pd.DataFrame(
                        [
                            ["Full URL", result["url"]],
                            ["Domain", result["domain"]],
                            ["Subdomain", result["subdomain"]],
                            ["Path", result["path"]],
                            ["Scheme", result["scheme"]],
                        ],
                        columns=["Field", "Value"]
                    )

                    st.dataframe(breakdown, use_container_width=True)

                    st.subheader("VirusTotal Verdict Counts")

                    verdict_df = pd.DataFrame(
                        {
                            "Category": [
                                "Malicious",
                                "Suspicious",
                                "Harmless",
                                "Undetected",
                                "Timeout"
                            ],
                            "Count": [
                                result["malicious"],
                                result["suspicious"],
                                result["harmless"],
                                result["undetected"],
                                result["timeout"],
                            ],
                        }
                    )

                    st.bar_chart(verdict_df.set_index("Category"))

                    st.subheader("Risk Indicators")

                    phishing_keywords = (
                        ", ".join(result["keywords"])
                        if result["keywords"]
                        else "None detected"
                    )

                    brand_indicators = (
                        ", ".join(result["brand_indicators"])
                        if result["brand_indicators"]
                        else "None detected"
                    )

                    st.write(f"**Phishing Keywords:** {phishing_keywords}")
                    st.write(f"**Brand Indicators:** {brand_indicators}")
                    st.write(f"**Suspicious Subdomain:** {result['suspicious_subdomain']}")

                    st.subheader("Recommended Action")
                    st.info(result["recommendation"])

                    st.subheader("Analyst Notes")
                    st.text_area(
                        "Copy-ready SOC notes",
                        result["analyst_notes"],
                        height=160
                    )

                    report_df = pd.DataFrame([result])

                    st.download_button(
                        "Download This Investigation as CSV",
                        report_df.to_csv(index=False).encode("utf-8"),
                        "single_url_investigation_report.csv",
                        "text/csv",
                    )

                except Exception as exc:
                    st.error(str(exc))


# ------------------------------------------------------
# Bulk CSV Tab
# ------------------------------------------------------
with tab2:
    st.subheader("Bulk URL Scan")

    st.write("Upload a CSV file with a column named `url`.")

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file:
        df = pd.read_csv(uploaded_file)

        st.write("Preview")
        st.dataframe(df.head(), use_container_width=True)

        if "url" not in df.columns:
            st.error("The CSV must contain a column named `url`.")
        elif st.button("Analyze CSV URLs", type="primary"):
            urls = df["url"].dropna().tolist()
            results = []

            progress = st.progress(0)

            for index, url in enumerate(urls):
                with st.spinner(f"Analyzing {url}..."):
                    try:
                        results.append(analyze_url(url))
                    except Exception as exc:
                        results.append(
                            {
                                "url": url,
                                "domain": "Error",
                                "subdomain": "Error",
                                "path": "Error",
                                "scheme": "Error",
                                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 0,
                                "undetected": 0,
                                "timeout": 0,
                                "keywords": [],
                                "brand_indicators": [],
                                "suspicious_subdomain": False,
                                "risk_score": 0,
                                "risk_level": "Error",
                                "recommendation": str(exc),
                                "analyst_notes": str(exc),
                            }
                        )

                progress.progress((index + 1) / len(urls))

            results_df = pd.DataFrame(results)

            st.subheader("Bulk Scan Results")
            st.dataframe(results_df, use_container_width=True)

            st.download_button(
                "Download Bulk Report as CSV",
                results_df.to_csv(index=False).encode("utf-8"),
                "bulk_url_triage_report.csv",
                "text/csv",
            )


# ------------------------------------------------------
# History Tab
# ------------------------------------------------------
with tab3:
    st.subheader("Previous Investigations")

    history_df = load_history()

    if history_df.empty:
        st.info("No previous scans found yet.")
    else:
        st.dataframe(history_df, use_container_width=True)

        st.download_button(
            "Download Full Scan History",
            history_df.to_csv(index=False).encode("utf-8"),
            "scan_history_export.csv",
            "text/csv",
        )
