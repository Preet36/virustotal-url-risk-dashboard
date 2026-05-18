import os
import time
import sqlite3
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st
import tldextract
from dotenv import load_dotenv
from requests.exceptions import TooManyRedirects

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

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rebrand.ly", "cutt.ly", "is.gd", "buff.ly", "shorturl.at"
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
            analyst_notes TEXT,
            final_url TEXT,
            final_domain TEXT,
            redirect_count INTEGER,
            redirect_chain TEXT,
            cross_domain_redirect TEXT,
            url_shortener_detected TEXT
        )
        """
    )

    new_columns = {
        "final_url": "TEXT",
        "final_domain": "TEXT",
        "redirect_count": "INTEGER",
        "redirect_chain": "TEXT",
        "cross_domain_redirect": "TEXT",
        "url_shortener_detected": "TEXT"
    }

    cursor.execute("PRAGMA table_info(scans)")
    existing_columns = [column[1] for column in cursor.fetchall()]

    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {column_name} {column_type}")

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
            suspicious_subdomain, risk_score, risk_level, recommendation, analyst_notes,
            final_url, final_domain, redirect_count, redirect_chain,
            cross_domain_redirect, url_shortener_detected
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            result["analyst_notes"],
            result["final_url"],
            result["final_domain"],
            result["redirect_count"],
            result["redirect_chain_text"],
            str(result["cross_domain_redirect"]),
            str(result["url_shortener_detected"])
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


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_local_or_private_host(hostname):
    if not hostname:
        return True

    hostname = hostname.lower()

    if hostname in ["localhost", "127.0.0.1", "0.0.0.0"]:
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def is_url_shortener(domain):
    return domain.lower() in URL_SHORTENERS


def analyze_redirect_chain(url, max_redirects=6):
    """
    Follows redirects and returns each hop in the redirect chain.
    This helps identify shortened URLs, tracking redirects, and suspicious final destinations.
    """

    session = requests.Session()
    session.max_redirects = max_redirects

    headers = {
        "User-Agent": "Mozilla/5.0 SOC-URL-Triage-Scanner"
    }

    try:
        parsed_start = urlparse(url)
        hostname = parsed_start.hostname

        if is_local_or_private_host(hostname):
            return {
                "redirect_chain": [
                    {
                        "url": url,
                        "status_code": "Blocked",
                        "domain": hostname or "Unknown",
                        "subdomain": "Unknown",
                        "path": "Unknown",
                        "reason": "Local or private host blocked for safety"
                    }
                ],
                "final_url": url,
                "final_domain": hostname or "Unknown",
                "redirect_count": 0,
                "cross_domain_redirect": False,
                "url_shortener_detected": False,
                "redirect_error": "Local or private host blocked for safety"
            }

        response = session.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers=headers,
            stream=True
        )

        chain = []

        all_responses = response.history + [response]

        for item in all_responses:
            parsed_item = parse_url_details(item.url)

            chain.append(
                {
                    "url": item.url,
                    "status_code": item.status_code,
                    "domain": parsed_item["domain"],
                    "subdomain": parsed_item["subdomain"],
                    "path": parsed_item["path"]
                }
            )

        response.close()

        original_domain = chain[0]["domain"] if chain else parse_url_details(url)["domain"]
        final_url = chain[-1]["url"] if chain else url
        final_domain = chain[-1]["domain"] if chain else original_domain

        domains_seen = list({hop["domain"] for hop in chain})
        cross_domain_redirect = len(domains_seen) > 1

        url_shortener_detected = any(
            is_url_shortener(hop["domain"])
            for hop in chain
        )

        return {
            "redirect_chain": chain,
            "final_url": final_url,
            "final_domain": final_domain,
            "redirect_count": max(len(chain) - 1, 0),
            "cross_domain_redirect": cross_domain_redirect,
            "url_shortener_detected": url_shortener_detected,
            "redirect_error": None
        }

    except TooManyRedirects:
        parsed_fallback = parse_url_details(url)

        return {
            "redirect_chain": [
                {
                    "url": url,
                    "status_code": "Error",
                    "domain": parsed_fallback["domain"],
                    "subdomain": parsed_fallback["subdomain"],
                    "path": parsed_fallback["path"],
                    "reason": "Too many redirects"
                }
            ],
            "final_url": url,
            "final_domain": parsed_fallback["domain"],
            "redirect_count": max_redirects,
            "cross_domain_redirect": False,
            "url_shortener_detected": is_url_shortener(parsed_fallback["domain"]),
            "redirect_error": "Too many redirects"
        }

    except requests.exceptions.RequestException as error:
        parsed_fallback = parse_url_details(url)

        return {
            "redirect_chain": [
                {
                    "url": url,
                    "status_code": "Error",
                    "domain": parsed_fallback["domain"],
                    "subdomain": parsed_fallback["subdomain"],
                    "path": parsed_fallback["path"],
                    "reason": str(error)
                }
            ],
            "final_url": url,
            "final_domain": parsed_fallback["domain"],
            "redirect_count": 0,
            "cross_domain_redirect": False,
            "url_shortener_detected": is_url_shortener(parsed_fallback["domain"]),
            "redirect_error": str(error)
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
    has_suspicious_subdomain,
    redirect_count=0,
    cross_domain_redirect=False,
    url_shortener_detected=False
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

    if redirect_count >= 2:
        score += 8

    if redirect_count >= 4:
        score += 7

    if cross_domain_redirect:
        score += 8

    if url_shortener_detected:
        score += 10

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
        f"{result['undetected']} undetected verdicts. The original URL was expanded through redirect analysis. "
        f"The final destination is {result['final_url']} with final domain {result['final_domain']}. "
        f"Redirect count: {result['redirect_count']}. Cross-domain redirect detected: "
        f"{result['cross_domain_redirect']}. URL shortener detected: {result['url_shortener_detected']}. "
        f"The extracted final-domain details are domain {result['domain']}, subdomain {result['subdomain']}, "
        f"and path {result['path']}. Phishing keywords found: {keyword_text}. "
        f"Brand-related indicators found: {brand_text}. Recommended action: {result['recommendation']}"
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

    redirect_analysis = analyze_redirect_chain(url)
    final_url = redirect_analysis["final_url"]

    parsed_details = parse_url_details(final_url)

    combined_url_for_detection = f"{url} {final_url}"

    keywords = detect_keywords(combined_url_for_detection)
    brand_indicators = detect_brand_impersonation(combined_url_for_detection)

    has_suspicious_subdomain = (
        parsed_details["subdomain"] != "None"
        and any(
            word in parsed_details["subdomain"].lower()
            for word in ["login", "secure", "verify", "account", "update"]
        )
    )

    analysis_id = submit_url_to_virustotal(final_url)
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
        redirect_count=redirect_analysis["redirect_count"],
        cross_domain_redirect=redirect_analysis["cross_domain_redirect"],
        url_shortener_detected=redirect_analysis["url_shortener_detected"],
    )

    risk_level = assign_risk_level(risk_score)
    recommendation = create_recommendation(risk_level)

    redirect_chain_text = " -> ".join(
        [
            f"{hop.get('url')} [{hop.get('status_code')}]"
            for hop in redirect_analysis["redirect_chain"]
        ]
    )

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
        "final_url": final_url,
        "final_domain": redirect_analysis["final_domain"],
        "redirect_count": redirect_analysis["redirect_count"],
        "redirect_chain": redirect_analysis["redirect_chain"],
        "redirect_chain_text": redirect_chain_text,
        "cross_domain_redirect": redirect_analysis["cross_domain_redirect"],
        "url_shortener_detected": redirect_analysis["url_shortener_detected"],
        "redirect_error": redirect_analysis["redirect_error"],
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
    "A SOC-style dashboard that uses VirusTotal threat intelligence, redirect-chain analysis, "
    "custom risk scoring, URL parsing, scan history, and exportable reports to support phishing alert triage."
)

with st.sidebar:
    st.header("Project Features")
    st.write("• Single URL investigation")
    st.write("• Bulk CSV scanning")
    st.write("• Custom risk scoring")
    st.write("• Phishing keyword detection")
    st.write("• Redirect chain analysis")
    st.write("• Final destination inspection")
    st.write("• URL shortener detection")
    st.write("• Cross-domain redirect detection")
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
            with st.spinner("Expanding redirects, submitting URL to VirusTotal, and analyzing results..."):
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
                            ["Original URL", result["url"]],
                            ["Final URL", result["final_url"]],
                            ["Final Domain", result["final_domain"]],
                            ["Domain", result["domain"]],
                            ["Subdomain", result["subdomain"]],
                            ["Path", result["path"]],
                            ["Scheme", result["scheme"]],
                        ],
                        columns=["Field", "Value"]
                    )

                    st.dataframe(breakdown, use_container_width=True)

                    st.subheader("Redirect Chain Analysis")

                    redirect_df = pd.DataFrame(result["redirect_chain"])
                    st.dataframe(redirect_df, use_container_width=True)

                    col5, col6, col7, col8 = st.columns(4)

                    col5.metric("Redirect Count", result["redirect_count"])
                    col6.metric("Final Domain", result["final_domain"])
                    col7.metric("Cross-Domain Redirect", str(result["cross_domain_redirect"]))
                    col8.metric("URL Shortener", str(result["url_shortener_detected"]))

                    if result["redirect_error"]:
                        st.warning(f"Redirect analysis warning: {result['redirect_error']}")

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
                    st.write(f"**Cross-Domain Redirect:** {result['cross_domain_redirect']}")
                    st.write(f"**URL Shortener Detected:** {result['url_shortener_detected']}")

                    st.subheader("Recommended Action")
                    st.info(result["recommendation"])

                    st.subheader("Analyst Notes")
                    st.text_area(
                        "Copy-ready SOC notes",
                        result["analyst_notes"],
                        height=180
                    )

                    report_df = pd.DataFrame([result])
                    report_df = report_df.drop(columns=["redirect_chain"], errors="ignore")

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
                                "final_url": url,
                                "final_domain": "Error",
                                "redirect_count": 0,
                                "redirect_chain": [],
                                "redirect_chain_text": "Error",
                                "cross_domain_redirect": False,
                                "url_shortener_detected": False,
                                "redirect_error": str(exc),
                            }
                        )

                progress.progress((index + 1) / len(urls))

            results_df = pd.DataFrame(results)
            results_df = results_df.drop(columns=["redirect_chain"], errors="ignore")

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
