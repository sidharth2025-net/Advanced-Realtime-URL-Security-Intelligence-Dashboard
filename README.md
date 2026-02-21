# Advanced-Realtime-URL-Security-Intelligence-Dashboard

An advanced Python-based URL Security Analyzer that detects malicious patterns, evaluates threat levels, simulates visitor behavior, and generates an interactive realtime security intelligence dashboard using Plotly.

---

## 🚀 Project Overview

The **URL Security Analyzer** is designed to:

- Validate and inspect URLs
- Detect malicious patterns and threat signatures
- Perform SSL and HTTPS verification
- Extract IP address and RDAP (WHOIS) information
- Simulate visitor traffic behavior
- Identify suspicious and blocked requests
- Detect third-party tracking sources
- Generate an advanced interactive security dashboard
- Export detailed security reports

This project demonstrates cybersecurity analytics, threat modeling, and security visualization.

---

## 🛠️ Tech Stack

- Python 3.x
- Pandas
- Plotly
- Requests
- IPWhois
- tldextract
- validators
- SSL & Socket libraries

---

## 📌 Features

### 🔎 URL Analysis
- URL format validation
- Domain extraction
- HTTP/HTTPS detection
- Long URL & subdomain risk detection
- Null byte / CRLF injection detection

### 🔒 Security Checks
- SSL certificate verification
- HTTP status code validation
- Redirect chain analysis
- Threat signature detection (SQLi, XSS, command injection patterns)

### 🌍 Intelligence Enrichment
- IP resolution
- RDAP lookup
- Country detection
- Organization identification

### 📊 Visitor Behavior Simulation
- Simulated total visitors
- Active vs bounced visitors
- Suspicious requests
- Blocked requests
- Third-party activity detection

### 📈 Advanced Dashboard
- Threat score gauge
- Risk distribution donut chart
- Security radar overview
- Threat heatmap
- Traffic behavior comparison
- Security events summary

---

## 🧠 Threat Scoring Logic

Threat scores are calculated based on:

| Condition | Score Impact |
|------------|--------------|
| Invalid URL | +30 |
| Malicious pattern detected | +20 |
| Multiple redirects | +15 |
| Third-party suspicious source | +25 |
| HTTP (not HTTPS) | +15 |
| SSL verification failure | +20 |
| Null byte injection | +30 |
| Long URL / excessive subdomains | +10 |

### Strength Classification

- 0 → STRONG
- 1–20 → MODERATE
- 21–50 → WEAK
- 51+ → CRITICAL

---

## 📂 Project Structure

```
url_security_analyzer/
│
├── main.py
├── url_security_report.csv
├── README.md
└── requirements.txt
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/url-security-analyzer.git
cd url-security-analyzer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the script:

```bash
python main.py
```

The program will:

1. Analyze predefined URLs
2. Simulate visitor behavior
3. Generate an interactive dashboard
4. Export a CSV report

---

## 📊 Sample URLs Tested

- https://www.google.com
- https://github.com
- http://example.com
- https://httpbin.org/get
- http://malware-test.com/attack?cmd=shell&exec(rm -rf /)
- https://phishing-login-verify-account-update-now.com

---

## 📤 Exported Report

The analyzer generates:

```
url_security_report.csv
```

Includes:

- URL
- Domain
- IP Address
- Country
- Organization
- Threat Score
- Strength Classification
- Visitor Metrics
- Suspicious & Blocked Requests
- Third-party Detection
- Timestamp

---

## 📈 Dashboard Components

The advanced dashboard includes:

- 🎯 Average Threat Score Gauge
- 🥧 Risk Distribution Donut
- 🕸 Security Radar Chart
- 🔥 Threat Intelligence Heatmap
- 📊 Traffic Behavior Analysis
- 🚨 Security Events Summary

---

## 🔐 Security Use Cases

- Phishing detection
- Malware URL screening
- Security analytics demonstration
- Cybersecurity portfolio project
- Threat modeling visualization
- SOC-style dashboard prototype

---

## 🌟 Future Improvements

- Real-time monitoring mode
- Machine Learning threat prediction
- Geographic IP threat mapping
- Live API integration
- Streamlit Web App version
- Database logging support
- Email alert system

---

## 📄 License

This project is open-source and available under the MIT License.

---

## 👨‍💻 Author

Your Name  
Cybersecurity & Data Analytics Enthusiast  

---

## ⭐ If You Like This Project

Give it a star on GitHub and share it!
