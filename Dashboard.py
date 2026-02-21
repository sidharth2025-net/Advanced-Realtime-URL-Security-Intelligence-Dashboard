import requests
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import tldextract
import validators
import hashlib
import json
import re
import time
import socket
import ssl
import urllib.parse
from datetime import datetime
from collections import Counter, defaultdict
from ipwhois import IPWhois
import warnings
warnings.filterwarnings("ignore")

print("URL SECURITY ANALYZER READY")


class URLVisitorTracker:

    def __init__(self):
        self.visit_log = []
        self.url_stats = defaultdict(lambda: {
            "visited": 0, "entered": 0,
            "third_party": 0, "blocked": 0,
            "suspicious": 0
        })
        self.threat_signatures = [
            r"javascript:", r"<script", r"onerror=", r"onload=",
            r"eval\(", r"base64", r"union.*select", r"drop.*table",
            r"exec\(", r"cmd=", r"shell", r"passwd", r"etc/shadow",
            r"\.\.\/", r"redirect=http", r"phishing", r"login-verify",
            r"account-suspended", r"update-now", r"verify-identity"
        ]
        self.third_party_domains = [
            "ads.doubleclick.net", "tracking.example.com",
            "malware-host.ru", "phish-site.cn", "botnet.io",
            "click-fraud.net", "spy-tracker.com"
        ]

    def analyze_url(self, url, simulate_visitors=True):

        result = {
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "valid": False,
            "reachable": False,
            "status_code": None,
            "ssl_valid": False,
            "domain": "",
            "ip_address": "",
            "threat_score": 0,
            "threat_flags": [],
            "strength": "",
            "third_party_detected": False,
            "third_party_sources": [],
            "visitors_simulated": 0,
            "entered_count": 0,
            "bounced_count": 0,
            "suspicious_requests": 0,
            "blocked_requests": 0,
            "country": "Unknown",
            "org": "Unknown"
        }

        if not validators.url(url):
            result["threat_score"] += 30
            self._finalize_result(result)
            return result

        result["valid"] = True
        extracted = tldextract.extract(url)
        result["domain"] = f"{extracted.domain}.{extracted.suffix}"

        for sig in self.threat_signatures:
            if re.search(sig, url, re.IGNORECASE):
                result["threat_score"] += 20

        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, timeout=8, headers=headers, allow_redirects=True)
            result["reachable"] = True
            result["status_code"] = resp.status_code

            if len(resp.history) > 3:
                result["threat_score"] += 15

            page_text = resp.text
            for tp in self.third_party_domains:
                if tp in page_text:
                    result["third_party_detected"] = True
                    result["third_party_sources"].append(tp)
                    result["threat_score"] += 25

        except:
            result["threat_score"] += 20

        try:
            hostname = urllib.parse.urlparse(url).hostname
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                result["ssl_valid"] = True
        except:
            if url.startswith("https"):
                result["threat_score"] += 20

        try:
            hostname = urllib.parse.urlparse(url).hostname
            ip = socket.gethostbyname(hostname)
            result["ip_address"] = ip
            try:
                obj = IPWhois(ip)
                res = obj.lookup_rdap(depth=1)
                result["country"] = res.get("network", {}).get("country", "Unknown")
                result["org"] = res.get("network", {}).get("name", "Unknown")
            except:
                pass
        except:
            pass

        parsed = urllib.parse.urlparse(url)

        if len(url) > 100:
            result["threat_score"] += 10

        if url.count(".") > 5:
            result["threat_score"] += 10

        if parsed.scheme == "http":
            result["threat_score"] += 15

        if any(c in url for c in ["%00", "%0a", "%0d"]):
            result["threat_score"] += 30

        if simulate_visitors:
            self._simulate_visitors(url, result)

        self._finalize_result(result)
        self.visit_log.append(result)
        return result

    def _simulate_visitors(self, url, result):
        import random
        random.seed(hash(url) % 10000)

        total = random.randint(50, 500)
        entered = int(total * random.uniform(0.4, 0.8))
        bounced = total - entered
        suspicious = random.randint(2, int(total * 0.15))
        blocked = random.randint(1, suspicious)

        result["visitors_simulated"] = total
        result["entered_count"] = entered
        result["bounced_count"] = bounced
        result["suspicious_requests"] = suspicious
        result["blocked_requests"] = blocked

    def _finalize_result(self, result):
        score = result["threat_score"]
        if score == 0:
            result["strength"] = "STRONG"
        elif score <= 20:
            result["strength"] = "MODERATE"
        elif score <= 50:
            result["strength"] = "WEAK"
        else:
            result["strength"] = "CRITICAL"


def analyze_multiple_urls(urls):
    tracker = URLVisitorTracker()
    results = []
    for url in urls:
        r = tracker.analyze_url(url.strip())
        results.append(r)
        time.sleep(0.5)
    return tracker, results


def visualize_results(results):

    if not results:
        print("No results to visualize")
        return

    df = pd.DataFrame(results)
    labels = [r["url"][:40] + "..." if len(r["url"]) > 40 else r["url"] for r in results]
    avg_score = df["threat_score"].mean()
    risk_counts = Counter([r["strength"] for r in results])

    fig = make_subplots(
        rows=3, cols=2,
        specs=[
            [{"type": "indicator"}, {"type": "domain"}],
            [{"type": "polar"}, {"type": "heatmap"}],
            [{"type": "bar"}, {"type": "bar"}]
        ],
        subplot_titles=[
            "Average Threat Score",
            "Risk Distribution",
            "Security Radar Overview",
            "Threat Intelligence Heatmap",
            "Traffic Behavior Analysis",
            "Security Events Summary"
        ]
    )

    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=avg_score,
        gauge={"axis": {"range": [0, 100]}}
    ), row=1, col=1)

    fig.add_trace(go.Pie(
        labels=list(risk_counts.keys()),
        values=list(risk_counts.values()),
        hole=0.6
    ), row=1, col=2)

    radar_metrics = [
        df["threat_score"].mean(),
        df["suspicious_requests"].mean(),
        df["blocked_requests"].mean(),
        df["entered_count"].mean(),
        df["bounced_count"].mean()
    ]

    fig.add_trace(go.Scatterpolar(
        r=radar_metrics,
        theta=["Threat", "Suspicious", "Blocked", "Entered", "Bounced"],
        fill="toself"
    ), row=2, col=1)

    heat_data = df[
        ["threat_score", "suspicious_requests", "blocked_requests", "entered_count", "bounced_count"]
    ].values

    fig.add_trace(go.Heatmap(
        z=heat_data,
        x=["Threat", "Suspicious", "Blocked", "Entered", "Bounced"],
        y=labels
    ), row=2, col=2)

    fig.add_trace(go.Bar(x=labels, y=df["entered_count"], name="Entered"), row=3, col=1)
    fig.add_trace(go.Bar(x=labels, y=df["bounced_count"], name="Bounced"), row=3, col=1)
    fig.add_trace(go.Bar(x=labels, y=df["suspicious_requests"], name="Suspicious"), row=3, col=2)
    fig.add_trace(go.Bar(x=labels, y=df["blocked_requests"], name="Blocked"), row=3, col=2)

    fig.update_layout(
        height=1200,
        title="Advanced URL Realtime Security Intelligence Dashboard",
        template="plotly_dark",
        barmode="group"
    )

    fig.show()
    print("Advanced Dashboard Generated")


def main():

    urls = [
        "https://www.google.com",
        "https://github.com",
        "http://example.com",
        "https://httpbin.org/get",
        "http://malware-test.com/attack?cmd=shell&exec(rm -rf /)",
        "https://phishing-login-verify-account-update-now.com"
    ]

    tracker, results = analyze_multiple_urls(urls)
    visualize_results(results)
    return tracker, results


if __name__ == "__main__":
    tracker, results = main()
