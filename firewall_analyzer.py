import re
import os
import pandas as pd
import requests
from ipaddress import ip_address
from tqdm import tqdm
from geoip2.database import Reader
from dotenv import load_dotenv
import os
import matplotlib.pyplot as plt
import seaborn as sns

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")



class FirewallAnalyzer:

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.df = None
        self.geo_reader = Reader("geoip/GeoLite2-City.mmdb")

    #  Detect log format
    def detect_format(self, line: str):
        if line.count(",") > 3:
            return ","
        elif line.count("|") > 3:
            return "|"
        else:
            return None  # raw log format

    #  Parse log file
    def parse_log(self):
        with open(self.log_path, "r") as f:
            first_line = f.readline().strip()

        delimiter = self.detect_format(first_line)

        if delimiter:
            print(f"[+] Detected delimited format ({delimiter})")
            self.df = pd.read_csv(self.log_path, delimiter=delimiter, engine='python')
        else:
            print("[+] Detected raw log format using regex parser")
            self.df = self.regex_parse()

        # Normalize required columns
        required_cols = ['timestamp', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'action']

        for col in required_cols:
            if col not in self.df.columns:
                self.df[col] = None

        self.normalize_data()

    #  Regex parsing for raw firewall logs
    def regex_parse(self):
        rows = []
        pattern = re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})?.*src=(?P<src_ip>[\d\.]+).*dst=(?P<dest_ip>[\d\.]+).*'
            r'spt=(?P<src_port>\d+).*dpt=(?P<dest_port>\d+).*proto=(?P<protocol>[A-Za-z]+).*action=(?P<action>\w+)'
        )

        with open(self.log_path, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    rows.append(match.groupdict())

        return pd.DataFrame(rows)

    #  Normalize timestamp & IP types
    def normalize_data(self):
        print("[+] Normalizing timestamps and tagging IP types...")

        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors="coerce")

        self.df['src_type'] = self.df['src_ip'].apply(self.check_internal)
        self.df['dest_type'] = self.df['dest_ip'].apply(self.check_internal)

        self.df['src_geo'] = self.df['src_ip'].apply(self.geo_lookup)
        self.df['dest_geo'] = self.df['dest_ip'].apply(self.geo_lookup)

        print("[+] Checking threat intelligence (VirusTotal & AbuseIPDB)...")

        unique_ips = list(set(self.df['src_ip']).union(set(self.df['dest_ip'])))
        intel_results = {}

        for ip in tqdm(unique_ips, desc="Threat Lookup"):
            if self.check_internal(ip) == "External":  # Only check public IPs
                vt_result = self.virustotal_lookup(ip)
                abuse_result = self.abuseip_lookup(ip)
                intel_results[ip] = f"VT: {vt_result} | Abuse: {abuse_result}"
            else:
                intel_results[ip] = "Internal / Skipped"

        self.df["intel_report_src"] = self.df["src_ip"].apply(lambda ip: intel_results[ip])
        self.df["intel_report_dest"] = self.df["dest_ip"].apply(lambda ip: intel_results[ip])


    # Detect internal/private IPs
    def check_internal(self, ip):
        try:
            return "Internal" if ip_address(ip).is_private else "External"
        except:
            return "Unknown"

    # GeoIP lookup
    def geo_lookup(self, ip):
        try:
            res = self.geo_reader.city(ip)
            country = res.country.name or "Unknown"
            city = res.city.name or "Unknown"
            return f"{city}, {country}"
        except:
            return "Unknown"



    def virustotal_lookup(self, ip):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": VIRUSTOTAL_KEY}

            response = requests.get(url, headers=headers)
            data = response.json()

            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious_count = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]

            if malicious_count > 5:
                return f"Malicious ({malicious_count} reports)"
            elif malicious_count > 0 or suspicious_count > 0:
                return f"Suspicious ({malicious_count} malicious / {suspicious_count} suspicious)"
            else:
                return "Clean"

        except Exception:
            return "Lookup Failed"




    #  Security Detection Rules
    def detect_threats(self):
        print("[+] Running detection logic...")

        alerts = []

        # 1. Port Scanning
        scan_counts = self.df.groupby(["src_ip"])["dest_port"].nunique()
        scans = scan_counts[scan_counts > 10]

        for ip in scans.index:
            alerts.append(("Port Scan", ip, f"Attempted {scans[ip]} unique ports"))

        # 2. Suspicious Remote Access Attempts
        suspicious_ports = [22, 23, 3389, 445]
        critical_hits = self.df[self.df['dest_port'].astype(str).isin([str(p) for p in suspicious_ports])]

        for _, row in critical_hits.iterrows():
            alerts.append(("Critical Port Access", row['src_ip'], f"Targeted port {row['dest_port']}"))

        return pd.DataFrame(alerts, columns=["Alert Type", "Source IP", "Details"])



    def abuseip_lookup(self, ip):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            response = requests.get(url, headers=headers, params=params)
            data = response.json()

            score = data["data"]["abuseConfidenceScore"]

            if score >= 80:
                return f"Malicious (Score: {score})"
            elif score >= 30:
                return f"Suspicious (Score: {score})"
            else:
                return f"Clean (Score: {score})"

        except Exception:
            return "Lookup Failed"




    def export_results(self):
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)

        threat_summary = self.df[["src_ip", "dest_ip", "intel_report_src", "intel_report_dest"]].drop_duplicates()

        self.df.to_excel(f"{output_dir}/parsed_logs.xlsx", index=False)
        threat_summary.to_excel(f"{output_dir}/threat_intel_report.xlsx", index=False)

        alerts_df = self.detect_threats()
        alerts_df.to_excel(f"{output_dir}/alerts.xlsx", index=False)

        # NEW: Generate Visuals
        self.generate_visualizations()

        print("\n📌 Reports created successfully!")
        print("parsed_logs.xlsx")
        print("threat_intel_report.xlsx")
        print("alerts.xlsx")
        print("Visual charts saved inside /output/charts/")


    def generate_visualizations(self):
            print("[+] Generating visual analytics...")

            output_dir = "output"
            os.makedirs(f"{output_dir}/charts", exist_ok=True)

            # ------------------------------
            # 1. Top 10 Source IPs
            # ------------------------------
            top_src = self.df["src_ip"].value_counts().head(10)
            
            plt.figure(figsize=(10, 5))
            sns.barplot(x=top_src.values, y=top_src.index, palette="Reds_r")
            plt.title("Top 10 Source IPs (Most Traffic/Attempts)")
            plt.xlabel("Count")
            plt.ylabel("Source IP")
            plt.tight_layout()
            plt.savefig(f"{output_dir}/charts/top_source_ips.png")
            plt.close()

            # ------------------------------
            # 2. Top 10 Destination Ports
            # ------------------------------
            top_ports = self.df["dest_port"].value_counts().head(10)

            plt.figure(figsize=(10, 5))
            sns.barplot(x=top_ports.values, y=top_ports.index.astype(str), palette="Blues_r")
            plt.title("Top 10 Targeted Destination Ports")
            plt.xlabel("Count")
            plt.ylabel("Port")
            plt.tight_layout()
            plt.savefig(f"{output_dir}/charts/top_destination_ports.png")
            plt.close()

            # ------------------------------
            # 3. Protocol Distribution (Pie Chart)
            # ------------------------------
            protocol_counts = self.df["protocol"].value_counts()

            plt.figure(figsize=(7, 7))
            plt.pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%', shadow=True)
            plt.title("Protocol Distribution")
            plt.tight_layout()
            plt.savefig(f"{output_dir}/charts/protocol_distribution.png")
            plt.close()

            # ------------------------------
            # 4. Threat Severity Overview
            # ------------------------------
            if "intel_report_src" in self.df.columns:
                severity = self.df["intel_report_src"].value_counts().head(7)

                plt.figure(figsize=(10, 6))
                sns.barplot(x=severity.index, y=severity.values, palette="PuRd_r")
                plt.xticks(rotation=45, ha="right")
                plt.title("Threat Intelligence Severity Classification (Source IPs)")
                plt.tight_layout()
                plt.savefig(f"{output_dir}/charts/threat_severity_levels.png")
                plt.close()