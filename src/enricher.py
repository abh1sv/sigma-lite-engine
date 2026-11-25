import base64
import ipaddress
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests


BASE64_CMD_PATTERN = re.compile(
    r"(?:-e|-en|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


class AlertEnricher:
    """Performs automated Tier 1 triage: Base64 decoding, IOC extraction, and cached Threat Intel."""

    def __init__(self, cache_db_path: str = "ioc_cache.db", abuseipdb_key: Optional[str] = None):
        self.cache_db_path = cache_db_path
        self.abuseipdb_key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY")
        self._init_cache()

    def _init_cache(self) -> None:
        with sqlite3.connect(self.cache_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    verdict TEXT,
                    confidence_score INTEGER,
                    isp TEXT,
                    country TEXT,
                    checked_at TEXT
                )
                """
            )

    @staticmethod
    def decode_powershell_b64(command_line: str) -> Optional[str]:
        """Extracts and decodes UTF-16LE Base64 payloads from PowerShell command lines."""
        if not command_line:
            return None

        match = BASE64_CMD_PATTERN.search(command_line)
        if not match:
            return None

        b64_blob = match.group(1)
        # Pad Base64 string if length is not a multiple of 4
        padding = len(b64_blob) % 4
        if padding:
            b64_blob += "=" * (4 - padding)

        try:
            raw_bytes = base64.b64decode(b64_blob)
            decoded = raw_bytes.decode("utf-16le", errors="ignore").strip("\x00").strip()
            return decoded if decoded else None
        except Exception:
            return None

    @staticmethod
    def extract_iocs(text_corpus: str) -> Dict[str, List[str]]:
        """Extracts unique public IPv4 addresses and URLs from event fields and decoded payloads."""
        urls = sorted(set(URL_PATTERN.findall(text_corpus)))
        raw_ips = set(IPV4_PATTERN.findall(text_corpus))

        public_ips: List[str] = []
        for ip_str in sorted(raw_ips):
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_global:
                    public_ips.append(ip_str)
            except ValueError:
                continue

        return {"ips": public_ips, "urls": urls}

    def check_ip_reputation(self, ip_str: str) -> Dict[str, Any]:
        """Checks SQLite cache first, then queries AbuseIPDB if configured, or uses offline triage."""
        with sqlite3.connect(self.cache_db_path) as conn:
            row = conn.execute(
                "SELECT verdict, confidence_score, isp, country FROM ip_reputation WHERE ip = ?",
                (ip_str,),
            ).fetchone()
            if row:
                return {
                    "ip": ip_str,
                    "verdict": row[0],
                    "confidence_score": row[1],
                    "isp": row[2],
                    "country": row[3],
                    "source": "SQLite Cache",
                }

        result = {
            "ip": ip_str,
            "verdict": "Suspicious (Unverified External C2)",
            "confidence_score": 50,
            "isp": "Unknown (Offline Mode)",
            "country": "N/A",
            "source": "Offline Heuristic",
        }

        if self.abuseipdb_key:
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip_str, "maxAgeInDays": "90"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore", 0))
                    verdict = "Malicious" if score >= 50 else ("Suspicious" if score > 10 else "Clean")
                    result = {
                        "ip": ip_str,
                        "verdict": verdict,
                        "confidence_score": score,
                        "isp": data.get("isp", "Unknown"),
                        "country": data.get("countryCode", "N/A"),
                        "source": "AbuseIPDB API",
                    }
            except requests.RequestException:
                pass

        with sqlite3.connect(self.cache_db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ip_reputation (ip, verdict, confidence_score, isp, country, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result["ip"],
                    result["verdict"],
                    result["confidence_score"],
                    result["isp"],
                    result["country"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        return result

    @staticmethod
    def map_mitre_techniques(tags: List[str]) -> List[str]:
        """Extracts clean MITRE ATT&CK technique IDs (e.g., T1059.001) from Sigma rule tags."""
        techniques = []
        for tag in tags:
            if tag.lower().startswith("attack.t"):
                techniques.append(tag.split(".", 1)[1].upper())
        return techniques

    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches an alert dictionary in-place with decoded commands, IOCs, and MITRE mapping."""
        event = alert.get("event", {})
        cmd_line = event.get("CommandLine", "")

        decoded_cmd = self.decode_powershell_b64(cmd_line)

        # Combine raw event fields + decoded command to extract all hidden IOCs
        corpus_parts = [str(v) for v in event.values() if v]
        if decoded_cmd:
            corpus_parts.append(decoded_cmd)
        full_corpus = " ".join(corpus_parts)

        iocs = self.extract_iocs(full_corpus)
        ip_reports = [self.check_ip_reputation(ip) for ip in iocs["ips"]]

        alert["enrichment"] = {
            "decoded_command": decoded_cmd,
            "mitre_techniques": self.map_mitre_techniques(alert.get("tags", [])),
            "urls": iocs["urls"],
            "ip_reputation": ip_reports,
        }
        return alert