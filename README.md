# Sigma-Lite: Automated Detection-as-Code & Alert Enrichment Pipeline

A lightweight, low-memory Python detection engine that evaluates offline Windows Event Logs (`.evtx` / `.xml`) or **live Windows Event Log channels** (`Security`, `System`, `Application`) against **Sigma-style YAML detection rules**, performs automated Tier-1 triage, and generates escalation-ready Markdown and JSON incident reports.

## Key Engineering Highlights
- **Streaming Log Ingestion (`<100 MB` RAM):** Processes Windows `.evtx` binary logs record-by-record via Python generators rather than loading entire log archives into memory.
- **Live Endpoint Triage (`--live`):** Leverages Windows' native `wevtutil` to snapshot and scan the last 24 hours of live `Security`, `System`, or `Application` logs on demand.
- **Vendor-Neutral Detection-as-Code:** Supports Sigma YAML syntax including `contains`, `startswith`, `endswith`, `re` modifiers, and `selection and not filter` false-positive suppression.
- **Automated Tier-1 Investigation:** Automatically decodes obfuscated UTF-16LE PowerShell payloads (`-enc`), extracts public IPv4/URL IOCs, queries AbuseIPDB with local SQLite caching (with graceful offline fallback), and maps hits to MITRE ATT&CK techniques.

## Detection Coverage (MITRE ATT&CK)
| Rule | Event ID | MITRE Tactic & Technique | Severity |
| :--- | :---: | :--- | :---: |
| `encoded_powershell.yml` | `4688` | Execution (`T1059.001`) | High |
| `lsass_credential_dump.yml` | `10` (Sysmon) | Credential Access (`T1003.001`) | Critical |
| `rdp_brute_force.yml` | `4625` | Credential Access (`T1110`) | Medium |
| `scheduled_task_persistence.yml` | `4698` | Persistence (`T1053.005`) | High |
| `audit_log_cleared.yml` | `1102` | Defense Evasion (`T1070.001`) | Critical |

## Quick Start
```bash
git clone [https://github.com/abh1sv/sigma-lite-engine.git](https://github.com/abh1sv/sigma-lite-engine.git)
cd sigma-lite-engine
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 1. Scan simulated multi-stage attack telemetry
python main.py -f samples/attack_simulation.xml -o reports/sample_incident_report.md

# 2. Scan live Windows System logs on the local machine
python main.py --live System -o reports/live_system_scan.md