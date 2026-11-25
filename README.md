# Sigma-Lite: Automated Detection-as-Code & Alert Enrichment Workbench

A lightweight, low-memory (<100 MB RAM) Python detection and triage engine that evaluates offline Windows Event Logs (`.evtx` / `.xml`) or **live Windows Event Log channels** (`Security`, `System`, `Application`) against **Sigma-style YAML detection rules**, enriches indicators with live AbuseIPDB threat intelligence, and generates forensic-grade Markdown and JSON incident reports.

## Key Engineering Highlights
- **Interactive Workbench & CLI Modes:** Run `python main.py` (or double-click `start.bat`) for a guided interactive menu with drag-and-drop log scanning, or pass CLI flags (`-f` / `--live`) for automated pipelines.
- **Streaming Log Ingestion (<100 MB RAM):** Processes binary `.evtx` logs record-by-record via Python generators rather than loading multi-gigabyte log archives into memory.
- **Live Endpoint Triage (`--live`):** Uses Windows' native `wevtutil` to snapshot and scan the last 24 hours of live `Security`, `System`, or `Application` channels on demand.
- **Vendor-Neutral Detection-as-Code:** Evaluates Sigma YAML rules supporting `contains`, `startswith`, `endswith`, `re` modifiers, and `selection and not filter` false-positive suppression.
- **Automated Tier-1 Investigation & Forensics:**
  - Computes cryptographic **SHA-256 hashes** of target evidence files before parsing for chain-of-custody integrity.
  - Decodes obfuscated **UTF-16LE Base64** PowerShell payloads (`-enc` / `-EncodedCommand`).
  - Extracts public IPv4/URL IOCs, queries the **AbuseIPDB v2 API** with local **SQLite caching** (with graceful offline fallback), and attaches **MITRE ATT&CK** containment playbooks.

## Detection Coverage (MITRE ATT&CK)
| Rule File | Event ID | MITRE Tactic & Technique | Severity |
| :--- | :---: | :--- | :---: |
| `encoded_powershell.yml` | `4688` | Execution (`T1059.001`) | High |
| `lsass_credential_dump.yml` | `10` (Sysmon) | Credential Access (`T1003.001`) | Critical |
| `rdp_brute_force.yml` | `4625` | Credential Access (`T1110`) | Medium |
| `scheduled_task_persistence.yml` | `4698` | Persistence (`T1053.005`) | High |
| `audit_log_cleared.yml` | `1102` | Defense Evasion (`T1070.001`) | Critical |

## Project Structure
```text
sigma-lite-engine/
├── rules/                  # Sigma-style YAML detection rules with false-positive filters
├── samples/                # Multi-stage attack simulation telemetry (attack_simulation.xml)
├── reports/                # Generated Markdown & JSON incident triage reports
├── src/
│   ├── parser.py           # Streaming .evtx & .xml log normalizer
│   ├── engine.py           # YAML rule loader & selection/filter evaluator
│   ├── enricher.py         # UTF-16LE Base64 decoder, IOC extractor & SQLite AbuseIPDB cache
│   └── reporter.py         # Deduplicated Markdown/JSON report & playbook builder
├── config.example.yaml     # Template configuration (copy to config.yaml to add API key)
├── main.py                 # Interactive workbench & CLI entry point
├── start.bat               # One-click Windows launcher
└── requirements.txt        # python-evtx, PyYAML, requests
```

## Quick Start
```bash
git clone [https://github.com/abh1sv/sigma-lite-engine.git](https://github.com/abh1sv/sigma-lite-engine.git)
cd sigma-lite-engine
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Optional: Enable live AbuseIPDB threat intelligence lookups
copy config.example.yaml config.yaml
# Paste your AbuseIPDB API key into config.yaml
```

## Usage
- **Interactive Menu (Recommended):**
  Run `python main.py` (or double-click `start.bat`) and select from scanning a `.evtx`/`.xml` file, scanning live Windows logs, or running the 5-rule attack simulation demo.
- **Command-Line Automation:**
  ```bash
  # Scan simulated multi-stage attack telemetry
  python main.py -f samples/attack_simulation.xml -o reports/sample_incident_report.md

  # Scan live Windows System logs (last 24h)
  python main.py --live System -o reports/live_system_scan.md
  ```

## Sample Output
See [`reports/sample_incident_report.md`](reports/sample_incident_report.md) for a complete generated incident report featuring SHA-256 evidence verification, de-obfuscated PowerShell payloads, live AbuseIPDB IP reputation tables, and remediation checklists.