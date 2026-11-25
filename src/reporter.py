import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List


REMEDIATION_PLAYBOOKS = {
    "T1059.001": [
        "Isolate the affected host from the network if unauthorized C2 traffic is confirmed.",
        "Block extracted external C2 IPs and payload URLs at the perimeter firewall and web proxy.",
        "Inspect parent process (e.g., WINWORD.EXE) and quarantine any originating phishing email or attachment.",
        "Enforce PowerShell Constrained Language Mode and Script Block Logging (Event ID 4104).",
    ],
    "T1003.001": [
        "Immediately isolate the endpoint to prevent lateral movement with harvested credentials.",
        "Force a password reset and Kerberos TGT reset for all users logged into the compromised host.",
        "Terminate and quarantine the offending source binary (`SourceImage`) and collect memory/disk artifacts.",
        "Verify Credential Guard / LSA Protection (`RunAsPPL`) is enabled on Windows endpoints.",
    ],
    "T1110": [
        "Block the offending source IP (`IpAddress`) at the perimeter firewall or VPN gateway.",
        "Verify if any failed attempts were followed by a successful logon (`EventID 4624`) from the same IP.",
        "Ensure Account Lockout Policies and Multi-Factor Authentication (MFA) are enforced on RDP/VPN endpoints.",
    ],
    "T1053.005": [
        "Disable and delete the malicious scheduled task (`schtasks /delete /tn <TaskName> /f`).",
        "Collect and hash (SHA-256) the referenced binary/script in AppData or Temp for malware analysis.",
        "Audit the creating user account (`SubjectUserName`) for signs of credential compromise.",
    ],
    "T1070.001": [
        "Treat immediately as high-priority post-exploitation defense evasion.",
        "Check centralized SIEM/syslog forwarding or Volume Shadow Copies to recover purged event history.",
        "Investigate recent privilege escalation (`EventID 4672`) or new service creations preceding the log wipe.",
    ],
}

DEFAULT_REMEDIATION = [
    "Validate whether the flagged activity corresponds to an approved change ticket.",
    "Preserve relevant Windows Event Logs and volatile memory before taking remediation actions.",
    "Escalate to Tier 2 Incident Response if unauthorized execution or persistence is confirmed.",
]


def deduplicate_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups identical alerts (same rule + host + command/source) and tracks occurrence count."""
    unique_map: Dict[str, Dict[str, Any]] = {}

    for alert in alerts:
        ev = alert.get("event", {})
        sig_key = f"{alert['rule_id']}|{ev.get('Computer')}|{ev.get('CommandLine', '')}|{ev.get('SourceImage', '')}"
        if sig_key not in unique_map:
            alert["occurrence_count"] = 1
            unique_map[sig_key] = alert
        else:
            unique_map[sig_key]["occurrence_count"] += 1

    return list(unique_map.values())


def generate_markdown_report(
    alerts: List[Dict[str, Any]],
    source_file: str,
    total_events_scanned: int,
    output_path: str,
    evidence_sha256: str = "N/A",
) -> str:
    """Compiles enriched alerts into an executive-ready Tier 1 SOC Markdown Incident Report."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    deduped = deduplicate_alerts(alerts)
    severity_counts = Counter(a["level"] for a in deduped)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        "# SOC Tier-1 Automated Triage & Incident Report",
        "",
        f"- **Generated At:** `{timestamp}`",
        f"- **Log Source:** `{source_file}`",
        f"- **Evidence SHA-256:** `{evidence_sha256}`",
        f"- **Total Events Scanned:** `{total_events_scanned}`",
        f"- **Unique Alerts Triggered:** `{len(deduped)}` (Raw hits: `{len(alerts)}`)",
        "",
        "## Severity Summary",
        "| Critical | High | Medium | Low |",
        "| :---: | :---: | :---: | :---: |",
        f"| {severity_counts.get('CRITICAL', 0)} | {severity_counts.get('HIGH', 0)} | {severity_counts.get('MEDIUM', 0)} | {severity_counts.get('LOW', 0)} |",
        "",
        "---",
        "",
    ]

    if not deduped:
        lines.append("> **Status:** No malicious activity matched active Sigma detection rules.")
    else:
        for idx, alert in enumerate(deduped, start=1):
            ev = alert["event"]
            enr = alert.get("enrichment", {})
            techniques = enr.get("mitre_techniques", [])
            mitre_str = ", ".join(techniques) if techniques else "N/A"

            lines.extend([
                f"## Alert #{idx}: [{alert['level']}] {alert['title']}",
                f"- **Rule ID:** `{alert['rule_id']}`",
                f"- **MITRE ATT&CK:** `{mitre_str}`",
                f"- **Affected Host:** `{ev.get('Computer', 'Unknown')}`",
                f"- **Event Timestamp:** `{ev.get('TimeCreated', 'Unknown')}`",
                f"- **Event ID:** `{ev.get('EventID')}` | **Occurrences:** `{alert.get('occurrence_count', 1)}`",
                f"- **Description:** {alert['description']}",
                "",
                "### Event Telemetry",
                "```json",
                json.dumps(ev, indent=2),
                "```",
                "",
            ])

            if enr.get("decoded_command"):
                lines.extend([
                    "### Automated Payload De-obfuscation (UTF-16LE Base64)",
                    "```powershell",
                    enr["decoded_command"],
                    "```",
                    "",
                ])

            if enr.get("urls") or enr.get("ip_reputation"):
                lines.append("### Extracted Indicators of Compromise (IOCs)")
                if enr.get("urls"):
                    for url in enr["urls"]:
                        lines.append(f"- **URL:** `{url}`")
                if enr.get("ip_reputation"):
                    lines.extend([
                        "",
                        "| IP Address | Verdict | Confidence | ISP | Country | Source |",
                        "| :--- | :--- | :---: | :--- | :---: | :--- |",
                    ])
                    for ip_info in enr["ip_reputation"]:
                        lines.append(
                            f"| `{ip_info['ip']}` | {ip_info['verdict']} | {ip_info['confidence_score']}% | "
                            f"{ip_info['isp']} | {ip_info['country']} | {ip_info['source']} |"
                        )
                lines.append("")

            playbook_steps: List[str] = []
            for tech in techniques:
                playbook_steps.extend(REMEDIATION_PLAYBOOKS.get(tech, []))
            if not playbook_steps:
                playbook_steps = DEFAULT_REMEDIATION

            lines.append("### Recommended Containment & Next Steps")
            for step in dict.fromkeys(playbook_steps):
                lines.append(f"- [ ] {step}")
            lines.extend(["", "---", ""])

    report_content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    return output_path

def generate_json_report(alerts: List[Dict[str, Any]], output_path: str) -> str:
    """Exports deduplicated alerts as machine-readable JSON for SOAR/SIEM pipelines."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    deduped = deduplicate_alerts(alerts)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)
    return output_path