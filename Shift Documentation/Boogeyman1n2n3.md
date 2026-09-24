# [INCIDENT REPORT]

* **Ticket ID:** INC-2023-BGY

* **Incident Status:** Unresolved

* **Verdict:** True Positive

* **Incident Severity:** SEV 2 (Critical)

* **Assigned Soc Analyst:** Z.Shamim (L1)

* **Analyst Comment:**
Multiple system compromise originating from spearphishing emails containing weaponized ZIP attachments. Initial access led to payload delivery via Living Off the Land (mshta.exe, rundll32.exe, powershell.exe), persistence established via scheduled tasks, UAC bypass using fodhelper.exe, and local credential harvesting from a renamed database tool (sq3.exe) and Mimikatz. The attacker moved laterally using harvested domain admin credentials to target WKSTN-1327 and attempt DCSync actions on the primary Domain Controller.

# [TECHNICAL ANALYSIS]

* **Target / Affected Asset(s):** 
  - Hostnames: `WKSTN-JULIANNE` (Finance), `HR-SPECIALIST-01`, `WKSTN-1327` (Exec/Admin), `DC-01` (Domain Controller)
  - IP Addresses: `10.0.4.15` (Workstation Subnet), `10.0.1.10` (DC)
  - User Accounts: `julianne.wescott`, `evan.hutchinson` (CEO), `itadmin`, `administrator`


## Timeline of Events (UTC)

| Time (UTC) | Telemetry | Activity | TTP |
| :--- | :--- | :--- | :--- |
| `2023-01-13 10:25` | Email Gateway | Inbound phishing email from `agriffin@bpakcaging[.]xyz` with attachment `Invoice.zip` to `julianne.wescott`. | T1566.001 (Spearphishing Attachment) |
| `2023-01-13 10:28` | Sysmon (Event ID 1) | User executed `Invoice_20230103.lnk`, spawning hidden PowerShell download cradle pointing to `files.bpakcaging[.]xyz/update`. | T1059.001 (PowerShell Execution) |
| `2023-01-13 10:35` | Endpoint Logs / JSON | Execution of `Seatbelt` for system reconnaissance and `sq3.exe` (renamed SQLite/database tool) targeting stored credentials. | T1082 (Sys Discovery) / T1555 (Credentials) |
| `2023-01-13 10:45` | Network / DNS Logs | Exfiltration of sensitive data via Hex-encoded DNS queries pointing to `cdn.bpakcaging[.]xyz`. | T1071.004 (DNS Exfiltration) |
| `2023-08-29 14:10` | Email Gateway / ELK | Follow-up attack targeting CEO `evan.hutchinson` with weaponized attachment `ProjectFinancialSummary_Q3.pdf` / ISO payload. | T1566 (Phishing) |
| `2023-08-29 14:15` | Sysmon (Event ID 1) | Attachment opened; `mshta.exe` (PID: 6392) executed, calling `xcopy.exe` to drop `review.dat` to `%TEMP%`. | T1218.005 (Mshta) / T1105 (Ingress Tool Transfer) |
| `2023-08-29 14:18` | Windows Event 4698 | Scheduled task `Review` created to run `rundll32.exe D:\review.dat,DllRegisterServer` daily at 06:00 AM. | T1053.005 (Scheduled Task Persistence) |
| `2023-08-29 14:22` | Sysmon (Event ID 3) | `rundll32.exe` established C2 communication with external IP `165.232.170[.]151:80`. | T1071.001 (Application Layer Protocol - C2) |
| `2023-08-29 14:30` | Endpoint Telemetry | Privileged execution using `fodhelper.exe` for UAC bypass to obtain high-integrity context. | T1548.002 (Bypass User Account Control) |
| `2023-08-29 14:40` | Process Logs / ELK | Mimikatz payload pulled from GitHub (`github.com/gentilkiwi/mimikatz/...`) to dump LSASS credentials (`itadmin` NT hash extracted). | T1003.001 (LSASS Memory Dumping) |
| `2023-08-29 15:02` | ELK Multi-Host Telemetry | Attacker authenticated remotely to `WKSTN-1327` using dumped `itadmin` NTLM hash (`F84769D250EB95EB2D7D8B4A1C5613F2`). | T1550.002 (Pass-the-Hash) |
| `2023-08-29 15:15` | Sysmon (Event ID 1) | On `WKSTN-1327`, attacker launched secondary Mimikatz payload to steal Domain `administrator` hash (`00f80f2538dcb54e7adc715c0e7091ec`). | T1003 (Credential Dumping) |


## Indicators of Compromise (IOCs)

### Network Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- | :--- |
| `15.235.99[.]80` | IPv4 | Phishing Originating Mail MTA Server |
| `165.232.170[.]151` | IPv4 | Primary Command & Control (C2) Server (Port 80) |
| `agriffin@bpakcaging[.]xyz` | Email | Sender address (Typosquatted domain) |
| `files.bpakcaging[.]xyz` | Domain | Payload Staging / Hosting Domain |
| `cdn.bpakcaging[.]xyz` | Domain | DNS Tunneling Exfiltration Endpoint |

### System Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- |
| `Invoice_20230103.lnk` | Shortcut File | Contained base64 PowerShell download cradle |
| `ProjectFinancialSummary_Q3.pdf` | Malicious ISO / File | Initial Stager trigger for `mshta.exe` |
| `IT_Automation.ps1` | Script | Discovered script used by attacker for privilege enumeration |
| `spoolsv.exe` | Target Process | Process injected with DLL shellcode via `review.dat` |
| `review.dat` | Malicious DLL / Payload | Dropped in `%TEMP%`, executed via `rundll32.exe` |
| `sq3.exe` | Renamed Binary | Renamed SQLite tool used to query local browser/KeePass DBs |
| `F84769D250EB95EB2D7D8B4A1C5613F2` | NTLM Hash | Extracted hash for user account `itadmin` |
| `00f80f2538dcb54e7adc715c0e7091ec` | NTLM Hash | Extracted hash for Domain `administrator` |


### Process Tree / Execution Lineage
```text
[mshta.exe] (PID: 6392)
  └── [cmd.exe]
        ├── [xcopy.exe]
C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
        └── [powershell.exe] -> Created Scheduled Task 'Review'
              └── [rundll32.exe] "C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat",DllRegisterServer
                    ├── Network Connection -> 165.232.170[.]151:80 (Sysmon Event ID 3)
                    └── [fodhelper.exe] (UAC Bypass Execution)
```


**TL;DR:** Phishing -> Malicious ISO/LNK execution -> Process Injection & Persistence -> Credential Dumping (Mimikatz) -> Lateral Movement -> Domain Controller / DCSync Risk.


## Possible Remediation Steps

- Immediate containment and active response required
- Enable protected users security group in AD for all administrative accounts to prevent NTLM caching and memory dumping
- Security ruling to block execution of Lining Off the Land binaries
- Privilege isolation for IT administrative accounts across server and workstation management
- Employee training against phishing campaigns, specifically double extension files and typo-squatted domains 
