# [INCIDENT REPORT]

* **Ticket ID:** INC-2023-CAR
* **Incident Status:** Unresolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 1 (Critical)
* **Assigned SOC Analyst:** Z.Shamim (L1)

* **Analyst Comment:**
The network log analysis reveals a multi-stage intrusion initiated by a malicious zip archive containing an executable loader. Initial execution triggered C2 beaconing to an external IP (`208[.]91[.]111[.]114`) over HTTP/HTTPS, followed by cobalt strike / malware payload retrieval. The adversary performed network scanning, LDAP enumerations via Nmap/PowerView, and executed lateral movement using PSExec and WinRM against internal endpoints (`10[.]0[.]2[.]10`, `10[.]0[.]2[.]12`). High-priority containment and remediation required immediately.


# [TECHNICAL ANALYSIS]

* **Target / Affected Asset(s):** 
  - Hostnames: `WORKSTATION-01`, `DC01.corp.local`
  - IP Addresses: `10[.]0[.]2[.]15` (Compromised Host), `10[.]0[.]2[.]10`, `10[.]0[.]2[.]12`
  - User Accounts: `m.smith`, `administrator`


## Timeline of Events (UTC)

| Time (UTC) | Telemetry | Activity | TTP |
| :--- | :--- | :--- | :--- |
| `2021-09-24 16:45` | HTTP / PCAP | User downloaded `document.zip` from `185[.]106[.]92[.]21`. | T1566.001 (Spearphishing Attachment) |
| `2021-09-24 16:48` | Packet / TCP | Host `10[.]0[.]2[.]15` initiated outbound C2 traffic to `208[.]91[.]111[.]114` via Port 80/443. | T1071.001 (Web Protocols) |
| `2021-09-24 17:05` | DNS / HTTP | Host queried malicious domains `msofficeloader[.]com` and `officeupdate[.]net`. | T1071.004 (DNS Traffic) |
| `2021-09-24 17:12` | SMB / DCE-RPC | Internal port scanning and RPC enumeration detected originating from `10[.]0[.]2[.]15`. | T1046 (Network Service Discovery) |
| `2021-09-24 17:25` | WinRM / SMB | Attacker attempted remote execution and lateral movement to host `10[.]0[.]2[.]10` via PsExec (`ADMIN$`). | T1021.002 (SMB/Windows Admin Shares) |


## Indicators of Compromise (IOCs)

### Network Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- |
| `185[.]106[.]92[.]21` | IPv4 | Malware Payload Hosting Server |
| `208[.]91[.]111[.]114` | IPv4 | Command & Control (C2) Server |
| `msofficeloader[.]com` | Domain | Primary C2 Domain |
| `officeupdate[.]net` | Domain | Payload Staging / Callback Domain |

### System Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- |
| `document.zip` | Malicious Archive | Downloaded zip file containing initial loader |
| `invoice.exe` | Executable | Payload executed from user `Downloads` directory |
| `psexesvc.exe` | Binary | Dropped service binary for lateral movement |


**TL;DR:** Malicious Zip Download -> Payload Execution -> C2 Beaconing (`208[.]91[.]111[.]114`) -> Internal Reconnaissance -> Lateral Movement via SMB/PsExec.


### Process Tree / Execution Lineage
```text
[explorer.exe]
  └── [chrome.exe] -> Downloaded document.zip
        └── [winrar.exe] / [zip extraction]
              └── [invoice.exe] (PID: 4812)
                    ├── Network Connection -> 208[.]91[.]111[.]114:80 (C2 Traffic)
                    └── [cmd.exe] /c net group "Domain Admins" /domain
```

## Possible Remediation Steps

- Immediately isolate `10[.]0[.]2[.]15` from the network to prevent further lateral movement.
- Block external IP addresses (`185[.]106[.]92[.]21`, `208[.]91[.]111[.]114`) and domains on the perimeter firewall/web proxy.
- Revoke all compromised domain user sessions and reset credentials for affected accounts (m.smith).
- Deploy EDR full-system scan on target host `10[.]0[.]2[.]10` to inspect for dropped lateral movement tools or persistence.
