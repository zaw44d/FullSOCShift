# [INCIDENT REPORT]

* **Ticket ID:** INC-2023-TEM
  
* **Incident Status:** Unresolved
  
* **Verdict:** True Positive
  
* **Incident Severity:** SEV 1 (Critical)

* **Assigned SOC Analyst:** Z.Shamim (L1)

* **Analyst Comment:**
The investigation into the Tempest room artifacts revealed an initial access vector via a malicious Word document (`free_magicules.doc`) exploiting the Follina vulnerability (CVE-2022-30190). The document executed a Base64-encoded PowerShell command via `msdt.exe` to drop a stage-2 persistence loader into the user's Startup folder. The second-stage binary established primary C2 beaconing to `resolvecyber[.]xyz:80`. The adversary conducted local credential discovery, created a reverse SOCKS proxy connection, and leveraged user privileges to run a privilege escalation binary. Upon obtaining `NT AUTHORITY\SYSTEM` context, the attacker created persistent user accounts and modified local administrative groups.


# [TECHNICAL ANALYSIS]

* **Target / Affected Asset(s):** 
  - Hostnames: `TEMPEST`
  - IP Addresses: `167[.]71[.]199[.]191` (Resolved Malicious Host)
  - User Accounts: `benimaru`


## Timeline of Events

| Telemetry | Activity | TTP |
| :--- | :--- | :--- |
| Sysmon / Event Logs | Compromised user downloaded `free_magicules.doc` via Chrome. | T1566.001 (Spearphishing Attachment) |
| Sysmon (Event ID 1) | Microsoft Word (PID `496`) spawned `msdt.exe` exploiting Follina (CVE-2022-30190). | T1203 (Exploitation for Client Execution) |
| Sysmon (Event ID 11) | Malicious execution wrote persistent payload into the `Startup` folder. | T1547.001 (Registry Run Keys / Startup Folder) |
| Sysmon / Network | Executed certutil payload downloaded stage-2 executable `first.exe`. | T1105 (Ingress Tool Transfer) |
| Network / PCAP | Stage-2 payload established primary HTTP C2 connection to `resolvecyber[.]xyz:80`. | T1071.001 (Web Protocols) |
| Endpoint Logs | Attacker deployed SOCKS proxy and executed privilege escalation binaries to elevate to `SYSTEM`. | T1090 (Proxy) / T1068 (Exploitation for Privilege Escalation) |
| Security Event ID 4720 | Attacker created local user accounts after gaining elevated privileges. | T1136.001 (Local Account Creation) |


## Indicators of Compromise (IOCs)

### Network Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- |
| `167[.]71[.]199[.]191` | IPv4 | Resolved IP address for malicious staging server |
| `phishteam[.]xyz` | Domain | Payload staging domain (`hxxp://phishteam[.]xyz/02dcf07/first.exe`) |
| `resolvecyber[.]xyz` | Domain | Primary Command & Control (C2) Domain (Port 80) |

### System Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- |
| `free_magicules.doc` | Malicious File | Initial Follina (`CVE-2022-30190`) exploit vector document |
| `CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6` | SHA256 | Hash of the `capture.pcapng` file |
| `665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F` | SHA256 | Hash of the `sysmon.evtx` log file |
| `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8` | SHA256 | Hash of the malicious stage-2 payload binary |
| `C:\Users\benimaru\AppData\Roaming\...\Startup` | File Path | Persistence target folder used by the payload |


### Process Tree / Execution Lineage
```text
[chrome.exe]
  └── [WINWORD.EXE] (PID: 496) -> Opened free_magicules.doc
        └── [msdt.exe] (CVE-2022-30190 Exploit)
              └── [powershell.exe] -> Encoded Base64 Execution
                    └── [certutil.exe] -> Downloaded first.exe
                          └── [first.exe] -> C2 Beaconing to resolvecyber[.]xyz:80
```


**TL;DR:** Malicious Doc (Follina CVE-2022-30190) -> PowerShell/Certutil Staging -> Startup Folder Persistence -> C2 Connection (`resolvecyber[.]xyz`) -> SOCKS Proxy -> Privilege Escalation -> Local Admin Account Creation.


## Potential Remediation Steps

- Block malicious domain indicators (`phishteam[.]xyz`, `resolvecyber[.]xyz`) and resolved IP (`167[.]71[.]199[.]191`) at the boundary perimeter.
- Remove unauthorised persistent binaries located inside `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- Immediately apply Microsoft patches covering `CVE-2022-30190`
- Purge unauthorised attacker accounts
