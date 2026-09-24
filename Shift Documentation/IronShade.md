# [INCIDENT REPORT]

* **Ticket ID:** INC-2023-IRN
* **Incident Status:** Unresolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 1 (Critical)
* **Assigned SOC Analyst:** Z.Shamim (L1)
* **Analyst Comment:**
The investigation into the IronShade room artifacts revealed an initial compromise stemming from a phishing campaign delivering a malicious password-protected archive. The user extracted and launched an executable that leveraged DLL search order hijacking to inject Cobalt Strike / RedLine Stealer payload into standard system processes. The malware executed local browser credential dumping, harvested cookies/tokens, established encrypted C2 traffic to `185.220.101[.]5`, and initiated network reconnaissance using native CLI tools (`net.exe`, `nltest.exe`). High-priority containment and credential reset required immediately.

# [TECHNICAL ANALYSIS]

* **Target / Affected Asset(s):**
* Hostnames: `IRONSHADE-WKSTN`
* IP Addresses: `10[.]0[.]2[.]15` (Compromised Host), `185[.]220[.]101[.]5` (Malicious C2)
* User Accounts: `a.smith`



## Timeline of Events (UTC)

| Time (UTC) | Telemetry | Activity | TTP |
| --- | --- | --- | --- |
| `Event Entry 1` | Mail / Browser Logs | User received phishing message and downloaded `Invoice_Details.zip`. | T1566.001 (Spearphishing Attachment) |
| `Event Entry 2` | Sysmon (Event ID 1) | User extracted and executed `Invoice.exe`, spawning hijacked DLL dependency (`version.dll`). | T1574.002 (DLL Side-Loading) |
| `Event Entry 3` | Endpoint Telemetry | Process accessed SQLite databases in Chrome/Edge profile directories to harvest stored passwords and session cookies. | T1555.003 (Credentials from Web Browsers) |
| `Event Entry 4` | Sysmon (Event ID 7) | Malware injected payload into legitimate process `svchost.exe` to blend with normal system activity. | T1055 (Process Injection) |
| `Event Entry 5` | Sysmon (Event ID 3) | Injected process initiated persistent TLS-encrypted C2 beaconing to `185[.]220[.]101[.]5:443`. | T1071.001 (Application Layer Protocol - C2) |
| `Event Entry 6` | Endpoint Logs | Attacker executed command-line discovery (`nltest /dclist:`, `net group "Domain Admins" /domain`). | T1087.002 (Domain Account Discovery) |

## Indicators of Compromise (IOCs)

### Network Indicators

| Indicator | Type | Details |
| --- | --- | --- |
| `185[.]220[.]101[.]5` | IPv4 | Command & Control (C2) Server (Port 443) |
| `update-service[.]ironshade-cdn[.]com` | Domain | Payload staging and callback domain |

### System Indicators

| Indicator | Type | Details |
| --- | --- | --- |
| `Invoice_Details.zip` | Archive | Compressed container delivering initial payload |
| `Invoice.exe` | Executable | Initial loader binary executed from `Downloads` folder |
| `version.dll` | Malicious DLL | Side-loaded DLL container executing second-stage payload |
| `7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B` | SHA256 | Hash of malicious payload executable |


### Process Tree / Execution Lineage

```text
[explorer.exe]
  └── [Invoice.exe] (PID: 3412)
        ├── [version.dll] (Side-Loaded DLL Payload)
        └── [svchost.exe] (Injected Process Context)
              ├── Network Connection -> 185.220.101[.]5:443
              └── [cmd.exe] /c net group "Domain Admins" /domain
```

**TL;DR:** Malicious Archive -> DLL Search Order Hijacking -> Injected Process C2 Beaconing -> Local Reconnaissance.


## Possible Remediation Steps

- Instantly disconnect `10[.]0[.][.]15` from the local network segment.
- Block foreign C2 IP address (`185[.]220[.]101[.]5`) and domain (`update-service[.]ironshade-cdn[.]com`) across core perimeter firewalls and proxies.
- Force corporate-wide session revocation and password resets for user `a.smith` across Active Directory and web services.
- Deploy EDR threat hunting queries for unauthorized DLL write actions within user-writable paths.
