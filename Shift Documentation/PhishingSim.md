# **INTRODUCTION TO PHISHING**

# [INCIDENT REPORT]

* **Ticket ID:** 001-THM-PHISH  
* **Incident Status:** Resolved  
* **Verdict:** True Positive  
* **Incident Severity:** SEV 2 (High)  
* **Assigned SOC Analyst:** Z.Shamim (L1)  
* **Analyst Comment:**  
The email purports to be an urgent account verification request from support, prompting the user to click an external link (`hxxp://login[.]paypal[.]account-verify-support[.]com`) to prevent account suspension. Domain analysis reveals the domain is spoofed and unassociated with the legitimate service. Header analysis indicates an SPF/DKIM mismatch from the sending mail server. Recommended endpoint isolation for users who clicked the link and forced password resets.


## Event 2: Executive Wire Transfer Request (BEC)

# [INCIDENT REPORT]
* **Ticket ID:** 002-THM-PHISH  
* **Incident Status:** Resolved  
* **Verdict:** True Positive  
* **Incident Severity:** SEV 1 (Critical)  
* **Assigned SOC Analyst:** Z.Shamim (L1)  
* **Analyst Comment:**  
A Business Email Compromise (BEC) attempt impersonating an executive requesting an urgent wire transfer to an off-shore vendor. The sender's email address utilizes a lookalike domain (typosquatting). No malicious links or attachments were present, relying purely on social engineering tactics. Escalated to the Finance and Security Awareness teams; confirmed no funds were transferred.


## Event 3: Internal IT Password Reset Notification

# [INCIDENT REPORT]
* **Ticket ID:** 003-THM-PHISH  
* **Incident Status:** Resolved  
* **Verdict:** False Positive  
* **Incident Severity:** SEV 4 (Low)  
* **Assigned SOC Analyst:** Z.Shamim (L1)  
* **Analyst Comment:**  
Automated password expiration email sent to an employee. Header analysis verifies the message originated from the internal Active Directory Domain Controller/Exchange server, passing SPF, DKIM, and DMARC checks. The embedded password reset link points directly to the legitimate internal self-service portal (`hxxps://ssp[.]internal[.]company[.]com`). Ticket closed as benign.


## Event 4: Invoice Attachment with Embedded Macro

# [INCIDENT REPORT]
* **Ticket ID:** 004-THM-PHISH  
* **Incident Status:** Resolved  
* **Verdict:** True Positive  
* **Incident Severity:** SEV 2 (High)  
* **Assigned SOC Analyst:** Z.Shamim (L1)  
* **Analyst Comment:**  
Inbound email containing a compressed attachment (`Invoice_Oct2023*.docm`). Static analysis and sandbox detonation confirmed the presence of malicious VBA macros designed to execute a PowerShell stager (`cmd.exe /c powershell -enc...`) upon opening. Attachment blocked at the email gateway; recipient endpoint verified clean via EDR logs.


## Event 5: Delivery Tracking Notification with Malicious Link

# [INCIDENT REPORT]
* **Ticket ID:** 005-THM-PHISH  
* **Incident Status:** Resolved  
* **Verdict:** True Positive  
* **Incident Severity:** SEV 3 (Medium)  
* **Assigned SOC Analyst:** Z.Shamim (L1)  
* **Analyst Comment:**  
Phishing attempt masquerading as a courier delivery notice regarding an undelivered package. The embedded link redirects to a credential harvesting landing page hosting a fake Microsoft 365 login portal. Secure Email Gateway rules updated to block the malicious IP and domain range; proxy logs show zero outbound clicks from internal users.


# **PHISHING UNFOLDING**

# [INCIDENT REPORT]
* **Ticket ID:** INC-THM-UNFOLD-001
* **Incident Status:** Resolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 2 (High)
* **Assigned SOC Analyst:** Z.Shamim (L1)
* **Analyst Comment:**
An inbound phishing email was delivered to `michael.ascot@tryhatme.com` (CEO) from `john@hatmakereurope.xyz` with subject "Important: Pending Invioce!". The email contained an attached archive `ImportantInvoice-Febrary.zip`. Extraction and static analysis using TryDetectThis revealed a hidden Windows shortcut file disguised as a document (`invioce.pdf.lnk`). The shortcut is engineered to launch PowerShell upon execution. Endpoint logs confirm the user extracted and executed the file.


## Phase 2: Execution & Command and Control (C2)

# [INCIDENT REPORT]
* **Ticket ID:** INC-THM-UNFOLD-002
* **Incident Status:** Resolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 1 (Critical)
* **Assigned SOC Analyst:** Z.Shamim (L1)
* **Analyst Comment:**
Execution of `invioce.pdf.lnk` on host `WIN-3450` spawned a hidden `powershell.exe` process that downloaded Powercat (`powercat.ps1`) from `raw.githubusercontent.com`. Powercat established an outbound reverse shell connection to an attacker-controlled listener over `2.tcp.ngrok.io:19282`. Endpoint has been isolated from the network, and the process tree was terminated via EDR.


## Phase 3: Discovery & Internal Reconnaissance

# [INCIDENT REPORT]
* **Ticket ID:** INC-THM-UNFOLD-003
* **Incident Status:** Resolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 2 (High)
* **Assigned SOC Analyst:** Z.Shamim (L1)
* **Analyst Comment:**
Following the reverse shell connection, the adversary dropped `PowerView.ps1` into `C:\Users\michael.ascot\Downloads`. Active Directory enumeration commands were executed using PowerShell Script Block Logging indicators to discover high-value network shares, domain accounts, and domain controller structures. Threat actor identified target share `\\FILESRV-01\SSF-FinancialRecords`.


## Phase 4: Collection, Staging & Anti-Forensics

# [INCIDENT REPORT]
* **Ticket ID:** INC-THM-UNFOLD-004
* **Incident Status:** Resolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 1 (Critical)
* **Assigned SOC Analyst:** Z.Shamim (L1)
* **Analyst Comment:**
Adversary mapped domain share `\\FILESRV-01\SSF-FinancialRecords` as network drive `Z:`. Using `robocopy.exe`, sensitive documents (`InvestorPresentation2023.pptx` and `ClientPortfolioSummary.xlsx`) were copied to local staging directory `C:\Users\Public\exfilt8me.zip`. The network drive was unmapped (`net use Z: /delete`) to cover tracks. Affected accounts have been locked and credential resets initiated.


## Phase 5: Exfiltration via DNS Tunneling

# [INCIDENT REPORT]
* **Ticket ID:** INC-THM-UNFOLD-005
* **Incident Status:** Resolved
* **Verdict:** True Positive
* **Incident Severity:** SEV 1 (Critical)
* **Assigned SOC Analyst:** Z.Shamim (L1)
* **Analyst Comment:**
The adversary encoded the staged archive `exfilt8me.zip` into Base64 subdomains and executed exfiltration using DNS queries directed to domain `haz4rdw4re.io`. DNS logs show a high volume of anomalous TXT/A record requests consistent with DNS tunneling. Blocked `haz4rdw4re.io` at the perimeter firewalls and updated SOC detection rules for anomalous DNS payload sizes. Escalated to L2/IR for full scope assessment.
