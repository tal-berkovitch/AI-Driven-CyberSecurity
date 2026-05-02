# Lab 1 - Cyber Threat Intelligence Report Mapping to MITRE ATT&CK

## Group members
* Tal Berkovitch

## Source CTI Report
* **Link:** [Cutting Edge: Suspected APT Targets Ivanti Connect Secure](https://cloud.google.com/blog/topics/threat-intelligence/suspected-apt-targets-ivanti-zero-day)
* **Publisher:** Google Cloud Threat Intelligence (Mandiant)

## Attack Summary
This report details a high-impact exploitation campaign targeting **Ivanti Connect Secure (ICS)** VPN appliances. A suspected espionage group (tracked as UNC5221) utilized two zero-day vulnerabilities - an authentication bypass (**CVE-2023-46805**) and a command injection (**CVE-2024-21887**) - to gain initial access.

Once inside, the attackers deployed custom web shells (such as `GLASSTOKEN`) to maintain persistence and used specialized tools to harvest credentials from the appliance's memory. The operation heavily utilized "living-off-the-land" techniques, meaning the attackers modified legitimate internal system scripts to evade the VPN's built-in integrity checks and hide their tracks.

## Attack Diagram

![The Unified Kill Chain Flow](https://upload.wikimedia.org/wikipedia/commons/c/c2/The_Unified_Kill_Chain.png)

*(A conceptual flow representing the stages of the APT attack, from initial zero-day exploitation through persistence, evasion, and lateral movement)*

## MITRE ATT&CK Mapping

| Tactic | Technique (ID & Link) | Observed Behavior from Report |
| :--- | :--- | :--- |
| **Initial Access** | [Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) | Exploitation of CVE-2023-46805 and CVE-2024-21887 in Ivanti VPN edge appliances to gain unauthenticated remote code execution. |
| **Persistence** | [Server Software Component: Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/) | Deployment of multiple custom web shells (e.g., `LIGHTWIRE`, `GLASSTOKEN`) to maintain backdoor access. |
| **Defense Evasion** | [Indicator Removal: File Deletion (T1070.004)](https://attack.mitre.org/techniques/T1070/004/) | Modification of the VPN's internal system scripts (like `lastcheck.js`) to bypass built-in integrity checks and hide malicious components. |
| **Credential Access** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) | Dumping credentials directly from the appliance's memory to forge tickets and prepare for lateral movement into the main corporate network. |
| **Exfiltration** | [Exfiltration Over C2 Channel (T1041)](https://attack.mitre.org/techniques/T1041/) | Exfiltrating stolen configuration data and user credentials by tunneling the data through the established web shell connections. |

## Insights
This analysis demonstrates the critical vulnerability of "edge" security devices. Because these appliances (like VPNs and firewalls) often lack traditional security monitoring agents like EDR, they serve as ideal, high-value entry points for Advanced Persistent Threat (APT) groups. 

Defense-in-depth for such systems requires a shift in strategy: standard antivirus is insufficient. Organizations must implement regular, external integrity audits of edge file systems and enforce strict internal network segmentation to ensure a compromised VPN doesn't grant immediate, unchecked access to the entire internal network.