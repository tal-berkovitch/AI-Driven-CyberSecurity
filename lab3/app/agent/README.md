# SecAI – Network Security Analyzer

## 1. Agent Name

**SecAI** – Network Security Analyzer

---

## 2. Agent Purpose

SecAI is a cybersecurity triage assistant. Its task is to help security analysts quickly understand and respond to network security events by calling dedicated tools before generating any explanation.

The agent is designed around three first-responder tasks that analysts perform daily:

- Classifying raw log lines to identify attack patterns and assign a severity level
- Checking whether a source IP address is a known threat (scanner, malware C2, Tor exit node, etc.)
- Looking up a CVE's CVSS score and the recommended remediation

The agent never guesses. It always invokes the relevant tool(s) first, then explains the structured result in plain English and ends with a short list of recommended actions.

---

## 3. Agent Tools

### `parse_log_entry(log_line: str) → str`

Scans a raw log line with regular expressions to detect known attack signatures.

**Input:** a raw log line or short log snippet (string)

**Output:** JSON string with the following fields:

| Field | Description |
|---|---|
| `status` | `"threat_detected"` or `"clean"` |
| `event_types` | list of matched pattern names |
| `severity` | `INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `detail` | human-readable match summary |

Detected patterns and their default severities:

| Pattern | Severity |
|---|---|
| failed / invalid login | LOW |
| port scan / SYN flood | MEDIUM |
| XSS payload | MEDIUM |
| SQL injection attempt | HIGH |
| Privilege escalation | HIGH |
| Large outbound data transfer | CRITICAL |

---

### `check_ip_reputation(ip_address: str) → str`

Looks up an IPv4 address in a local threat-intelligence database (simulating services such as AbuseIPDB or VirusTotal).

**Input:** a valid IPv4 address string (e.g. `"185.220.101.5"`)

**Output:** JSON string with the following fields:

| Field | Description |
|---|---|
| `ip` | the queried address |
| `reputation` | `clean` / `suspicious` / `scanner` / `malicious` / `tor_exit` |
| `country` | country of origin |
| `abuse_reports` | number of recorded abuse reports |
| `recommendation` | `ALLOW` / `MONITOR` / `BLOCK` |

---

### `lookup_cve(cve_id: str) → str`

Returns severity and remediation information for a known CVE from an offline reference database.

**Input:** a CVE identifier string (e.g. `"CVE-2021-44228"`)

**Output:** JSON string with the following fields:

| Field | Description |
|---|---|
| `cve_id` | the queried identifier |
| `description` | short description of the vulnerability |
| `cvss_score` | CVSS v3 base score (0.0 – 10.0) |
| `severity` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `affected` | affected software and versions |
| `fix` | recommended remediation action |

CVEs currently in the local database: `CVE-2021-44228` (Log4Shell), `CVE-2022-0778` (OpenSSL), `CVE-2023-23397` (Outlook NTLM leak), `CVE-2024-3094` (XZ Utils backdoor), `CVE-2023-44487` (HTTP/2 Rapid Reset).

---

## 4. Example Interaction

**User:**
```
Analyze this log: Failed login attempt from 185.220.101.5 for user admin
```

**Step – `parse_log_entry` (visible in Chainlit UI):**
```
Input:  "Failed login attempt from 185.220.101.5 for user admin"
Output: {
  "status": "threat_detected",
  "event_types": ["failed_login"],
  "severity": "LOW",
  "detail": "Matched pattern(s): failed_login"
}
```

**Step – `check_ip_reputation` (visible in Chainlit UI):**
```
Input:  "185.220.101.5"
Output: {
  "ip": "185.220.101.5",
  "reputation": "tor_exit",
  "country": "DE",
  "abuse_reports": 210,
  "recommendation": "BLOCK"
}
```

**SecAI final response:**

The log shows a failed login attempt targeting the `admin` account. On its own this is a LOW-severity event — single failed logins are common. However, the source IP `185.220.101.5` is a **known Tor exit node** with 210 recorded abuse reports, which substantially raises the risk level.

**Recommended Actions:**
- 🔴 Block `185.220.101.5` at the firewall immediately
- Enable account lockout after repeated failed attempts on privileged accounts
- Review authentication logs for other requests originating from Tor exit nodes
- Consider adding Tor exit-node ranges to your blocklist

---

**User:**
```
What is CVE-2021-44228?
```

**Step – `lookup_cve` (visible in Chainlit UI):**
```
Input:  "CVE-2021-44228"
Output: {
  "cve_id": "CVE-2021-44228",
  "description": "Log4Shell – Apache Log4j2 RCE via JNDI lookup",
  "cvss_score": 10.0,
  "severity": "CRITICAL",
  "affected": "Apache Log4j 2.x < 2.15.0",
  "fix": "Upgrade to Log4j 2.15.0 or later"
}
```

**SecAI final response:**

CVE-2021-44228, known as **Log4Shell**, is a remote code execution vulnerability in Apache Log4j 2 with a CVSS score of **10.0 (CRITICAL)** — the maximum possible. An attacker can exploit it by sending a crafted JNDI lookup string in any field that gets logged, causing the server to execute attacker-controlled code.

**Recommended Actions:**
- 🔴 Upgrade Apache Log4j to version 2.15.0 or later immediately
- Scan your environment for any service using Log4j 2.x < 2.15.0
- Check WAF rules for JNDI lookup strings in incoming requests
- Review logs for any past exploitation attempts (`${jndi:` patterns)
