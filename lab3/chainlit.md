# SecAI – Network Security Analyzer 🛡️

Welcome to **SecAI**, your AI-powered network security analyst.

## What I can do

| Capability | Example prompt |
|---|---|
| **Log analysis** | `Analyze: Failed login for admin from 185.220.101.5` |
| **IP reputation** | `Is 45.33.32.156 a known threat?` |
| **CVE lookup** | `What is CVE-2021-44228?` |

## How it works

1. You describe a security event (log line, IP, or CVE)
2. The agent decides which tool(s) to call
3. Tool results appear as **Steps** in the chat
4. The agent explains findings and recommends actions

## Sample inputs to try

```
Analyze this log: Failed login attempt from 185.220.101.5 for user admin
```
```
Check the reputation of 45.33.32.156
```
```
Tell me about CVE-2023-44487 and how serious it is
```
```
I see this in my logs: 1=1 OR DROP TABLE users -- from IP 80.82.77.33
```

---
*Lab 3 · AI-Enhanced Cybersecurity · Single-Agent with Tool Usage*
