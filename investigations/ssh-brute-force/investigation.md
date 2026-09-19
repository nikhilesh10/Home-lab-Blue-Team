\# SSH Brute-Force Investigation



\## 1. Objective



Investigate simulated SSH authentication attacks against a Windows 10 system and determine whether repeated failed authentication attempts resulted in a successful session and subsequent command execution.



The investigation was performed using Splunk Enterprise as the SIEM and Splunk Universal Forwarder for log collection.



\---



\## 2. Lab Environment



| Component | Role | IP Address |

|---|---|---|

| Kali Linux | Attack simulation | 192.168.56.103 |

| Windows 10 | Target endpoint | 192.168.56.105 |

| Splunk Ubuntu | SIEM | 192.168.56.104 |



\### Data Flow



Kali Linux → Windows 10 → Splunk Universal Forwarder → Splunk Enterprise



\---



\## 3. Attack Simulation



Controlled SSH authentication attempts were generated from the Kali Linux machine against the Windows 10 target.



Both failed and successful SSH authentication attempts were intentionally generated for investigation and detection testing.



This was an authorized lab simulation.



\---



\## 4. Windows Event IDs Used



\### Event ID 4625 — Failed Logon



Event ID 4625 records a failed authentication attempt.



The investigation filtered these events for the Windows OpenSSH process:



```spl

index=main EventCode=4625

| search Caller\_Process\_Name="\*sshd.exe"

