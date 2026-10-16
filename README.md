# Home Lab — Blue Team / SOC

A hands-on cybersecurity home lab for developing practical skills in security monitoring, SIEM analysis, detection engineering, and incident investigation.

This project documents security activity generated in a controlled virtual environment, the telemetry collected from target systems, the detections developed in Splunk, and the investigation process used to analyze suspicious behavior.

The focus is on the defensive workflow: **generate activity, collect evidence, detect suspicious behavior, investigate the findings, and document the results.**

## Objectives

- Build practical SOC and Blue Team investigation skills.
- Collect and analyze Windows and Linux security logs.
- Configure log forwarding and ingestion into Splunk Enterprise.
- Develop and validate detection logic using Splunk Search Processing Language (SPL).
- Investigate authentication events, process activity, and other security-relevant telemetry.
- Correlate events using timestamps, accounts, logon IDs, source information, and process details.
- Map observed behavior to MITRE ATT&CK where applicable.
- Document investigation timelines, evidence, findings, and recommendations.
- Develop repeatable detection and investigation workflows.

## Lab Architecture

The lab runs in Oracle VirtualBox using an isolated Host-Only network for communication between the virtual machines. NAT interfaces are used where internet access is required.

```text
                 ┌──────────────────────┐
                 │      Kali Linux      │
                 │  Attack Simulation   │
                 │  192.168.56.103      │
                 └──────────┬───────────┘
                            │
                     Controlled Activity
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
┌────────────────────────┐   ┌────────────────────────┐
│      Windows 10        │   │     Ubuntu Server      │
│     Investigation      │   │     Linux Target       │
│  192.168.56.105        │   │  192.168.56.101        │
│  Windows Security Logs │   │  Authentication Logs   │
└────────────┬───────────┘   └────────────┬───────────┘
             │                            │
             └──────────────┬─────────────┘
                            │
                    Log Forwarding
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Splunk Enterprise  │
                 │     SIEM / Analysis  │
                 │  192.168.56.104      │
                 └──────────────────────┘
```

### Virtual Machines

| System | Role | Host-Only IP |
|---|---|---|
| Kali Linux | Attack simulation | `192.168.56.103` |
| Ubuntu Server | Linux target | `192.168.56.101` |
| Windows 10 | Windows telemetry and investigation target | `192.168.56.105` |
| Ubuntu Server | Splunk Enterprise SIEM | `192.168.56.104` |

**Note:** The Splunk instance runs on a separate Ubuntu Server VM. The Splunk Universal Forwarder is used to forward configured telemetry to Splunk Enterprise. The configured receiving port is TCP `9997`.

## Tools and Technologies

**SIEM and Detection**
- Splunk Enterprise
- Splunk Universal Forwarder
- Splunk Search Processing Language (SPL)

**Operating Systems**
- Kali Linux
- Ubuntu Server
- Windows 10

**Security Analysis**
- Windows Security Event Logs
- Windows Event Viewer
- Linux authentication and system logs
- Wireshark
- Nmap
- MITRE ATT&CK

**Virtualization**
- Oracle VirtualBox

## SOC Investigation Workflow

The lab follows a repeatable investigation process:

```text
Controlled Security Activity
             ↓
      Target System
             ↓
      Log Generation
             ↓
       Log Forwarding
             ↓
    Splunk Data Ingestion
             ↓
      Detection Using SPL
             ↓
     Event Investigation
             ↓
    Event Correlation
             ↓
   MITRE ATT&CK Mapping
             ↓
   Findings and Reporting
```

Each investigation aims to connect the activity performed with the resulting telemetry and the evidence available to a defender.

## Investigations

### 1. SSH Authentication Attack Simulation

**Status:** Completed

A controlled SSH password-guessing simulation was performed in the lab to study authentication telemetry and investigate the resulting events.

**Investigation areas:**
- Failed and successful authentication events.
- Windows Security Event IDs `4625` and `4624`.
- Process creation telemetry, including Event ID `4688`.
- OpenSSH-related logs and process activity.
- Splunk field extraction and search queries.
- Detection of repeated authentication failures.
- Correlation of authentication activity with subsequent successful logons.
- Logon ID and process-chain analysis.
- MITRE ATT&CK technique mapping.

**Observed process chain during the controlled successful SSH session:**

```text
sshd.exe
   ↓
conhost.exe
   ↓
cmd.exe
   ↓
whoami.exe
```

**MITRE ATT&CK mapping:**
- `T1110.001` — Password Guessing
- `T1021.004` — SSH

The investigation documents activity intentionally generated in the lab. The observed events are analyzed in context rather than automatically classified as malicious.

See the investigation report: [`investigations/ssh-brute-force/investigation.md`](investigations/ssh-brute-force/investigation.md).

## Detection Engineering

Detection development is maintained separately from investigation reports to keep detection logic reusable and easier to validate.

Current work focuses on:
- Authentication anomaly detection.
- Repeated failed-login detection.
- Correlation of failed and successful authentication activity.
- Windows process and authentication event analysis.
- Splunk searches for investigating security-relevant activity.

Future detection coverage will expand as additional telemetry is generated, ingested, and validated in the lab.

Detection rules will be documented with their purpose, relevant log sources, SPL queries, investigation notes, and known limitations where applicable.

## Planned Work

The next investigation is SQL injection, followed by additional network and endpoint investigations as the lab develops.

Planned areas include:

- **Web security:** SQL injection and other controlled web attack simulations.
- **Network monitoring:** Port scanning, network reconnaissance, and analysis of suspicious network activity.
- **Windows endpoint monitoring:** Sysmon, process creation, PowerShell logging, and suspicious process execution.
- **Detection engineering:** Reusable SPL searches, detection validation, event correlation, and alert investigation.
- **Incident response:** Investigation timelines, evidence collection, escalation criteria, and incident reporting.
- **MITRE ATT&CK:** Mapping observed behavior to relevant techniques and documenting supporting evidence.

These are planned extensions, not claims of completed implementations.

## Repository Structure

```text
Home-lab-Blue-Team/
│
├── README.md
│
├── architecture/
│   ├── lab-architecture.png
│   └── network-diagram.md
│
├── investigations/
│   ├── ssh-brute-force/
│   │   ├── investigation.md
│   │   └── screenshots/
│   ├── sql-injection/
│   ├── port-scanning/
│   └── dns-tunneling/
│
├── detections/
│   ├── splunk/
│   └── sigma/
│
├── docs/
│   ├── splunk-setup.md
│   ├── windows-logging.md
│   ├── sysmon.md
│   └── mitre-mapping.md
│
└── screenshots/
```

Directories for future investigations and detection formats may be populated as the corresponding work is completed.

## Investigation Methodology

Each investigation follows these steps:

1. **Generate activity:** Perform a controlled attack simulation or other security-relevant action against an authorized lab system.
2. **Identify telemetry:** Determine which events, logs, processes, or network records capture the activity.
3. **Collect and ingest evidence:** Configure the relevant log sources and verify that the data reaches Splunk.
4. **Develop detection logic:** Write SPL searches to identify relevant patterns or suspicious behavior.
5. **Investigate the events:** Correlate timestamps, users, source information, event IDs, logon IDs, processes, and related activity.
6. **Validate the findings:** Compare the search results with the generated activity and available evidence. Identify false positives and telemetry gaps.
7. **Map the behavior:** Apply MITRE ATT&CK mappings where supported by the observed behavior.
8. **Document the outcome:** Record the investigation timeline, evidence, detection logic, conclusions, limitations, and potential defensive improvements.

## Lab Safety

- All attack simulations are restricted to authorized, controlled lab systems.
- Virtual machines communicate through the configured lab network.
- No real-world systems are intentionally targeted.
- Credentials, tokens, and other secrets must not be committed to the repository.
- Screenshots and logs must be reviewed and sanitized before publication.
- VM disks, unnecessary binary files, and large packet captures are excluded from Git unless a specific artifact is required for the project.

## Project Status

**Current phase:** SOC investigation and detection development.

**Completed:**
- VirtualBox lab environment.
- Kali Linux attack-simulation VM.
- Ubuntu Server Linux target.
- Windows 10 target for security telemetry.
- Splunk Enterprise SIEM setup.
- Splunk Universal Forwarder configuration.
- Linux authentication-log ingestion.
- Windows Security Event ingestion.
- Controlled SSH password-guessing simulation.
- Authentication investigation and process-chain analysis.
- Initial investigation report and GitHub documentation workflow.

**Next:** SQL injection investigation, followed by additional telemetry collection and detection development.

Project status reflects the work completed and verified in the lab. Planned investigations will be marked complete only after the activity, telemetry, detection, and findings have been documented.

## Author

**Nikhilesh Ramesh**

B.Tech Information Technology  
Cybersecurity | SOC | Blue Team

## Disclaimer

This repository is an educational cybersecurity project documenting authorized security simulations and defensive analysis in a controlled virtual lab. All techniques are intended for cybersecurity learning, authorized testing, and defensive research.
