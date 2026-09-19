# Home Lab Network Diagram

This document describes the network architecture of the **Home-lab-Blue-Team** environment and explains how the attacker, target systems, and SIEM communicate.

---

## 1. Architecture Overview

The lab uses **Oracle VirtualBox** with two main network types:

- **NAT** — provides internet access to virtual machines when required.
- **Host-Only Adapter** — provides an isolated lab network for communication between the host and virtual machines.

The primary security-lab traffic stays on the Host-Only network:

```text
                         HOST MACHINE
                              |
                    VirtualBox Host-Only
                         192.168.56.1
                              |
              ────────────────┼────────────────
                              |
                  192.168.56.0/24
                     Isolated Lab Network
                              |
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
 ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
 │ Kali Linux  │       │Ubuntu Server│       │ Windows 10  │
 │  Attacker   │       │ Linux Target│       │   Target    │
 │    .103     │       │    .101     │       │    .105     │
 └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
        │                     │                     │
        │ Attack traffic      │ Logs                │ Windows
        │                     │                     │ Event Logs
        │                     ▼                     │
        │              ┌─────────────┐              │
        │              │ Universal   │              │
        │              │ Forwarder   │              │
        │              └──────┬──────┘              │
        │                     │ TCP 9997            │
        │                     └──────────┐           │
        │                                │           │
        │                                ▼           │
        │                         ┌─────────────┐     │
        │                         │   Splunk    │◄────┘
        │                         │ Enterprise  │
        │                         │    .104     │
        │                         │     SIEM    │
        │                         └─────────────┘     │
        │                                            │
        └──────────── Controlled attack / testing ───┘
```

> The diagram represents the current lab design. Specific services and telemetry sources will expand as additional investigations are added.

---

## 2. Virtual Machines

| System | Role | Host-Only IP | Primary Purpose |
|---|---|---:|---|
| Kali Linux | Attacker | `192.168.56.103` | Attack simulation, reconnaissance and security testing |
| Ubuntu Server | Linux Target | `192.168.56.101` | Linux target, services and Linux telemetry |
| Windows 10 | Windows Target | `192.168.56.105` | Windows authentication, process and endpoint telemetry |
| Splunk Ubuntu | SIEM | `192.168.56.104` | Splunk Enterprise and centralized log analysis |

All four systems communicate over the VirtualBox Host-Only network `192.168.56.0/24`.

---

## 3. Network Types

### Host-Only Network

The Host-Only adapter creates an isolated network between the host machine and the virtual machines.

```text
Host
192.168.56.1
      |
      +── Kali       192.168.56.103
      +── Ubuntu     192.168.56.101
      +── Windows    192.168.56.105
      +── Splunk     192.168.56.104
```

This network is used for the majority of security-lab communication.

Examples:

- Kali → Windows SSH
- Kali → Ubuntu services
- Ubuntu → Splunk Forwarder
- Windows → Splunk Forwarder
- Host → Splunk Web

### NAT

The VMs also use NAT interfaces when internet access is needed.

NAT is intentionally separated from the main lab communication so that attack and monitoring traffic can use the Host-Only network.

---

## 4. Splunk Data Flow

### Linux telemetry

The Ubuntu target generates authentication logs such as:

```text
/var/log/auth.log
```

The Splunk Universal Forwarder on Ubuntu monitors the relevant log and forwards events to Splunk Enterprise.

```text
Ubuntu Target
192.168.56.101
      |
      | /var/log/auth.log
      ▼
Splunk Universal Forwarder
      |
      | TCP 9997
      ▼
Splunk Enterprise
192.168.56.104
```

The current Linux SSH investigation demonstrated this flow using failed SSH authentication events.

---

### Windows telemetry

The Windows target generates Windows Event Logs, including Security events.

The Splunk Universal Forwarder on Windows collects the Security event log and forwards it to Splunk Enterprise.

```text
Windows 10
192.168.56.105
      |
      | Windows Security Event Log
      ▼
Splunk Universal Forwarder
      |
      | TCP 9997
      ▼
Splunk Enterprise
192.168.56.104
```

The SSH investigation used:

- Event ID `4625` — failed logon
- Event ID `4624` — successful logon
- Event ID `4688` — process creation

---

## 5. Current SSH Investigation Flow

The first completed investigation used Kali to generate controlled SSH authentication activity against Windows.

```text
Kali Linux
192.168.56.103
      |
      | SSH authentication attempts
      | TCP/22
      ▼
Windows 10
192.168.56.105
      |
      | Security Event Logs
      | 4625 / 4624 / 4688
      ▼
Splunk Universal Forwarder
      |
      | TCP/9997
      ▼
Splunk Enterprise
192.168.56.104
      |
      ▼
SPL Investigation
      |
      ├── Authentication failures
      ├── Successful authentication
      ├── Logon ID correlation
      └── Process chain
              |
              └── sshd.exe
                    ↓
                  conhost.exe
                    ↓
                   cmd.exe
                    ↓
                 whoami.exe
```

This activity was deliberately generated as part of the lab and was treated as an **authorized lab simulation**.

---

## 6. Important Ports

| Port | Protocol | Purpose |
|---:|---|---|
| `22` | TCP | SSH |
| `8000` | TCP | Splunk Web |
| `8089` | TCP | Splunk management/API |
| `9997` | TCP | Splunk receiving port for forwarded data |

---

## 7. Security Boundaries

The lab is separated into several logical roles:

### Attacker

**Kali Linux**

Used to generate controlled attack and reconnaissance activity.

### Targets

**Ubuntu Server**

Used for Linux services, logs and future web/network attack exercises.

**Windows 10**

Used for Windows authentication, process creation, endpoint telemetry and future Windows detection exercises.

### SIEM

**Splunk Enterprise**

Receives telemetry, provides search and correlation, and is used to develop detections and investigate incidents.

---

## 8. SOC Workflow

The architecture supports the following repeatable workflow:

```text
1. Generate controlled attack
          ↓
2. Target produces telemetry
          ↓
3. Universal Forwarder collects logs
          ↓
4. Splunk receives events
          ↓
5. Analyst searches with SPL
          ↓
6. Events are correlated
          ↓
7. Suspicious behavior is investigated
          ↓
8. Activity is mapped to MITRE ATT&CK
          ↓
9. Findings are documented
          ↓
10. Detection/report is added to GitHub
```

This workflow will be reused for future investigations such as SQL injection, port scanning, DNS tunneling, malicious file downloads and Windows endpoint activity.

---

## 9. Lab Design Principles

The lab is being built around a few principles:

1. **Generate the telemetry yourself.**  
   Do not rely only on pre-made datasets.

2. **Understand the raw event before writing the detection.**  
   Know what the target actually logged.

3. **Correlate multiple events when possible.**  
   A single event rarely tells the complete story.

4. **Separate detection from investigation.**  
   A query that finds activity is not automatically a complete investigation.

5. **Document evidence and reasoning.**  
   Record what happened, how it was detected, and why the conclusion was reached.

6. **Keep the environment controlled.**  
   Security testing is performed only against the lab systems.

---

## 10. Future Expansion

The architecture will be expanded as the project progresses.

Planned additions include:

- Web application target
- Apache/Nginx web telemetry
- Network IDS/NSM telemetry
- Suricata
- Zeek
- Sysmon
- PowerShell logging
- Additional Windows event collection
- Detection rules
- Incident response playbooks
- Multi-stage attack simulation

The architecture document should be updated whenever a major component is added or the network design changes.

---

## Related Documentation

- [Project README](../README.md)
