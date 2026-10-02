# Remote Code Execution (RCE) Lab

## 1. Objective

Demonstrate how a vulnerable PHP web application can execute operating-system commands supplied through an HTTP request, then collect and investigate process-execution telemetry using Linux Audit (`auditd`) and Splunk.

This is an intentionally vulnerable application used in an isolated home lab.

## 2. Lab Environment

| Component             | Details                      |
| --------------------- | ---------------------------- |
| Attacker VM           | Kali Linux                   |
| Target VM             | Ubuntu Server                |
| SIEM                  | Splunk Enterprise            |
| Log collection        | Splunk Universal Forwarder   |
| Web server            | Apache                       |
| Application           | PHP                          |
| Target host-only IP   | `192.168.56.101`             |
| Attacker host-only IP | `192.168.56.103`             |
| Vulnerable endpoint   | `http://192.168.56.101/rce/` |
| Audit log             | `/var/log/audit/audit.log`   |

## 3. Vulnerability

The application accepts a command through the `cmd` HTTP parameter and passes it directly to PHP's `shell_exec()` function.

Relevant vulnerable code:

```php
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $output = shell_exec($cmd);
}
```

The application does not restrict which commands can be supplied. As a result, a request such as `?cmd=id` causes the server to execute the `id` program.

This demonstrates command execution through a web application. The term *remote code execution (RCE)* describes the security impact: a remote client can cause code or commands to run on the target. In this lab, the demonstrated execution is limited to harmless commands.

## 4. Reproduction

### Baseline

Open the application without a command:

```text
http://192.168.56.101/rce/
```

This confirms that the application is reachable before testing command execution.

### Controlled command execution

Open:

```text
http://192.168.56.101/rce/?cmd=id
```

Expected output includes:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Other harmless commands tested in the lab included:

```text
?cmd=whoami
?cmd=pwd
?cmd=uname%20-a
```

The results confirmed that commands were executed by the web application.

**Security observation:** The commands ran as `www-data`, the Apache service account, rather than root. This limits the demonstrated privileges but does not make the vulnerability safe.

## 5. Apache Access Log Evidence

The target's Apache access log recorded requests from the Kali host (`192.168.56.103`).

Relevant examples:

```text
192.168.56.103 - - [30/Sep/2026:14:40:42 +0000] "GET /rce/?cmd=id HTTP/1.1" 200 480 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

192.168.56.103 - - [30/Sep/2026:14:41:39 +0000] "GET /rce/?cmd=whoami HTTP/1.1" 200 456 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

These records show the client IP, requested URL, HTTP method, response status and user agent.

A limitation is that the default Apache access log records the URL, not the complete process-execution context. URL encoding and application behavior can also affect how commands appear in logs.

## 6. Linux Audit Configuration

The `auditd` service was installed and verified as running.

The following audit rule records `execve` system calls for processes whose real UID is `33`:

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -F uid=33 -k web_cmd_exec
```

Verify the active rules:

```bash
sudo auditctl -l
```

Expected rule:

```text
-a always,exit -F arch=b64 -S execve -F uid=33 -F key=web_cmd_exec
```

Search for matching events on the target:

```bash
sudo ausearch -k web_cmd_exec -ts recent -i
```

### What the rule means

* `-a always,exit`: record matching events when the system call exits.
* `-F arch=b64`: match the 64-bit system-call architecture.
* `-S execve`: monitor program execution.
* `-F uid=33`: match processes running with real UID 33.
* `-k web_cmd_exec`: attach a searchable audit key to the event.

The rule is temporary and may not survive a reboot. It is scoped to UID 33, so it can record other processes using that UID—not only RCE activity.

## 7. Audit Evidence

The controlled `id` request produced audit records for both the shell and the command.

Representative event fields:

```text
type=SYSCALL
syscall=execve
success=yes
exit=0
uid=33
euid=33
comm="id"
exe="/usr/lib/cargo/bin/coreutils/id"
key="web_cmd_exec"
```

A related event recorded the shell:

```text
comm="sh"
exe="/usr/bin/dash"
uid=33
euid=33
key="web_cmd_exec"
```

Interpretation:

* `comm="sh"` identifies the shell process.
* `comm="id"` identifies the executed command.
* `exe` provides the executable path.
* `uid` and `euid` show the identity under which the process ran.
* `success=yes` indicates that the `execve` system call succeeded.
* `key="web_cmd_exec"` indicates that the event matched the configured audit rule.

The audit event's `auid` was unset. This is consistent with a process launched by a system service rather than a normal interactive login.

## 8. Splunk Log Collection

The Splunk Universal Forwarder was configured to monitor:

```text
/var/log/audit/audit.log
```

Input stanza:

```ini
[monitor:///var/log/audit/audit.log]
disabled = false
index = main
sourcetype = linux:audit
```

The forwarder was restarted and verified as running. Splunk subsequently returned the audit events from the `linux:audit` sourcetype.

## 9. Splunk Detection Search

The following search successfully returned the shell and `id` events:

```spl
index=main sourcetype="linux:audit" "web_cmd_exec"
| search "comm=\"id\"" OR "comm=\"sh\""
| table _time host source _raw
| sort - _time
```

### Detection logic

1. Search the `main` index for Linux audit events.
2. Restrict results to events tagged with `web_cmd_exec`.
3. Retain events whose raw content identifies the `sh` or `id` process.
4. Display the timestamp, host, source and raw audit event.
5. Sort newest events first.

This search is a **lab-specific detection and investigation query**. It validates that the expected process-execution telemetry is present; it is not a universal RCE detector.

The custom `rex` extraction attempt used earlier returned no results. The raw-event search above was tested successfully and is retained here as the working query.

## 10. Investigation Findings

The controlled test established the following chain:

1. Kali requested the vulnerable RCE endpoint.
2. PHP passed the supplied command to `shell_exec()`.
3. The shell and `id` process executed under the `www-data` account.
4. Linux Audit recorded the process-execution events.
5. The Universal Forwarder sent the audit log to Splunk.
6. Splunk displayed the matching shell and command events.

The combination of the controlled HTTP request, command output and OS audit events supports the conclusion that command execution occurred through the vulnerable application.

## 11. Detection Limitations

* The audit rule monitors UID 33, not the origin of the command. Other processes running as `www-data` may also match.
* The `web_cmd_exec` key is a manually configured audit rule label, not a built-in indicator of RCE.
* The search relies on the custom key and the process names `sh` and `id`. Different commands, shells, execution methods or identities may not match.
* Apache access logs and audit events are separate telemetry sources. This lab search does not automatically correlate a particular HTTP request with a particular process.
* The rule uses `arch=b64`; it does not cover 32-bit execution.
* The demonstrated execution ran as `www-data`, not root. No privilege escalation was demonstrated.
* The lab tested harmless commands only.

A more mature detection would correlate suspicious HTTP requests with process-execution telemetry, account for normal web-server behavior, and alert on unexpected child processes or command interpreters.

## 12. Mitigation

* Do not pass untrusted input directly to `shell_exec()` or similar process-execution functions.
* Prefer safe library functions over invoking a shell.
* If operating-system commands are essential, use strict allowlists and validate arguments independently.
* Run the web server with the minimum required privileges.
* Monitor web-server process creation and retain relevant audit and application logs.
* Restrict network access to the application and remove intentionally vulnerable code after the lab.

## 13. Evidence Screenshots

Screenshots are stored on the external lab drive and should also be copied into the repository's `screenshots/` directory.

* `rce-baseline.png` — the application before command execution.
* `rce-success.png` — successful execution of the harmless `id` command.
* `rce-detection.png` — Splunk results showing the shell and `id` audit events.

## 14. Conclusion

This lab demonstrated how a vulnerable PHP application can execute a client-supplied command and how Linux Audit and Splunk can provide evidence of the resulting process execution.

The main lesson is that web access logs and operating-system telemetry answer different questions. Apache shows the incoming request; auditd shows which processes executed and under which identity. Combining both sources creates a stronger investigation trail than relying on either source alone.



## Cross-Source Investigation and Correlation

### Objective

Correlate Apache HTTP access logs with Linux Audit process-execution events to investigate whether a request to the vulnerable RCE endpoint coincided with command execution on the Ubuntu target.

### 1. Apache HTTP Evidence

Splunk search:

```spl
index=main sourcetype="apache:access" "/rce/"
| table _time host source _raw
| sort - _time
```

Relevant events included:

| Time (UTC)          | Source IP      | Request        | HTTP status |
| ------------------- | -------------- | -------------- | ----------- |
| 2026-10-02 06:49:51 | 192.168.56.103 | `/rce/?cmd=id` | 200         |
| 2026-10-02 06:52:07 | 192.168.56.103 | `/rce/?cmd=id` | 200         |

The source IP belongs to the Kali attacker VM in this lab. HTTP status `200` indicates that the server returned a successful HTTP response; by itself, it does not prove that a command executed successfully.

### 2. Linux Audit Evidence

Splunk search:

```spl
index=main sourcetype="linux:audit" "web_cmd_exec"
| search "comm=\"id\"" OR "comm=\"sh\""
| table _time host source _raw
| sort _time
```

Relevant audit events:

| Time (UTC)              | Process |  PID | Parent PID | User       |
| ----------------------- | ------- | ---: | ---------: | ---------- |
| 2026-10-02 06:52:07.805 | `sh`    | 2067 |       1359 | `www-data` |
| 2026-10-02 06:52:07.809 | `id`    | 2068 |       2067 | `www-data` |

Both events reported `success=yes` and `exit=0`. The recorded working directory was `/var/www/html/rce`.

The process relationship was:

```text
apache2 worker (PID 1359)
└── sh -c -- id (PID 2067)
    └── id (PID 2068)
```

The Apache worker's identity was subsequently checked on the Ubuntu target. The `ps` output identified PID 1359 as an Apache worker running as `www-data`. The child processes had already exited by then, so their historical relationship is established primarily through the audit records.

### 3. Combined Timeline in Splunk

The following search places the relevant HTTP and process-execution evidence in one chronological view:

```spl
index=main
(
  (sourcetype="apache:access" "/rce/")
  OR
  (sourcetype="linux:audit" "web_cmd_exec")
)
| eval evidence_type=case(
    sourcetype="apache:access", "Apache HTTP request",
    sourcetype="linux:audit" AND (like(_raw,"%comm=\"sh\"%") OR like(_raw,"%comm=\"id\"%")), "Linux process execution",
    true(), "Other audit event"
  )
| search evidence_type!="Other audit event"
| table _time evidence_type host source _raw
| sort _time
```

This search returned two Apache requests and two process-execution events relevant to the controlled test. The second HTTP request at `06:52:07` aligns with the `sh` and `id` audit events at `06:52:07.805` and `06:52:07.809`.

### 4. Investigation Assessment

The combined evidence supports successful command execution during the controlled RCE test:

* Apache recorded a request containing the `cmd=id` parameter.
* Linux Audit recorded a shell launching `id` from the RCE application's working directory.
* Both processes ran as `www-data`.
* The shell and `id` events were recorded within milliseconds of the corresponding Apache request.
* The parent-child relationship is consistent with the vulnerable PHP application's use of `shell_exec()`.

**Assessment:** The evidence strongly supports command execution associated with the controlled RCE test. Timestamp alignment alone is not universal proof that a specific HTTP request caused a process; correlation should consider the test context, timestamps, process ancestry, execution details, and any additional available telemetry.

### 5. Detection Scope and Limitations

The audit rule used in this lab was:

```text
-a always,exit -F arch=b64 -S execve -F uid=33 -F key=web_cmd_exec
```

It records `execve` activity for processes running with UID 33 and tags matching events with `web_cmd_exec`.

Limitations:

* UID 33 is specific to this Ubuntu configuration's `www-data` account and may differ on other systems.
* The rule monitors matching process executions, not HTTP requests themselves.
* The rule does not prove that every recorded execution originated from a web request.
* It covers 64-bit `execve` activity matching this rule; it is not a complete detector for every execution technique or architecture.
* The Apache access log records the request URI, but default access logging does not capture the complete POST body.
* The combined Splunk search is a lab investigation aid, not a universal standalone RCE detection.

### 6. Key Learning

This investigation connected three evidence layers:

1. **HTTP telemetry:** What request reached the web application?
2. **Operating-system telemetry:** Which process executed, under which identity, and with what parent process?
3. **SIEM correlation:** Do the timestamps and process relationships support a common investigation narrative?

The important skill is not merely detecting a suspicious string in a URL. It is combining independent evidence sources, testing the process relationship, documenting uncertainty, and explaining what the available telemetry can—and cannot—prove.
