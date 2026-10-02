# Command Injection Detection

## Objective

Demonstrate a controlled command injection vulnerability, capture Apache evidence, forward the logs to Splunk, and create a Splunk detection for suspicious command-separator patterns.

## Lab Setup

- Attacker: Kali Linux — `192.168.56.103`
- Target: Ubuntu Server — `192.168.56.101`
- SIEM: Splunk — `192.168.56.104`
- Web server: Apache
- Log source: `/var/log/apache2/access.log`
- Splunk sourcetype: `apache:access`
- Vulnerable application: `/cmdinject/`

## Baseline Request

Normal request:

```text
GET /cmdinject/?host=127.0.0.1 HTTP/1.1
```

Apache recorded:

```text
192.168.56.103 - - [29/Sep/2026:14:08:43 +0000] "GET /cmdinject/?host=127.0.0.1 HTTP/1.1" 200 597 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

## Controlled Command Injection

Controlled payload:

```text
127.0.0.1; id
```

HTTP request:

```text
GET /cmdinject/?host=127.0.0.1;%20id HTTP/1.1
```

The application returned:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This demonstrated command execution in the Apache web-server process context.

Apache recorded:

```text
192.168.56.103 - - [29/Sep/2026:14:09:02 +0000] "GET /cmdinject/?host=127.0.0.1;%20id HTTP/1.1" 200 620 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

An earlier controlled run was also recorded at `13:58:33` with the same payload and HTTP 200 response.

## Apache Evidence

Additional lab requests included:

```text
192.168.56.103 - - [29/Sep/2026:14:07:29 +0000] "GET /cmdinject/ HTTP/1.1" 200 446 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

192.168.56.103 - - [29/Sep/2026:14:08:29 +0000] "GET /cmdinject/host=127.0.0.1;%20id HTTP/1.1" 404 533 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

192.168.56.103 - - [29/Sep/2026:14:08:43 +0000] "GET /cmdinject/?host=127.0.0.1 HTTP/1.1" 200 597 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

192.168.56.103 - - [29/Sep/2026:14:09:02 +0000] "GET /cmdinject/?host=127.0.0.1;%20id HTTP/1.1" 200 620 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

The `14:08:29` request returned 404 because `host=...` was placed in the URL path rather than the query string.

## Splunk Investigation

The Apache events were successfully forwarded to Splunk:

```spl
index=main sourcetype="apache:access" "/cmdinject/"
```

Splunk identified:

```text
host       = nikhilesh
source     = /var/log/apache2/access.log
sourcetype = apache:access
```

## Final Detection

```spl
index=main sourcetype="apache:access"
| rex field=_raw "^(?<clientip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] \"(?<method>\S+) (?<uri>\S+) (?<protocol>[^\"]+)\" (?<status>\d+) (?<bytes>\d+) \"(?<referrer>[^\"]*)\" \"(?<useragent>[^\"]*)\""
| search uri="/cmdinject/*"
| regex uri="(?i)(;|%3b|%26%26|%7c|\||%60|%24\28)"
| table _time clientip method uri protocol status bytes referrer useragent
| sort - _time
```

The detection searches for command-separator or shell-related patterns including `;`, encoded semicolons, command chaining, pipes, backticks, and encoded command-substitution characters.

## Detection Result

The detection returned the controlled request:

```text
clientip = 192.168.56.103
method   = GET
uri      = /cmdinject/?host=127.0.0.1;%20id
protocol = HTTP/1.1
status   = 200
```

## Analyst Interpretation

This was an authorized command-injection simulation against an intentionally vulnerable application in the isolated home lab.

Evidence chain:

```text
Kali
  ↓
crafted HTTP request
  ↓
vulnerable /cmdinject/ application
  ↓
Apache access.log
  ↓
Splunk Universal Forwarder
  ↓
Splunk
  ↓
command-injection detection
```

The observed `uid=33(www-data)` output demonstrates command execution under the Apache web-server account in this lab.

## Detection Limitations

This is a lab-specific detection, not a complete production command-injection detector.

- Shell characters can occur legitimately.
- Attackers can use alternative encodings and syntax.
- A suspicious URI alone does not prove command execution.
- Apache access logs do not contain the command's stdout.
- HTTP status 200 does not prove that an injected command executed.
- Production detection should correlate web requests with process telemetry, application logs, authentication context, and endpoint/EDR data.

## MITRE ATT&CK

Relevant technique:

- **T1059 — Command and Scripting Interpreter**

The exact sub-technique depends on the interpreter invoked by the vulnerable application.

## Screenshots

```text
screenshots/command-injection-baseline.png
screenshots/command-injection-success.png
screenshots/command-injection-detection.png
```

## Analyst Conclusion

The lab demonstrated the complete workflow:

```text
Baseline request
→ controlled injection
→ command execution
→ Apache evidence
→ Splunk ingestion
→ Splunk detection
→ analyst interpretation
```
