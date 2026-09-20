\# XSS Detection — Encoded Script Tag



\## Objective



Detect reflected Cross-Site Scripting (XSS) attempts against the vulnerable `/xss/` application using Apache access logs ingested into Splunk.



\## Lab Setup



\- Attacker: Kali Linux — `192.168.56.103`

\- Target: Ubuntu Server — `192.168.56.101`

\- Web server: Apache2

\- SIEM: Splunk Enterprise — `192.168.56.104`

\- Log source: `/var/log/apache2/access.log`

\- Splunk sourcetype: `apache:access`



\## Attack Simulation



A reflected XSS payload was submitted through the `name` query parameter:



```text

<script>alert(1)</script>





Apache access logs did not automatically provide the fields we wanted as Splunk fields, so rex was used to extract:



Source IP

HTTP method

URI

HTTP status

User-Agent



The query string was then extracted from the URI.



Detection

index=main sourcetype="apache:access"

| rex field=\_raw "^(?<clientip>\\S+) \\S+ \\S+ \\\[(?<timestamp>\[^\\]]+)\\] \\"(?<method>\\S+) (?<uri>\\S+) (?<protocol>\[^\\"]+)\\" (?<status>\\d+) (?<bytes>\\d+) \\"(?<referrer>\[^\\"]\*)\\" \\"(?<useragent>\[^\\"]\*)\\""

| rex field=uri "\\?(?<query>.\*)"

| search query="\*%3Cscript%3E\*"

| table \_time clientip method uri query status useragent

| sort - \_time

Result



The detection returned 4 matching events from Kali (192.168.56.103).

