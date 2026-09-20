\# SQL Injection / Repeated POST Detection



\## Objective



Detect repeated POST requests to the SQL Injection lab application from the same source IP within a short time window.



This detection is designed to identify suspicious repeated interaction with the application's login endpoint.



\## Data Source



\- Source: Apache access logs

\- Log file: `/var/log/apache2/access.log`

\- Splunk index: `main`

\- Sourcetype: `apache:access`



\## Detection Logic



The detection identifies:



\- HTTP `POST` requests

\- Requests targeting `/sqli/`

\- Three or more requests

\- From the same source IP

\- Within a five-minute window



\## SPL



```spl

index=main sourcetype="apache:access"

| rex field=\_raw "^(?<clientip>\\S+) \\S+ \\S+ \\\[(?<timestamp>\[^\\]]+)\\] \\"(?<method>\\S+) (?<uri>\\S+) (?<protocol>\[^\\"]+)\\" (?<status>\\d+) (?<bytes>\\d+) \\"(?<referrer>\[^\\"]\*)\\" \\"(?<useragent>\[^\\"]\*)\\""

| search method=POST uri="/sqli/"

| bin \_time span=5m

| stats count by \_time clientip uri

| where count >= 3

| sort - \_time

