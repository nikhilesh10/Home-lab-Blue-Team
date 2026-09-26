# Directory Traversal Detection

## Objective

Demonstrate a controlled directory traversal vulnerability, capture the resulting Apache evidence, forward the logs to Splunk, and build a Splunk detection for traversal patterns in HTTP request URIs.

## Lab Setup

- Attacker: Kali Linux — `192.168.56.103`
- Web target: Ubuntu Server — `192.168.56.101`
- SIEM: Splunk Enterprise — `192.168.56.104`
- Web server: Apache
- Log source: `/var/log/apache2/access.log`
- Splunk sourcetype: `apache:access`

## Vulnerable Application

The application accepts a `file` parameter and directly appends it to a filesystem path:

```php
$file = $_GET['file'];
$path = "/var/www/html/traversal/files/" . $file;

Baseline Request

A legitimate request was tested first:

http://192.168.56.101/traversal/?file=readme.txt

The application returned:

This is a public lab file.

This established the expected behavior before testing traversal.

Controlled Traversal

A harmless file was created outside the intended files/ directory:

/var/www/html/traversal/secret.txt

The traversal request was:

http://192.168.56.101/traversal/?file=../secret.txt

The application constructed:

/var/www/html/traversal/files/../secret.txt

The .. component moves to the parent directory, resolving the path to:

/var/www/html/traversal/secret.txt

The application returned:

Traversal lab secret: path traversal succeeded.

This demonstrated successful directory traversal using a harmless lab file.



Apache Evidence

The Apache access log recorded the traversal request:

192.168.56.103 - - [25/Sep/2026:14:51:14 +0000] "GET /traversal/?file=../secret.txt HTTP/1.1" 200 478 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
Important fields:

Source IP: 192.168.56.103
HTTP method: GET
URI: /traversal/?file=../secret.txt
Protocol: HTTP/1.1
Status: 200
Response size: 478
User agent: Firefox on Linux

The legitimate baseline request was also recorded:

192.168.56.103 - - [25/Sep/2026:14:36:45 +0000] "GET /traversal/?file=readme.txt HTTP/1.1" 200 470 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

Splunk Investigation

The Apache events were successfully forwarded to Splunk.

index=main sourcetype="apache:access"
| rex field=_raw "^(?<clientip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] \"(?<method>\S+) (?<uri>\S+) (?<protocol>[^\"]+)\" (?<status>\d+) (?<bytes>\d+) \"(?<referrer>[^\"]*)\" \"(?<useragent>[^\"]*)\""
| regex uri="(?i)(\.\./|%2e%2e|%252e%252e)"
| table _time clientip method uri protocol status bytes referrer useragent
| sort - _time

_time                  clientip        method  uri                                  protocol  status  bytes
2026-09-25 14:51:14    192.168.56.103  GET     /traversal/?file=../secret.txt     HTTP/1.1  200     478


Detection Logic

The detection searches the parsed request URI for:

../
%2e%2e
%252e%252e

These represent common literal or encoded forms of the parent-directory sequence.

The detection is broader than the specific /traversal/ application so that the same logic can identify traversal indicators in other logged HTTP requests.

Analyst Interpretation

The event shows a request from the Kali lab host containing a directory-traversal sequence in the URI and receiving an HTTP 200 response.

In this exercise, the request was intentionally generated as part of the authorized home lab. It should therefore be classified as a lab simulation, not a real compromise.

For a real investigation, additional evidence would be needed before concluding that exploitation occurred. Useful follow-up evidence could include:

Additional requests from the same source
Other traversal attempts
Apache error logs
Application logs
Endpoint telemetry
Authentication activity
Requested files and response behavior
Whether the source is an authorized security-testing system
MITRE ATT&CK Mapping

T1190 — Exploit Public-Facing Application

This mapping is relevant because the exercise demonstrates exploitation of a web application exposed through HTTP.

Limitations

This detection is not a complete production-grade directory-traversal detector.

Limitations include:

../ can appear in legitimate requests and therefore create false positives.
Additional encoding and obfuscation techniques may not be covered.
A traversal-looking request does not by itself prove successful exploitation.
Apache access logs do not contain HTTP POST bodies by default.
HTTP status 200 indicates a successful HTTP response but does not independently prove that sensitive information was accessed.

A production detection should be tuned to the application's expected URL patterns and correlated with application logs, endpoint telemetry, response behavior, and other security signals.