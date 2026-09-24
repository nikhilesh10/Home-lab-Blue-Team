# CSRF Suspicious State-Change Detection

## Objective

Detect suspicious cross-site POST requests targeting a state-changing
application endpoint.

This lab demonstrates a Cross-Site Request Forgery (CSRF) attack against
a vulnerable PHP application and develops a Splunk detection using
Apache access logs.

## Lab Environment

### Target

-   Ubuntu Server 26.04 LTS
-   IP: `192.168.56.101`
-   Apache HTTP Server
-   Vulnerable PHP CSRF application
-   Apache access log: `/var/log/apache2/access.log`

### Attacker

-   Kali Linux
-   IP: `192.168.56.103`

### SIEM

-   Splunk Enterprise 10.4.3
-   IP: `192.168.56.104`
-   Receiving port: TCP/9997

### Log Pipeline

``` text
Kali
  |
  | HTTP request
  v
Ubuntu Apache
  |
  | /var/log/apache2/access.log
  v
Splunk Universal Forwarder
  |
  | TCP/9997
  v
Splunk Enterprise
```

## Vulnerable Application

The vulnerable application contained an authenticated `change-email.php`
endpoint.

The endpoint accepted a POST request containing a new email address
without requiring a CSRF token.

The application therefore accepted a state-changing request without
verifying that it originated from the legitimate application workflow.

## Attack Simulation

A simulated attacker-controlled page was created at:

``` text
http://192.168.56.101/csrf-attacker/
```

The page contained a form targeting:

``` text
http://192.168.56.101/csrf/change-email.php
```

with a hidden email value:

``` text
attacker@example.com
```

The victim first authenticated to the vulnerable application.

While the authenticated session remained active, the victim visited the
simulated attacker page and submitted the form.

The browser then sent the POST request to the target application using
the victim's existing authenticated session.

The email address was changed successfully.

## Important CSRF Concept

CSRF does not require the attacker to steal the victim's session cookie.

The attack works because:

1.  The victim is already authenticated.
2.  The victim's browser already has the application's session
    credentials.
3.  The attacker causes the browser to send a request to the target.
4.  The browser sends the applicable authentication credentials with the
    request.
5.  The vulnerable application accepts the state-changing request
    without verifying its origin.

This is different from session hijacking, where an attacker obtains and
uses the victim's session identifier.

## Apache Evidence

The Apache access log recorded the attack request.

Example:

``` text
192.168.56.103 - - [24/Sep/2026:13:42:42 +0000] "POST /csrf/change-email.php HTTP/1.1" 200 626 "http://192.168.56.101/csrf-attacker/" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

Important indicators:

``` text
Source IP:
192.168.56.103

HTTP method:
POST

Target:
/csrf/change-email.php

HTTP status:
200

Referrer:
http://192.168.56.101/csrf-attacker/
```

A second controlled attack was also recorded at `2026-09-24 13:36:46`.

## Splunk Field Extraction

The Apache access log is initially stored as a raw event.

``` spl
index=main sourcetype="apache:access"
| search "/csrf/change-email.php"
| rex field=_raw "^(?<clientip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] \"(?<method>\S+) (?<uri>\S+) (?<protocol>[^\"]+)\" (?<status>\d+) (?<bytes>\d+) \"(?<referrer>[^\"]*)\" \"(?<useragent>[^\"]*)\""
| table _time clientip method uri protocol status referrer useragent
| sort - _time
```

### Parsed Fields

-   `clientip`
-   `method`
-   `uri`
-   `protocol`
-   `status`
-   `referrer`
-   `useragent`

The parsing successfully produced the expected values, including:

``` text
_time                 clientip          method  uri
2026-09-24 13:42:42   192.168.56.103    POST    /csrf/change-email.php
```

and:

``` text
status:
200

referrer:
http://192.168.56.101/csrf-attacker/
```

## Detection Logic

The lab detection searches for POST requests to the state-changing
endpoint where the referrer identifies the simulated attacker page.

``` spl
index=main sourcetype="apache:access"
| rex field=_raw "^(?<clientip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] \"(?<method>\S+) (?<uri>\S+) (?<protocol>[^\"]+)\" (?<status>\d+) (?<bytes>\d+) \"(?<referrer>[^\"]*)\" \"(?<useragent>[^\"]*)\""
| search method="POST" uri="/csrf/change-email.php"
| search referrer="*/csrf-attacker/*"
| table _time clientip method uri status referrer useragent
| sort - _time
```

### Detection Result

The query identified the controlled CSRF requests:

``` text
2026-09-24 13:42:42
192.168.56.103
POST
/csrf/change-email.php
200
http://192.168.56.101/csrf-attacker/

2026-09-24 13:36:46
192.168.56.103
POST
/csrf/change-email.php
200
http://192.168.56.101/csrf-attacker/
```

## Detection Interpretation

The detection identifies:

> A POST request to a state-changing endpoint with a referrer associated
> with the simulated attacker page.

Within this controlled lab, this is strong evidence of the simulated
CSRF attack.

However, the detection should not be interpreted as a universal CSRF
detector. A real-world implementation would need additional context and
application-specific logic.

## Telemetry Limitation

Apache's default access log does not record the POST request body.

Therefore, Splunk cannot determine from this log alone whether the
request contained:

``` text
email=attacker@example.com
```

The log provides evidence that the state-changing endpoint was accessed,
but not the exact POST parameters.

This is an important telemetry limitation.

## False Positive Considerations

A legitimate application workflow may also generate:

``` text
POST /csrf/change-email.php
```

Therefore, simply detecting a POST to the endpoint is not sufficient to
classify an event as malicious.

The simulated attacker referrer provides additional context in this lab.

In production, `Referer` should be treated as an indicator rather than
definitive proof because it may be absent or affected by browser privacy
and referrer-policy behavior.

Detection logic should therefore be adapted to the specific
application's normal behavior.

## MITRE ATT&CK Mapping

### Tactic

Initial Access

### Technique

**T1189 --- Drive-by Compromise**

This lab demonstrates a malicious web page causing interaction with a
vulnerable application.

The specific CSRF vulnerability itself is an application-layer weakness
rather than a direct one-to-one MITRE ATT&CK technique.

## Investigation Workflow

When an alert is generated:

1.  Identify the source IP.
2.  Identify the target endpoint.
3.  Determine whether the request was a state-changing operation.
4.  Examine the referrer.
5.  Review the surrounding Apache events.
6.  Determine whether the request matches a legitimate user workflow.
7.  Correlate with application logs if available.
8.  Determine whether the affected account or resource was modified.
9.  Document the activity and response.

## Lab Assessment

### Attack

Controlled CSRF simulation

### Target

Authenticated email-change functionality

### Evidence

Apache access log

### SIEM

Splunk Enterprise

### Detection

POST to state-changing endpoint with simulated attacker referrer

### Result

Detection successfully identified the controlled CSRF requests.

### Limitation

Default Apache access logs do not contain the POST body.

### Status

-   [x] Vulnerable CSRF application created
-   [x] Legitimate login tested
-   [x] Legitimate state-changing workflow tested
-   [x] Attacker-controlled page created
-   [x] CSRF attack successfully demonstrated
-   [x] Apache evidence collected
-   [x] Logs forwarded to Splunk
-   [x] `rex` field extraction created
-   [x] Suspicious state-change detection created
-   [x] Telemetry limitation documented
-   [ ] Vulnerability remediation demonstrated
-   [ ] Remediation detection comparison completed
