# Detection Catalogue

Every rule with its hypothesis, ATT&CK mapping, documented false positives,
evasion analysis and response guidance.

The **evasion** section is the one most detection documentation omits. A rule you
cannot explain how to beat is a rule you do not understand, and knowing the gap is
what tells you which rule has to cover it.


## Atomic detections

### Successful Authentication After Repeated Failures  *(disabled — see note)*

`auth_success_after_failures` · **CRITICAL** · stable

**Hypothesis.** Authentication succeeded from a source that had just failed many times, indicating a guessed or sprayed credential

**ATT&CK.** T1078, T1110

**Known false positives.**
- A legitimate user who eventually recalled the correct password
- Stateless evaluation fires on ALL successful logins - see note above

**Evasion.** Authenticate from a different source address than the one used for guessing, which is standard practice with credential marketplaces. Covered by the behavioural baseline (new host, unusual hour) rather than by source correlation.

**Response.**
1. Treat as confirmed compromise until proven otherwise
1. Capture the session history for the account on the target host
1. Rotate the credential and revoke active sessions and keys
1. Hunt for persistence created after the successful login

---

### Honeypot Post-Compromise Command Execution

`honeypot_command` · **CRITICAL** · stable

**Hypothesis.** Attacker executed commands inside the honeypot after a successful fake login, revealing post-exploitation tradecraft

**ATT&CK.** T1059, T1105

**Known false positives.**
- None

**Evasion.** Same.

**Response.**
1. Extract any downloaded payload hashes for threat intel
1. Record the command sequence as adversary tradecraft for detection tuning

---

### Security Audit Log Cleared

`win_audit_log_cleared` · **CRITICAL** · stable

**Hypothesis.** The Windows security event log was cleared, a classic anti-forensics action

**ATT&CK.** T1070.001

**Known false positives.**
- Deliberate log rotation during system maintenance (should be rare and documented)

**Evasion.** Disable auditing rather than clearing the log, or clear logs on a host that does not forward to the SIEM. The second is why forwarding matters more than local retention.

**Response.**
1. Treat as likely intrusion cleanup; preserve the host for forensics
1. Pull logs forwarded to the SIEM before the clear to reconstruct activity
1. Identify the account that performed the clear and when it logged on

---

### Honeypot Interaction

`honeypot_interaction` · **HIGH** · stable

**Hypothesis.** Any interaction with the honeypot sensor, which has no legitimate purpose and therefore no false positives

**ATT&CK.** T1110

**Known false positives.**
- None. Nothing should ever talk to a honeypot.

**Evasion.** Avoid the honeypot. Requires knowing it exists, which is the whole value of deception.

**Response.**
1. Add the source to the blocklist; interaction is definitionally hostile
1. Harvest the attempted credentials to check against real account passwords

---

### SSH Brute Force

`ssh_brute_force` · **HIGH** · stable

**Hypothesis.** Repeated SSH authentication failures from a single source address in a short window

**ATT&CK.** T1110.001

**Threshold.** 10 events per `source.ip` within 60s

**Known false positives.**
- Misconfigured automation or backup agent with stale credentials
- A user whose saved password expired and whose client retries aggressively
- Vulnerability scanners during an authorised assessment window

**Evasion.** Pace attempts below 10 per minute, or distribute across a botnet so no single source crosses the threshold. Covered by the password-spray rule (10-minute window) and by the behavioural baseline, which does not depend on volume.

**Response.**
1. Confirm whether any authentication from this source later succeeded
1. Check source.geo and threat.indicator context on the alert
1. Block the source at the perimeter if external and unrecognised
1. If a success followed, treat as compromise and rotate the account credentials

---

### SSH Password Spray

`ssh_password_spray` · **HIGH** · stable

**Hypothesis.** One source attempting authentication against many distinct usernames

**ATT&CK.** T1110.003

**Threshold.** 5 distinct `user.name` per `source.ip` within 10m

**Known false positives.**
- Shared jump host where many users authenticate from one NAT address
- Load balancer or proxy that masks true client addresses

**Evasion.** Target fewer than 5 usernames, or spread attempts beyond the 10-minute window. Partially covered by brute-force counting and by first-seen source novelty.

**Response.**
1. Identify whether any sprayed account exists and is enabled
1. Review whether any of the sprayed accounts are privileged
1. Force password reset on any account that authenticated successfully

---

### SQL Injection Attempt

`web_sql_injection` · **HIGH** · stable

**Hypothesis.** SQL syntax in a URL parameter, indicating injection probing against the application

**ATT&CK.** T1190

**Known false positives.**
- Application pages that legitimately accept SQL keywords in search text

**Evasion.** Encode the payload beyond URL encoding, use time-based blind injection without SQL keywords, or inject via POST body (not captured in access logs). Partially covered by the Suricata IDS rule and by tool user-agent detection.

**Response.**
1. Check the response codes; a 200 on an injected parameter suggests success
1. Review application logs for database errors at the same timestamps
1. Confirm parameterised queries are in use on the affected endpoint

---

### XSS or Path Traversal Attempt

`web_xss_traversal` · **HIGH** · stable

**Hypothesis.** Script injection or directory traversal payload in a request path

**ATT&CK.** T1190, T1083

**Known false positives.**
- Security researchers testing with authorisation

**Evasion.** Double-encode, or deliver via POST. Same limitation as above.

**Response.**
1. Check whether the payload was reflected in the response
1. Review output encoding on the affected endpoint

---

### Windows Account Brute Force

`win_brute_force` · **HIGH** · stable

**Hypothesis.** Repeated Windows logon failures (4625) from one source address

**ATT&CK.** T1110.001

**Threshold.** 10 events per `source.ip` within 60s

**Known false positives.**
- Service account with an expired password retrying on a schedule
- Mapped drives or scheduled tasks using stale credentials

**Evasion.** Pace below threshold, or use Kerberos pre-auth failures (4771) which this rule does not cover.

**Response.**
1. Identify whether the targeted account exists and is privileged
1. Check for a subsequent 4624 from the same source

---

### User Added to Privileged Group

`win_privileged_group_add` · **HIGH** · stable

**Hypothesis.** An account was added to a privileged group, a common persistence and escalation step

**ATT&CK.** T1098, T1078.002

**Known false positives.**
- Planned administrative onboarding with an approved change ticket

**Evasion.** Modify group membership via a method that does not generate 4732, or target a privileged group not on the list.

**Response.**
1. Verify an approved change request exists for this group membership
1. If unapproved, remove the membership and investigate the granting account

---

### Suspicious Process Execution

`win_suspicious_process` · **HIGH** · experimental

**Hypothesis.** Execution of living-off-the-land binaries with arguments associated with download or encoded execution

**ATT&CK.** T1059.001, T1105

**Known false positives.**
- Legitimate administrative scripts and software deployment tooling

**Evasion.** Rename the binary, use an uncommon LOLBin, or obfuscate arguments past the string matches. Command-line obfuscation is an arms race; this catches commodity tooling.

**Response.**
1. Capture the full command line and decode any base64 payload
1. Check the parent process for an unusual chain (office app spawning a shell)
1. Isolate the host if the payload reaches an external address

---

### Authentication From New Country

`auth_new_country` · **MEDIUM** · experimental

**Hypothesis.** Successful authentication from a geography not previously seen for this source, outside business hours

**ATT&CK.** T1078

**Known false positives.**
- Employee travel or VPN exit node changes
- Mobile carrier IP reassignment

**Evasion.** Use a VPN or proxy in the expected geography. Routine for a competent attacker.

**Response.**
1. Confirm with the user whether the login was theirs
1. Compare against travel and VPN records before escalating

---

### Network IDS Alert

`suricata_ids_alert` · **MEDIUM** · stable

**Hypothesis.** Suricata signature fired on network traffic

**ATT&CK.** T1190

**Known false positives.**
- Noisy signatures such as generic policy violations; tune per-signature

**Evasion.** Encrypt the payload, or use a technique without a signature. Inherits every limitation of signature-based network detection.

**Response.**
1. Review the signature category; policy alerts differ from exploit attempts
1. Correlate with host logs on the destination to confirm impact

---

### Web Directory Scanning

`web_scanning` · **MEDIUM** · stable

**Hypothesis.** High volume of not-found responses from a single source, consistent with automated directory enumeration

**ATT&CK.** T1595.003

**Threshold.** 15 events per `source.ip` within 5m

**Known false positives.**
- Search engine crawlers following stale links
- Broken internal links after a site migration
- Uptime monitoring probing removed endpoints

**Evasion.** Request only paths that return 200, or pace requests below 15 per 5 minutes. Covered by the sensitive-path rule, which does not depend on status code.

**Response.**
1. Review which paths were requested for sensitive targets
1. Correlate with later authentication activity from the same source
1. Rate-limit or block if the volume is sustained

---

### Sensitive File Probing

`web_sensitive_paths` · **MEDIUM** · stable

**Hypothesis.** Requests for configuration, credential or backup files that no legitimate user browses to

**ATT&CK.** T1595.003, T1083

**Known false positives.**
- Security scanning during an authorised assessment

**Evasion.** Use paths not on the list. The list is necessarily incomplete; this rule is a high-confidence tripwire, not a complete inventory.

**Response.**
1. Verify the requested files are not actually served (check for 200 responses)
1. If any returned 200, treat as data exposure and rotate exposed secrets

---

### Attack Tool User-Agent

`web_attack_tool_agent` · **LOW** · stable

**Hypothesis.** Client identifies itself as a known offensive security tool

**ATT&CK.** T1595

**Known false positives.**
- Authorised penetration testing
- Internal vulnerability management scans

**Evasion.** Change the user agent string. Trivially evaded - this rule is low severity precisely because it only catches the careless, and earns its place as a corroborating signal in correlation chains.

**Response.**
1. Confirm whether an authorised assessment is scheduled
1. Low severity alone, but a strong corroborating signal when correlated

---


## Correlation chains

### Web Exploitation Followed by Host Access

`chain_exploit_to_access` · **CRITICAL** · experimental

**Hypothesis.** Application attack payloads from a source that subsequently authenticated to a host.

**ATT&CK.** T1190, T1078

**Chain.** exploitation → access  (within 2h, ordered)

**Response.**
1. Check the web application for webshells written in the exploitation window
1. Review database audit logs for unauthorised queries

---

### Full Intrusion Chain - Recon to Compromise

`chain_recon_to_compromise` · **CRITICAL** · experimental

**Hypothesis.** A single source performed reconnaissance, then credential attacks, then authenticated successfully.

**ATT&CK.** T1595, T1110, T1078

**Chain.** reconnaissance → credential_attack → compromise  (within 4h, ordered)

**Response.**
1. Page the on-call analyst; this is a confirmed intrusion pattern
1. Isolate the target host and preserve volatile memory before reboot
1. Rotate every credential the source could have reached
1. Begin the incident response process and open a formal case

---

### Reconnaissance Followed by Credential Attack

`chain_scan_to_spray` · **HIGH** · experimental

**Hypothesis.** A source that enumerated the environment then attempted credential attacks, indicating a targeted operation rather than opportunistic noise.

**ATT&CK.** T1595, T1110.003

**Chain.** recon → credential_attack  (within 6h, ordered)

**Response.**
1. Elevate monitoring on accounts targeted during the spray
1. Consider pre-emptive blocking of the source range

---

## Behavioral detections

Implemented in `siem/correlation.py::Baseline`. These learn from a training window
rather than matching a pattern.

### Authentication at Unusual Hour for User
`behavior_unusual_hour` · **MEDIUM** · T1078

**Hypothesis.** A compromised account is operated by someone in a different timezone
or working around the legitimate user's schedule.

**Known false positives.** Shift changes, on-call rotations, travel. Suppressed
entirely for internal sources after tuning — see docs/TUNING.md.

**Evasion.** Operate the account during its normal hours.

---

### User Authenticated to Host Never Used Before
`behavior_new_host` · **MEDIUM** · T1021

**Hypothesis.** Lateral movement reaches hosts the legitimate user never touches.

**Known false positives.** Role changes, project onboarding, new infrastructure.

**Evasion.** Move only to hosts within the account's normal footprint, which
constrains the attacker usefully even when it works.

---

### Anomalous Event Volume From Source
`behavior_volume_outlier` · **LOW** · T1595

**Hypothesis.** Automated tooling generates volume well outside the population norm
(3 sigma above mean).

**Known false positives.** Jump hosts, CI runners, monitoring. Restricted to
external sources after tuning.

**Evasion.** Throttle to blend into normal volume.

---

## Coverage gaps

Honest inventory of what this ruleset does **not** detect:

- Kerberos attacks (Kerberoasting, AS-REP roasting, golden ticket) — needs 4768/4769 collection
- DNS tunnelling and C2 beaconing — needs Zeek DNS and conn logs with periodicity analysis
- Cloud control-plane abuse — needs CloudTrail or equivalent
- Data exfiltration by volume — needs network flow records
- Insider threat with legitimate credentials and normal behaviour — largely undetectable by these methods
- Supply-chain and signed-binary abuse — needs integrity monitoring

Each gap is a known limitation with a known telemetry requirement, not an oversight.

