# Detection rules

| Rule ID | Severity | Trigger | Likely investigation |
|---|---|---|---|
| AUTH_BRUTE_FORCE | High | 5 failures from one IP in 10 minutes | Review account/host, rate-limit and MFA controls |
| AUTH_PASSWORD_SPRAY | High | Failed attempts against 4 unique usernames from one IP in 15 minutes | Review account targeting and IAM alerts |
| AUTH_SUCCESS_AFTER_FAILURES | Critical | Success for same IP+username after 3 failures in 15 minutes | Verify successful sign-in identity, IP, MFA, and device |
| HTTP_RATE_SPIKE | Medium | 20 requests from one IP in 60 seconds | Compare normal traffic and permitted crawlers |
| HTTP_SENSITIVE_PATH | Medium | URL path includes a sensitive file/admin signature | Check response codes, server posture, and WAF logs |

## Detection methodology

The analyzer sorts events by timestamp and processes them with per-IP deques. An event entering a deque causes entries outside that rule's time window to expire. This is simpler than a production SIEM: no geo-IP enrichment, no threat intel, no persistent state, no log-source integrity controls, and no distributed correlation. Thresholds are demonstration settings, not universal safe defaults.

## Responsible use

Only analyze logs you are authorized to access. Treat findings as leads for review, not automatic proof of malicious activity. Documentation IP ranges used in the sample (`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`) are intentionally non-routable examples.
