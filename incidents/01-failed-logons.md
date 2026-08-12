# Incident 01 — Multiple Failed Logons

## Alert

Detection of multiple failed logon attempts against a Windows account.

## Data Source

- Windows Security Event 4625

## Initial Triage

Host:
DC01

Target Account:
Administrator

Event ID:
4625

Logon Result:
Failed authentication

Observed Behavior:
Multiple failed authentication attempts against the same account within a short time window.

## Investigation

1. Reviewed Windows Security Event 4625 entries.
2. Identified the account targeted by the failed authentication attempts.
3. Counted the number of failed logons within the detection window.
4. Reviewed the source address and logon type.
5. Checked whether the failed attempts targeted one account or several accounts.
6. Correlated the activity with Event ID 4624 to determine whether a successful logon occurred afterwards.
7. Reviewed surrounding host activity for additional suspicious behavior.

## Findings

Multiple failed authentication attempts were generated against the `Administrator` account.

Source: Local host

Number of attempts: 12

Interval: FirstSeen [UTC] 2026-08-12T01:08:15.0026446Z / LastSeen [UTC] 2026-08-12T01:19:22.3804201Z

Logon type: 2/interactive

Successful authentication afterwards: No

The activity matched the detection condition for repeated failed logons.

No evidence of a successful authentication following the failed attempts was identified during the investigated time window.

No additional suspicious activity was observed on the host.

The events were intentionally generated as part of the SOC lab.

## MITRE ATT&CK

T1110 — Brute Force

## Verdict

True Positive — Benign Simulation

## Security Impact

None.

The authentication attempts failed and no unauthorized access occurred.

## Escalation

Not required.

The behavior was confirmed as an intentional lab simulation and no successful authentication or subsequent malicious activity was identified.

## Potential False Positives

- User repeatedly entering an incorrect password
- Recently changed passwords
- Cached or stale credentials
- Misconfigured services or scheduled tasks
- Applications using outdated credentials
- Administrative testing
- Legitimate troubleshooting

## Detection Improvements

The current rule detects repeated failed authentication attempts based primarily on Event ID 4625.

Future tuning could include:

- grouping failed attempts by target account and source IP;
- considering the logon type to distinguish interactive, network and remote authentication attempts;
- increasing severity when many accounts are targeted from the same source;
- increasing severity when a successful Event ID 4624 follows repeated failures;
- excluding known service accounts or expected authentication failures;
- adjusting the failed-attempt threshold and time window based on the normal environment baseline;
- correlating repeated failures with subsequent privilege escalation or suspicious process execution.

## Analyst Conclusion

The detection successfully identified repeated failed authentication attempts against the monitored Windows account.

The activity represents a true positive for the behavior targeted by the rule, but investigation confirmed that it was a controlled benign simulation.

No escalation was required.

