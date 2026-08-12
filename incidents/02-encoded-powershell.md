# Incident 02 — Encoded PowerShell Execution

## Alert

Detection of PowerShell executed with an encoded command.

## Data Sources

- Windows Security Event 4688
- Sysmon Event 1
- PowerShell Event 4104

## Initial Triage

Host:
DC01

User:
Administrator

Process:
powershell.exe

Parent:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Command Line:

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAQwA6AFwATABhAGIAXABlAG4AYwBvAGQAZQBkAC0AdABlAHMAdAAtADIALgB0AHgAdAAgAC0AVgBhAGwAdQBlACAAIgBTAEUAQwBPAE4ARAAtAFMATwBDAC0AVABFAFMAVAAiAA=="

## Investigation

1. Reviewed process creation.
2. Identified encoded PowerShell arguments.
3. Decoded the Base64 payload.
4. Correlated execution with Sysmon.
5. Reviewed PowerShell Script Block logs.
6. Reviewed surrounding host activity.

## Findings

The rule successfully detected the behavior it was designed to detect. The following investigation revealed that it was a benign simulation.

## MITRE ATT&CK

T1059.001 — PowerShell

## Verdict

True Positive — Benign Simulation

## Escalation

Not required.

## Potential False Positives

- Administrative scripts
- Deployment tooling
- Software management
- Legitimate automation

## Detection Improvements

The current rule detects any PowerShell execution using encoded arguments, which may generate false positives from legitimate administration.
- considering the parent process and execution path;
- excluding approved administrative tooling;
- increasing severity when encoded PowerShell is followed by network, credential-access, or persistence activity.