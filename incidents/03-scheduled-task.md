# Incident 03 — Scheduled Task Creation

## Alert

Detection of a new Windows scheduled task created on the monitored host.

## Data Source

- Windows Security Event 4698

## Initial Triage

Host:
DC01

Task Name:
SOC-Lab-Notepad

Creator Account:
Administrator

Trigger:
User logon

Executable:
notepad.exe

Arguments:
None


Creation Time:
11/08/2026 18:37:31

## Investigation

1. Reviewed Windows Security Event 4698.
2. Identified the newly created scheduled task.
3. Reviewed the task XML contained in the event.
4. Identified the account responsible for creating the task.
5. Reviewed the configured trigger.
6. Identified the executable and command-line arguments.
7. Reviewed the execution context and privilege level.
8. Checked surrounding host activity for additional suspicious behavior.
9. Determined whether the task could provide persistence.
10. Confirmed whether the activity was expected or malicious.

## Findings

A new scheduled task named `SOC-Lab-Notepad` was created on `DC01`.

The task was configured to execute:

`notepad.exe`

The configured trigger was:

`User logon`

No additional command-line arguments or malicious payloads were identified.

The scheduled task provides a persistence mechanism because it can automatically execute a program when a user logs on.

However, investigation confirmed that the task was intentionally created as part of the SOC lab and only launches Windows Notepad.

No additional suspicious activity was identified around the creation of the task.

## MITRE ATT&CK

T1053.005 — Scheduled Task/Job: Scheduled Task

## Verdict

True Positive — Benign Simulation

## Security Impact

None.

The scheduled task was successfully created and demonstrated a persistence-capable mechanism, but its configured action was benign.

## Escalation

Not required.

The activity was confirmed as an intentional lab simulation and no malicious payload or subsequent suspicious behavior was identified.

## Potential False Positives

- Administrative scheduled tasks
- Software installation or update tasks
- Backup software
- Monitoring agents
- Maintenance scripts
- Enterprise management tools
- Legitimate user automation

## Detection Improvements

The current rule detects the creation of any scheduled task through Windows Security Event 4698.

Future tuning could include:

- excluding known and approved scheduled tasks;
- monitoring unusual task names or paths;
- increasing severity when tasks execute from user-writable or temporary directories;
- identifying suspicious executables such as PowerShell, cmd.exe, wscript.exe or rundll32.exe;
- reviewing encoded or obfuscated command-line arguments;
- correlating task creation with suspicious process execution or network activity;
- increasing severity when the task runs with elevated privileges or as SYSTEM;
- baselining commonly created tasks to reduce administrative noise.

## Analyst Conclusion

The detection successfully identified the creation of a new scheduled task on `DC01`.

The task had persistence capability because it was configured to execute automatically at user logon.

Investigation confirmed that the task only launched `notepad.exe` and was deliberately created for detection validation.

The alert therefore represents a true positive for scheduled task creation, but the underlying activity was benign.

No escalation was required.
