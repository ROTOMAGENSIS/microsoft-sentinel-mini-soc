# Windows Auditing Configuration

## Overview

Windows auditing was configured on `DC01` to generate the security events required by the lab detections.

The goal was to make sure important authentication, process creation, and scheduled task activity was recorded locally before being collected by Azure Monitor Agent and sent to Microsoft Sentinel.

Local validation was performed before troubleshooting Sentinel ingestion. This helped distinguish Windows auditing issues from Azure Monitor Agent, Data Collection Rule, or Log Analytics issues.

---

## Logon Auditing

Logon auditing was enabled for both successful and failed authentication attempts.

Verification:

```powershell
auditpol /get /subcategory:"Logon"
```

Expected configuration:

```text
Logon    Success and Failure
```

This allows Windows to generate authentication events such as:

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |

### Failed Logon Test

Event ID 4625 was generated with:

```cmd
runas /user:Administrator cmd.exe
```

An intentionally incorrect password was entered.

The event was then validated locally before checking its ingestion in Microsoft Sentinel.

Example validation:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
} -MaxEvents 5 |
Format-List TimeCreated, Id, Message
```

---

## Process Creation Auditing

Process creation auditing was enabled to generate Windows Security Event ID 4688.

Verification:

```powershell
auditpol /get /subcategory:"Process Creation"
```

If required, it can be enabled with:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Event ID 4688 provides information about newly created processes and was used in the Encoded PowerShell detection scenario.

Example local validation:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 5 |
Format-List TimeCreated, Id, Message
```

The event can contain useful information such as:

- the account that created the process;
- the new process path;
- the parent process;
- the command line.

---

## Command-Line Visibility

Process creation events are more useful when command-line arguments are available.

This was important for detecting PowerShell execution using arguments such as:

```text
-EncodedCommand
```

The Encoded PowerShell scenario relied on Event ID 4688 to identify the PowerShell process and its command line.

Additional context was then obtained from:

- Sysmon Event ID 1;
- PowerShell Event ID 4104.

---

## Scheduled Task Auditing

Scheduled task activity was also used in the lab.

The main events of interest were:

| Event ID | Description |
|---|---|
| 4698 | A scheduled task was created |
| 4702 | A scheduled task was updated |

The lab created the following benign scheduled task:

```text
SOC-Lab-Notepad
```

The task launches:

```text
notepad.exe
```

when a user logs on.

Event ID 4698 was used to detect the creation of the task.

Example validation:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4698
} -MaxEvents 5 |
Format-List TimeCreated, Id, Message
```

---

## Sysmon

Sysmon was installed to provide additional process telemetry.

The main event used in the lab was:

| Event ID | Description |
|---|---|
| 1 | Process creation |

The Sysmon operational log is:

```text
Microsoft-Windows-Sysmon/Operational
```

Example local validation:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=1
} -MaxEvents 5 |
Format-List TimeCreated, Id, Message
```

Sysmon Event ID 1 was used as an additional source for the Encoded PowerShell investigation.

---

## PowerShell Logging

PowerShell Script Block Logging was used to provide visibility into executed PowerShell code.

The main event used was:

| Event ID | Description |
|---|---|
| 4104 | PowerShell Script Block Logging |

The PowerShell operational log is:

```text
Microsoft-Windows-PowerShell/Operational
```

Example local validation:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 5 |
Format-List TimeCreated, Id, Message
```

Event ID 4104 was used to review the PowerShell content during the Encoded PowerShell investigation.

---

## Events Used in the Lab

The main Windows events used by the project were:

| Source | Event ID | Purpose |
|---|---:|---|
| Windows Security | 4624 | Successful logon |
| Windows Security | 4625 | Failed logon |
| Windows Security | 4688 | Process creation |
| Windows Security | 4698 | Scheduled task creation |
| Windows Security | 4702 | Scheduled task update |
| Sysmon | 1 | Process creation |
| PowerShell | 4104 | Script block logging |

---

## Validation Approach

The same validation approach was used throughout the lab:

1. Generate the activity on `DC01`.
2. Confirm that the expected event exists locally.
3. Confirm that the event reaches Log Analytics.
4. Hunt the event with KQL in Microsoft Sentinel.
5. Use the telemetry to build or validate an analytics rule.

This approach helped avoid troubleshooting the cloud ingestion pipeline when the expected event had not been generated locally.

---

## Scope

The auditing configuration in this lab was intentionally limited to the telemetry required by the implemented detections.

The project does not attempt to enable every available Windows audit category.

The goal was to collect useful telemetry for:

- authentication monitoring;
- process execution monitoring;
- PowerShell investigation;
- scheduled task detection;
- basic SOC Tier 1 triage.

More information about how these events are collected and sent to Microsoft Sentinel is available in:

`configs/data-collection.md`
