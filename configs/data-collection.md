# Data Collection Configuration

## Overview

The mini SOC collects selected Windows telemetry from `DC01` and forwards it to the Log Analytics workspace `law-mini-soc` through Azure Monitor Agent.

The environment uses two main ingestion paths:

- Windows Security Events → `SecurityEvent`
- Operational Windows Event Logs → `Event`

This separation allows native Windows Security auditing, Sysmon telemetry and PowerShell logging to be investigated independently while still being correlated in Microsoft Sentinel.

---

## SecurityEvent

Windows Security events are collected through the **Windows Security Events via AMA** connector.

Relevant event IDs used in the lab include:

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 4698 | Scheduled task creation |
| 4702 | Scheduled task update |

These events are stored in the:

`SecurityEvent`

table in Log Analytics / Microsoft Sentinel.

### Example use cases

- `4625` → Detect repeated failed authentication attempts
- `4688` → Detect suspicious process execution and command-line arguments
- `4698` → Detect creation of scheduled tasks that may provide persistence

---

## Event

Operational Windows logs are collected through the custom DCR:

`dcr-mini-soc-operational`

The DCR currently collects selected events using XPath filters.

### Sysmon

Log:

`Microsoft-Windows-Sysmon/Operational`

Collected event:

`Event ID 1 — Process Creation`

XPath:

`Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1)]]`

Sysmon Event ID 1 provides additional process execution telemetry that can be correlated with Windows Security Event 4688.

The data is stored in the:

`Event`

table.

---

### PowerShell

Log:

`Microsoft-Windows-PowerShell/Operational`

Collected event:

`Event ID 4104 — Script Block Logging`

XPath:

`Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]`

Event 4104 provides visibility into PowerShell script content and is useful for investigating suspicious or encoded PowerShell execution.

The data is also stored in the:

`Event`

table.

---

## Data Flow

```text
DC01
│
├── Windows Security Log
│      ↓
│   Windows Security Events via AMA
│      ↓
│   SecurityEvent
│
├── Sysmon Operational
│      ↓
│   dcr-mini-soc-operational
│      ↓
│   Event
│
└── PowerShell Operational
       ↓
    dcr-mini-soc-operational
       ↓
    Event
```

## Why Not Collect Everything?

The lab collects only the telemetry required for the implemented detection scenarios.

Reasons include:

- Reduce ingestion volume
- Reduce unnecessary noise
- Control Log Analytics / Sentinel costs
- Keep investigations focused
- Make the dataset easier to understand
- Improve signal-to-noise ratio

Data Collection Rules allow filtering to occur at collection time, meaning irrelevant events do not need to be forwarded to the workspace.

---

## Detection Coverage

The collected telemetry currently supports the following lab detections:

| Detection | Primary telemetry |
|---|---|
| Multiple Failed Logons | Security Event 4625 |
| Encoded PowerShell Execution | Security Event 4688 + Sysmon Event 1 + PowerShell 4104 |
| Scheduled Task Creation | Security Event 4698 |

The objective is not to collect every possible Windows event, but to collect enough high-value telemetry to demonstrate the full SOC workflow:

`telemetry → hunting → detection → alert → incident → investigation`