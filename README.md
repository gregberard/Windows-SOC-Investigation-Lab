# Windows SOC Investigation Lab

## Overview

This project simulates a junior Security Operations Center (SOC) investigation using native Windows security logging and endpoint telemetry.

The investigation focuses on identifying failed authentication attempts, analyzing Windows process creation events, correlating activity across multiple security events, and determining whether observed behavior is benign, suspicious, or malicious.

The investigation follows a practical SOC workflow:

**Alert → Evidence Collection → Analysis → Correlation → Verdict → Response → Documentation**

---

## Objectives

* Investigate failed Windows authentication events
* Analyze Windows Security Event ID 4625
* Investigate process creation using Event ID 4688
* Analyze parent/child process relationships
* Identify system and network discovery activity
* Investigate PowerShell execution
* Develop basic detection logic
* Document investigation findings and recommended response actions
* Practice distinguishing suspicious activity from confirmed malicious behavior

---

## Environment

**Operating System:** Windows 11

**Host:** GREGPC

**Test Account:** SOC_Test

**Tools:**

* Windows Event Viewer
* Windows Security Event Log
* Command Prompt
* PowerShell
* auditpol
* Windows Security Event IDs 4625 and 4688

---

## Investigation Scenario

A dedicated test account was created to simulate a potentially compromised user account.

Multiple failed authentication attempts were generated against the account to simulate password-guessing or unauthorized authentication activity.

The resulting Windows Security events were investigated to determine:

* Which account was targeted
* Where the authentication attempts originated
* Whether the attempts were local or remote
* Why authentication failed
* Whether authentication eventually succeeded
* What processes executed under the account
* Whether the resulting activity represented normal administration or suspicious behavior

---

## Investigation 1 — Failed Authentication

### Event ID 4625

Windows Security Event ID 4625 records failed logon attempts.

### Observed Evidence

| Field                  | Value      |
| ---------------------- | ---------- |
| Target Account         | SOC_Test   |
| Logon Type             | 2          |
| Workstation            | GREGPC     |
| Source IP              | 127.0.0.1  |
| Status                 | 0xc000006d |
| SubStatus              | 0xc000006a |
| Authentication Package | Negotiate  |

### Analysis

The authentication attempts originated from the local host.

The `0xc000006a` substatus indicated that an incorrect password was supplied.

Although repeated failed authentication attempts can indicate password guessing or brute-force activity, the local source address and controlled nature of the test indicated that this activity was expected laboratory behavior.

### Verdict

**Benign — Expected Test Activity**

---

## Investigation 2 — Endpoint Process Activity

### Event ID 4688

Windows Security Event ID 4688 records process creation.

The investigation used Event ID 4688 to identify processes and establish parent/child relationships.

### Observed Process Activity

The lab generated the following process relationships:

* `cmd.exe` → `whoami.exe`
* `cmd.exe` → `HOSTNAME.EXE`
* `cmd.exe` → `ipconfig.exe`
* `runas.exe` → `powershell.exe`
* `powershell.exe` → `conhost.exe`

The discovery commands `whoami`, `hostname`, and `ipconfig` are commonly used by both administrators and attackers.

Because of that, the activity was classified as **suspicious / requiring further investigation**, rather than automatically considered malicious.

---

## Discovery Activity

The following discovery commands were executed:

* `whoami`
* `hostname`
* `ipconfig`
* `Get-Process`
* `Get-NetTCPConnection`

These commands are legitimate Windows administration utilities but can also be used by attackers during post-compromise reconnaissance.

### Analysis

The commands alone were not sufficient to establish malicious activity.

A SOC analyst should correlate the process activity with:

* Authentication events
* User identity
* Process ancestry
* Command-line arguments
* Network connections
* Privilege changes
* Persistence mechanisms
* Additional endpoint telemetry

### Verdict

**Suspicious — Investigate Further**

The activity was not classified as confirmed malicious because there was insufficient evidence of compromise.

---

## Detection Logic

The project includes basic detection concepts for authentication failures, discovery activity, and PowerShell execution.

### Multiple Failed Logons

Potential detection logic:

* Event ID 4625
* Five or more failures
* Same source
* Within a ten-minute window

Investigation should determine:

* Target account
* Source system
* Local versus remote origin
* Whether a successful login followed the failures
* Whether multiple accounts were targeted
* Whether related endpoint activity occurred

---

### Suspicious Discovery Activity

Potential detection logic:

* `whoami.exe`
* Combined with one or more discovery utilities such as:

  * `hostname.exe`
  * `ipconfig.exe`
  * `systeminfo.exe`
  * `tasklist.exe`
* Executed by the same user within a short time period

The presence of these commands should trigger investigation rather than an automatic malicious verdict.

---

### PowerShell Activity

PowerShell execution should receive additional investigation when associated with:

* Suspicious parent processes
* Encoded commands
* Download activity
* Unusual users
* Privilege escalation
* Persistence
* Network connections
* Other suspicious endpoint activity

PowerShell itself should not automatically be classified as malicious because it is a legitimate administrative tool.

---

## Analyst Workflow

### 1. Detect

Identify authentication or endpoint activity that may require investigation.

### 2. Collect Evidence

Extract relevant fields from Windows Security events.

### 3. Analyze

Determine what occurred, who performed the activity, and where it originated.

### 4. Correlate

Compare authentication events with process activity and other available telemetry.

### 5. Determine Verdict

Classify the activity as:

* Benign
* Suspicious
* Malicious

### 6. Respond

Recommend additional investigation, containment, remediation, or escalation based on the evidence.

### 7. Document

Record the evidence, reasoning, verdict, and recommended actions.

---

## Evidence

The repository includes screenshots demonstrating the investigation:

* `evidence-4625-failed-login.png` — Windows failed authentication event
* `evidence-4688-process-creation.png` — Windows process creation investigation

Additional investigation details are documented in:

* `incident-report.md`
* `investigation-notes.md`
* `detections.md`

---

## Key Lessons

This investigation demonstrated several important SOC analyst skills:

* Windows authentication investigation
* Windows event log analysis
* Process investigation
* Parent/child process analysis
* System discovery detection
* PowerShell monitoring
* Evidence-based decision making
* Basic detection engineering
* Incident documentation
* Differentiating suspicious behavior from confirmed compromise

A major lesson from the investigation was that suspicious activity should not automatically be classified as malicious.

Individual commands such as `whoami`, `hostname`, and `ipconfig` can be completely legitimate. Context, correlation, and additional evidence are required before determining whether an incident represents an actual compromise.

---

## Future Improvements

Potential future enhancements include:

* Forwarding Windows logs to a SIEM
* Building equivalent detections in Microsoft Sentinel or another SIEM
* Adding Sysmon telemetry
* Creating PowerShell-specific detections
* Simulating a successful unauthorized login
* Adding network-based investigation
* Investigating persistence mechanisms
* Creating automated alerting and response workflows

---

## Project Outcome

This lab demonstrates a practical SOC investigation workflow using native Windows telemetry.

Rather than simply identifying individual security events, the investigation focuses on **evidence collection, event correlation, analytical reasoning, verdict determination, and incident documentation**.

These skills form the foundation for working with enterprise SIEM, EDR, and security monitoring platforms.
