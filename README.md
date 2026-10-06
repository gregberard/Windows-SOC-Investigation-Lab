\# Windows SOC Investigation Lab



\## Overview



This project simulates a junior Security Operations Center (SOC) investigation using native Windows security logging and endpoint telemetry.



The investigation focuses on identifying failed authentication attempts, analyzing Windows process creation events, correlating activity across multiple security events, and determining whether observed behavior is benign, suspicious, or malicious.



The project was designed to demonstrate the investigation workflow used by SOC analysts:



\*\*Alert → Evidence Collection → Analysis → Correlation → Verdict → Response\*\*



\---



\## Objectives



\* Investigate failed Windows authentication events.

\* Analyze Windows Security Event ID 4625.

\* Investigate process creation using Event ID 4688.

\* Analyze parent/child process relationships.

\* Identify system and network discovery activity.

\* Investigate PowerShell execution.

\* Develop basic detection logic.

\* Document investigation findings and recommended response actions.

\* Practice distinguishing suspicious activity from confirmed malicious behavior.



\---



\## Environment



\*\*Operating System:\*\* Windows 11



\*\*Host:\*\* GREGPC



\*\*Test Account:\*\* SOC\_Test



\*\*Tools:\*\*



\* Windows Event Viewer

\* Windows Security Event Log

\* Command Prompt

\* PowerShell

\* `auditpol`

\* Windows Event IDs 4625 and 4688



\---



\## Investigation Scenario



A dedicated test account was created to simulate a potentially compromised user account.



Multiple failed authentication attempts were generated against the account to simulate password-guessing or unauthorized authentication activity.



The resulting Windows Security events were investigated to determine:



\* Which account was targeted.

\* Where the authentication attempts originated.

\* Whether the attempts were local or remote.

\* Why authentication failed.

\* Whether authentication eventually succeeded.

\* What processes executed under the account.

\* Whether the resulting activity represented normal administration or suspicious behavior.



\---



\## Investigation 1 — Failed Authentication



\### Event ID 4625



Windows Security Event ID 4625 records failed logon attempts.



Observed evidence:



| Field                  | Value        |

| ---------------------- | ------------ |

| Target Account         | `SOC\_Test`   |

| Logon Type             | `2`          |

| Workstation            | `GREGPC`     |

| Source IP              | `127.0.0.1`  |

| Status                 | `0xc000006d` |

| SubStatus              | `0xc000006a` |

| Authentication Package | `Negotiate`  |



\### Analysis



The authentication attempts originated from the local host.



The `0xc000006a` substatus indicated that an incorrect password was supplied.



Although repeated failed authentication attempts can indicate password guessing or brute-force activity, the source address and controlled nature of the test indicated that this activity was expected laboratory behavior.



\### Verdict



\*\*Benign — Expected Test Activity\*\*



\---



\## Investigation 2 — Endpoint Process Activity



\### Event ID 4688



Windows Security Event ID 4688 records process creation.



Process activity associated with the test account included:



```text

cmd.exe

└── whoami.exe



cmd.exe

└── HOSTNAME.EXE



cmd.exe

└── ipconfig.exe



runas.exe

└── powershell.exe

&#x20;   └── conhost.exe

```



\### Discovery Activity



The following discovery commands were executed:



\* `whoami`

\* `hostname`

\* `ipconfig`

\* `Get-Process`

\* `Get-NetTCPConnection`



These commands are legitimate Windows administration utilities but can also be used by attackers during post-compromise reconnaissance.



\### Analysis



The commands alone were not sufficient to establish malicious activity.



A SOC analyst should correlate the process activity with:



\* Authentication events

\* User identity

\* Process ancestry

\* Command-line arguments

\* Network connections

\* Privilege changes

\* Persistence mechanisms

\* Additional endpoint telemetry



\### Verdict



\*\*Suspicious — Investigate Further\*\*



The activity was not classified as confirmed malicious because there was insufficient evidence of compromise.



\---



\## Detection Logic



The project includes basic detection concepts for:



\### Multiple Failed Logons



Alert when:



```text

Event ID = 4625

AND

5 or more failures

FROM

the same source

WITHIN

10 minutes

```



\### Suspicious Discovery Activity



Look for multiple discovery utilities executed by the same user within a short period:



```text

whoami.exe

AND

(hostname.exe OR ipconfig.exe OR systeminfo.exe OR tasklist.exe)

WITHIN

5 minutes

```



\### PowerShell Activity



PowerShell execution should receive additional investigation when associated with:



\* Suspicious parent processes

\* Encoded commands

\* Download activity

\* Unusual users

\* Privilege escalation

\* Persistence

\* Network connections

\* Other suspicious endpoint activity



PowerShell itself should not automatically be classified as malicious because it is a legitimate administrative tool.



\---



\## Analyst Workflow



The investigation followed this workflow:



\### 1. Detect



Identify authentication or endpoint activity that may require investigation.



\### 2. Collect Evidence



Extract relevant fields from Windows Security events.



\### 3. Analyze



Determine what occurred, who performed the activity, and where it originated.



\### 4. Correlate



Compare authentication events with process activity and other available telemetry.



\### 5. Determine Verdict



Classify the activity as:



\* Benign

\* Suspicious

\* Malicious



\### 6. Respond



Recommend additional investigation, containment, remediation, or escalation based on the evidence.



\### 7. Document



Record the evidence, reasoning, verdict, and recommended actions.



\---



\## Key Lessons



This investigation demonstrated several important SOC analyst skills:



\* Windows authentication investigation

\* Windows event log analysis

\* Process investigation

\* Parent/child process analysis

\* System discovery detection

\* PowerShell monitoring

\* Evidence-based decision making

\* Basic detection engineering

\* Incident documentation

\* Differentiating suspicious behavior from confirmed compromise



A major lesson from the investigation was that suspicious activity should not automatically be classified as malicious.



Individual commands such as `whoami`, `hostname`, and `ipconfig` can be completely legitimate. Context, correlation, and additional evidence are required before determining whether an incident represents an actual compromise.



\---



\## Future Improvements



Potential future enhancements include:



\* Forwarding Windows logs to a SIEM.

\* Building equivalent detections in Microsoft Sentinel or another SIEM.

\* Adding Sysmon telemetry.

\* Creating PowerShell-specific detections.

\* Simulating a successful unauthorized login.

\* Adding network-based investigation.

\* Investigating persistence mechanisms.

\* Creating automated alerting and response workflows.



\---



\## Project Outcome



This lab demonstrates a practical SOC investigation workflow using native Windows telemetry.



Rather than simply identifying individual security events, the investigation focuses on \*\*evidence collection, event correlation, analytical reasoning, verdict determination, and incident documentation\*\*.



These skills form the foundation for working with enterprise SIEM, EDR, and security monitoring platforms.



