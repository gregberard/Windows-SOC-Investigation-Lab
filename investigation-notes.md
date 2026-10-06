\# Investigation Notes



\## Detection



\### Event ID 4625 — Failed Logon



Multiple failed authentication attempts were observed against the `SOC\_Test` account.



Key evidence:



\- TargetUserName: `SOC\_Test`

\- LogonType: `2`

\- WorkstationName: `GREGPC`

\- IpAddress: `127.0.0.1`

\- Status: `0xc000006d`

\- SubStatus: `0xc000006a`

\- AuthenticationPackageName: `Negotiate`



\### Interpretation



The authentication attempts originated from the local system and used an incorrect password.



Because the source was `127.0.0.1`, the activity did not indicate an external network-based authentication attempt.



\---



\## Endpoint Investigation



\### Event ID 4688 — Process Creation



Process creation auditing was enabled to investigate endpoint activity.



Observed process chains:



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

Discovery Activity

The following commands were executed under the SOC_Test account:

whoami
hostname
ipconfig
Get-Process
Get-NetTCPConnection

These commands can be used for legitimate administration but are also commonly associated with attacker discovery activity.

Analyst Reasoning

The investigation demonstrates why individual events should not automatically be classified as malicious.

A SOC analyst should correlate:

Authentication activity
Account identity
Source address
Process ancestry
Command-line arguments
Timing
Network connections
Privilege level
Persistence activity
Additional endpoint and SIEM telemetry

The available evidence in this controlled lab did not establish compromise.

The discovery activity was therefore classified as:

Suspicious — Investigate Further

rather than confirmed malicious activity.
