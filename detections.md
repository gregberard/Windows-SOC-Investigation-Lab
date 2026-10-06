\# Detection Rules



\## Detection 1 — Multiple Failed Logons



\### Purpose



Identify repeated failed authentication attempts that may indicate password guessing, brute-force activity, or unauthorized access.



\### Windows Event



\* Event ID: 4625

\* Log Source: Windows Security



\### Investigation Fields



\* TargetUserName

\* LogonType

\* WorkstationName

\* IpAddress

\* Status

\* SubStatus



\### Example Detection Logic



Alert when:



Event ID = 4625



AND



5 or more failures



FROM



the same source



WITHIN



10 minutes



\### Analyst Investigation



When triggered, determine:



1\. Which account was targeted?

2\. Where did the attempts originate?

3\. Were the attempts local or remote?

4\. Did a successful login occur afterward?

5\. Were multiple accounts targeted?

6\. What processes executed around the same time?

7\. Is the source host known and trusted?



\---



\## Detection 2 — Suspicious Discovery Activity



\### Purpose



Identify common discovery commands that may indicate an attacker attempting to understand the compromised system.



\### Windows Event



\* Event ID: 4688

\* Log Source: Windows Security



\### Example Processes



whoami.exe

hostname.exe

ipconfig.exe

net.exe

systeminfo.exe

tasklist.exe



\### Example Detection Logic



Alert when multiple discovery utilities execute under the same user within a short period.



Example:



whoami.exe



AND



(hostname.exe OR ipconfig.exe OR systeminfo.exe OR tasklist.exe)



WITHIN



5 minutes



\### Analyst Investigation



Determine:



1\. Which user executed the commands?

2\. What process launched them?

3\. Was PowerShell involved?

4\. Was the activity interactive or automated?

5\. Did authentication activity occur beforehand?

6\. Were network connections established afterward?

7\. Is the behavior expected for this user or system?



\---



\## Detection 3 — PowerShell Execution



\### Purpose



Identify PowerShell activity that may require additional investigation.



\### Windows Event



\* Event ID: 4688

\* Log Source: Windows Security



\### Investigation Fields



\* NewProcessName

\* ParentProcessName

\* CommandLine

\* SubjectUserName



\### Analyst Considerations



PowerShell is a legitimate administrative tool and should not automatically be classified as malicious.



Investigate further when PowerShell execution is associated with:



\* Suspicious parent processes

\* Encoded commands

\* Download activity

\* Unusual users

\* Privilege escalation

\* Persistence

\* Network connections

\* Other suspicious endpoint activity



