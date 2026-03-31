<img width="683" height="1024" alt="image" src="https://github.com/user-attachments/assets/b9a09f79-ff7a-4886-bc4d-d66623d0e34e" />

# SOC Incident Investigation: Azuki: Port of Entry

**Analyst:** Adrian Bolt\
**Date Completed:** 31 March 2026\
**Environment Investigated:** Azuki Infrastructure (`azuki-sl`)\
**Timeframe:** 19 November 2025 (UTC) \
**Platform:** Microsoft Defender for Endpoint (MDE) + Microsoft Sentinel — KQL / Log Analytics Workspace\
**Source:** Cyber Range with SancLogic 

---

## Table of Contents

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Environment Overview](#environment-overview)
3. [Key Findings](#key-findings)
4. [Attack Timeline](#attack-timeline)
5. [All Flags Quick Reference](#all-flags-quick-reference)
6. [Flag-by-Flag Analysis](#flag-by-flag-analysis)
7. [Conclusion](#conclusion)
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Recommendations](#recommendations)

---


## 1. Executive Summary

This investigation found that an attacker broke into the Azuki system by logging in through Remote Desktop (RDP) using a stolen account (`kenji.sato`) from an outside IP (88.97.178.12). Once inside `azuki-sl`, the attacker looked around the network (`arp.exe`), hid files in `C:\ProgramData\WindowsCache`, and used built-in Windows tools like `certutil.exe` to download more malware. They avoided detection by turning off parts of Windows Defender and made sure they could stay in the system by creating a scheduled task ("Windows Update Check") and a backdoor account (`support`). The attacker stole passwords from memory using `mm.exe` with `sekurlsa::logonpasswords`, connected to a command-and-control server (78.141.196.6 over port 443), and compressed stolen data into `export-data.zip` before sending it out through Discord. They also cleared security logs (`wevtutil.exe`) to hide their actions and attempted to move to another system (10.1.0.188) using RDP (`mstsc.exe`). All findings were identified using Microsoft Defender for Endpoint (MDE) logs and KQL queries by analyzing activity across logon, process, file, registry, and network events.



---

## 2. Environment Overview

| Host     | Role                     | OS      | Compromise Status        |
|----------|--------------------------|---------|--------------------------|
| azuki-sl | Primary workstation      | Windows | **Fully compromised**    |

**Victim Organization:** Azuki Environment (Cyber Range)  
**Incident Date:** November 19, 2025  
**Attack Type:** Multi-stage intrusion (RDP → Persistence → Credential Access → Exfiltration)  
**C2 Server:** `78.141.196.6`  
**Exfiltration Channel:** `Discord`  

---

## 3. Key Findings

## Key Findings

- The attacker got into the system using Remote Desktop (RDP) from IP `88.97.178.12` with a stolen account `kenji.sato` on `azuki-sl`

- After getting in, the attacker looked around the network using a basic command (`arp.exe -a`) to see other devices

- The attacker hid their files in `C:\ProgramData\WindowsCache` to keep them out of sight

- They turned off parts of Windows Defender by excluding certain file types and a folder (`C:\Users\KENJI~1.SAT\AppData\Local\Temp`) so they wouldn’t get caught

- The attacker used a built-in Windows tool (`certutil.exe`) to download more malicious files

- They made sure they could stay in the system by creating a scheduled task called "Windows Update Check" that runs a fake file (`svchost.exe`)

- They also created a secret backup account called `support` to get back in anytime

- The attacker stole passwords from memory using a tool (`mm.exe`) with the command `sekurlsa::logonpasswords`

- The system was talking to an attacker-controlled server (`78.141.196.6`) over port 443, which looks like normal internet traffic

- The attacker collected data and saved it into a file called `export-data.zip`

- The stolen data was sent out using Discord

- The attacker deleted security logs using `wevtutil.exe` to hide what they did

- They tried to move to another computer (`10.1.0.188`) using Remote Desktop (`mstsc.exe`)

---

## 4. Attack Timeline

## Attack Timeline

| Timestamp (UTC)       | Tactic              | Action                                                                 | Key Artifact                          |
|----------------------|--------------------|------------------------------------------------------------------------|----------------------------------------|
| 2025-11-19 18:36:18  | Initial Access     | RDP login to `azuki-sl` using compromised account                      | `88.97.178.12`, `kenji.sato`          |
| 2025-11-19 18:37:26  | Command & Control  | Initial outbound connection to attacker-controlled server              | `78.141.196.6`                        |
| 2025-11-19 18:49:27  | Defense Evasion    | Windows Defender exclusions added (extensions + temp directory)        | Registry modifications                |
| 2025-11-19 19:03:18  | Execution          | Malicious script executed to automate attack chain                     | `wupdate.ps1`                         |
| 2025-11-19 19:04:01  | Discovery          | Network enumeration performed using `arp.exe -a`                       | `arp.exe`                             |
| 2025-11-19 19:05:33  | Defense Evasion    | Malware staged in hidden directory                                     | `C:\ProgramData\WindowsCache`         |
| 2025-11-19 19:06:58  | Execution          | Additional payload downloaded using `certutil.exe`                     | `certutil.exe`                        |
| 2025-11-19 19:07:46  | Persistence        | Scheduled task created for persistence                                 | `"Windows Update Check"`              |
| 2025-11-19 19:08:26  | Credential Access  | Credential dumping tool executed                                       | `mm.exe`, `sekurlsa::logonpasswords`  |
| 2025-11-19 19:08:58  | Collection         | Data compressed into archive                                           | `export-data.zip`                     |
| 2025-11-19 19:09:21  | Exfiltration       | Data transmitted externally over HTTPS (Discord channel)               | Port `443`, `Discord`                 |
| 2025-11-19 19:09:48  | Persistence        | Backdoor account created                                               | `support`                             |
| 2025-11-19 19:10:37  | Lateral Movement   | Attempted RDP connection to internal system                            | `10.1.0.188`                          |
| 2025-11-19 19:10:41  | Lateral Movement   | RDP tool executed                                                      | `mstsc.exe`                           |
| 2025-11-19 19:11:39  | Anti-Forensics     | Security logs cleared to hide attacker activity                        | `wevtutil.exe`                        |

---

## 5. All Flags Quick Reference

| #  | Section              | Flag Name                     | Answer / Finding                                      |
|----|---------------------|------------------------------|------------------------------------------------------|
|  1 | Initial Access      | Remote Access Source         | `88.97.178.12`                                       |
|  2 | Initial Access      | Compromised Account          | `kenji.sato`                                         |
|  3 | Discovery           | Network Reconnaissance       | `arp.exe -a`                                         |
|  4 | Defense Evasion     | Malware Staging Directory    | `C:\ProgramData\WindowsCache`                        |
|  5 | Defense Evasion     | File Extension Exclusions    | `3`                                                  |
|  6 | Defense Evasion     | Temp Folder Exclusion        | `C:\Users\KENJI~1.SAT\AppData\Local\Temp`            |
|  7 | Defense Evasion     | Download Utility Abuse       | `certutil.exe`                                       |
|  8 | Persistence         | Scheduled Task Name          | `Windows Update Check`                               |
|  9 | Persistence         | Scheduled Task Target        | `C:\ProgramData\WindowsCache\svchost.exe`            |
| 10 | Command & Control   | C2 Server Address            | `78.141.196.6`                                       |
| 11 | Command & Control   | C2 Communication Port        | `443`                                                |
| 12 | Credential Access   | Credential Dumping Tool      | `mm.exe`                                             |
| 13 | Credential Access   | Memory Extraction Module     | `sekurlsa::logonpasswords`                           |
| 14 | Collection          | Data Archive                 | `export-data.zip`                                    |
| 15 | Exfiltration        | Exfiltration Channel         | `Discord`                                            |
| 16 | Anti-Forensics      | Log Tampering                | `Security`                                           |
| 17 | Persistence         | Backdoor Account             | `support`                                            |
| 18 | Execution           | Malicious Script             | `wupdate.ps1`                                        |
| 19 | Lateral Movement    | Target System                | `10.1.0.188`                                         |
| 20 | Lateral Movement    | Remote Access Tool           | `mstsc.exe`                                          |





---

## Flag-by-Flag Analysis

---

### 🚩 Flag 1: Initial Access | Remote Access Source

**Objective**
Identify the external source of the intrusion.

**Hunt Question**
Identify the source IP address of the Remote Desktop Protocol connection?

**Answer:** `88.97.178.12`

**Query Used**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, RemoteDeviceName, LogonType, AdditionalFields
| sort by TimeGenerated asc
```

**Key Observations**
- Remote login detected from external IP
- Successful authentication recorded
- Entry point confirmed on `azuki-sl`

**Analysis**
We used `DeviceLogonEvents` because RDP activity shows up as login events. The presence of an external IP confirms this was not a local login. This indicates the attacker gained access using valid credentials over RDP.

**MITRE ATT&CK Mapping**

| Field     | Value                                           |
|-----------|-------------------------------------------------|
| Tactic    | Initial Access                                  |
| Technique | T1078: Valid Accounts                           |


**Evidence**

<img width="1499" height="508" alt="image" src="https://github.com/user-attachments/assets/fb2989fb-1aa3-4b3d-8270-f6387be6766e" />


---



### 🚩 Flag 2: Initial Access | Compromised Account

**Objective**
Identify which account was used to gain access.

**Hunt Question**
Identify the user account that was compromised for initial access?

**Answer:** `kenji.sato`

**Query Used**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AdditionalFields.IsLocalLogon == "false"
| project TimeGenerated, AccountName, RemoteIP, RemoteDeviceName, LogonType, AdditionalFields
| sort by TimeGenerated asc
```

**Key Observations**
- Account `kenji.sato` performed remote login
- Login originated from external IP

**Analysis**
The attacker used valid credentials instead of exploiting a vulnerability. This confirms credential compromise as the initial access method

**MITRE ATT&CK Mapping**

| Field     | Value                                           |
|-----------|-------------------------------------------------|
| Tactic    | Initial Access                                  |
| Technique | T1078: Valid Accounts                           |

**Evidence**

<img width="1499" height="508" alt="image" src="https://github.com/user-attachments/assets/0b8949b5-a6e5-4bef-a02c-940d9f192eb1" />



 

---

### 🚩 Flag 3: Initial Access | User Interaction

**Objective**
Determine the parent process of the payload execution to confirm whether a user manually launched the file or whether it was executed through another mechanism.

**Hunt Question**
Identify the command and argument used to enumerate network neighbours?

**Answer:** `"ARP.EXE"`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("arp", "ipconfig", "net view", "nbtstat", "whoami", "hostname", "net user", "net localgroup", "tasklist")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Command used to list network devices
- Executed shortly after initial access


**Analysis**
The attacker began mapping the environment immediately after access to identify other systems.


**MITRE ATT&CK Mapping**

| Field     | Value                                         |
|-----------|-----------------------------------------------|
| Tactic    | Execution                                     |
| Technique | T1016: System Network Configuration Discovery |

**Evidence**
 
<img width="1499" height="512" alt="image" src="https://github.com/user-attachments/assets/f8d856e2-8578-407d-8c08-a81f29bde82c" />


---

### 🚩 Flag 4: Defence Evasion | Malware Staging Directory

**Objective**
Identify where the attacker stored malware on the system.

**Hunt Question**
Identify the PRIMARY staging directory where malware was stored?

**Answer:** `C:\ProgramData\WindowsCache`

**Query Used**

```kql
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated asc
| where ProcessCommandLine has_any ("attrib") 
```

**Key Observations**
- Hidden files were manipulated using `attrib`
- Activity pointed to `C:\ProgramData\WindowsCache`
- Directory used consistently across attack steps

**Analysis**
Attackers commonly use hidden directories to store malware. The use of `attrib` indicates files were intentionally hidden to avoid detection, confirming this directory as the staging locatio


**MITRE ATT&CK Mapping**

| Field     | Value                                           |
|-----------|-------------------------------------------------|
| Tactic    | Defense Evasion                                 |
| Technique | T1564: Hide Artifacts                           |

**Evidence**

<img width="1495" height="479" alt="image" src="https://github.com/user-attachments/assets/81d16f87-1998-4ba0-9c43-c0a2028afd2d" />


---

### 🚩 Flag 5: Defence Evasion | File Extension Exclusions

**Objective**
Identify how Windows Defender protections were weakened.

**Hunt Question**
How many file extensions were excluded from Windows Defender scanning?

**Answer:** `3`

**Query Used**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where RegistryKey contains "Exclusions\\Extensions"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Key Observations**
- Defender exclusions modified
- Multiple extensions excluded
- Changes occurred early in attack

**Analysis**
By excluding file extensions, the attacker ensured certain files would not be scanned, reducing the chance of detection.

**MITRE ATT&CK Mapping**

| Field     | Value                     |
|-----------|---------------------------|
| Tactic    | Defense Evasion           |
| Technique | T1562: Impair Defenses    |

**Evidence**

<img width="1498" height="507" alt="image" src="https://github.com/user-attachments/assets/25cc7703-86a6-4c3c-9e0e-eb322bd70f39" />




---

### 🚩 Flag 6: Defence Evasion | Temporary Folder Exclusion

**Objective**
Identify excluded directories from security scanning.

**Hunt Question**
What temporary folder path was excluded from Windows Defender scanning?

**Answer:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

**Query Used**

```kql
 DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where RegistryKey contains "Exclusions\\Paths"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Key Observations**
- Temp directory excluded from scanning
- Common malware execution location


**Analysis**
Excluding the temp folder allows malware to run freely without triggering Defender alerts.

**MITRE ATT&CK Mapping**

| Field     | Value                                                   |
|-----------|---------------------------------------------------------|
| Tactic    | Command and Control                                     |
| Technique | T1562: Impair Defenses                                  |

**Evidence**

<img width="1501" height="451" alt="image" src="https://github.com/user-attachments/assets/34132809-1b41-4f3a-9d49-b7e2a9968ed7" />


---

### 🚩 Flag 7: Defence Evasion | Download Utility Abuse

**Objective**
dentify how malware was downloaded.

**Hunt Question**
Identify the Windows-native binary the attacker abused to download files?

**Answer:** `certutil.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine has_any ("certutil.exe") 
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- `certutil.exe` used to retrieve payloads
- Native Windows binary leveraged


**Analysis**
Using built-in tools like `certutil.exe` helps attackers blend in and avoid detection.

**MITRE ATT&CK Mapping**

| Field     | Value                                                   |
|-----------|---------------------------------------------------------|
| Tactic    | Command and Control                                     |
| Technique | T1105: Ingress Tool Transfer                            |

**Evidence**

<img width="1506" height="510" alt="image" src="https://github.com/user-attachments/assets/ecc403b5-4072-4a5e-aa98-37897290c3ff" />




---

### 🚩 Flag 8: Persistence | Scheduled Task Name

**Objective**
Identify persistence mechanism.

**Hunt Question**
Identify the name of the scheduled task created for persistence?

**Answer:** `Windows Update Check`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine has_any ("schtasks.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Scheduled task created
- Legitimate-looking name
 

**Analysis**
Attackers use trusted-looking names to avoid suspicion and maintain persistence.


**MITRE ATT&CK Mapping**

| Field     | Value                                             |
|-----------|---------------------------------------------------|
| Tactic    | Resource Development                              |
| Technique | T1053: Scheduled Task/Job                         |

**Evidence**

<img width="1499" height="512" alt="image" src="https://github.com/user-attachments/assets/79f59334-0fa3-446f-a251-b8d95550abe8" />



---

### 🚩 Flag 9: Persistence | Scheduled Task Target

**Objective**
Identify payload executed by scheduled task.

**Hunt Question**
Identify the executable path configured in the scheduled task?

**Answer:** `C:\ProgramData\WindowsCache\svchost.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine has_any ("schtasks.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Scheduled task configured to run executable
- Binary located in non-standard directory
- File name mimics legitimate system process

**Analysis**
The attacker disguised malware as `svchost.exe` to blend in with legitimate system processes while maintaining persistence.
 
**MITRE ATT&CK Mapping**

| Field     | Value                                                          |
|-----------|----------------------------------------------------------------|
| Tactic    | Credential Access                                              |
| Technique | T1036: Masquerading                                            |

**Evidence**

<img width="1496" height="447" alt="image" src="https://github.com/user-attachments/assets/0d21afc6-ae30-41ad-8abe-7f861b4fa14b" />



---

### 🚩 Flag 10: Credential Access | Local Staging

**Objective**
Identify where the extracted registry hives were saved locally to establish the staging location used prior to offline processing.

**Hunt Question**
What directory were the extracted credential files saved to?

**Answer:** `C:\Users\Public`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:00:00Z) .. datetime(2026-01-15T04:30:00Z))
| where DeviceName == "as-pc1"
| where FileName == "reg.exe"
| where ProcessCommandLine has_any ("save", "export")
| where ProcessCommandLine has_any ("SAM", "SYSTEM", "SECURITY")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Staging directory: `C:\Users\Public`
- Readable and writable by all local users without elevation in most configurations
- Files written here survive user session changes and are accessible across accounts

**Analysis**
`C:\Users\Public` is a deliberate choice. Unlike a user-specific temp directory, this path is accessible to any local account, making it a useful handoff point between different user contexts within the same compromise. If the attacker needs to access the hive files under a different account later (e.g., during lateral movement), they can retrieve them from this shared location without needing to modify permissions. The use of a legitimate Windows directory also reduces the likelihood of detection from file path-based monitoring rules that focus on unusual system or temp paths.

> 💡 *Newer hunters: notice that Flags 9, 10, and 11 are all answered by a single query. When a flag asks "what account", "what directory", and "what hives" about the same event, one well-projected query can cover all three. Project every relevant column up front instead of running three separate searches.*

**MITRE ATT&CK Mapping**

| Field     | Value                                      |
|-----------|--------------------------------------------|
| Tactic    | Collection                                 |
| Technique | T1074.001: Data Staged: Local Data Staging |

**Evidence**
> <img width="1138" height="290" alt="image" src="https://github.com/user-attachments/assets/8cefe41b-5460-4805-b986-a85fd52c0d8f" />


---

*With the staging location confirmed, the investigation determined the user context for credential extraction.*

---

### 🚩 Flag 11: Credential Access | Execution Identity

**Objective**
Establish the user account under which credential extraction was performed to define the scope of account compromise.

**Hunt Question**
What user account performed the credential extraction?

**Answer:** `sophie.turner`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:00:00Z) .. datetime(2026-01-15T04:30:00Z))
| where DeviceName == "as-pc1"
| where FileName == "reg.exe"
| where ProcessCommandLine has_any ("save", "export")
| where ProcessCommandLine has_any ("SAM", "SYSTEM", "SECURITY")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Credential extraction performed by: `sophie.turner`
- The initial payload executed in `sophie.turner`'s user context
- This account is the primary identity for Sections 1–5 of the attack

**Analysis**
`sophie.turner` is the initial compromised account; the user who double-clicked the CV. The fact that this account had sufficient permissions to run `reg save` against `SAM` and `SYSTEM` hives indicates they held elevated local rights, likely local Administrator membership. This amplifies the impact of the initial compromise: a standard user account would not have the required privileges for registry hive extraction, meaning a principle of least privilege policy would have broken this step of the attack chain.

**MITRE ATT&CK Mapping**

| Field     | Value                                                          |
|-----------|----------------------------------------------------------------|
| Tactic    | Credential Access                                              |
| Technique | T1003.002: OS Credential Dumping: Security Account Manager     |

**Evidence**
> <img width="1138" height="290" alt="image" src="https://github.com/user-attachments/assets/d5a4dc8f-0ba1-4605-b4a4-cca75de72ac2" />


---

*With credential access fully documented, the investigation moved to the attacker's discovery phase.*

---

### 🚩 Flag 12: Discovery | User Context

**Objective**
Identify the command used by the attacker to confirm their current user identity, the standard first step in post-compromise situational awareness.

**Hunt Question**
What command did the attacker run to confirm their user context?

**Answer:** `whoami.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T03:55:00Z) .. datetime(2026-01-15T04:10:00Z))
| where DeviceName == "as-pc1"
| where FileName == "whoami.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Command executed: `whoami.exe` at 03:58:55Z, seconds after initial payload execution
- Confirms the attacker performed immediate post-exploitation reconnaissance

**Analysis**
`whoami.exe` is the first command most post-exploitation operators run after gaining a shell. It answers the most important immediate question: who am I, and what can I do from here? Knowing the username, domain membership, and privilege level shapes every decision that follows. The execution of `whoami` seconds after the payload ran confirms this is scripted or tooled behavior, not manual browsing. Detection rules triggering on `whoami.exe` executed by child processes of user-facing applications represent a low-noise, high-value detection opportunity.

**MITRE ATT&CK Mapping**

| Field     | Value                              |
|-----------|------------------------------------|
| Tactic    | Discovery                          |
| Technique | T1033: System Owner/User Discovery |

**Evidence**
> <img width="1017" height="252" alt="image" src="https://github.com/user-attachments/assets/c716a61c-ba93-49f5-83ac-8c48cff23404" />


---

*With user context confirmed, the attacker turned to enumerating network resources.*

---

### 🚩 Flag 13: Discovery | Network Enumeration

**Objective**
Identify the command used to enumerate network shares, establishing what resources the attacker identified as potential lateral movement and data access targets.

**Hunt Question**
What command was used to enumerate available network shares?

**Answer:** `net view`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T03:55:00Z) .. datetime(2026-01-15T04:10:00Z))
| where DeviceName == "as-pc1"
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine contains "view"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Command executed: `net view` without arguments, listing all visible hosts and shares on the network
- Executed in close temporal proximity to `whoami.exe`, indicating a sequential post-exploitation discovery checklist

**Analysis**
`net view` queries the network for visible hosts and shared resources. In an Active Directory environment, this reveals servers, workstations, and their exposed shares, exactly the information an attacker needs to identify file servers and determine which systems are worth pivoting to. The identification of `as-srv` as a file server through this enumeration step directly informed the later data access phase. Correlating `whoami`, `net view`, and local group enumeration in a short time window from a non-administrative user account is a strong behavioral indicator of post-compromise reconnaissance.

**MITRE ATT&CK Mapping**

| Field     | Value                          |
|-----------|--------------------------------|
| Tactic    | Discovery                      |
| Technique | T1135: Network Share Discovery |

**Evidence**
> <img width="1007" height="262" alt="image" src="https://github.com/user-attachments/assets/a4deae04-7bbd-49e6-b01b-4ce5969110ea" />


---

*With network resources mapped, the attacker enumerated local group membership.*

---

### 🚩 Flag 14: Discovery | Local Admins

**Objective**
Identify which local group the attacker queried to enumerate privileged accounts on the compromised host.

**Hunt Question**
What local group was queried by the attacker?

**Answer:** `administrators`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T03:55:00Z) .. datetime(2026-01-15T04:10:00Z))
| where DeviceName == "as-pc1"
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine contains "localgroup"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Group queried: `Administrators`
- Full command consistent with `net localgroup Administrators`
- Reveals which accounts hold local administrative rights on the machine

**Analysis**
Querying the local `Administrators` group tells the attacker which accounts can perform privileged operations locally. This information directly informs the persistence and lateral movement phases: knowing the local admin landscape helps the attacker choose which existing accounts to leverage, whether their current context has sufficient rights, and what needs to be created or elevated for durable access. This recon step connects directly to the backdoor account creation (`svc_backup`) in Section 7.

**MITRE ATT&CK Mapping**

| Field     | Value                                                |
|-----------|------------------------------------------------------|
| Tactic    | Discovery                                            |
| Technique | T1069.001: Permission Groups Discovery: Local Groups |

**Evidence**
> <img width="1029" height="281" alt="image" src="https://github.com/user-attachments/assets/256a3ffa-be4e-40a9-a7e6-362ce4e2a1b6" />


---

*With discovery complete, the investigation tracked the attacker's first persistence action: deploying AnyDesk.*

---

### 🚩 Flag 15: Persistence: Remote Tool | Remote Tool

**Objective**
Identify the commercial remote access tool installed by the attacker to establish a persistent, legitimate-looking access channel that survives credential resets and reboots.

**Hunt Question**
What remote administration software was installed by the attacker?

**Answer:** `AnyDesk`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T03:55:00Z) .. datetime(2026-01-15T04:10:00Z))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| where ProcessCommandLine has_any ("http", ".exe", "download", "urlcache")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated desc
```

**Key Observations**
- Remote tool installed: `AnyDesk`
- Installation used silent flags to suppress user-visible prompts

**Analysis**
We used a broad spectrum query that is tool agnostic, hunting for behavior rather than a specific software. AnyDesk is a legitimate, widely-used commercial remote desktop application. Installing it as a persistence mechanism is highly effective: it generates minimal security alerts, is unlikely to be blocked by application whitelisting policies that permit commercial software, and provides a full graphical remote session without relying on the Windows RDP service. Even if the initial payload is removed, AnyDesk continues operating as a fully functional backdoor.


**MITRE ATT&CK Mapping**

| Field     | Value                         |
|-----------|-------------------------------|
| Tactic    | Persistence                   |
| Technique | T1219: Remote Access Software |

**Evidence**
> <img width="1202" height="311" alt="image" src="https://github.com/user-attachments/assets/00a9973f-3f1b-4b70-bd90-7ea3412e1f60" />


---

*With the tool identified, the investigation captured its hash for deconfliction and IOC distribution.*

---

### 🚩 Flag 16: Persistence: Remote Tool | Remote Tool Hash

**Objective**
Capture the SHA256 hash of the AnyDesk binary to determine whether a legitimate or trojanized installer was used.

**Hunt Question**
What is the SHA256 hash of the AnyDesk remote access tool binary?

**Answer:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:00:00Z) .. datetime(2026-01-15T04:30:00Z))
| where DeviceName == ("as-pc1")
| where FileName =~ "anydesk.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
```

**Key Observations**
- SHA256: `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`
- Hash is distinct from the initial payload hash; confirms a separate binary

**Analysis**
Capturing this hash enables deconfliction: cross-referencing against known-good AnyDesk installer hashes from the official distribution determines whether the attacker used an unmodified tool or a trojanized version. Either way, the hash provides a consistent artifact for hunting across the environment. This hash can be added to endpoint protection block lists and used for retrospective searching across any host that may have received the same binary outside the observed deployment window.

**MITRE ATT&CK Mapping**

| Field     | Value                         |
|-----------|-------------------------------|
| Tactic    | Persistence                   |
| Technique | T1219: Remote Access Software |

**Evidence**
> <img width="1121" height="249" alt="image" src="https://github.com/user-attachments/assets/8283ea89-1a79-4eac-8b36-b8a5f8d8c249" />


---

*With the hash captured, the investigation identified the native Windows binary used to download AnyDesk.*

---

### 🚩 Flag 17: Persistence: Remote Tool | Download Method

**Objective**
Identify the native Windows binary used to download AnyDesk, confirming the attacker's continued reliance on living-off-the-land techniques.

**Hunt Question**
What native Windows binary was used to download the remote access tool?

**Answer:** `certutil.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T03:55:00Z) .. datetime(2026-01-15T04:10:00Z))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| where ProcessCommandLine has "anydesk"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

**Key Observations**
- Download binary: `certutil.exe`
- Usage consistent with `certutil -urlcache -f <url> <output>` for file retrieval
- Continues the attacker's pattern of using signed Microsoft binaries for all operational steps

**Analysis**
`certutil.exe` is one of the most widely abused LOLBins in the Windows ecosystem. Its `-urlcache` flag allows arbitrary file downloads from any URL, and because it is a signed Microsoft binary, it is not blocked by most application control policies. Using it to retrieve AnyDesk continues the attacker's consistent pattern of avoiding custom tooling in favor of what Windows already provides. Detection of `certutil.exe` downloading executables from external URLs is a reliable, high-fidelity indicator that should be monitored in any environment.

**MITRE ATT&CK Mapping**

| Field     | Value                          |
|-----------|--------------------------------|
| Tactic    | Defense Evasion                |
| Technique | T1105: Ingress Tool Transfer   |

**Evidence**
> <img width="1152" height="256" alt="image" src="https://github.com/user-attachments/assets/fc51bd09-a3ac-43d4-9415-795744445891" />


---

*With the download mechanism confirmed, the investigation located the AnyDesk configuration file.*

---

### 🚩 Flag 18: Persistence: Remote Tool | Configuration Access

**Objective**
Identify the AnyDesk configuration file accessed after installation to understand how unattended access was configured.

**Hunt Question**
What is the full path of the AnyDesk configuration file that was accessed?

**Answer:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:00:00Z) .. datetime(2026-01-15T04:30:00Z))
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any (".conf", ".ini", ".json")
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Key Observations**
- Configuration file accessed: `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`
- `system.conf` is where AnyDesk stores its unattended access password
- Path in `sophie.turner`'s user profile confirms deployment within the initially compromised account context

**Analysis**
`system.conf` stores the unattended access password for AnyDesk. By accessing this file after installation, the attacker was writing a predetermined password to allow persistent re-entry without any interaction from the compromised workstation. The path under `sophie.turner`'s `AppData\Roaming` directory tells us AnyDesk was installed in the user context of the initially compromised account rather than as a system-wide service, an important distinction for remediation scoping. Any `system.conf` creation or write event under an AnyDesk folder path is a precise hunting target.

**MITRE ATT&CK Mapping**

| Field     | Value                        |
|-----------|------------------------------|
| Tactic    | Persistence                  |
| Technique | T1219: Remote Access Software |

**Evidence**
> <img width="1012" height="240" alt="image" src="https://github.com/user-attachments/assets/476aa8f4-69b1-4986-8ad8-bf837202d96a" />


---

*With the configuration file located, the investigation recovered the unattended access password.*

---

### 🚩 Flag 19: Persistence: Remote Tool | Access Credentials

**Objective**
Recover the unattended access password configured for AnyDesk to understand the persistent re-entry mechanism and enable immediate credential revocation.

**Hunt Question**
What password was configured for unattended AnyDesk access?

**Answer:** `intrud3r!`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:00:00Z) .. datetime(2026-01-15T04:30:00Z))
| where DeviceName == "as-pc1"
| where ProcessCommandLine contains "AnyDesk"
| where ProcessCommandLine contains "set-password"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Unattended access password: `intrud3r!`
- Password hardcoded in the AnyDesk deployment command, visible in process telemetry
- Same password applied across all three hosts where AnyDesk was deployed

**Analysis**
The password `intrud3r!` appearing in process command-line telemetry is an operational security failure by the attacker. Passing credentials as command-line arguments writes them into process execution logs, making them trivially recoverable from any telemetry source that captures `ProcessCommandLine`. This kind of mistake is common when attackers script their deployment for speed and convenience, trading forensic hygiene for operational efficiency.

From a response perspective, this password must be treated as a known-compromised credential: any AnyDesk instance with `intrud3r!` configured is a live backdoor, even after other artifacts have been removed. Remediation must include removing AnyDesk from all three hosts and auditing for any other systems where this password may have been applied.

**MITRE ATT&CK Mapping**

| Field     | Value                        |
|-----------|------------------------------|
| Tactic    | Persistence                  |
| Technique | T1219: Remote Access Software |

**Evidence**
> <img width="1019" height="279" alt="image" src="https://github.com/user-attachments/assets/ca590cab-3cf4-4549-b299-0c15ffdd74db" />


---

*With the password recovered, the investigation confirmed the full deployment footprint.*

---

### 🚩 Flag 20: Persistence: Remote Tool | Deployment Footprint

**Objective**
Enumerate all hosts where AnyDesk was installed to define the complete scope of persistent remote access and ensure full remediation coverage.

**Hunt Question**
Which hostnames had AnyDesk installed by the attacker?

**Answer:** `as-pc1`, `as-pc2`, `as-srv`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:00:00Z) .. datetime(2026-01-15T05:00:00Z))
| where FileName endswith ".exe"
| where FolderPath contains "AnyDesk"
| where ActionType == "FileCreated"
| summarize DeployedOn = make_set(DeviceName) by FileName
```

**Key Observations**
- AnyDesk deployed to: `as-pc1`, `as-pc2`, `as-srv`
- Three hosts in the environment received the installation

**Analysis**
Deploying AnyDesk to multiple hosts in the environment, not just the initial foothold machine, demonstrates deliberate intent to own the environment rather than maintain a single access point. If `as-pc1` were reimaged and `sophie.turner`'s credentials rotated, the attacker would still have authenticated access to `as-pc2` and `as-srv`. This is the hallmark of an attacker who plans for partial detection.

> 💡 *Newer hunters: `make_set()` in KQL returns a deduplicated dynamic array. Here, it collapses every `DeviceName` value into a single clean list per filename, so you see all affected hosts in one row rather than one row per event. It's a useful function worth adding to your summarize toolkit.*

**MITRE ATT&CK Mapping**

| Field     | Value                        |
|-----------|------------------------------|
| Tactic    | Persistence                  |
| Technique | T1219: Remote Access Software |

**Evidence**
> <img width="821" height="257" alt="image" src="https://github.com/user-attachments/assets/57b64309-d1a6-4ef7-8721-2f665b9b6b57" />


---

*With persistence established, the investigation tracked the attacker's lateral movement, beginning with the failed attempts.*

---

### 🚩 Flag 21: Lateral Movement | Failed Execution

**Objective**
Identify the remote execution tools the attacker attempted before succeeding, revealing their preferred techniques and the controls that blocked them.

**Hunt Question**
What two tools did the attacker try that failed for remote execution?

**Answer:** `wmic.exe`, `psexec.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:15:00Z) .. datetime(2026-01-15T04:35:00Z))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName in~ ("wmic.exe", "psexec.exe", "psexec64.exe", "powershell.exe", "cmd.exe")
| where ProcessCommandLine has_any ("/node:", "\\\\", "-ComputerName", "Invoke-Command")
| extend TargetHost = extract(@"(?:/node:|\\\\)([^\s]+)", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, TargetHost, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Failed tools: `wmic.exe` and `psexec.exe`
- Both attempted with remote execution syntax targeting a specific host
- No corresponding successful logon or child process on the target side confirms the failure

**Analysis**
Confirming failure requires two steps: identifying the attempts, then verifying no corresponding activity appeared on the target side. `wmic.exe /node:` and `psexec.exe \\host` are two of the most commonly used lateral movement techniques in post-exploitation frameworks. Their failure indicates that host-based firewall rules or security policy blocked the required ports: DCOM for WMI remote execution and SMB admin shares for PsExec. The fact that the attacker tried both before pivoting suggests they were working through a methodical checklist. For defenders, the attempted-but-failed execution events are themselves valuable detection signals regardless of outcome.

> 💡 *Newer hunters: absence of evidence is evidence, but you have to go looking for it. A failed lateral movement attempt won't produce a "failure" event on the source machine. You confirm the failure by pivoting to the target (`as-pc2`) and checking for `WmiPrvSE` child processes or `LogonFailed` events during the attempt window. If neither exists, the attempt didn't land.*

**MITRE ATT&CK Mapping**

| Field     | Value                                                              |
|-----------|--------------------------------------------------------------------|
| Tactic    | Lateral Movement                                                   |
| Technique | T1021.003: Remote Services: Distributed Component Object Model     |

**Evidence**
> <img width="1205" height="450" alt="image" src="https://github.com/user-attachments/assets/f9c49ac6-9c20-4537-8227-4f9e9eec28d3" />


---

*With the failed attempts documented, the investigation identified the specific host targeted.*

---

### 🚩 Flag 22: Lateral Movement | Target Host

**Objective**
Identify the host targeted in the failed remote execution attempts to establish the intended movement path.

**Hunt Question**
What hostname was targeted in the failed execution attempts?

**Answer:** `as-pc2`

**Query Used**

*(Same query as Flag 21, reviewed for hostname value in `ProcessCommandLine`)*

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:15:00Z) .. datetime(2026-01-15T04:35:00Z))
| where DeviceName == "as-pc1"
| where FileName in~ ("wmic.exe", "psexec.exe", "psexec64.exe")
| where ProcessCommandLine has_any ("/node:", "\\\\")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Targeted host: `as-pc2`
- Both `wmic.exe` and `psexec.exe` attempts referenced `as-pc2` in their command-line arguments

**Analysis**
`as-pc2` as the target of both failed attempts confirms the intended movement path. The attacker was not randomly probing; they had a specific destination in mind. This targeted approach, combined with the prior network enumeration via `net view`, suggests they had already identified `as-pc2` as an accessible host before initiating the attempts.

**MITRE ATT&CK Mapping**

| Field     | Value                                                |
|-----------|------------------------------------------------------|
| Tactic    | Lateral Movement                                     |
| Technique | T1021.002: Remote Services: SMB/Windows Admin Shares |

**Evidence**
> <img width="1204" height="408" alt="image" src="https://github.com/user-attachments/assets/3308e871-8f83-44a8-b4d5-06f959c799b2" />


---

*With the target confirmed, the investigation identified the method that ultimately achieved lateral movement.*

---

### 🚩 Flag 23: Lateral Movement | Successful Pivot

**Objective**
Identify the Windows executable that successfully facilitated lateral movement after the initial attempts failed.

**Hunt Question**
What Windows executable achieved the successful lateral movement?

**Answer:** `mstsc.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:25:00Z) .. datetime(2026-01-15T04:45:00Z))
| where DeviceName == "as-pc1"
| where AccountName =~ "sophie.turner"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc

and

DeviceNetworkInfo
| where TimeGenerated between (datetime(2026-01-15T04:25:00Z) .. datetime(2026-01-15T05:25:00Z))
| where IPAddresses has_any ("10.1.0.183","10.1.0.203" )
| project TimeGenerated, DeviceName, IPAddresses[0].IPAddress

and

DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-15T04:25:00Z) .. datetime(2026-01-15T04:45:00Z))
| where LogonType == "RemoteInteractive"
| where DeviceName == "as-pc2"
| project TimeGenerated, AccountDomain, AccountName, ActionType, AdditionalFields.IsLocalLogon
```

**Key Observations**
- Successful pivot method: `mstsc.exe` (Microsoft Terminal Services Client, RDP)
- RDP succeeded where WMI and SMB-based execution failed
- Provides a full graphical desktop session on the target

**Analysis**
We use the first query to see PsExec appear to fail, more network exploration, then mstsc.exe called with an IP address. We use the second query to confirm the devices those addresses are attached to. The third query shows us the remote logon success. RDP succeeding where WMI and PsExec failed suggests the target environment had port restrictions limiting DCOM and SMB admin share access but left TCP 3389 open between workstations. This is a common configuration gap in environments where RDP is permitted for IT support purposes without network segmentation restricting peer-to-peer RDP traffic.

Using `mstsc.exe` for lateral movement is effective from an evasion perspective: it generates RemoteInteractive logon events (type 10) that look like normal user sessions, produces less anomalous telemetry than WMI or PsExec, and provides a full desktop session that makes tasks like browsing file shares and opening documents far more convenient than command-line-only methods.

**MITRE ATT&CK Mapping**

| Field     | Value                                               |
|-----------|-----------------------------------------------------|
| Tactic    | Lateral Movement                                    |
| Technique | T1021.001: Remote Services: Remote Desktop Protocol |

**Evidence**
> <img width="947" height="429" alt="image" src="https://github.com/user-attachments/assets/7fcec0e9-2989-4890-9051-53cbf8385070" />

> <img width="805" height="376" alt="image" src="https://github.com/user-attachments/assets/aa690210-5626-4853-a8cd-279c1bf4da44" />

> <img width="1006" height="229" alt="image" src="https://github.com/user-attachments/assets/a6a46b35-15cd-45be-a170-d846bf2c373f" />


---

*With the movement method confirmed, the investigation reconstructed the full lateral movement path.*

---

### 🚩 Flag 24: Lateral Movement | Movement Path

**Objective**
Reconstruct the full sequence of lateral movement to establish the complete scope of host compromise.

**Hunt Question**
What is the full lateral movement path in order?

**Answer:** `as-pc1` > `as-pc2` > `as-srv`

**Query Used**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-15T04:30:00Z) .. datetime(2026-01-15T05:00:00Z))
| where LogonType in ("RemoteInteractive", "Network")
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where RemoteDeviceName != ""
| where ActionType != "LogonFailed"
| project TimeGenerated,RemoteDeviceName, DeviceName, AccountName, RemoteIP
| order by TimeGenerated asc
```

**Key Observations**
- Movement path: `as-pc1` to `as-pc2` to `as-srv`
- Two-hop movement: initial foothold to intermediate workstation, then to file server
- All three hosts confirmed compromised in sequence

**Analysis**
The two-hop path to `as-srv` is deliberate. Rather than attempting to reach the file server directly from `as-pc1`, which may have had additional access restrictions or monitoring, the attacker used `as-pc2` as an intermediate relay. This has a forensic benefit for the attacker: the origin of the `as-srv` logon events is `as-pc2`, not the originally compromised machine. An analyst looking only at `as-srv` authentication logs would initially attribute the file server access to `as-pc2` as the source rather than tracing it back to the initial compromise on `as-pc1`. All three hosts are compromised and require full investigation and recovery.

**MITRE ATT&CK Mapping**

| Field     | Value                                               |
|-----------|-----------------------------------------------------|
| Tactic    | Lateral Movement                                    |
| Technique | T1021.001: Remote Services: Remote Desktop Protocol |

**Evidence**
> <img width="798" height="344" alt="image" src="https://github.com/user-attachments/assets/a0234bfb-ccbb-4cdc-bc7d-0b7c594fdd03" />


---

*With the movement path established, the investigation identified the account used for authentication.*

---

### 🚩 Flag 25: Lateral Movement | Compromised Account

**Objective**
Identify the account used for successful lateral movement to define the credential blast radius and inform reset priorities.

**Hunt Question**
What username was used to authenticate during lateral movement?

**Answer:** `david.mitchell`

**Query Used**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-15T04:30:00Z) .. datetime(2026-01-15T05:00:00Z))
| where LogonType in ("RemoteInteractive", "Network")
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where RemoteDeviceName != ""
| where ActionType != "LogonFailed"
| project TimeGenerated,RemoteDeviceName, DeviceName, AccountName, RemoteIP
| order by TimeGenerated asc
```

**Key Observations**
- Account used for lateral movement: `david.mitchell`
- Account was disabled prior to attacker activation (confirmed in Flag 26)
- Authenticated successfully via RDP across both pivot points

**Analysis**
`david.mitchell` is the second compromised identity in this investigation, separate from the initial access account `sophie.turner`. Using a distinct account for lateral movement adds operational separation: if `sophie.turner`'s account is detected and reset, the attacker's RDP sessions running as `david.mitchell` remain unaffected. The fact that `david.mitchell`'s account was disabled before the attacker used it implies the credentials were obtained through the registry hive dump in Section 3, with the attacker specifically selecting a dormant, potentially unmonitored account to reduce detection risk.

**MITRE ATT&CK Mapping**

| Field     | Value                   |
|-----------|-------------------------|
| Tactic    | Lateral Movement        |
| Technique | T1078: Valid Accounts   |

**Evidence**
> <img width="798" height="344" alt="image" src="https://github.com/user-attachments/assets/cb0d885f-d831-40bc-8dfb-1140d09f949d" />


---

*With the account identified, the investigation captured the exact command used to re-enable it.*

---

### 🚩 Flag 26: Lateral Movement | Account Activation

**Objective**
Identify the specific `net.exe` parameter used to re-enable the disabled `david.mitchell` account.

**Hunt Question**
What `net.exe` parameter was used to activate the account?

**Answer:** `/active:yes`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:20:00Z) .. datetime(2026-01-15T04:45:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine contains "user"
| where ProcessCommandLine contains "active"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Parameter used: `/active:yes`
- Full command consistent with `net user david.mitchell /active:yes`
- Executed prior to the first successful RDP session under `david.mitchell`

**Analysis**
`net user /active:yes` re-enables a disabled Windows user account. Disabled accounts cannot log on interactively, but they are often under-monitored because they are perceived as dormant and low-risk. An attacker who re-enables a disabled account exploits that blind spot: the account becomes active without being newly created, and may not trigger detections focused on `net user /add` events. Alerting on `net user /active:yes` executed outside of approved IT change windows is a high-value detection rule that many environments lack.

**MITRE ATT&CK Mapping**

| Field     | Value                       |
|-----------|-----------------------------|
| Tactic    | Persistence                 |
| Technique | T1098: Account Manipulation |

**Evidence**
> <img width="862" height="281" alt="image" src="https://github.com/user-attachments/assets/b39995fc-ae2d-4d7f-ac19-ab3ffc13edec" />


---

*With the activation command confirmed, the investigation identified the user context under which it ran.*

---

### 🚩 Flag 27: Lateral Movement | Activation Context

**Objective**
Establish which user context executed the account activation command to clarify the privilege chain.

**Hunt Question**
Which user performed the account activation?

**Answer:** `david.mitchell`

**Query Used**


```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:20:00Z) .. datetime(2026-01-15T04:45:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has "user"
| where ProcessCommandLine has "active"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Activation performed under: `david.mitchell`
- The account re-enablement was executed within `david.mitchell`'s token context while the account was technically still disabled

**Analysis**
`david.mitchell` executing their own account activation is a subtle but significant observation. It tells us the attacker had already obtained `david.mitchell`'s credentials, likely from the SAM/SYSTEM registry dump, and was able to execute commands under that token even while the account was disabled in Active Directory. The telemetry reflects the credential context in use at time of execution. Regardless of the precise mechanism, the AccountName confirms the attacker was operating with `david.mitchell`'s credentials before issuing the re-enablement command. This changes the scoping picture: the attacker possessed valid `david.mitchell` credentials before needing to re-enable the account for interactive RDP.

**MITRE ATT&CK Mapping**

| Field     | Value                       |
|-----------|-----------------------------|
| Tactic    | Persistence                 |
| Technique | T1098: Account Manipulation |

**Evidence**
> <img width="862" height="281" alt="image" src="https://github.com/user-attachments/assets/fec67100-3ab0-4d62-a43b-43bd5da04799" />


---

*With lateral movement fully documented, the investigation moved to the attacker's second persistence layer: a scheduled task.*

---

### 🚩 Flag 28: Persistence: Scheduled Task | Scheduled Persistence

**Objective**
Identify the scheduled task created for persistence, designed to survive if AnyDesk were discovered and removed.

**Hunt Question**
What is the name of the scheduled task created for persistence?

**Answer:** `MicrosoftEdgeUpdateCheck`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:35:00Z) .. datetime(2026-01-15T05:00:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has "schtasks"
| where ProcessCommandLine has "/create"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Scheduled task name: `MicrosoftEdgeUpdateCheck`
- Name mimics a legitimate Microsoft Edge update verification task
- Designed to blend into a scheduled task audit

**Analysis**
`MicrosoftEdgeUpdateCheck` is a convincing masquerade. Microsoft Edge and Chromium-based browsers generate legitimate update-related scheduled tasks, and a task with this name would not stand out in a standard `schtasks /query` review in an environment where Edge is the default browser. Defenders auditing scheduled tasks should cross-reference task names against expected executables and their hashes; a task named after an Edge utility that executes a binary with a payload SHA256 is an immediate red flag.

**MITRE ATT&CK Mapping**

| Field     | Value                                         |
|-----------|-----------------------------------------------|
| Tactic    | Persistence                                   |
| Technique | T1053.005: Scheduled Task/Job: Scheduled Task |

**Evidence**
> <img width="1124" height="283" alt="image" src="https://github.com/user-attachments/assets/989326b8-4e79-4c45-941d-38d2c0a3055a" />


---

*With the task name confirmed, the investigation identified the binary it was configured to execute.*

---

### 🚩 Flag 29: Persistence: Scheduled Task | Renamed Binary

**Objective**
Identify the filename used for the persistence payload to understand how the attacker disguised the binary in the file system.

**Hunt Question**
What filename was the persistence payload renamed to?

**Answer:** `RuntimeBroker.exe`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:35:00Z) .. datetime(2026-01-15T05:00:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName == "RuntimeBroker.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

**Key Observations**
- Persistence binary renamed to: `RuntimeBroker.exe`
- File created outside of expected system directories (`System32`, `SysWOW64`)
- `RuntimeBroker.exe` is a legitimate Windows process, making the name blend into process listings

**Analysis**
In flag 28 we see the scheduled task is pointing toward RuntimeBroker.exe in C:\Users\Public. `RuntimeBroker.exe` is a genuine Windows process responsible for managing permissions for apps from the Windows Store. Appearing in normal process trees, it would not raise immediate suspicion in a process listing review. The combination of a masqueraded task name (`MicrosoftEdgeUpdateCheck`) and a masqueraded binary name (`RuntimeBroker.exe`) creates layered concealment: the task name passes a task audit, and the process name passes a process listing review. Only path-based or hash-based inspection reveals the deception.

**MITRE ATT&CK Mapping**

| Field     | Value                                                      |
|-----------|------------------------------------------------------------|
| Tactic    | Defense Evasion                                            |
| Technique | T1036.005: Masquerading: Match Legitimate Name or Location |

**Evidence**
> <img width="1144" height="274" alt="image" src="https://github.com/user-attachments/assets/973923ae-4c4f-4fad-aada-105678f2aa49" />


---

*With the renamed binary identified, the investigation confirmed its hash, revealing the critical link back to the original payload.*

---

### 🚩 Flag 30: Persistence: Scheduled Task | Persistence Hash

**Objective**
Capture the hash of the persistence binary and confirm whether it shares lineage with previously observed artifacts.

**Hunt Question**
What is the SHA256 hash of the persistence payload?

**Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:35:00Z) .. datetime(2026-01-15T05:00:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName == "RuntimeBroker.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

**Key Observations**
- SHA256: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`
- **This is the same hash as the initial payload** (`daniel_richardson_cv.pdf.exe`) from Flag 2
- The attacker reused the same binary, renaming it for each purpose

**Analysis**
The hash match between `daniel_richardson_cv.pdf.exe` and the `RuntimeBroker.exe` persistence binary is the single most significant cross-section finding in this investigation. It confirms that the initial access tool and the long-term persistence mechanism are the same binary under different names. For defenders, this is operationally powerful: a single hash-based block at any endpoint protection layer covers both the delivery artifact and the persistence artifact across the entire environment simultaneously.

> 💡 *Newer hunters: capture hashes early and check them against new artifacts as the investigation progresses. A hash match across two differently-named files (like this one) is something automated tooling can miss if it's only matching on filename. Manual cross-referencing of SHA256 values at each persistence flag is what surfaces this kind of binary reuse.*

**MITRE ATT&CK Mapping**

| Field     | Value                                                      |
|-----------|------------------------------------------------------------|
| Tactic    | Defense Evasion                                            |
| Technique | T1036.005: Masquerading: Match Legitimate Name or Location |

**Evidence**
> <img width="1144" height="274" alt="image" src="https://github.com/user-attachments/assets/4eb26735-8c25-41f9-ac12-e42023c588c6" />


---

*With the scheduled task persistence fully documented, the investigation identified the final persistence mechanism: a backdoor account.*

---

### 🚩 Flag 31: Persistence: Scheduled Task | Backdoor Account

**Objective**
Identify the local user account created as a final persistence failsafe independent of all other access paths.

**Hunt Question**
What username was created as the backdoor account?

**Answer:** `svc_backup`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T04:35:00Z) .. datetime(2026-01-15T05:10:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine contains "user"
| where ProcessCommandLine contains "/add"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Backdoor account created: `svc_backup`
- Account naming mimics a service account, common and low-suspicion in Windows environments
- Created as a third, independent persistence layer alongside AnyDesk and the scheduled task

**Analysis**
`svc_backup` is a carefully chosen name. Service accounts prefixed with `svc_` are standard in enterprise Windows environments and are often excluded from routine account audits because they are assumed to be IT-managed. Three persistence mechanisms now exist: AnyDesk for remote access, the scheduled task for local code execution, and `svc_backup` for authenticated logon. Each is independent. Removing any one of them leaves the other two intact. This redundancy is the hallmark of an attacker who expects partial detection and engineers against it.

**MITRE ATT&CK Mapping**

| Field     | Value                                    |
|-----------|------------------------------------------|
| Tactic    | Persistence                              |
| Technique | T1136.001: Create Account: Local Account |

**Evidence**
> <img width="833" height="308" alt="image" src="https://github.com/user-attachments/assets/e94091ed-6c56-474e-b3ab-603845be1d10" />


---

*With all persistence mechanisms documented, the investigation turned to the attacker's primary objective: accessing sensitive data.*

---

### 🚩 Flag 32: Data Access | Sensitive Document

**Objective**
Identify the specific file accessed on the file server to establish what data was placed at risk and what business impact the intrusion created.

**Hunt Question**
What sensitive document was accessed on the file server?

**Answer:** `BACS_Payments_Dec2025.ods`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:35:00Z) .. datetime(2026-01-15T05:10:00Z))
| where DeviceName =~ "as-srv"
// Filter for common extensions
| where FileName has_any (".ods", ".xlsx", ".csv", ".pdf", ".docx", ".zip", ".7z")
// Focus on file modifications, renaming, or creation (staging)
| where ActionType in~ ("FileModified", "FileCreated", "FileRenamed")
| summarize 
    FirstSeen = min(TimeGenerated),
    ActionTypes = make_set(ActionType),
    FolderPaths = make_set(FolderPath),
    Accounts = make_set(RequestAccountName)
    by FileName
| order by FirstSeen asc
```

**Key Observations**
- Sensitive document: `BACS_Payments_Dec2025.ods`
- BACS (Bankers' Automated Clearing Services) payment file; contains financial transaction data
- December 2025 payment data accessed in January 2026, when the data is recent and actionable

**Analysis**
BACS payment files contain the raw financial transaction data used to process bank transfers. Access to `BACS_Payments_Dec2025.ods` represents a direct threat to financial integrity: the data could be used to redirect payments, profile employee salaries and supplier relationships, or provide the foundation for financial fraud. For a recruitment firm, this file likely contains payroll disbursements and contractor payments. The access has immediate financial and regulatory implications.

**MITRE ATT&CK Mapping**

| Field     | Value                                   |
|-----------|-----------------------------------------|
| Tactic    | Collection                              |
| Technique | T1039: Data from Network Shared Drive   |

**Evidence**
> <img width="1160" height="541" alt="image" src="https://github.com/user-attachments/assets/6e9d2b11-aa75-4c63-9bcf-6b317c0dc6e0" />


---

*With the accessed document identified, the investigation confirmed whether the file was merely viewed or actively edited.*

---

### 🚩 Flag 33: Data Access | Modification Evidence

**Objective**
Identify the file artifact that proves the document was opened for editing rather than simply viewed, establishing active interaction with the financial data.

**Hunt Question**
What file artifact proves the document was opened for editing?

**Answer:** `.~lock.BACS_Payments_Dec2025.ods#`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:40:00Z) .. datetime(2026-01-15T05:00:00Z))
| where DeviceName == "as-srv"
| where FileName startswith ".~lock"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType
```

**Key Observations**
- Lock file created: `.~lock.BACS_Payments_Dec2025.ods#`
- LibreOffice creates `.~lock.*#` files when a document is opened for editing (write mode)
- Lock file creation is unambiguous evidence the file was opened in a full editing application, not just read

**Analysis**
The `.~lock.` prefix is a LibreOffice and OpenDocument format artifact; when LibreOffice opens a file for editing, it creates this lock file to prevent simultaneous edits. Its creation proves the attacker did not simply view the file via a file listing or read-only preview: they opened it in a full editing application, with an opportunity to view, copy, and potentially modify the financial records.

For defenders: monitoring for `.~lock.` file creation in sensitive share directories provides a precise signal for active document interaction, independent of which application is in use.

**MITRE ATT&CK Mapping**

| Field     | Value                                  |
|-----------|----------------------------------------|
| Tactic    | Collection                             |
| Technique | T1039: Data from Network Shared Drive  |

**Evidence**
> <img width="933" height="321" alt="image" src="https://github.com/user-attachments/assets/b30a59f7-fd3b-4a99-8fde-c32a876106db" />


---

*With active document interaction confirmed, the investigation identified from which host the access originated.*

---

### 🚩 Flag 34: Data Access | Access Origin

**Objective**
Identify the workstation used to access the file server data, confirming the lateral movement path's connection to the data access phase.

**Hunt Question**
Which hostname accessed the sensitive file on the server?

**Answer:** `as-pc2`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:40:00Z) .. datetime(2026-01-15T05:00:00Z))
| where DeviceName == "as-srv"
| where FileName startswith ".~lock"
| project TimeGenerated, DeviceName, FileName, ActionType, RequestAccountName, RequestSourceIP
| order by TimeGenerated asc
```

**Key Observations**
- Access origin: `as-pc2`
- Network logon from `as-pc2` precedes file access events on `as-srv`

**Analysis**
Our query shows the requesting account name and IP that are both previously verified from as-pc2. `as-pc2` as the origin of the file server access ties the data phase directly to the lateral movement path. The attacker moved from `as-pc1` to `as-pc2` via RDP, then used `as-pc2` as a launchpad to access `as-srv`. This two-hop structure means file server access logs pointing to `as-pc2` would initially appear to be legitimate activity from that workstation, obscuring the root cause without tracing back through the logon chain.

**MITRE ATT&CK Mapping**

| Field     | Value                                               |
|-----------|-----------------------------------------------------|
| Tactic    | Lateral Movement                                    |
| Technique | T1021.001: Remote Services: Remote Desktop Protocol |

**Evidence**
> <img width="1016" height="307" alt="image" src="https://github.com/user-attachments/assets/d6750fe9-d273-45b6-9bb5-035ed15787a4" />


---

*With the access origin confirmed, the investigation located the archive created to package the collected data.*

---

### 🚩 Flag 35: Data Access | Exfil Archive

**Objective**
Identify the archive file created to package collected data for staging and potential exfiltration.

**Hunt Question**
What is the filename of the archive prepared for exfiltration?

**Answer:** `Shares.7z`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:45:00Z) .. datetime(2026-01-15T05:10:00Z))
| where DeviceName in ("as-pc2", "as-srv")
| where FileName endswith ".7z"
   or FileName endswith ".zip"
   or FileName endswith ".tar"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```

**Key Observations**
- Exfiltration archive: `Shares.7z`
- 7-Zip format, commonly used for password-protected archiving to prevent content inspection
- Filename `Shares` suggests the archive contains file share content broadly rather than a specifically named dataset

**Analysis**
We saw the file in our flag 32 query results earlier. `Shares.7z` is a generic but descriptive name indicating the attacker likely archived content from file shares rather than creating a specifically targeted package. The full scope of what was archived would require examining the archive creation process's command-line arguments to identify source paths, a query pivot worth pursuing in a full investigation to quantify the complete data loss. No outbound network transfer of `Shares.7z` was directly confirmed in available telemetry; the archive is documented as staged for exfiltration, not confirmed exfiltrated.

**MITRE ATT&CK Mapping**

| Field     | Value                                                  |
|-----------|--------------------------------------------------------|
| Tactic    | Collection                                             |
| Technique | T1560.001: Archive Collected Data: Archive via Utility |

**Evidence**
> <img width="1043" height="301" alt="image" src="https://github.com/user-attachments/assets/903890d3-2385-4978-a269-20784d3dc347" />


---

*With the archive identified, the investigation captured its hash for IOC tracking.*

---

### 🚩 Flag 36: Data Access | Archive Hash

**Objective**
Capture the SHA256 hash of the exfiltration archive to enable detection of this specific data package in any future context.

**Hunt Question**
What is the SHA256 hash of the exfiltration archive?

**Answer:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T04:45:00Z) .. datetime(2026-01-15T05:10:00Z))
| where FileName == "Shares.7z"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
```

**Key Observations**
- Archive SHA256: `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`
- Hash is unique; does not match any previously observed artifact in this investigation

**Analysis**
The archive hash is a distinct IOC specific to this data package. If this hash appears on any other system in the environment or in network proxy telemetry during a data transfer event, it confirms the same package was moved. For threat intelligence teams, this hash can be shared as a high-fidelity indicator associated with this specific incident.

**MITRE ATT&CK Mapping**

| Field     | Value                                                  |
|-----------|--------------------------------------------------------|
| Tactic    | Collection                                             |
| Technique | T1560.001: Archive Collected Data: Archive via Utility |

**Evidence**
> <img width="997" height="205" alt="image" src="https://github.com/user-attachments/assets/2190fbc4-42c0-4344-954c-23b84f6310a2" />


---

*With the data access phase fully documented, the investigation turned to the anti-forensics techniques used before departure.*

---

### 🚩 Flag 37: Anti-Forensics | Log Clearing

**Objective**
Identify which Windows event logs were cleared to establish the scope of forensic evidence destruction.

**Hunt Question**
Name any two Windows event logs that were cleared.

**Answer:** `Security`, `System`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15T05:00:00Z) .. datetime(2026-01-15T05:15:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has_any ("cl ", "clear-log")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

**Key Observations**
- Logs cleared: `Security`, `System`, and `Application`
- `Security` log contains authentication events, account changes, and privilege use
- `System` log contains service installation and driver load events
- `Application` log contains events written by applications and services 

**Analysis**
Clearing the `Security` and `System` logs at the end of the intrusion targets the two most forensically valuable Windows event log sources. The `Security` log would have contained every logon event, privilege use, account modification, and policy change from the incident window. The `System` log would have contained service installation records including evidence of AnyDesk service deployment. The `Application` log would have contained application-level errors, crashes, and service events that could reveal execution artifacts, failed persistence attempts, or tooling instability during the intrusion.

The fact that this investigation was still able to reconstruct the full attack narrative is owed entirely to MDE telemetry, which operates independently of Windows event logs and cannot be cleared via `wevtutil`. This architectural benefit of endpoint detection platforms, their survival of local log clearing that would otherwise destroy the forensic record, is the central reason this investigation succeeded.

**MITRE ATT&CK Mapping**

| Field     | Value                                                    |
|-----------|----------------------------------------------------------|
| Tactic    | Defense Evasion                                          |
| Technique | T1070.001: Indicator Removal: Clear Windows Event Logs   |

**Evidence**
> <img width="939" height="431" alt="image" src="https://github.com/user-attachments/assets/7b4a2d7c-1442-4f4c-9787-cf2a9cbc46cd" />


---

*With log clearing confirmed, the investigation identified evidence of reflective code loading.*

---

### 🚩 Flag 38: Anti-Forensics | Reflective Loading

**Objective**
Identify the MDE `ActionType` that recorded reflective module loading, confirming the attacker used in-memory execution to avoid leaving tools on disk.

**Hunt Question**
What `ActionType` value in MDE telemetry recorded the reflective loading activity?

**Answer:** `ClrUnbackedModuleLoaded`

**Query Used**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-15T05:05:00Z) .. datetime(2026-01-15T05:15:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType contains "Module" 
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    AdditionalFields.ModuleILPathOrName
| order by TimeGenerated asc
```

**Key Observations**
- ActionType: `ClrUnbackedModuleLoaded`
- Fires when a .NET assembly is loaded into a process without a corresponding file on disk
- Confirms the use of fileless, in-memory .NET execution

**Analysis**
`ClrUnbackedModuleLoaded` is one of the most important advanced hunting events in MDE for detecting fileless execution. When a .NET assembly is loaded into a process entirely in memory with no file backing it on the disk, the CLR (Common Language Runtime) records this as an "unbacked" module. Traditional file-based detection cannot catch this: there is no file to hash or quarantine.

The presence of `ClrUnbackedModuleLoaded` confirmed the attacker used reflective loading as a deliberate evasion technique, executing their credential theft tool without ever writing it to disk.

**MITRE ATT&CK Mapping**

| Field     | Value                          |
|-----------|--------------------------------|
| Tactic    | Defense Evasion                |
| Technique | T1620: Reflective Code Loading |

**Evidence**
> <img width="1212" height="366" alt="image" src="https://github.com/user-attachments/assets/ca468f71-62d8-4138-bc5a-36704a3aaabf" />


---

*With the loading mechanism confirmed, the investigation identified the specific tool executed in memory.*

---

### 🚩 Flag 39: Anti-Forensics | Memory Tool

**Objective**
Identify the credential theft tool executed reflectively in memory to assess the downstream impact of the intrusion.

**Hunt Question**
What tool was loaded directly into memory for credential theft?

**Answer:** `SharpChrome`

**Query Used**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-15T05:05:00Z) .. datetime(2026-01-15T05:15:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType contains "Module" 
| project
    TimeGenerated,    
    ActionType,    
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    AdditionalFields.ModuleILPathOrName
| order by TimeGenerated asc
```

**Key Observations**
- Memory tool: `SharpChrome`
- .NET-based tool that extracts saved credentials from Chromium-based browsers using Windows DPAPI
- Loaded entirely in memory; no file creation event, no hash on disk

**Analysis**
SharpChrome targets the Chrome and Chromium browser credential store, decrypting saved usernames and passwords using Windows DPAPI without requiring LSASS access. In an enterprise environment where staff use Chrome to access web applications, cloud services, SaaS tools, and email, SharpChrome can harvest credentials for dozens of systems in a single execution. The attacker's reach extends far beyond the Ashford Sterling Recruitment network itself; every saved browser credential is now potentially compromised.

The deliberate choice to execute SharpChrome reflectively, as the final act of the intrusion after logs had been cleared, reflects technical sophistication: the attacker understood that file-based credential tools are easily detected and hash-identified, and chose a fileless execution path specifically for this high-value final operation.

**MITRE ATT&CK Mapping**

| Field     | Value                                       |
|-----------|---------------------------------------------|
| Tactic    | Credential Access                           |
| Technique | T1555.003: Credentials from Web Browsers    |

**Evidence**
> <img width="1046" height="338" alt="image" src="https://github.com/user-attachments/assets/c54e45fb-d887-41c2-bcdb-ff337cf95e18" />


---

*With the memory tool identified, the investigation confirmed which process it was injected into, closing the loop back to the initial access chain.*

---

### 🚩 Flag 40: Anti-Forensics | Host Process

**Objective**
Identify the legitimate process hosting the reflectively loaded credential theft tool, confirming the end-to-end connection between the initial payload behavior and the final operation.

**Hunt Question**
What legitimate process was used as the host for the reflectively loaded credential theft tool?

**Answer:** `notepad.exe`

**Query Used**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-15T05:05:00Z) .. datetime(2026-01-15T05:15:00Z))
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType contains "Module" 
| project
    TimeGenerated,    
    ActionType,    
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    AdditionalFields.ModuleILPathOrName
| order by TimeGenerated asc
```

**Key Observations**
- Host process: `notepad.exe`
- SharpChrome was loaded into the same `notepad.exe` process spawned by the payload at 05:09:53Z
- The payload had been running for over an hour before spawning this injection host as its very last action before the credential harvest

**Analysis**
This is the defining observation of the BROKER investigation. At 05:09:53Z, the payload spawned `notepad.exe ""`: a blank, untitled window. The visual decoy provided cover while the process itself served as a clean injection container. Fifteen seconds later, at 05:10:08Z, `SharpChrome` was loaded reflectively into that `notepad.exe` process via `ClrUnbackedModuleLoaded`. The `InitiatingProcessFileName` confirmed it.

The payload had been operating under its own process identity for the entire hour of the intrusion. Only at the very end, after clearing the forensic record via log clearing, did it adopt the process injection technique. This late-stage use of process injection for the highest-value operation (credential theft) reflects careful operational planning: use the most evasive technique only when it matters most, and only after the primary evidence sources have been destroyed.

`notepad.exe` is never expected to access browser DPAPI stores or load unmanaged .NET assemblies. Any detection rule triggering on `ClrUnbackedModuleLoaded` events where `InitiatingProcessFileName` is a non-development, non-scripting process like Notepad is a high-fidelity, low-noise behavioral indicator that would catch this technique regardless of what tool is being loaded.

**MITRE ATT&CK Mapping**

| Field     | Value                                           |
|-----------|-------------------------------------------------|
| Tactic    | Defense Evasion                                 |
| Technique | T1055: Process Injection                        |

**Evidence**
> <img width="1163" height="349" alt="image" src="https://github.com/user-attachments/assets/eafc20e6-f1e2-4329-885f-82d3a7f02f65" />


---

## Conclusion

The BROKER intrusion against Ashford Sterling Recruitment represents a highly methodical compromise executed with deliberate operational discipline. A single double-extension CV payload served as the entry point, but unlike a typical stager that terminates after dropping a secondary tool, this binary acted as the primary C2 agent for the entire hour-long operation. From this native foothold, the attacker leveraged LOLBins (`certutil`, `wevtutil`, `schtasks`, `reg`), legitimate commercial software (AnyDesk), and valid user accounts to extract credentials, establish layered persistence, and move laterally to the file server. Financial payment data was accessed, edited, and staged for exfiltration. In the final minutes, the attacker cleared the Windows event logs and executed a clean in-memory credential harvest hosted inside a decoy `notepad.exe` process.

What makes this intrusion technically instructive is the planning evident across the full hour: the payload running exposed but unchallenged for sixty minutes; AnyDesk deployed to every host before the first lateral movement attempt; the re-enablement of a dormant account specifically to reduce monitoring exposure; and the SharpChrome injection arriving only after the primary forensic logs had been cleared. None of these decisions are accidental. Each reflects an attacker who anticipated defensive responses and built the operation to survive partial detection at any single stage.

Despite the log clearing and fileless execution, the MDE telemetry layer preserved the behavioral sequence necessary to reconstruct the true attack narrative. Every discovery, credential, persistence, movement, and anti-forensics action left a traceable behavioral artifact in MDE event tables that no `wevtutil` command could touch. The lesson for defenders is not just that MDE is valuable, it is that independent, attacker-inaccessible telemetry is the only forensic layer that can be trusted to survive a sophisticated intrusion.

---

## Remediation Recommendations

### Email and File Delivery Controls
- Block double-extension executables (e.g., `*.pdf.exe`) at the email gateway layer
- Enforce `Show file extensions` via Group Policy across all endpoints
- Sandbox all inbound executable-capable attachments before delivery

### Credential Security
- Implement LAPS to eliminate shared local admin passwords across endpoints
- Alert on `reg save` targeting `SAM` or `SYSTEM` or `APPLICATION` executed by non-SYSTEM accounts
- Reset `sophie.turner` and `david.mitchell`; disable and remove `svc_backup`
- Enforce least privilege: standard users should not hold local Administrator rights

### Account and Access Monitoring
- Alert on `net user /active:yes` executed outside approved IT change windows
- Alert on `net user /add` on any endpoint by any non-IT account
- Monitor disabled account modification events; treat reactivation as an incident-level indicator

### Remote Access Controls
- Remove AnyDesk from `as-pc1`, `as-pc2`, and `as-srv` immediately
- Block unapproved commercial remote access tools via application control policy
- Restrict RDP to management jump hosts only; deny peer-to-peer RDP via host-based firewall GPO
- Alert on `certutil.exe` with `-urlcache` downloading executables from external URLs

### Endpoint Detection Improvements
- Alert on `ClrUnbackedModuleLoaded` where `InitiatingProcessFileName` is not a known development tool
- Alert on `wevtutil cl` executed by any non-SYSTEM process
- Monitor `notepad.exe` for unexpected child processes, network connections, or module loads
- Correlate `whoami`, `net view`, `net localgroup` in sequence within a short window as a discovery cluster

### Data Protection
- Restrict access to BACS payment files to named users with documented business justification
- Alert on `.~lock.` file creation in sensitive network share directories
- Alert on archive creation (`.7z`, `.zip`) in non-standard directories outside known backup paths
- Enable file access auditing on financial directories on `as-srv`

---

## 🧭 MITRE ATT&CK Mapping

| Tactic              | Technique ID  | Technique Name                                               | Confidence  |
|---------------------|---------------|--------------------------------------------------------------|-------------|
| Initial Access      | T1566.001     | Phishing: Spearphishing Attachment                           | 🔴 High     |
| Execution           | T1204.002     | User Execution: Malicious File                               | 🔴 High     |
| Execution           | T1218         | System Binary Proxy Execution                                | 🔴 High     |
| Defense Evasion     | T1036.005     | Masquerading: Match Legitimate Name or Location              | 🔴 High     |
| Defense Evasion     | T1105         | Ingress Tool Transfer                                        | 🔴 High     |
| Defense Evasion     | T1620         | Reflective Code Loading                                      | 🔴 High     |
| Defense Evasion     | T1055         | Process Injection                                            | 🔴 High     |
| Defense Evasion     | T1070.001     | Indicator Removal: Clear Windows Event Logs                  | 🔴 High     |
| Command and Control | T1071.001     | Application Layer Protocol: Web Protocols                    | 🔴 High     |
| Resource Development| T1608.001     | Stage Capabilities: Upload Malware                           | 🟠 Medium   |
| Credential Access   | T1003.002     | OS Credential Dumping: Security Account Manager              | 🔴 High     |
| Credential Access   | T1555.003     | Credentials from Web Browsers                                | 🔴 High     |
| Discovery           | T1033         | System Owner/User Discovery                                  | 🔴 High     |
| Discovery           | T1135         | Network Share Discovery                                      | 🔴 High     |
| Discovery           | T1069.001     | Permission Groups Discovery: Local Groups                    | 🔴 High     |
| Persistence         | T1219         | Remote Access Software                                       | 🔴 High     |
| Persistence         | T1053.005     | Scheduled Task/Job: Scheduled Task                           | 🔴 High     |
| Persistence         | T1136.001     | Create Account: Local Account                                | 🔴 High     |
| Persistence         | T1098         | Account Manipulation                                         | 🔴 High     |
| Collection          | T1039         | Data from Network Shared Drive                               | 🔴 High     |
| Collection          | T1074.001     | Data Staged: Local Data Staging                              | 🔴 High     |
| Collection          | T1560.001     | Archive Collected Data: Archive via Utility                  | 🔴 High     |
| Lateral Movement    | T1021.001     | Remote Services: Remote Desktop Protocol                     | 🔴 High     |
| Lateral Movement    | T1078         | Valid Accounts                                               | 🔴 High     |
| Lateral Movement    | T1021.003     | Remote Services: Distributed Component Object Model          | 🟠 Medium   |
| Lateral Movement    | T1021.002     | Remote Services: SMB/Windows Admin Shares                    | 🟠 Medium   |

> 🔴 **High** — Directly observed in telemetry, confirmed with evidence\
> 🟠 **Medium** — Inferred from correlated behavior; attempted but outcome unconfirmed or indirectly evidenced\
> 🟡 **Low** — Suspected based on pattern, not directly confirmed

The ATT&CK coverage across this investigation is heavily weighted toward **Defense Evasion**, **Persistence**, and **Credential Access**: the three tactic areas where the attacker invested the most deliberate effort. Defense Evasion techniques appear at every major phase, from the double-extension masquerade at delivery through LOLBin-only tool acquisition, log clearing at departure, and reflective in-memory execution for the final credential harvest. The breadth of persistence mechanisms (three independent methods across three hosts) and the depth of credential targeting (registry hives plus browser DPAPI) reflect an attacker who was not conducting a rapid smash-and-grab; they were establishing long-term residency with layered fallback paths.

---

## Final Thoughts & What I Learned

The BROKER was the a demanding and the most lengthy challenge I have worked through. There were multiple points where I had to step back, reconsider the timeline, and rebuild my mental model of the attack chain. One of the hardest moments came in Section 8. When hunting for modification evidence on the BACS payment file, I made an assumption that Microsoft Office was the editing application and searched for `.xlsx` or a `~$` temporary file. I hit a wall. Stepping back and running a broader file type search was the pivot that broke it open: an `.ods` file! This confirmed LibreOffice rather than Office. The artifact type (`~lock.#`) followed directly from the application. That sequence was a clean lesson in letting the logs define the answer rather than narrowing the query around an assumption. Any time a query comes back empty and you are confident the event happened, the first question should be whether you have assumed the wrong table, application, format, or tool.

The `ClrUnbackedModuleLoaded` event was genuinely new territory for me. I was aware of memory injection conceptually, but the initial instinct was to look for the injection in `DeviceProcessEvents`. However, nothing there explained how `SharpChrome` was operating inside `notepad.exe` with no file creation event anywhere in the chain. Pivoting to `DeviceEvents` and working through the distinct `ActionType` values present in the final minutes of the intrusion (after hitting a dead end in `DeviceProcessEvents` precisely because there was no file to find) made the technique real in a way documentation does not. Understanding why an "unbacked" module means no file ever touched disk, and how that breaks traditional file-based detection entirely, is now a permanent part of how I think about defensive gaps for .NET-based tooling. That `ActionType` will go into every future hunt template I build.

The most satisfying analytical moment in the whole investigation was reconstructing the `notepad.exe` story. The corrected telemetry showed that `notepad.exe ""` was not spawned immediately at infection as a naive decoy; it was spawned at 05:09:53Z, over an hour into the operation, after the event logs had been cleared. The payload held its own process identity for sixty minutes, then pre-positioned a trusted process as an injection host for the final operation. That is operational planning, not opportunism. Understanding that timeline correctly changed the entire interpretive frame for Flags 4, 5, and 40, and connecting all three flags into a single deliberate three-step sequence (logs cleared, Notepad spawned, SharpChrome injected) was the clearest example in this hunt of why chronological validation has to come before narrative construction.


---

## Credits

Thanks to Josh Madakor and Mohammed A for the scenario design and Cyber Range environment.

---

## Disclaimer

This report is based on a controlled Cyber Range scenario. All systems, users, files, and IP addresses are simulated.
