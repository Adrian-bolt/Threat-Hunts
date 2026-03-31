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
8. [Recommendations](#recommendations)
9. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---


## 1. Executive Summary

## Executive Summary

This investigation found that an attacker broke into the Azuki system by logging in through Remote Desktop (RDP) using a stolen account (`kenji.sato`) from an outside IP (88.97.178.12). Once inside `azuki-sl`, the attacker looked around the network (`arp.exe`), hid files in `C:\ProgramData\WindowsCache`, and used built-in Windows tools like `certutil.exe` to download more malware. They avoided detection by turning off parts of Windows Defender and made sure they could stay in the system by creating a scheduled task ("Windows Update Check") and a backdoor account (`support`). The attacker stole passwords from memory using `mm.exe` with `sekurlsa::logonpasswords`, connected to a command-and-control server (78.141.196.6 over port 443), and compressed stolen data into `export-data.zip` before sending it out through Discord. They also cleared security logs (`wevtutil.exe`) to hide their actions and attempted to move to another system (10.1.0.188) using RDP (`mstsc.exe`). All findings were identified using Microsoft Defender for Endpoint (MDE) logs and KQL queries by analyzing activity across logon, process, file, registry, and network events.



---

## 2. Environment Overview

## Environment Overview

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

## All Flags Quick Reference

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

### 🚩 Flag 10: Command & Control | C2 Server Address

**Objective**
Identify attacker-controlled infrastructure.

**Hunt Question**
Identify the IP address of the command and control server?

**Answer:** `78.141.196.6`

**Query Used**

```kql
 DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where InitiatingProcessFileName in~ ("powershell.exe", "curl.exe", "certutil.exe", "wget.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated asc
```

**Key Observations**
- Outbound connection to external IP
- Communication initiated by LOLBins


**Analysis**
This IP represents attacker infrastructure used to control the compromised system.



**MITRE ATT&CK Mapping**

| Field     | Value                                      |
|-----------|--------------------------------------------|
| Tactic    | Collection                                 |
| Technique | T1071: Application Layer Protocol          |

**Evidence**

<img width="1495" height="509" alt="image" src="https://github.com/user-attachments/assets/7a41db9d-352d-4147-9299-a28adeedcc81" />




---

### 🚩 Flag 11: Command & Control | C2 Communication Port

**Objective**
Identify communication channel used by attacker.

**Hunt Question**
Identify the destination port used for command and control communications?

**Answer:** `443`

**Query Used**

```kql
 DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where InitiatingProcessFileName in~ ("powershell.exe", "curl.exe", "certutil.exe", "wget.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated asc
```

**Key Observations**
- HTTPS port used for communication
- Traffic appears legitimate


**Analysis**
Using port 443 helps attackers hide within normal encrypted web traffic.

**MITRE ATT&CK Mapping**

| Field     | Value                                                          |
|-----------|----------------------------------------------------------------|
| Tactic    | Credential Access                                              |
| Technique | T1071: Application Layer Protocol                              |

**Evidence**

<img width="1497" height="513" alt="image" src="https://github.com/user-attachments/assets/26a745a2-f860-4814-8905-ce9d3bf1ca04" />




---

### 🚩 Flag 12: Credential Access | Credential Theft Tool

**Objective**
Identify tool used for credential dumping.

**Hunt Question**
Identify the filename of the credential dumping tool?

**Answer:** `mm.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where FolderPath contains "ProgramData\\WindowsCache"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Executable located in staging directory
- Tool executed shortly after persistence

**Analysis**
The attacker used `mm.exe` to dump credentials from memory to escalate access.

**MITRE ATT&CK Mapping**

| Field     | Value                              |
|-----------|------------------------------------|
| Tactic    | Discovery                          |
| Technique | T1003: OS Credential Dumping       |

**Evidence**

<img width="1498" height="513" alt="image" src="https://github.com/user-attachments/assets/7563585c-5c1d-45c7-87e3-ea66f05e7599" />




---

### 🚩 Flag 13: Credential Access | Memory Extraction Module

**Objective**
Identify method used to extract credentials.

**Hunt Question**
Identify the module used to extract logon passwords from memory?

**Answer:** `sekurlsa::logonpasswords`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine contains "::"   //Hint 2: Look for module::command
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Memory extraction command executed
- Indicates credential harvesting

**Analysis**
This module extracts plaintext credentials from memory, allowing attackers to move laterally.

**MITRE ATT&CK Mapping**

| Field     | Value                          |
|-----------|--------------------------------|
| Tactic    | Discovery                      |
| Technique | T1003: OS Credential Dumping   |

**Evidence**

<img width="1498" height="517" alt="image" src="https://github.com/user-attachments/assets/8291b960-3395-415f-8628-c90e5363a3a6" />






---

### 🚩 Flag 14: Collection | Data Staging Archive

**Objective**
Identify collected data prior to exfiltration.

**Hunt Question**
Identify the compressed archive filename used for data exfiltration?

**Answer:** `export-data.zip`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where FileName contains ".zip"  //Hint 1: Search for ZIP file creation in the staging directory during the collection phase.
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Key Observations**
- Archive created in staging phase
- Indicates data collection complete


**Analysis**
The attacker compressed data to prepare it for exfiltration.

**MITRE ATT&CK Mapping**

| Field     | Value                                                |
|-----------|------------------------------------------------------|
| Tactic    | Discovery                                            |
| Technique | T1560: Archive Collected Data                        |

**Evidence**

<img width="1497" height="515" alt="image" src="https://github.com/user-attachments/assets/31405e91-493c-446d-adbe-3f7ef4f1784f" />




---

### 🚩 Flag 15: Exfiltration | Exfiltration Channel

**Objective**
Identify how data was exfiltrated.

**Hunt Question**
Identify the cloud service used to exfiltrate stolen data?

**Answer:** `discord`

**Query Used**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where InitiatingProcessFileName in~ ("powershell.exe", "curl.exe", "certutil.exe", "wget.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated asc
```

**Key Observations**
- Communication with Discord domains
- Outbound data transfer observed
- 
**Analysis**
Discord was used as an exfiltration channel to blend malicious traffic with legitimate activity.


**MITRE ATT&CK Mapping**

| Field     | Value                                |
|-----------|--------------------------------------|
| Tactic    | Persistence                          |
| Technique | T1567: Exfiltration Over Web Service |

**Evidence**

<img width="1496" height="518" alt="image" src="https://github.com/user-attachments/assets/a74de953-94b2-4b66-ab0b-1fe5154311da" />




---

### 🚩 Flag 16: Anti-Forensics | Log Tampering

**Objective**
Identify log deletion activity.

**Hunt Question**
Identify the first Windows event log cleared by the attacker?

**Answer:** `security`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine has_any ("wevtutil.exe")  //Hint 2: Look for wevtutil.exe executions and identify which log was cleared first.
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- `wevtutil.exe` used
- Security logs cleared first

**Analysis**
Log clearing is used to erase evidence and delay detection.

**MITRE ATT&CK Mapping**

| Field     | Value                         |
|-----------|-------------------------------|
| Tactic    | Persistence                   |
| Technique | T1070: Indicator Removal      |

**Evidence**

<img width="1497" height="511" alt="image" src="https://github.com/user-attachments/assets/b5a7eaa4-d22c-4564-965d-7b59881bbb70" />




---

### 🚩 Flag 17: Impact | Persistence Account

**Objective**
Identify attacker-created account.

**Hunt Question**
Identify the backdoor account username created by the attacker?

**Answer:** `support`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine has_any ("/add") //Hint 2: Look for commands with the /add parameter followed by administrator group additions.
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Account created using command line
- Added for persistence


**Analysis**
Backdoor accounts provide attackers with continued access.

**MITRE ATT&CK Mapping**

| Field     | Value                          |
|-----------|--------------------------------|
| Tactic    | Defense Evasion                |
| Technique | T1136: Create Account          |

**Evidence**

<img width="1498" height="506" alt="image" src="https://github.com/user-attachments/assets/90c9785e-0dbe-4c06-9e50-710f89e18c6a" />




---

### 🚩 Flag 18: Execution | Malicious Script

**Objective**
Identify automation used in attack.

**Hunt Question**
Identify the PowerShell script file used to automate the attack chain?

**Answer:** `wupdate.ps1`

**Query Used**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where InitiatingProcessCommandLine endswith ".ps1" or FileName endswith ".bat"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Key Observations**
- Script execution detected
- Used early in attack


**Analysis**
The script likely automated multiple steps in the attack chain.

**MITRE ATT&CK Mapping**

| Field     | Value                                      |
|-----------|--------------------------------------------|
| Tactic    | Persistence                                |
| Technique | T1059: Command and Scripting Interpreter   |

**Evidence**

<img width="1892" height="510" alt="image" src="https://github.com/user-attachments/assets/d1a29527-f22f-41f2-8b97-46838bb13f60" />




---

### 🚩 Flag 19: Lateral Movement | Secondary Target

**Objective**
Identify lateral movement target.

**Hunt Question**
What IP address was targeted for lateral movement?

**Answer:** `10.1.0.188`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine has_any ("cmdkey", "mstsc")  //Hint 2: Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- Internal IP targeted
- RDP credentials prepared


**Analysis**
The attacker attempted to pivot to another system within the network.


**MITRE ATT&CK Mapping**

| Field     | Value                        |
|-----------|------------------------------|
| Tactic    | Persistence                  |
| Technique | T1021: Remote Services       |

**Evidence**

<img width="1334" height="513" alt="image" src="https://github.com/user-attachments/assets/df3ec10d-4b4a-4f41-9a5c-2b5d039ff0cb" />




---

### 🚩 Flag 20: Lateral Movement | Remote Access Tool

**Objective**
Identify tool used for lateral movement.

**Hunt Question**
Identify the remote access tool used for lateral movement?

**Answer:** `mstsc.exe`

**Query Used**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName =~ "azuki-sl"
| where ProcessCommandLine contains "/v:"  // NOTE: "/v:" finds RDP connections
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp asc
```

**Key Observations**
- RDP tool executed
- Connection attempt to internal host

**Analysis**
`mstsc.exe` confirms RDP-based lateral movement.

**MITRE ATT&CK Mapping**

| Field     | Value                        |
|-----------|------------------------------|
| Tactic    | Persistence                  |
| Technique | T1021: Remote Services       |

**Evidence**


<img width="1335" height="515" alt="image" src="https://github.com/user-attachments/assets/e56b60e3-4e53-4887-9c47-8fb1f2f1d277" />




---

## Conclusion

## Conclusion

This investigation shows how an attacker broke into the Azuki system using a stolen account (`kenji.sato`) through Remote Desktop (RDP) from an outside IP (`88.97.178.12`). Instead of using obvious malware, the attacker used normal Windows tools to stay hidden. They connected to a control server (`78.141.196.6`) over port 443, changed Windows Defender settings to avoid detection, and stored malware in a hidden folder (`C:\ProgramData\WindowsCache`). They also downloaded files using `certutil.exe`, which looks like normal system activity.

To stay in the system, the attacker created a scheduled task ("Windows Update Check") that runs a fake system file (`svchost.exe`) and added a backdoor account (`support`). They then stole passwords from memory using `mm.exe` with `sekurlsa::logonpasswords`. After that, they collected data, saved it as `export-data.zip`, and sent it out using Discord. Before leaving, they deleted security logs with `wevtutil.exe` to hide what they did and tried to move to another system (`10.1.0.188`) using RDP (`mstsc.exe`).

Even though the attacker tried to hide their actions, the logs from Microsoft Defender for Endpoint still showed everything they did. This shows that even when attackers use normal tools to blend in, their behavior can still be tracked. The main lesson is that watching behavior and using good logging tools is very important for finding and understanding attacks like this.

---

## Recommendations



### Credential Security

- Reset credentials for `kenji.sato` immediately and investigate for reuse across other systems  
- Enforce Multi-Factor Authentication (MFA) for all remote access (especially RDP)  
- Disable or restrict accounts with remote login privileges unless absolutely required  
- Monitor for abnormal login behavior (e.g., external IP logins like `88.97.178.12`)  

---

### Remote Access Controls

- Restrict RDP access to approved IP ranges or VPN-only access  
- Block direct external RDP connections to endpoints  
- Alert on `LogonType == RemoteInteractive` from external IPs  
- Monitor and alert on `mstsc.exe` usage between internal systems  

---

### Endpoint Hardening (Defender Protection)

- Prevent modification of Windows Defender exclusions via Group Policy  
- Alert on changes to:
  - `Exclusions\Extensions`
  - `Exclusions\Paths`
- Specifically monitor exclusions involving:
  - Temp directories (`AppData\Local\Temp`)  
- Enable tamper protection in Microsoft Defender  

---

### Living-Off-the-Land Binary (LOLBins) Monitoring

- Alert on suspicious use of:
  - `certutil.exe`
  - `powershell.exe`
  - `cmd.exe`
- Specifically detect:
  - `certutil.exe -urlcache` downloading files  
- Block or restrict LOLBins via application control policies where possible  

---

### Persistence Detection

- Alert on `schtasks.exe` usage outside of approved administrative activity  
- Monitor creation of scheduled tasks with suspicious names (e.g., "Windows Update Check")  
- Alert on new local account creation using:
  - `net user /add`  
- Monitor addition of accounts to administrator groups  

---

### Credential Dumping Detection

- Alert on execution of credential dumping tools such as `mm.exe`  
- Detect commands containing:
  - `sekurlsa::logonpasswords`  
- Monitor access to LSASS memory  
- Enable Credential Guard where possible  

---

### Command & Control (C2) Detection

- Block or alert on outbound connections to suspicious IPs like `78.141.196.6`  
- Monitor outbound traffic on port `443` that originates from:
  - LOLBins (certutil, PowerShell, curl, etc.)  
- Use threat intelligence feeds to identify known malicious infrastructure  

---

### Data Exfiltration Monitoring

- Alert on outbound connections to cloud platforms such as Discord  
- Monitor unusual upload behavior from endpoints  
- Alert on archive creation (`.zip`) in non-standard directories  
- Monitor staging locations like:
  - `C:\ProgramData\WindowsCache`  

---

### Anti-Forensics Detection

- Alert on `wevtutil.exe` execution, especially:
  - `wevtutil cl` (log clearing)  
- Treat log deletion as a high-severity incident  
- Ensure logs are forwarded to a centralized SIEM (so attackers cannot delete them locally)  

---

### File and Directory Monitoring

- Monitor suspicious directories such as:
  - `C:\ProgramData\WindowsCache`  
- Alert on hidden file activity using:
  - `attrib` commands  
- Track execution of files in non-standard directories  

---

### Lateral Movement Detection

- Monitor use of:
  - `mstsc.exe`
  - `cmdkey.exe`  
- Alert on connections to internal IPs like `10.1.0.188` from compromised hosts  
- Restrict peer-to-peer RDP communication between endpoints  

---

### Logging and Visibility

- Ensure full logging is enabled across:
  - Logon events  
  - Process execution  
  - Network connections  
  - Registry changes  
- Centralize logs in Microsoft Defender / Sentinel  
- Regularly audit logs for suspicious sequences of activity  


---

## 🧭 MITRE ATT&CK Mapping


| Tactic              | Technique ID  | Technique Name                                               | Confidence  |
|---------------------|---------------|--------------------------------------------------------------|-------------|
| Initial Access      | T1078         | Valid Accounts                                               | 🔴 High     |
| Execution           | T1059.001     | Command and Scripting Interpreter: PowerShell                | 🔴 High     |
| Execution           | T1105         | Ingress Tool Transfer                                        | 🔴 High     |
| Defense Evasion     | T1562.001     | Impair Defenses: Disable or Modify Tools                     | 🔴 High     |
| Defense Evasion     | T1036         | Masquerading                                                 | 🔴 High     |
| Defense Evasion     | T1070.001     | Indicator Removal: Clear Windows Event Logs                  | 🔴 High     |
| Defense Evasion     | T1564         | Hide Artifacts                                               | 🔴 High     |
| Command and Control | T1071.001     | Application Layer Protocol: Web Protocols                    | 🔴 High     |
| Credential Access   | T1003         | OS Credential Dumping                                        | 🔴 High     |
| Discovery           | T1016         | System Network Configuration Discovery                       | 🔴 High     |
| Persistence         | T1053.005     | Scheduled Task/Job: Scheduled Task                           | 🔴 High     |
| Persistence         | T1136.001     | Create Account: Local Account                                | 🔴 High     |
| Collection          | T1074.001     | Data Staged: Local Data Staging                              | 🔴 High     |
| Collection          | T1560.001     | Archive Collected Data                                       | 🔴 High     |
| Exfiltration        | T1567         | Exfiltration Over Web Service                                | 🔴 High     |
| Lateral Movement    | T1021.001     | Remote Services: Remote Desktop Protocol                     | 🔴 High     |

> 🔴 **High** — Directly observed in telemetry, confirmed with evidence\
> 🟠 **Medium** — Inferred from correlated behavior; attempted but outcome unconfirmed or indirectly evidenced\
> 🟡 **Low** — Suspected based on pattern, not directly confirmed

The attacker broke into the system using a stolen account and Remote Desktop (RDP), without needing any exploits. They relied on built-in Windows tools to stay hidden instead of using obvious malware.
To avoid detection, the attacker turned off parts of Windows Defender, hid files in a non-standard folder, used tools like `certutil.exe`, and cleared logs with `wevtutil.exe`. This shows they were trying to stay unnoticed the entire time. They kept access by creating a scheduled task and a backdoor account. They then stole passwords from memory using `mm.exe` with `sekurlsa::logonpasswords`, allowing them to move further in the system.
The attacker collected data, saved it as `export-data.zip`, and sent it out using Discord, making the traffic look normal. Overall, this attack shows a “living-off-the-land” approach, where the attacker used normal system tools and behavior to stay hidden while keeping control of the system.

---
 
