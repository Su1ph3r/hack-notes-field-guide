---
tags:
  - hack-notes
  - hashcat
---

## Table of Contents

- [Basic Syntax](#basic-syntax)
- [Attack Modes](#attack-modes)
- [Common Hash Types](#common-hash-types)
- [Hash Identification](#hash-identification)
- [Dictionary Attacks](#dictionary-attacks)
- [Rule-Based Attacks](#rule-based-attacks)
- [Mask Attacks (Brute-Force)](#mask-attacks-brute-force)
- [Combination Attacks](#combination-attacks)
- [Hybrid Attacks](#hybrid-attacks)
- [Performance Optimization](#performance-optimization)
- [Session Management](#session-management)
- [Output Options](#output-options)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)

---

## Basic Syntax

bash

```bash
hashcat [options] hashfile [mask|wordfiles|directories]
```

### Essential Options

bash

```bash
-m, --hash-type           # Hash type (see common modes below)
-a, --attack-mode         # Attack mode (0-9)
-o, --outfile             # Output file for cracked hashes
--outfile-format          # Output format (default: 3)
-w, --workload-profile    # Performance profile (1-4)
--session                 # Session name for resume
--restore                 # Restore session
--show                    # Show cracked passwords
--username                # Enable username in hash file
--remove                  # Remove hash after crack
--force                   # Ignore warnings
--status                  # Auto-update status screen
--status-timer            # Seconds between status updates
```

---

## Attack Modes

|Mode|Name|Description|
|---|---|---|
|0|Straight|Dictionary attack|
|1|Combination|Combine words from multiple wordlists|
|3|Brute-force|Mask attack (specify character sets)|
|6|Hybrid Wordlist + Mask|Dictionary words + mask on the right|
|7|Hybrid Mask + Wordlist|Mask on the left + dictionary words|
|9|Association|Special attack mode|

---

## Common Hash Types

### Web Application Hashes

bash

```bash
# MD5
-m 0      # MD5
-m 10     # md5($pass.$salt)
-m 20     # md5($salt.$pass)
-m 30     # md5(unicode($pass).$salt)
-m 40     # md5($salt.unicode($pass))
-m 3800   # md5($salt.$pass.$salt)

# SHA Family
-m 100    # SHA1
-m 110    # sha1($pass.$salt)
-m 120    # sha1($salt.$pass)
-m 1400   # SHA256
-m 1410   # sha256($pass.$salt)
-m 1420   # sha256($salt.$pass)
-m 1700   # SHA512
-m 1710   # sha512($pass.$salt)
-m 1720   # sha512($salt.$pass)
```

### Database Hashes

bash

```bash
-m 12     # PostgreSQL
-m 131    # MSSQL (2000)
-m 132    # MSSQL (2005)
-m 1731   # MSSQL (2012, 2014)
-m 200    # MySQL323
-m 300    # MySQL4.1/MySQL5
-m 3100   # Oracle H: Type (Oracle 7+)
-m 112    # Oracle S: Type (Oracle 11+)
-m 7500   # Kerberos 5 AS-REQ Pre-Auth etype 23
-m 13100  # Kerberos 5 TGS-REP etype 23
```

### Operating System Hashes

bash

```bash
# Windows
-m 1000   # NTLM
-m 3000   # LM
-m 5500   # NetNTLMv1
-m 5600   # NetNTLMv2
-m 13100  # Kerberos 5 TGS-REP etype 23

# Linux/Unix
-m 500    # md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
-m 1800   # sha512crypt $6$, SHA512 (Unix)
-m 7400   # sha256crypt $5$, SHA256 (Unix)
-m 3200   # bcrypt $2*$, Blowfish (Unix)
-m 1500   # descrypt, DES (Unix), Traditional DES
```

### Application-Specific Hashes

bash

```bash
# WordPress
-m 400    # phpass

# Joomla
-m 11     # Joomla < 2.5.18

# Drupal
-m 7900   # Drupal7

# vBulletin
-m 2611   # vBulletin < v3.8.5
-m 2711   # vBulletin >= v3.8.5

# WPA/WPA2
-m 2500   # WPA/WPA2 (deprecated, use 22000)
-m 22000  # WPA-PBKDF2-PMKID+EAPOL
-m 22001  # WPA-PMK-PMKID+EAPOL

# PDF
-m 10400  # PDF 1.1 - 1.3 (Acrobat 2 - 4)
-m 10500  # PDF 1.4 - 1.6 (Acrobat 5 - 8)
-m 10600  # PDF 1.7 Level 3 (Acrobat 9)
-m 10700  # PDF 1.7 Level 8 (Acrobat 10 - 11)

# Office
-m 9400   # MS Office 2007
-m 9500   # MS Office 2010
-m 9600   # MS Office 2013

# Archive
-m 11600  # 7-Zip
-m 13600  # WinZip
-m 17200  # PKZIP (Compressed)
-m 17210  # PKZIP (Uncompressed)
-m 17220  # PKZIP (Compressed Multi-File)
-m 17230  # PKZIP (Uncompressed Multi-File)
```

### Modern/Secure Hashes

bash

```bash
-m 3200   # bcrypt $2*$, Blowfish (Unix)
-m 1800   # sha512crypt $6$
-m 7400   # sha256crypt $5$
-m 10900  # PBKDF2-HMAC-SHA256
-m 11900  # PBKDF2-HMAC-MD5
-m 12000  # PBKDF2-HMAC-SHA1
-m 12100  # PBKDF2-HMAC-SHA512
-m 28200  # Exodus Desktop Wallet (scrypt)
-m 8900   # scrypt
-m 15700  # Ethereum Wallet, PBKDF2-HMAC-SHA256
```

---

## Hash Identification

bash

```bash
# Identify hash type
hashcat --identify hash.txt
hashcat --identify 'e10adc3949ba59abbe56e057f20f883e'

# Alternative tools
hashid hash.txt
hash-identifier
```

### Common Hash Formats

bash

```bash
# MD5 (32 characters)
5f4dcc3b5aa765d61d8327deb882cf99

# SHA1 (40 characters)
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# SHA256 (64 characters)
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# NTLM (32 characters, looks like MD5)
8846f7eaee8fb117ad06bdd830b7586c

# bcrypt (starts with $2a$, $2b$, $2x$, $2y$)
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy

# sha512crypt (starts with $6$)
$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/
```

---

## Dictionary Attacks

### Basic Dictionary Attack

bash

```bash
# Simple dictionary attack
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# With output file
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt

# Multiple wordlists
hashcat -m 0 -a 0 hashes.txt wordlist1.txt wordlist2.txt wordlist3.txt

# Show cracked passwords
hashcat -m 0 hashes.txt --show
```

### Common Wordlists

bash

```bash
# Popular wordlists
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/fasttrack.txt
/usr/share/seclists/Passwords/
/usr/share/wordlists/dirb/
```

---

## Rule-Based Attacks

### Using Rules

bash

```bash
# Single rule file
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r rules/best64.rule

# Multiple rule files
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r rules/best64.rule -r rules/d3ad0ne.rule

# Generate rules on the fly
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r rules/InsidePro-PasswordsPro.rule
```

### Common Rule Files

bash

```bash
# Located in: /usr/share/hashcat/rules/
best64.rule              # 64 of the best rules
d3ad0ne.rule            # Popular rules
dive.rule               # Comprehensive ruleset
InsidePro-PasswordsPro.rule
leetspeak.rule
rockyou-30000.rule
unix-ninja-leetspeak.rule
toggles1.rule           # Toggle case rules
```

### Custom Rules Examples

bash

```bash
# Rule syntax
:                       # Do nothing (passthrough)
l                       # Lowercase all
u                       # Uppercase all
c                       # Capitalize first, lowercase rest
C                       # Lowercase first, uppercase rest
t                       # Toggle case of all characters
TN                      # Toggle case at position N
r                       # Reverse
d                       # Duplicate entire word
f                       # Duplicate first character
{                       # Rotate left
}                       # Rotate right
$X                      # Append character X
^X                      # Prepend character X
[                       # Delete first character
]                       # Delete last character
DN                      # Delete character at position N
xNM                     # Extract substring from N to M
iNX                     # Insert character X at position N
oNX                     # Overwrite character at position N with X
sXY                     # Replace all instances of X with Y

# Example custom rules file
echo '$1' > custom.rule                 # Append '1'
echo '$!' >> custom.rule                # Append '!'
echo 'c $1 $2 $3' >> custom.rule       # Capital + 123
echo 'c $!' >> custom.rule              # Capital + !
echo 'u $1 $!' >> custom.rule           # Uppercase + 1!

# Use custom rules
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r custom.rule
```

### Rule Debugging

bash

```bash
# Test rules on stdin
echo "password" | hashcat -r rules/best64.rule --stdout

# Generate candidates to file
hashcat -a 0 rockyou.txt -r rules/best64.rule --stdout > candidates.txt
```

---

## Mask Attacks (Brute-Force)

### Character Sets

bash

```bash
?l = abcdefghijklmnopqrstuvwxyz                    # lowercase
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ                    # uppercase
?d = 0123456789                                     # digits
?h = 0123456789abcdef                               # hex lowercase
?H = 0123456789ABCDEF                               # hex uppercase
?s = !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~          # special characters
?a = ?l?u?d?s                                       # all printable
?b = 0x00 - 0xff                                    # all raw bytes
```

### Custom Charsets

bash

```bash
# Define custom charsets with -1 through -4, reference them as ?1 ?2 ?3 ?4
hashcat -m 0 -a 3 hashes.txt -1 ?l?d ?1?1?1?1?1?1     # 6 chars from lowercase + digits
hashcat -m 0 -a 3 hashes.txt -1 ?l?u ?1?1?1?1?1        # 5 chars from mixed case
hashcat -m 0 -a 3 hashes.txt -1 ?l?d?u -2 ?s ?1?1?1?1?2  # two custom sets combined
```

### Mask Examples

bash

```bash
# 8-char lowercase brute-force
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?l

# Common pattern: Capital + 5 lowercase + 2 digits (e.g. Summer23)
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?l?l?d?d

# 8 chars, all printable
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# Increment mode (try shorter lengths first, up to the mask length)
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a --increment
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a --increment --increment-min 4 --increment-max 8

# Mask from a file (.hcmask, one mask per line)
hashcat -m 0 -a 3 hashes.txt masks.hcmask
```

---

## Combination Attacks

bash

```bash
# Attack mode 1: every word in the left list joined with every word in the right list
hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Same list combined with itself (e.g. "summer" + "2023")
hashcat -m 0 -a 1 hashes.txt rockyou.txt rockyou.txt

# Apply a single rule to each side: -j left, -k right
hashcat -m 0 -a 1 hashes.txt left.txt right.txt -j '$-' -k '$!'   # append '-' to left, '!' to right
```

Note: `-j` and `-k` apply one rule to each left and right word respectively. For more than two words, generate a combined wordlist first with `combinator.bin` from hashcat-utils.

---

## Hybrid Attacks

bash

```bash
# Mode 6: dictionary word + mask appended (e.g. password2023)
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d?d

# Mode 7: mask prepended + dictionary word (e.g. 2023password)
hashcat -m 0 -a 7 hashes.txt ?d?d?d?d rockyou.txt

# Word + 3 digits + 1 special (e.g. summer123!)
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d?s

# Custom charset inside a hybrid mask
hashcat -m 0 -a 6 hashes.txt rockyou.txt -1 ?d?s ?1?1
```

---

## Performance Optimization

bash

```bash
# Workload profiles (-w): 1=low, 2=default, 3=high, 4=nightmare
hashcat -m 0 -a 0 hashes.txt rockyou.txt -w 3

# Optimized kernels (-O): much faster, but caps the maximum password length
hashcat -m 0 -a 0 hashes.txt rockyou.txt -O

# Benchmark
hashcat -b -m 0          # benchmark a single mode
hashcat -b               # benchmark all modes

# Devices
hashcat -I                                        # list detected devices
hashcat -m 0 hashes.txt rockyou.txt -d 1          # use device 1
hashcat -m 0 hashes.txt rockyou.txt -D 2          # device type: 1=CPU, 2=GPU

# Thermal safety and host overhead
hashcat -m 0 hashes.txt rockyou.txt --hwmon-temp-abort 90
hashcat -m 0 hashes.txt rockyou.txt -w 4 --hwmon-disable
```

---

## Session Management

bash

```bash
# Named session (resumable)
hashcat -m 0 -a 0 hashes.txt rockyou.txt --session=crackjob

# Interactive keys during a run: [p]ause, [r]esume, [b]ypass, [c]heckpoint, [q]uit
# Resume a saved session by name
hashcat --session=crackjob --restore

# Restore/session files live in ~/.local/share/hashcat/sessions/

# Distribute keyspace across machines with --skip and --limit
hashcat -m 0 -a 0 hashes.txt rockyou.txt --skip 0 --limit 1000000

# Show the total keyspace for a given attack
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a --keyspace
```

---

## Output Options

bash

```bash
# Write cracked results to a file
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt

# Outfile format (--outfile-format): 1=hash 2=plain 3=hash:plain 4=hex_plain 5=hash:hex_plain
hashcat -m 0 hashes.txt rockyou.txt -o plains.txt --outfile-format 2

# Show already-cracked (from the potfile) and emit just the plaintext
hashcat -m 0 hashes.txt --show
hashcat -m 0 hashes.txt --show --outfile-format 2 -o plains.txt

# List the still-uncracked (left) hashes
hashcat -m 0 hashes.txt --left

# Potfile control
hashcat -m 0 hashes.txt rockyou.txt --potfile-path job.potfile
hashcat -m 0 hashes.txt rockyou.txt --potfile-disable

# Username-prefixed input (user:hash) and username-aware output
hashcat -m 1000 -a 0 hashes.txt rockyou.txt --username
hashcat -m 1000 hashes.txt --show --username
```

Default potfile: `~/.local/share/hashcat/hashcat.potfile`. Delete it to force re-cracking of hashes hashcat thinks it already solved.

---

## Common Workflows

### Crack NTLM hashes from a secretsdump / NTDS dump

bash

```bash
# Keep user:nt from the secretsdump output (user:rid:lm:nt:::)
cut -d: -f1,4 ntds.txt > ntlm.txt
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule --username
hashcat -m 1000 ntlm.txt --show --username
```

### Crack a captured WPA2 handshake or PMKID

bash

```bash
# Convert the capture to 22000 format first (hcxtools)
hcxpcapngtool -o hash.22000 capture.pcapng
hashcat -m 22000 -a 0 hash.22000 wordlist.txt
hashcat -m 22000 -a 3 hash.22000 ?d?d?d?d?d?d?d?d        # 8-digit keys
```

### Crack Kerberoast and AS-REP roast tickets

bash

```bash
hashcat -m 13100 -a 0 kerberoast.txt rockyou.txt -r rules/best64.rule   # TGS-REP (Kerberoast)
hashcat -m 18200 -a 0 asrep.txt rockyou.txt -r rules/best64.rule        # AS-REP roast
```

### Staged approach (fast to slow)

bash

```bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt                       # 1. straight dictionary
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r rules/best64.rule  # 2. dictionary + rules
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?d?d?d?d              # 3. hybrid
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a --increment        # 4. brute-force
```

Related: see [NetExec and Impacket](NetExec%20and%20Impacket.md) for dumping NTDS, [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md) for generating roast hashes, and [Wireless](Wireless.md) for capturing handshakes.

---

## Troubleshooting

bash

```bash
# "No devices found/left": install GPU drivers / OpenCL runtime, or force CPU
hashcat -I                                       # list what hashcat can see
hashcat -m 0 hashes.txt rockyou.txt -D 1         # CPU only

# "Token length exception": wrong -m mode or a malformed hash line
hashcat --identify hash.txt

# "Separator unmatched": --username used on a file without user: prefix (or vice versa)

# Self-test failures on some GPUs
hashcat -m 0 hashes.txt rockyou.txt --self-test-disable

# Force past warnings (thermal, unsupported hardware)
hashcat -m 0 hashes.txt rockyou.txt --force

# Slow performance: raise workload and enable the optimized kernel
hashcat -m 0 hashes.txt rockyou.txt -w 3 -O

# Re-test hashes hashcat already cracked (clear the potfile)
rm ~/.local/share/hashcat/hashcat.potfile

# Watch status on a long-running or stuck job
hashcat -m 0 hashes.txt rockyou.txt --status --status-timer 10
```

## Related

- Checklists: [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md), [Wireless Network Assessment](../Checklists/Wireless%20Network%20Assessment.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
