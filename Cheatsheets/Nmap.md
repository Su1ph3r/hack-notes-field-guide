---
tags:
  - hack-notes
  - nmap
---

# Nmap Cheatsheet

## Table of Contents

- [Basic Syntax](#basic-syntax)
- [Target Specification](#target-specification)
- [Host Discovery](#host-discovery)
- [Port Scanning Techniques](#port-scanning-techniques)
- [Port Specification](#port-specification)
- [Service and Version Detection](#service-and-version-detection)
- [OS Detection](#os-detection)
- [Timing and Performance](#timing-and-performance)
- [NSE Scripts](#nse-scripts)
- [Firewall/IDS Evasion](#firewallids-evasion)
- [Output Formats](#output-formats)
- [Advanced Scanning Techniques](#advanced-scanning-techniques)
- [Common Penetration Testing Workflows](#common-penetration-testing-workflows)
- [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
- [Integration with Other Tools](#integration-with-other-tools)
- [Troubleshooting](#troubleshooting)
- [Quick Reference](#quick-reference)

---

## Basic Syntax

bash

```bash
nmap [Scan Type] [Options] {target specification}
```

### Essential Options

bash

```bash
-sS        # TCP SYN scan (default, requires root)
-sT        # TCP connect scan (no root required)
-sU        # UDP scan
-sV        # Version detection
-O         # OS detection
-A         # Aggressive scan (OS, version, script, traceroute)
-p         # Port specification
-Pn        # Skip host discovery (treat all hosts as online)
-n         # No DNS resolution
-R         # Always resolve DNS
-v         # Verbose output
-vv        # Very verbose output
-oA        # Output in all formats
```

---

## Target Specification

bash

```bash
# Single IP
nmap 192.168.1.1

# Hostname
nmap scanme.nmap.org

# IP range
nmap 192.168.1.1-254

# CIDR notation
nmap 192.168.1.0/24

# Multiple targets
nmap 192.168.1.1 192.168.1.2 192.168.1.3

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1

# Exclude from file
nmap 192.168.1.0/24 --excludefile exclude.txt

# Input from file
nmap -iL targets.txt

# Random targets
nmap -iR 10

# IPv6
nmap -6 fe80::1
```

### Target File Format

bash

```bash
# targets.txt
192.168.1.1
192.168.1.10-20
192.168.2.0/24
10.0.0.*
scanme.nmap.org
```

---

## Host Discovery

### Ping Scanning

bash

```bash
# Default ping scan (ICMP echo, TCP SYN to 443, TCP ACK to 80, ICMP timestamp)
nmap -sn 192.168.1.0/24

# No ping (treat all hosts as online)
nmap -Pn 192.168.1.0/24

# ICMP echo only
nmap -PE 192.168.1.0/24

# ICMP timestamp
nmap -PP 192.168.1.0/24

# ICMP address mask
nmap -PM 192.168.1.0/24

# TCP SYN ping (port 80 by default)
nmap -PS 192.168.1.0/24

# TCP SYN ping to specific ports
nmap -PS22,80,443,3389 192.168.1.0/24

# TCP ACK ping
nmap -PA 192.168.1.0/24

# UDP ping
nmap -PU 192.168.1.0/24

# ARP ping (local network only)
nmap -PR 192.168.1.0/24

# Disable DNS resolution
nmap -sn -n 192.168.1.0/24

# List scan (no ping or port scan)
nmap -sL 192.168.1.0/24
```

---

## Port Scanning Techniques

### Scan Types

bash

```bash
# TCP SYN scan (stealth, default with root)
nmap -sS 192.168.1.1

# TCP Connect scan (no root required)
nmap -sT 192.168.1.1

# UDP scan
nmap -sU 192.168.1.1

# TCP ACK scan (check firewall rules)
nmap -sA 192.168.1.1

# TCP Window scan
nmap -sW 192.168.1.1

# TCP Maimon scan
nmap -sM 192.168.1.1

# TCP NULL scan
nmap -sN 192.168.1.1

# TCP FIN scan
nmap -sF 192.168.1.1

# TCP Xmas scan
nmap -sX 192.168.1.1

# Custom TCP scan
nmap --scanflags URGACKPSHRSTSYNFIN 192.168.1.1

# Idle/Zombie scan
nmap -sI zombie_host target_host

# IP protocol scan
nmap -sO 192.168.1.1

# SCTP INIT scan
nmap -sY 192.168.1.1

# SCTP COOKIE-ECHO scan
nmap -sZ 192.168.1.1
```

### Scan Combinations

bash

```bash
# TCP SYN + UDP (common)
nmap -sSU 192.168.1.1

# Comprehensive scan
nmap -sS -sU -T4 -A -v 192.168.1.1

# Quick scan (top 100 ports)
nmap -F 192.168.1.1

# Intense scan
nmap -T4 -A -v 192.168.1.1
```

---

## Port Specification

bash

```bash
# Single port
nmap -p 22 192.168.1.1

# Multiple ports
nmap -p 22,80,443 192.168.1.1

# Port range
nmap -p 1-1000 192.168.1.1

# All ports
nmap -p- 192.168.1.1

# Top 100 most common ports
nmap -F 192.168.1.1

# Top N ports
nmap --top-ports 20 192.168.1.1

# Specific protocol ports
nmap -p U:53,T:80,443 192.168.1.1

# Port ranges by protocol
nmap -p U:53,111,137,T:21-25,80,139,8080 192.168.1.1

# All ports except
nmap -p-1000,1002-65535 192.168.1.1

# Fast scan (top 100)
nmap -F 192.168.1.1

# Consecutive port ranges
nmap -p 1-65535 192.168.1.1
```

### Port State Explanations

bash

```bash
open           # Application is accepting connections
closed         # Port accessible but no application listening
filtered       # Firewall/filter blocking, can't determine if open
unfiltered     # Accessible but can't determine open/closed
open|filtered  # Can't determine if open or filtered
closed|filtered # Can't determine if closed or filtered
```

---

## Service and Version Detection

bash

```bash
# Basic version detection
nmap -sV 192.168.1.1

# Intensity levels (0-9, default 7)
nmap -sV --version-intensity 0 192.168.1.1    # Light
nmap -sV --version-intensity 9 192.168.1.1    # All probes

# Light version detection
nmap -sV --version-light 192.168.1.1

# Aggressive version detection
nmap -sV --version-all 192.168.1.1

# Set version probe trace
nmap -sV --version-trace 192.168.1.1

# RPC scan
nmap -sR 192.168.1.1

# Combined service scan
nmap -sS -sV -O 192.168.1.1
```

---

## OS Detection

bash

```bash
# Basic OS detection
nmap -O 192.168.1.1

# Aggressive OS detection
nmap -O --osscan-guess 192.168.1.1

# Limit OS detection (fast)
nmap -O --osscan-limit 192.168.1.1

# Maximum retries for OS detection
nmap -O --max-os-tries 1 192.168.1.1

# OS detection with version scanning
nmap -A 192.168.1.1
```

---

## Timing and Performance

### Timing Templates

bash

```bash
-T0    # Paranoid (IDS evasion, very slow)
-T1    # Sneaky (IDS evasion, slow)
-T2    # Polite (less bandwidth, slower)
-T3    # Normal (default)
-T4    # Aggressive (fast, local networks)
-T5    # Insane (very fast, may miss results)

# Examples
nmap -T0 192.168.1.1    # Stealth scan
nmap -T4 192.168.1.1    # Fast scan
```

### Performance Options

bash

```bash
# Parallelization
--min-hostgroup 256        # Parallel host scan group
--max-hostgroup 1024

# Timeouts
--host-timeout 10m         # Give up on slow hosts
--scan-delay 1s            # Delay between probes
--max-scan-delay 10s

# RTT timeout
--initial-rtt-timeout 100ms
--max-rtt-timeout 1000ms
--min-rtt-timeout 10ms

# Retries
--max-retries 3

# Packet rate
--min-rate 1000            # Minimum packets per second
--max-rate 10000           # Maximum packets per second

# Parallelism
--min-parallelism 100
--max-parallelism 256
```

### Performance Examples

bash

```bash
# Fast scan (local network)
nmap -T4 -F 192.168.1.0/24

# Aggressive scan
nmap -T4 -A -v --min-rate 1000 192.168.1.1

# Slow/stealthy scan
nmap -T2 --scan-delay 1s 192.168.1.1

# Maximum speed
nmap -T5 --min-rate 5000 192.168.1.0/24
```

---

## NSE Scripts

### Script Categories

bash

```bash
auth          # Authentication scripts
broadcast     # Network broadcast discovery
brute         # Brute force attacks
default       # Default scripts (-sC)
discovery     # Network discovery
dos           # Denial of service
exploit       # Exploitation scripts
external      # Sends data to third party
fuzzer        # Fuzzing scripts
intrusive     # May crash target or use resources
malware       # Malware detection
safe          # Safe scripts (won't crash)
version       # Version detection enhancement
vuln          # Vulnerability detection
```

### Running Scripts

bash

```bash
# Default scripts
nmap -sC 192.168.1.1

# Specific script
nmap --script=http-title 192.168.1.1

# Multiple scripts
nmap --script=http-title,http-headers 192.168.1.1

# Script category
nmap --script=vuln 192.168.1.1

# Multiple categories
nmap --script=default,safe 192.168.1.1

# All scripts except
nmap --script "not dos" 192.168.1.1

# Wildcard
nmap --script "http-*" 192.168.1.1

# Script with arguments
nmap --script=mysql-brute --script-args userdb=users.txt,passdb=pass.txt 192.168.1.1

# Update script database
nmap --script-updatedb

# Script help
nmap --script-help http-title

# Script trace
nmap --script=http-title --script-trace 192.168.1.1
```

### Common NSE Scripts

#### Web Server Scripts

bash

```bash
# HTTP enumeration
nmap --script=http-enum 192.168.1.1

# HTTP methods
nmap --script=http-methods 192.168.1.1

# HTTP headers
nmap --script=http-headers 192.168.1.1

# HTTP title
nmap --script=http-title 192.168.1.1

# HTTP auth methods
nmap --script=http-auth 192.168.1.1

# HTTP vulnerabilities
nmap --script=http-vuln* 192.168.1.1

# HTTP backup files
nmap --script=http-backup-finder 192.168.1.1

# Robots.txt
nmap --script=http-robots.txt 192.168.1.1

# Shellshock
nmap --script=http-shellshock 192.168.1.1

# SSL/TLS vulnerabilities
nmap --script=ssl-heartbleed 192.168.1.1
nmap --script=ssl-poodle 192.168.1.1
nmap --script=ssl-dh-params 192.168.1.1
nmap --script=ssl-cert 192.168.1.1
nmap --script=ssl-enum-ciphers 192.168.1.1
```

#### SMB Scripts

bash

```bash
# SMB enumeration
nmap --script=smb-enum-shares 192.168.1.1
nmap --script=smb-enum-users 192.168.1.1
nmap --script=smb-enum-domains 192.168.1.1
nmap --script=smb-enum-groups 192.168.1.1
nmap --script=smb-enum-processes 192.168.1.1
nmap --script=smb-enum-services 192.168.1.1
nmap --script=smb-enum-sessions 192.168.1.1

# SMB vulnerabilities
nmap --script=smb-vuln* 192.168.1.1
nmap --script=smb-vuln-ms17-010 192.168.1.1  # EternalBlue
nmap --script=smb-vuln-ms08-067 192.168.1.1

# SMB OS discovery
nmap --script=smb-os-discovery 192.168.1.1

# SMB security mode
nmap --script=smb-security-mode 192.168.1.1

# SMB protocols
nmap --script=smb-protocols 192.168.1.1

# SMB signing
nmap --script=smb2-security-mode 192.168.1.1
```

#### DNS Scripts

bash

```bash
# DNS zone transfer
nmap --script=dns-zone-transfer --script-args dns-zone-transfer.domain=example.com 192.168.1.1

# DNS brute force
nmap --script=dns-brute 192.168.1.1

# DNS recursion
nmap --script=dns-recursion 192.168.1.1

# DNS cache snoop
nmap --script=dns-cache-snoop 192.168.1.1
```

#### FTP Scripts

bash

```bash
# FTP anonymous login
nmap --script=ftp-anon 192.168.1.1

# FTP brute force
nmap --script=ftp-brute 192.168.1.1

# FTP bounce attack
nmap --script=ftp-bounce 192.168.1.1

# FTP vulnerabilities
nmap --script=ftp-vuln* 192.168.1.1
```

#### SSH Scripts

bash

```bash
# SSH authentication methods
nmap --script=ssh-auth-methods 192.168.1.1

# SSH host key
nmap --script=ssh-hostkey 192.168.1.1

# SSH version
nmap --script=ssh2-enum-algos 192.168.1.1

# SSH brute force
nmap --script=ssh-brute 192.168.1.1
```

#### SMTP Scripts

bash

```bash
# SMTP commands
nmap --script=smtp-commands 192.168.1.1

# SMTP user enumeration
nmap --script=smtp-enum-users 192.168.1.1

# SMTP open relay
nmap --script=smtp-open-relay 192.168.1.1

# SMTP vulnerabilities
nmap --script=smtp-vuln* 192.168.1.1
```

#### Database Scripts

bash

```bash
# MySQL
nmap --script=mysql-info 192.168.1.1
nmap --script=mysql-databases 192.168.1.1
nmap --script=mysql-empty-password 192.168.1.1
nmap --script=mysql-brute 192.168.1.1

# MSSQL
nmap --script=ms-sql-info 192.168.1.1
nmap --script=ms-sql-empty-password 192.168.1.1
nmap --script=ms-sql-brute 192.168.1.1
nmap --script=ms-sql-config 192.168.1.1

# MongoDB
nmap --script=mongodb-info 192.168.1.1
nmap --script=mongodb-databases 192.168.1.1

# Oracle
nmap --script=oracle-sid-brute 192.168.1.1
nmap --script=oracle-enum-users 192.168.1.1
```

#### VNC Scripts

bash

```bash
# VNC authentication
nmap --script=vnc-info 192.168.1.1

# VNC brute force
nmap --script=vnc-brute 192.168.1.1
```

#### RDP Scripts

bash

```bash
# RDP information
nmap --script=rdp-enum-encryption 192.168.1.1

# RDP vulnerabilities
nmap --script=rdp-vuln-ms12-020 192.168.1.1
```

#### SNMP Scripts

bash

```bash
# SNMP info
nmap --script=snmp-info 192.168.1.1

# SNMP interfaces
nmap --script=snmp-interfaces 192.168.1.1

# SNMP processes
nmap --script=snmp-processes 192.168.1.1

# SNMP brute force
nmap --script=snmp-brute 192.168.1.1
```

#### Active Directory Scripts

bash

```bash
# LDAP enumeration
nmap --script=ldap-rootdse 192.168.1.1
nmap --script=ldap-search 192.168.1.1

# Kerberos
nmap --script=krb5-enum-users --script-args krb5-enum-users.realm='domain.local' 192.168.1.1
```

#### Vulnerability Scanning Scripts

bash

```bash
# All vulnerability scripts
nmap --script=vuln 192.168.1.1

# Specific vulnerabilities
nmap --script=smb-vuln-ms17-010 192.168.1.1     # EternalBlue
nmap --script=ssl-heartbleed 192.168.1.1        # Heartbleed
nmap --script=http-vuln-cve2017-5638 192.168.1.1  # Struts
nmap --script=smb-vuln-cve-2017-7494 192.168.1.1  # SambaCry
```

---

## Firewall/IDS Evasion

### Fragment Packets

bash

```bash
# Fragment packets
nmap -f 192.168.1.1

# Set custom MTU (must be multiple of 8)
nmap --mtu 24 192.168.1.1
```

### Decoys

bash

```bash
# Use decoys
nmap -D RND:10 192.168.1.1

# Specific decoys
nmap -D decoy1,decoy2,ME,decoy3 192.168.1.1

# Random decoys
nmap -D RND:5 192.168.1.1
```

### Source Port

bash

```bash
# Spoof source port
nmap --source-port 53 192.168.1.1
nmap -g 53 192.168.1.1
```

### MAC Address Spoofing

bash

```bash
# Spoof MAC address
nmap --spoof-mac 0 192.168.1.1          # Random
nmap --spoof-mac Apple 192.168.1.1      # Apple vendor
nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1  # Specific MAC
```

### Data Length

bash

```bash
# Append random data
nmap --data-length 25 192.168.1.1
```

### IP Options

bash

```bash
# Loose source routing
nmap --ip-options "L 192.168.1.100 192.168.1.1"

# Strict source routing
nmap --ip-options "S 192.168.1.100 192.168.1.1"
```

### Bad Checksums

bash

```bash
# Send packets with bad checksums (to evade simple filters)
nmap --badsum 192.168.1.1
```

### Idle/Zombie Scan

bash

```bash
# Use zombie host
nmap -sI zombie_host target_host
```

### Complete Stealth Example

bash

```bash
nmap -sS -Pn -f -D RND:10 --source-port 53 --data-length 25 -T2 192.168.1.1
```

---

## Output Formats

### Output Options

bash

```bash
# Normal output
nmap -oN output.txt 192.168.1.1

# XML output
nmap -oX output.xml 192.168.1.1

# Grepable output
nmap -oG output.gnmap 192.168.1.1

# Script kiddie output
nmap -oS output.skid 192.168.1.1

# All formats
nmap -oA scan_name 192.168.1.1
# Creates: scan_name.nmap, scan_name.xml, scan_name.gnmap

# Append to file
nmap -oN output.txt --append-output 192.168.1.1

# Resume scan
nmap --resume output.nmap
```

### Verbosity and Debugging

bash

```bash
# Increase verbosity
nmap -v 192.168.1.1
nmap -vv 192.168.1.1

# Debugging
nmap -d 192.168.1.1
nmap -dd 192.168.1.1

# Packet trace
nmap --packet-trace 192.168.1.1

# Show only open ports
nmap --open 192.168.1.1

# Show reason for port state
nmap --reason 192.168.1.1

# Show all packets sent/received
nmap --packet-trace 192.168.1.1
```

### Interactive Options

bash

```bash
# During scan, press:
v / V    # Increase/decrease verbosity
d / D    # Increase/decrease debugging
p / P    # Enable/disable packet tracing
?        # Help
```

---

## Advanced Scanning Techniques

### Comprehensive Network Scan

bash

```bash
# Full network enumeration
nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" 192.168.1.0/24
```

### Web Server Deep Scan

bash

```bash
# Comprehensive web server scan
nmap -p 80,443,8080,8443 -sV --script=http-enum,http-headers,http-methods,http-php-version,http-robots.txt,http-title,http-trace,http-vuln*,ssl-cert,ssl-enum-ciphers,ssl-known-key 192.168.1.1
```

### SMB/CIFS Deep Scan

bash

```bash
# Complete SMB enumeration
nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups,smb-enum-services,smb-os-discovery,smb-protocols,smb-security-mode,smb-vuln* 192.168.1.1
```

### Active Directory Scan

bash

```bash
# AD enumeration
nmap -p 88,389,445,464,636,3268,3269 --script=ldap-rootdse,ldap-search,smb-os-discovery,smb-enum-domains,smb-enum-shares,krb5-enum-users 192.168.1.1
```

### Database Server Scan

bash

```bash
# MySQL scan
nmap -p 3306 --script=mysql-info,mysql-databases,mysql-empty-password,mysql-users,mysql-variables 192.168.1.1

# MSSQL scan
nmap -p 1433 --script=ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info 192.168.1.1

# PostgreSQL scan
nmap -p 5432 --script=pgsql-brute 192.168.1.1

# MongoDB scan
nmap -p 27017 --script=mongodb-info,mongodb-databases 192.168.1.1
```

### Wireless Network Scanning

bash

```bash
# Identify wireless access points (requires proper setup)
nmap -sP -PS --script broadcast-dhcp-discover

# Detect rogue DHCP servers
nmap --script broadcast-dhcp-discover
```

### IPv6 Scanning

bash

```bash
# Basic IPv6 scan
nmap -6 fe80::1

# IPv6 range
nmap -6 2001:db8::/64

# IPv6 with scripts
nmap -6 -sS -sV --script=default fe80::1
```

### Aggressive Discovery

bash

```bash
# All discovery methods
nmap -PE -PP -PM -PS21,22,23,25,80,113,443,3389 -PA80,113,443,10042 --source-port 53 192.168.1.0/24
```

---

## Common Penetration Testing Workflows

### External Network Pentest

#### Phase 1: Discovery

bash

```bash
# Host discovery
nmap -sn -T4 target_range -oA discovery

# Quick port scan
nmap -F -T4 target_range -oA quick_scan

# Parse live hosts
grep "Status: Up" discovery.gnmap | cut -d' ' -f2 > live_hosts.txt
```

#### Phase 2: Port Scanning

bash

```bash
# Full TCP scan on live hosts
nmap -p- -T4 -iL live_hosts.txt -oA full_tcp

# Top UDP ports
nmap -sU --top-ports 100 -T4 -iL live_hosts.txt -oA top_udp

# Parse open ports
grep "open" full_tcp.gnmap | cut -d' ' -f2,4- > open_ports.txt
```

#### Phase 3: Service Enumeration

bash

```bash
# Version detection on open ports
nmap -sV -T4 -iL live_hosts.txt -oA version_scan

# Aggressive scan
nmap -A -T4 -iL live_hosts.txt -oA aggressive_scan

# Default scripts
nmap -sC -T4 -iL live_hosts.txt -oA script_scan
```

#### Phase 4: Vulnerability Assessment

bash

```bash
# Vulnerability scripts
nmap --script=vuln -T4 -iL live_hosts.txt -oA vuln_scan

# SSL/TLS assessment
nmap -p 443 --script=ssl-cert,ssl-enum-ciphers,ssl-known-key,ssl-heartbleed,ssl-poodle -iL live_hosts.txt -oA ssl_scan
```

### Internal Network Pentest

#### Phase 1: Quick Discovery

bash

```bash
# ARP scan (local network)
nmap -sn -PR 192.168.1.0/24 -oA arp_discovery

# Fast SYN scan
nmap -sS -F -T4 192.168.1.0/24 -oA quick_internal
```

#### Phase 2: Service Identification

bash

```bash
# Common internal services
nmap -p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,636,993,995,1433,1521,3268,3306,3389,5432,5900,8080,8443 -T4 192.168.1.0/24 -oA internal_services

# Version detection
nmap -sV -p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,636,993,995,1433,1521,3268,3306,3389,5432,5900,8080,8443 -T4 192.168.1.0/24 -oA internal_versions
```

#### Phase 3: Windows Enumeration

bash

```bash
# SMB enumeration
nmap -p 139,445 --script=smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-domains,smb-security-mode,smb-protocols,smb-vuln-ms17-010 192.168.1.0/24 -oA windows_enum
```

#### Phase 4: Active Directory

bash

```bash
# AD/LDAP enumeration
nmap -p 88,389,445,636,3268,3269 --script=ldap-rootdse,smb-os-discovery,smb-enum-domains 192.168.1.1 -oA ad_enum

# Kerberos user enumeration
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.LOCAL',userdb=users.txt 192.168.1.1
```

### Web Application Testing

bash

```bash
# Initial scan
nmap -p 80,443,8080,8443 -sV --script=http-title,http-headers 192.168.1.1

# Directory enumeration
nmap -p 80,443 --script=http-enum 192.168.1.1

# Vulnerability check
nmap -p 80,443 --script=http-vuln* 192.168.1.1

# SSL/TLS check
nmap -p 443 --script=ssl-cert,ssl-enum-ciphers,ssl-heartbleed 192.168.1.1

# HTTP methods
nmap -p 80,443 --script=http-methods --script-args http-methods.url-path='/upload' 192.168.1.1
```

### Wireless Network Testing

bash

```bash
# Detect wireless networks
nmap --script broadcast-dhcp-discover

# Identify captive portals
nmap -p 80,443,8080 --script=http-title 192.168.1.0/24

# DNS servers
nmap -p 53 --script=dns-recursion 192.168.1.0/24
```

### Database Server Assessment

bash

```bash
# MySQL
nmap -p 3306 --script=mysql-info,mysql-databases,mysql-empty-password,mysql-users 192.168.1.1

# MSSQL
nmap -p 1433 --script=ms-sql-info,ms-sql-empty-password,ms-sql-dump-hashes 192.168.1.1

# PostgreSQL
nmap -p 5432 --script=pgsql-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1

# MongoDB
nmap -p 27017 --script=mongodb-info,mongodb-databases 192.168.1.1

# Redis
nmap -p 6379 --script=redis-info 192.168.1.1
```

### VPN/Remote Access Testing

bash

```bash
# RDP enumeration
nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020 192.168.1.0/24

# VNC detection
nmap -p 5900-5910 --script=vnc-info 192.168.1.0/24

# SSH enumeration
nmap -p 22 --script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos 192.168.1.0/24
```

### IoT/Embedded Device Scanning

bash

```bash
# Common IoT ports
nmap -p 21,22,23,80,443,554,1883,5000,8080,8443,8883,9200 192.168.1.0/24

# UPnP discovery
nmap -p 1900 --script=upnp-info 192.168.1.0/24

# RTSP cameras
nmap -p 554 --script=rtsp-methods 192.168.1.0/24
```

---

## Nmap Scripting Engine (NSE)

### Script Locations

bash

```bash
# Default script location
/usr/share/nmap/scripts/

# User scripts
~/.nmap/scripts/

# List all scripts
ls /usr/share/nmap/scripts/

# Search for scripts
ls /usr/share/nmap/scripts/ | grep http

# Update script database
nmap --script-updatedb
```

### Script Development

bash

```bash
# Basic NSE script structure
description = [[
  Script description here
]]

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Dependencies
local shortport = require "shortport"
local http = require "http"

-- Port rule
portrule = shortport.http

-- Action function
action = function(host, port)
  local result = {}
  -- Script logic here
  return result
end
```

### Script Arguments

bash

```bash
# Pass arguments to scripts
nmap --script=http-wordpress-enum --script-args http-wordpress-enum.root="/blog/" 192.168.1.1

# Multiple arguments
nmap --script=mysql-brute --script-args userdb=users.txt,passdb=passwords.txt,brute.delay=2 192.168.1.1

# Argument file
nmap --script=http-brute --script-args-file args.txt 192.168.1.1
```

### Custom Script Example

bash

```bash
# Save as: custom-http-check.nse
description = [[
  Checks if a specific file exists on web server
]]

author = "Pentester"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
  local path = "/admin"
  local response = http.get(host, port, path)
  
  if response.status == 200 then
    return "Admin page found at " .. path
  else
    return "Admin page not found"
  end
end

# Use custom script
nmap --script=custom-http-check.nse 192.168.1.1
```

---

## Integration with Other Tools

### Parse Nmap Output

bash

```bash
# Extract IPs with port 80 open
grep "80/open" scan.gnmap | cut -d' ' -f2 > web_servers.txt

# Extract all open ports
grep "open" scan.gnmap | cut -d' ' -f2,4 > open_ports.txt

# Count hosts by OS
grep "OS:" scan.gnmap | cut -d':' -f3 | sort | uniq -c
```

### Convert Nmap XML

bash

```bash
# XML to HTML
xsltproc nmap.xml -o nmap.html

# XML to CSV (using custom tools)
python3 nmap_xml_parser.py scan.xml > output.csv
```

### Integration with Metasploit

bash

```bash
# Import Nmap XML into Metasploit
msf6> db_import scan.xml

# Run Nmap from Metasploit
msf6> db_nmap -sS -A 192.168.1.0/24

# View imported hosts
msf6> hosts

# View services
msf6> services
```

### Integration with Nessus

bash

```bash
# Use Nmap results to target Nessus scans
# Export live hosts to Nessus target list
grep "Status: Up" scan.gnmap | cut -d' ' -f2 > nessus_targets.txt
```

### Automation with Bash

bash

```bash
#!/bin/bash
# Auto-scan script

TARGETS="targets.txt"
OUTPUT_DIR="./scans"

mkdir -p $OUTPUT_DIR

# Discovery
nmap -sn -iL $TARGETS -oA $OUTPUT_DIR/discovery

# Extract live hosts
grep "Status: Up" $OUTPUT_DIR/discovery.gnmap | cut -d' ' -f2 > $OUTPUT_DIR/live_hosts.txt

# Port scan
nmap -p- -T4 -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/port_scan

# Service detection
nmap -sV -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/service_scan

# Vulnerability scan
nmap --script=vuln -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/vuln_scan

echo "Scan complete. Results in $OUTPUT_DIR"
```

### nmaptocsv

bash

```bash
# Install nmaptocsv
pip install python-libnmap

# Convert to CSV
python3 nmaptocsv.py -i scan.xml -o output.csv
```

### Searchsploit Integration

bash

```bash
# Extract services and search exploits
nmap -sV -oX scan.xml 192.168.1.1
searchsploit --nmap scan.xml
```

---

## Troubleshooting

### Common Issues

#### Permission Denied

bash

```bash
# Some scans require root
sudo nmap -sS 192.168.1.1

# Use TCP connect scan (no root)
nmap -sT 192.168.1.1
```

#### Slow Scans

bash

```bash
# Increase timing template
nmap -T4 192.168.1.1

# Skip host discovery
nmap -Pn 192.168.1.1

# Reduce retries
nmap --max-retries 1 192.168.1.1

# Disable DNS resolution
nmap -n 192.168.1.1
```

#### No Results / Filtered Ports

bash

```bash
# Skip ping
nmap -Pn 192.168.1.1

# Try different ping types
nmap -PS 192.168.1.1
nmap -PA 192.168.1.1

# Use ACK scan to check firewall
nmap -sA 192.168.1.1

# Fragment packets
nmap -f 192.168.1.1
```

#### Too Many Open Files

bash

```bash
# Reduce parallelism
nmap --max-parallelism 10 192.168.1.0/24

# Increase system limits (Linux)
ulimit -n 4096
```

#### Script Errors

bash

```bash
# Update script database
sudo nmap --script-updatedb

# Check script exists
ls /usr/share/nmap/scripts/ | grep script_name

# Run with debug
nmap --script=script_name --script-trace 192.168.1.1
```

### Debugging

bash

```bash
# Basic debugging
nmap -d 192.168.1.1

# More verbose debugging
nmap -dd 192.168.1.1
nmap -ddd 192.168.1.1

# Packet trace
nmap --packet-trace 192.168.1.1

# Show reason for port state
nmap --reason 192.168.1.1

# Version detection trace
nmap -sV --version-trace 192.168.1.1
```

---

## Quick Reference

### Quick Scans

bash

```bash
# Fast scan top 100 ports
nmap -F 192.168.1.1

# Quick scan with version detection
nmap -sV -F 192.168.1.1

# Aggressive scan
nmap -A 192.168.1.1

# Quick network sweep
nmap -sn 192.168.1.0/24
```

### Common Commands

bash

```bash
# Default scan
nmap 192.168.1.1

# Full TCP port scan
nmap -p- 192.168.1.1

# Version detection
nmap -sV 192.168.1.1

# OS detection
nmap -O 192.168.1.1

# Script scan
nmap -sC 192.168.1.1

# All in one
nmap -A -oA output 192.168.1.1

# Stealth scan
nmap -sS -T2 -f 192.168.1.1

# UDP scan
nmap -sU --top-ports 20 192.168.1.1

# Show only open ports
nmap --open 192.168.1.1
```

### One-Liner Pentesting Commands

bash

```bash
# Quick Windows enumeration
nmap -p 445 --script=smb-os-discovery,smb-security-mode,smb-enum-shares 192.168.1.1

# Web vulnerability scan
nmap -p 80,443 --script=http-vuln* 192.168.1.1

# Check for common vulnerabilities
nmap --script=vuln --open 192.168.1.1

# Find live hosts and open web ports
nmap -p 80,443 --open 192.168.1.0/24 -oG - | grep "/open" | cut -d' ' -f2

# Identify web servers
nmap -p 80,443,8080,8443 --open -sV 192.168.1.0/24

# Check for EternalBlue
nmap -p 445 --script=smb-vuln-ms17-010 192.168.1.0/24

# SSL/TLS assessment
nmap -p 443 --script=ssl-enum-ciphers,ssl-cert 192.168.1.1
```

---

## Advanced Tips

### Performance Tuning

bash

```bash
# Maximum performance (use with caution)
nmap -T5 --min-rate 10000 --max-retries 1 192.168.1.0/24

# Balanced speed and accuracy
nmap -T4 --min-rate 1000 --max-retries 2 192.168.1.0/24

# Stealth but thorough
nmap -T2 --max-retries 3 --scan-delay 1s 192.168.1.1
```

### Large Network Scanning

bash

```bash
# Split network into smaller chunks
nmap -sn 10.0.0.0/24 -oG - | grep "Status: Up" | cut -d' ' -f2 > hosts.txt

# Parallel scanning (using GNU parallel)
cat hosts.txt | parallel -j 10 "nmap -p- -T4 {} -oA scans/{}"

# Progressive scanning
for net in {1..10}; do nmap -sn 192.168.$net.0/24 -oG - | grep "Up" >> live.txt; done
```

### Custom Reporting

bash

```bash
# Generate HTML report
nmap -sV -A 192.168.1.0/24 -oX scan.xml && xsltproc scan.xml -o report.html

# Create summary
echo "=== Scan Summary ===" > summary.txt
echo "Total Hosts:" >> summary.txt
grep "Host:" scan.nmap | wc -l >> summary.txt
echo "Open Ports:" >> summary.txt
grep "open" scan.nmap | wc -l >> summary.txt
```

### Environment Variables

bash

```bash
# Set custom Nmap data directory
export NMAPDIR=/custom/path/to/nmap/data

# Set custom script directory
export NMAP_SCRIPT_DIR=/custom/scripts
```

---

## Nmap Alternatives and Complements

bash

```bash
# Masscan (faster port scanning)
masscan 192.168.1.0/24 -p 1-65535 --rate 10000

# Rustscan (fast port scanner)
rustscan -a 192.168.1.1 -- -sV -sC

# Unicornscan
unicornscan 192.168.1.1:1-65535

# Zmap (internet-wide scanning)
zmap -p 443 192.168.1.0/24
```

---

## Resources

### Official Resources

- Nmap Documentation: [https://nmap.org/docs.html](https://nmap.org/docs.html)
- Nmap Book: [https://nmap.org/book/](https://nmap.org/book/)
- NSE Library: [https://nmap.org/nsedoc/](https://nmap.org/nsedoc/)
- Nmap Mailing List: [https://nmap.org/mailman/listinfo/dev](https://nmap.org/mailman/listinfo/dev)

### NSE Script Resources

- Nmap Scripts: [https://nmap.org/nsedoc/scripts/](https://nmap.org/nsedoc/scripts/)
- GitHub NSE Scripts: [https://github.com/nmap/nmap/tree/master/scripts](https://github.com/nmap/nmap/tree/master/scripts)
- Custom Scripts: [https://github.com/cldrn/nmap-nse-scripts](https://github.com/cldrn/nmap-nse-scripts)

### Cheat Sheets

- HackTricks: [https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/nmap](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/nmap)
- SANS: [https://www.sans.org/posters/nmap-cheat-sheet/](https://www.sans.org/posters/nmap-cheat-sheet/)
- StationX: [https://www.stationx.net/nmap-cheat-sheet/](https://www.stationx.net/nmap-cheat-sheet/)

### Books

- "Nmap Network Scanning" by Gordon "Fyodor" Lyon
- "Nmap 7: Network Exploration and Security Auditing" by Paulino Calderon

---

## Best Practices

### General Guidelines

1. **Always get authorization** before scanning networks
2. **Start with less intrusive scans** and escalate as needed
3. **Use appropriate timing** - faster isn't always better
4. **Save all output** - use `-oA` for comprehensive logging
5. **Document everything** - include scope, date, findings
6. **Verify results** - cross-reference with other tools
7. **Respect rate limits** - don't overwhelm targets
8. **Update regularly** - keep Nmap and NSE scripts current

### Scan Strategy

1. **Discovery** - Find live hosts
2. **Port Scanning** - Identify open ports
3. **Service Detection** - Determine versions
4. **OS Detection** - Identify operating systems
5. **Vulnerability Assessment** - Run vuln scripts
6. **Targeted Scanning** - Deep dive specific services
7. **Documentation** - Generate reports

### Legal and Ethical Considerations

- **Always obtain written permission** before scanning
- **Respect scope limitations** - don't scan out of scope
- **Be aware of local laws** - unauthorized scanning is illegal
- **Document authorization** - keep evidence of permission
- **Minimize impact** - avoid DoS conditions
- **Report responsibly** - follow disclosure practices

---

## Notes for Penetration Testing

### Pre-Engagement

- Confirm scanning is authorized in scope document
- Identify critical systems to avoid
- Establish communication channels
- Plan scan timing to minimize impact

### During Engagement

- Start with passive reconnaissance
- Progress from less to more intrusive
- Document all findings immediately
- Monitor for defensive responses
- Be prepared to pause/stop if issues arise

### Post-Engagement

- Analyze all scan results
- Correlate findings across tools
- Prioritize vulnerabilities
- Generate comprehensive reports
- Securely store and transmit results

### Red Team Considerations

- Use stealth techniques for covert operations
- Employ evasion techniques appropriately
- Avoid detection by blue team monitoring
- Simulate APT behavior when required
- Document detection points for debrief

## Related

- Checklists: [External Network Penetration Test](../Checklists/External%20Network%20Penetration%20Test.md), [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
