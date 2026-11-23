---
tags:
  - hack-notes
  - checklist
  - segmentation
---

# Network Segmentation Testing Checklist

> Use for an authorized segmentation assessment: proving that defined network zones (above all a PCI cardholder data environment) are isolated so only documented flows cross the boundaries. PCI DSS v4.0 requirement 11.4.5 drives this work: segmentation controls that take the CDE out of scope must be validated at least every 12 months and after any change to segmentation controls. The method is a from/to zone-pair matrix: from each lower-trust zone, attempt to reach each higher-trust zone and the CDE, and confirm only the documented flows answer. Command syntax lives in the linked cheatsheets; this is the ordered method, the pass/fail signal, and the evidence to bank.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Documentation and Architecture Review](#2-documentation-and-architecture-review)
- [3. Test-Host Placement and Baseline](#3-test-host-placement-and-baseline)
- [4. Segmentation Validation](#4-segmentation-validation)
- [5. Firewall and ACL Effectiveness](#5-firewall-and-acl-effectiveness)
- [6. Egress Filtering](#6-egress-filtering)
- [7. VLAN and Layer-2 Security](#7-vlan-and-layer-2-security)
- [8. Management Plane Separation](#8-management-plane-separation)
- [9. Routing and Lateral Paths](#9-routing-and-lateral-paths)
- [10. Wireless-to-Wired Segmentation](#10-wireless-to-wired-segmentation)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

A segmentation test is not a general internal pentest. The question is narrow and binary per zone pair: can traffic cross a boundary that the design says is closed? Scope the zones and the boundaries before anything is sent, because the whole value of the test is that it maps to the documented architecture.

### Objective and Driver
- [ ] **Segmentation objective in writing:** confirm the engagement is validating isolation of named zones, not finding exploitable services inside them. The deliverable is a per-boundary pass/fail, not a vuln list.
- [ ] **PCI DSS 11.4.5 cadence:** confirm whether this is the annual validation or a post-change validation. 11.4.5 requires testing at least every 12 months and after any changes to segmentation controls; record which trigger applies and the date of the last test.
- [ ] **CDE definition agreed:** get the exact CDE boundary from the client: which subnets, VLANs, and hosts store, process, or transmit cardholder data, and which systems are connected-to or security-impacting (CDE-adjacent). The CDE-adjacent systems are in scope for 11.4.5, not just the CDE itself.
- [ ] **Trust zones named:** list every zone and its trust level (untrusted/internet, guest, corporate/user, DMZ, PCI CDE, out-of-band management). Segmentation is only meaningful relative to a named set of zones.
- [ ] **Segmentation is the scope-reduction basis:** confirm with the client that they are relying on this segmentation to keep systems out of PCI scope. If they are, the test is not optional hardening, it is the evidence their reduced scope stands up, and every unvalidated boundary is a risk to their assessment.

### Zone-Pair Matrix
- [ ] **Build the from/to matrix:** lay out a grid with every zone as both source and destination. Each cell is a test: from zone X, can I reach zone Y, and is any reachable flow documented? This matrix is the test plan and later the coverage report.
- [ ] **Documented-flows list obtained:** get the client's list of intended cross-boundary flows (source, destination, port, purpose). A documented flow is only acceptable if it is actually documented, not merely present. Anything reachable that is not on this list is a finding.
- [ ] **Direction matters:** record each documented flow's direction. A flow allowed CDE-to-update-server outbound does not authorize update-server-to-CDE inbound. Test both directions of every pair regardless of what the list claims.
- [ ] **Prioritize the high-trust-gap pairs:** order the matrix so the largest trust gaps come first (untrusted-to-CDE, guest-to-corp). These are where a failure is most severe and where a client is most likely to have a gap they did not expect.

### Rules of Engagement
- [ ] **Signed authorization in hand:** confirm a countersigned SOW/RoE names the testing window, the zones, and the legal entity. Placing a test host inside a CDE is an intrusive act; do not do it before authorization lands.
- [ ] **Test-host placement authorized:** confirm in writing that you may connect a controlled device into each in-scope zone, including the CDE and CDE-adjacent segments, and who physically places or ports it.
- [ ] **Deconfliction channel agreed:** name a contact and out-of-band channel. A full TCP/UDP sweep across a firewall can light up the SOC; agree whether this test is announced or blind.
- [ ] **Depth limit agreed:** segmentation testing proves reachability, it does not require exploiting what answers. Agree that confirming an open port and a documented-vs-undocumented verdict is the deliverable, and that you will not pivot beyond the zone you are authorized to test from.
- [ ] **QSA alignment:** confirm who consumes the result (an internal team, an external QSA, or both) and the evidence format they need. The assessor cares about method, coverage, and per-pair evidence, so agree the deliverable shape now rather than reworking it later.
- [ ] **Scope-reduction claims recorded:** note every claim that segmentation takes a system out of PCI scope. Each such claim is a boundary this test must validate; an unvalidated scope-reduction claim is the finding the whole engagement exists to catch.

```
⚠️ A segmentation test host sits inside production zones, including the CDE. Confirm exactly
   which switch port, VLAN, or SSID you are authorized on before you connect. Do NOT use the
   test host as a pivot to reach a zone you are not authorized to originate from; reaching an
   unauthorized zone through your own test host is not a segmentation failure, it is you
   crossing the boundary. Capture position proof (IP/gateway) before any scan.
```

---

## 2. Documentation and Architecture Review

The test is a comparison: reality against the documented design. You cannot report "undocumented flow" without the documentation, and the places where the diagram and the network disagree are where the real findings live.

### Diagrams and Data Flows
- [ ] **Current network diagram:** obtain the network diagram that PCI DSS requires the client to maintain, with every zone, firewall, and segmentation control shown. Note its date; a diagram older than the last network change is a lead, not a reference.
- [ ] **Cardholder data-flow diagram:** obtain the data-flow diagram showing how account data moves across systems and zones. Every documented CDE boundary crossing should trace back to a flow on this diagram.
- [ ] **Diagram-vs-reality deltas:** as you enumerate later, flag every host, subnet, or flow present on the wire but absent from the diagram, and every documented element that does not exist. Both directions of mismatch are findings.
- [ ] **Diagram completeness for 11.4.5:** confirm the diagram actually shows the segmentation controls and all connections to the CDE, including wireless, cloud, and third-party links. A diagram that omits a connection type is where the untested boundary hides.

### Rules and Address Plan
- [ ] **Firewall rulesets collected:** request the running configs of every firewall and layer-3 ACL enforcing a boundary. Reading the ruleset is faster than inferring it from scans and lets you target the risky rules directly in phase 5.
- [ ] **VLAN and subnet map:** get the VLAN-to-subnet mapping and the switch/trunk topology. You need to know which VLAN each zone lives on to confirm your test host's position and to reason about layer-2 attacks.
- [ ] **Segmentation control inventory:** list what actually enforces each boundary (firewall, router ACL, VRF, private VLAN, air gap, physical separation). "Segmented" with no enforcing control named is a documentation gap worth raising on its own.
- [ ] **Shared infrastructure note:** record where one physical switch, firewall, or hypervisor carries multiple zones. Shared hardware is not automatically a failure, but it is where a single misconfiguration bridges zones, so it steers the layer-2 and routing phases.
- [ ] **Review is a lead source, not the test:** the config tells you where to look, but a rule that reads tight can still be bypassed at layer 2 or by a path that never hits the firewall. Treat everything here as a hypothesis to prove on the wire, not a verdict.
- [ ] **Change history since last test:** ask what changed since the previous 11.4.5 validation. A new rule, a new VLAN, a new peering, or a new VPN since the last test is exactly the "after any change" trigger and the most likely place a boundary silently opened.
- [ ] **Prior report as a regression check:** read the last segmentation test's findings and confirm each was actually closed. A finding that reappears, or a fix that was reverted, is a result on its own and a sign the change process is not catching segmentation drift.

---

## 3. Test-Host Placement and Baseline

Reachability is a property of a (source zone, destination) pair, so you need a controlled origin in each relevant zone. A blocked scan from one host does not prove the zone is sealed; test every pair from a host actually sitting in the source zone.

### Position Confirmation
- [ ] **Host in each relevant zone:** place or arrange a controlled test host in each source zone the matrix requires: untrusted/guest, corporate, DMZ, and each CDE-adjacent segment. The highest-value origins are the lower-trust zones aiming at the CDE.
- [ ] **Confirm position before testing:** record the host's IP, netmask, gateway, and resolved VLAN in each zone, and confirm it matches the expected subnet for that zone. A test run from the wrong VLAN proves nothing and quietly invalidates the whole matrix column.
- [ ] **DHCP vs static behavior:** note whether the zone hands out DHCP and what scope. A guest VLAN that leases a corporate-range address is itself a segmentation smell.
- [ ] **NAC and 802.1X behavior:** note whether the port runs 802.1X or NAC and what it does to an unknown device: drop, quarantine VLAN, or open access. The quarantine VLAN is itself a zone whose reachability you then test.
- [ ] **Re-confirm after any move:** every time the test host changes port, SSID, or VLAN, re-run the position check before trusting a result. A single uncaught drift onto the wrong segment quietly invalidates every crossing claimed from it.

```bash
# Confirm which zone the test host actually landed in (anchor only; full tooling in cheatsheet)
ip -br addr; ip route get 1.1.1.1
# sanity-check the local segment before trusting any cross-zone result
arp -a; nmap -sn $(ip -o -f inet addr show | awk '{print $4}' | head -1)
```

### Baseline Reachability
- [ ] **Intra-zone baseline:** from each test host, confirm you can reach something in its own zone (gateway, a local host). If local reachability is broken, a "blocked" cross-zone result is a connectivity artifact, not a control.
- [ ] **Internet baseline where expected:** from a zone that is meant to reach the internet, confirm it does. A zone that cannot reach anything is an outage, not a sealed boundary, and would make every cross-zone deny meaningless.
- [ ] **Gateway and path note:** record the default gateway and first few hops from each zone (`traceroute`). You need the path to tell a firewall drop from a routing black hole later.
- [ ] **Time-sync the evidence:** set clocks and note timestamps on every host. The report pairs a source capture with a destination result; skewed clocks make the pairing unprovable.
- [ ] **Capture at both ends where you can:** where you control a host in the destination zone too, run a capture there as well as at the source. A packet seen arriving inside the zone is the strongest possible proof a flow crossed; a source-only result can be argued with.

---

## 4. Segmentation Validation

This is the core of the engagement. From each lower-trust zone, attempt to reach each higher-trust zone and the CDE across the full port range, and confirm that only the documented flows answer. Everything else must be dropped.

### Cross-Boundary Port Sweep
- [ ] **Full TCP sweep across each boundary:** from the source zone, scan all 65535 TCP ports against the destination zone's hosts (or the destination subnet where host-by-host is impractical). Top-1000 is not enough; an undocumented management port hides at 8443 or 9000 as easily as anywhere.
- [ ] **Targeted UDP sweep:** scan the UDP services that matter for pivoting and management (53, 123, 161, 500, 1194, 4500, 514, 69). UDP is slow, so scope it, but a permissive UDP path is a real egress and tunneling lead.
- [ ] **Reachable means answering through the boundary:** an open port in the destination zone is a potential finding only if the traffic traversed the segmentation control. Distinguish a port answered by a host inside the zone from a port answered by the firewall itself (see false positives).
- [ ] **Compare every open port to the documented list:** for each port that answers, check it against the documented-flows list for that exact source/destination pair. On the list and matching direction: pass. Not on the list: finding. CDE reachable from an untrusted zone on any undocumented port is critical.
- [ ] **A present flow is not a documented flow:** a port that answers and happens to be useful is not approved just because it works. Only a flow on the client's list, matching source, destination, and direction, passes. Everything else is reported, however legitimate it looks.

```bash
# Cross-segment reachability sweep from a placed test host (anchor only; full flags in cheatsheet)
nmap -p- -Pn --min-rate 800 -oA cde_from_corp 10.20.0.0/24
nmap -sUV --top-ports 30 -Pn -oA cde_udp_from_corp 10.20.0.0/24
# single documented-port confirmation with the source zone recorded in the filename
nmap -p 443 -Pn --reason -oA cde_443_from_guest 10.20.0.10
```

### Both Directions and CDE-Adjacent
- [ ] **Test the reverse direction:** from the higher-trust zone, attempt to reach back into the lower-trust zone on the pairs where only one direction is documented. Asymmetric rules are common and a return path is still a boundary crossing.
- [ ] **CDE-adjacent systems included:** test reachability to and from the connected-to/security-impacting systems, not only the CDE core. 11.4.5 scopes these in, and they are the usual stepping stone into the CDE.
- [ ] **Shared services as a pivot:** where a shared service (AD, DNS, patching, logging) sits adjacent to the CDE and is reachable from a lower-trust zone, note that the documented flow to that service may itself be a path toward the CDE. A permitted flow to a dual-purpose server is still a crossing to reason about.
- [ ] **Every pair, not a sample:** a sealed boundary from the guest VLAN says nothing about the corporate VLAN. Walk the full matrix; one blocked origin is not proof the destination is isolated from all origins.
- [ ] **Protocol-level confirmation:** where a port answers, confirm it is the expected service and not a captive-portal or firewall interstitial. A TCP handshake completed by an inline device is not a flow into the zone.
- [ ] **Host-alive sweep separate from port sweep:** run a reachability sweep for live hosts first, then port-scan what answers. A zone that returns zero live hosts from a source zone is a clean pass for that pair and worth recording as such.
- [ ] **Traceroute the crossing:** for any flow that reaches the destination zone, traceroute it and confirm it transits the segmentation device you expect. A flow that reaches the CDE without passing the firewall is a worse finding than one that passes it on an undocumented permit.
- [ ] **Fragment and flag probing:** where a straight SYN scan is cleanly dropped, probe with ACK, FIN, and small-fragment packets (`hping3`, `nmap -sA`/`-f`) to confirm a stateful default-deny rather than a firewall that only filters SYN. A boundary that lets ACK through is not sealed.

---

## 5. Firewall and ACL Effectiveness

The boundary is only as good as the rule that enforces it. Read the ruleset you collected in phase 2 against what the scans actually proved, and look for the rules that make the segmentation claim hollow.

### Ruleset Analysis
- [ ] **Any-any and overly broad rules:** search for `permit ip any any`, large source/destination objects, and `any` service rules on any CDE boundary. A single forgotten any-any rule flattens the segment regardless of every other control. Grep the ruleset and prove it with a live cross-zone connection, do not report it from the config alone.
- [ ] **Overly broad object groups:** check whether source/destination groups silently include more than intended (a `/16` where a `/24` was meant, a group that grew over time). The rule reads tight but resolves wide.
- [ ] **Stale and temporary rules:** flag rules with change-ticket comments, expired justifications, or "temp" labels still live. Rules outlive the reason they were added; a true rule with a false or expired reason is what the next engineer deletes blindly.
- [ ] **Shadowed and redundant rules:** identify rules never reached because an earlier rule matches first, and permits that a later deny supposedly covers. A shadowed deny is a control that cannot fire.

### Enforcement Testing
- [ ] **Rules enforce as written:** for the rules that should block, confirm on the wire that they do, and for the rules that should permit only a narrow flow, confirm nothing wider gets through. Verify the control actually fires, do not assume the config is the behavior.
- [ ] **Deny-by-default confirmed:** confirm each boundary ends in an explicit default-deny, and that it is reached. Test a port that no rule permits and confirm it is dropped, not silently allowed by a missing bottom rule.
- [ ] **Firewall is not the endpoint:** confirm you are testing a flow through the firewall into the zone, not a service on the firewall's own interface. A management port answering on the firewall is a different finding from a flow reaching a host behind it.
- [ ] **Logging and alerting on the boundary:** note whether blocked cross-zone attempts are logged and alerted. Silent drops are a monitoring gap worth raising; a boundary that blocks but never tells anyone is half a control.

### Direction and Statefulness
- [ ] **Direction of the permit:** confirm each permit rule is scoped to the direction it needs. A rule written symmetrically where only outbound was intended opens an inbound path nobody asked for.
- [ ] **Stateful vs stateless behavior:** confirm whether the boundary device tracks connection state. A stateless ACL that permits the return ports of a documented flow leaves those ports open to anyone, not just the established session.
- [ ] **Rule counters as a lead:** where you can read hit counters, flag high-traffic permits you did not expect and zero-hit rules that may be dead. Counters point you at the flows that are actually used versus the ones that only exist on paper.

---

## 6. Egress Filtering

Outbound control from the CDE is where the real-world damage lives. Ransomware double-extortion and C2 both depend on a CDE host reaching the internet; a CDE that can talk out on arbitrary ports is a finding even when inbound is perfectly sealed. Inbound-only segmentation testing misses this entirely, which is why it gets its own phase.

### Outbound Reachability
- [ ] **Arbitrary outbound ports:** from a CDE or CDE-adjacent host, attempt outbound TCP/UDP to an external listener across a wide port range. Only the documented egress (specific update mirrors, payment processors, time servers) should succeed. Everything else should be dropped.
- [ ] **Egress to a controlled collector:** stand up an external host you control and test which ports reach it from inside the CDE. This proves egress reachability end to end, where an internal-only scan cannot.
- [ ] **UDP egress too:** do not stop at TCP. Test outbound UDP to the collector across a range; a CDE that blocks outbound TCP but passes UDP has an open exfil path that a TCP-only check misses.

### Tunneling and Exfil Channels
- [ ] **DNS egress / tunneling:** test whether the CDE can resolve arbitrary external names through an unfiltered resolver and whether a DNS tunnel carries data out (iodine/dnscat2-class). Permissive recursive DNS is a data-exfil and C2 channel even when every TCP port is blocked.
- [ ] **ICMP egress / tunneling:** test outbound ICMP echo to an external host and whether a payload rides in it. Ping that reaches the internet from the CDE is a tunneling path operators forget to close.
- [ ] **HTTP(S) egress breadth:** confirm whether outbound 80/443 is filtered to named destinations or open to any host. Open 443 to the internet is the single most common C2 path; a proxy that only logs is not a filter.
- [ ] **NTP and other allow-listed UDP as a channel:** where outbound 123 or another UDP service is permitted to the internet, confirm it is scoped to named servers. A blanket UDP allow to any host is a covert channel regardless of the service name on the port.
- [ ] **Outbound-to-internal as well as internet:** test egress from the CDE toward internal zones too, not only the internet. A CDE host that can initiate to the corporate zone is a return path an attacker inside the CDE uses to pull tools in and push data out.
- [ ] **Exfil-channel summary:** record every working outbound channel from the CDE as a candidate exfil/C2 path, with the destination and port. This is the section a QSA and an incident responder both read first.

### Proxy and Egress-Device Behavior
- [ ] **Proxy bypass:** where egress is meant to force traffic through a proxy, test reaching the internet directly, bypassing the proxy. A proxy that can be sidestepped is not an egress control; confirm the default route drops non-proxied outbound.
- [ ] **TLS inspection vs allow-any:** confirm whether the egress device filters destinations or merely inspects and forwards. Full TLS inspection with no destination allowlist still lets a CDE host reach any host on 443.
- [ ] **Non-standard ports outbound:** test outbound on ports that look benign but are rarely filtered (53/tcp, 123, 8080, 8443). Filtering that only covers well-known ports leaves the quiet ones open.
- [ ] **Full outbound range, not top ports:** sweep the whole outbound TCP range to a collector, not just common ports. An egress policy that blocks the top 1000 but leaves 1024-65535 open to any host is an open door that a top-ports check calls closed.

```
⚠️ Egress tests send data to a host on the public internet from inside the CDE. Use only a
   collector you own, send only benign markers, and never push real cardholder data or any
   production record out to prove the channel. The point is to show the channel exists, not
   to exfiltrate anything.
```

---

## 7. VLAN and Layer-2 Security

Segmentation enforced at layer 3 can be undone at layer 2. If zones are separated by VLAN alone and the switch is misconfigured, a host in one VLAN can reach another without ever passing the firewall. These tests need a physical or virtual port on the segment, so confirm the placement authorization from phase 1 before firing them.

### VLAN Hopping
- [ ] **Switch-spoofing VLAN hop:** test whether the access port negotiates a trunk. If DTP is left on `dynamic auto`/`desirable`, a host that speaks trunk negotiation can receive all VLANs and bypass the layer-3 boundary entirely. Confirm access ports are hard-set to `switchport mode access` with DTP off.
- [ ] **Double-tagging (802.1Q) hop:** from a host on the native VLAN, send a frame with two 802.1Q tags (outer = native, inner = target) and confirm whether it lands in the target VLAN. This is one-way and works even on properly set access ports when the native VLAN is reused; the fix is a dedicated unused native VLAN.
- [ ] **DTP abuse:** send DTP negotiation frames (`yersinia`) and watch whether the switch forms a trunk. A single successful trunk negotiation from an access port hands you every allowed VLAN and is a direct CDE-boundary bypass where the CDE rides a VLAN on that trunk.

### Trunk and Native VLAN
- [ ] **Trunk port exposure:** check for trunk ports reachable from a user or guest area (wall ports, unused drops, AP uplinks). A reachable trunk carries every VLAN it is allowed and is a direct segmentation bypass.
- [ ] **Native VLAN hygiene:** confirm the native VLAN on trunks is not a data VLAN and not VLAN 1. A data VLAN as native is what makes double-tagging work.
- [ ] **Allowed-VLAN pruning:** confirm trunks carry only the VLANs they need (`switchport trunk allowed vlan`). A trunk that carries the CDE VLAN where it is not needed extends the CDE's layer-2 reach for no reason.
- [ ] **CDP/LLDP leakage:** check whether neighbor-discovery protocols leak switch, VLAN, and management details to a data-zone port. The leak is minor on its own but it hands an attacker the VLAN IDs that make a hop worth attempting.

### Private VLAN and Port Controls
- [ ] **Private VLAN bypass:** where private VLANs isolate hosts within a segment, test the router/gateway-MAC trick (send to an allowed uplink MAC with the victim's IP) to confirm isolated ports cannot reach each other through the gateway.
- [ ] **Unused-port posture:** check whether unused access ports are shut or parked in a dead VLAN. A live unused port in a data or CDE VLAN is a plug-in-and-cross finding.

```bash
# VLAN double-tag probe toward a target VLAN (anchor only; full scapy/yersinia usage in cheatsheet)
# outer tag = native VLAN, inner tag = target VLAN; craft and send, then watch for a reply in the target
python3 -c "from scapy.all import *; sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=40)/IP(dst='10.40.0.10')/ICMP())"
```

---

## 8. Management Plane Separation

A shared management network is the quietest way to defeat segmentation: every zone's switches and firewalls answer on one VLAN, and reaching that VLAN reaches everything. Test the management plane as its own boundary.

### Management Network Isolation
- [ ] **Out-of-band / management VLAN isolation:** confirm device management interfaces (switch/firewall/hypervisor/iLO/iDRAC) live on a dedicated management network that data zones cannot reach. From each data zone, attempt to reach the management addresses and confirm they are blocked.
- [ ] **Shared management across zones:** check whether one management VLAN spans multiple trust zones, including the CDE. A management network that touches both the corporate zone and the CDE is a bridge between them; reaching it from corporate is a path into the CDE.
- [ ] **Management protocol sweep:** from data zones, sweep for SSH (22), HTTPS admin (443/8443), SNMP (161), Telnet (23), and vendor management ports reaching infrastructure. Any of these reachable from a data zone to infrastructure is a management-plane leak.
- [ ] **SNMP reach and strings:** where SNMP answers from a data zone, test for default/community strings. A readable `public` community from the wrong zone leaks topology and is a reachability finding on top of the weak string.

### Jump Host
- [ ] **Jump-host enforcement:** confirm that management access is forced through the jump/bastion host and that the jump host is the only path. Test reaching a managed device directly, bypassing the jump host, from an administrative segment.
- [ ] **Jump-host bypass:** test whether the jump host can be sidestepped: a second NIC, an alternate management port, a direct SSH/RDP/HTTPS to the device that does not transit the bastion. A jump host that is one of several paths is not a control.
- [ ] **Jump-host dual-homing:** confirm the jump host itself does not bridge the admin zone straight into the CDE in a way that an attacker on the jump host inherits. The bastion is a deliberate crossing point, so its own exposure is in scope.
- [ ] **Session recording is not access control:** a jump host that records sessions but does not restrict which devices and ports it can reach still grants broad access. Confirm the bastion limits where an operator can go, not just that it watches them go there.

---

## 9. Routing and Lateral Paths

Even with tight firewall rules, a path can exist that never passes the firewall: a host with a foot in two zones, a leaked route, or a VPN that stitches zones together. These flatten segmentation without any rule being wrong.

### Bridged Hosts and Routes
- [ ] **Dual-homed hosts:** identify hosts with interfaces in two zones (backup servers, management stations, monitoring boxes, hypervisors). A dual-homed host bridges the zones it sits in regardless of the firewall; enumerate them and test whether one side reaches the other through the host.
- [ ] **Routing leaks between zones:** check routing tables and test for routes that carry traffic between zones outside the firewall path. A static route or a redistributed prefix can create a path the ruleset never sees.
- [ ] **Dynamic routing exposure:** where OSPF/EIGRP/BGP runs, check whether a data zone can inject or receive routes it should not. A routing protocol reachable from the wrong zone can reshape the paths the segmentation depends on.
- [ ] **Hypervisor and virtual switch paths:** where zones share a hypervisor, confirm the virtual switching keeps CDE and non-CDE VMs apart. A port group that spans zones, or a VM with NICs in two, bridges them inside the host where no physical firewall sees it.
- [ ] **Asymmetric and alternate paths:** where a flow is blocked on the expected path, check for a second path (a backup link, an alternate gateway) that is not filtered. Segmentation holds only if every path between the zones is controlled, not just the primary one.

### VPN and Cloud Links
- [ ] **VPN flattening:** test whether site-to-site or client VPN tunnels land traffic directly into the CDE or let a remote/less-trusted network reach it. A VPN that terminates inside the CDE extends the CDE boundary to wherever the tunnel starts.
- [ ] **Cloud-to-onprem links:** where a cloud VPC/VNet is peered or VPN-linked to on-prem, test whether the link flattens segmentation: can a cloud subnet reach the on-prem CDE, or vice versa, without a boundary control in between. Transit gateways and peerings quietly merge zones.
- [ ] **Third-party and vendor connections:** enumerate partner, processor, and managed-service links into the estate and test what each can reach. A vendor tunnel scoped wider than its one documented flow is a boundary into the CDE through someone else's network.
- [ ] **IPv6 as an unfiltered parallel:** check whether hosts carry IPv6 addresses and whether the segmentation controls apply to IPv6 as well as IPv4. A firewall policy written only for IPv4 leaves an entire parallel path open; test the same pairs over IPv6 where it is enabled.

---

## 10. Wireless-to-Wired Segmentation

Wireless is a zone like any other, and the common failure is a guest or corporate SSID that bridges onto a wired segment it should never touch. Test each SSID as a source zone in the matrix. PCI DSS scopes wireless into the CDE where it can reach it, so a payment environment with any wireless nearby owes this phase.

### SSID Isolation
- [ ] **Guest-WiFi-to-corp isolation:** from the guest SSID, attempt to reach the corporate and CDE wired segments. Guest wireless should reach the internet and nothing internal; any internal host that answers is a bleed.
- [ ] **Client isolation on guest:** confirm guest clients cannot reach each other (wireless client/peer isolation). Lack of client isolation is a lateral path within the guest zone and often the first hop to the gateway.
- [ ] **Corporate-WiFi-to-CDE isolation:** from the corporate SSID, confirm the CDE is unreachable unless a documented flow exists. Corporate wireless is a trusted-feeling zone that frequently has a broader path to the CDE than intended.
- [ ] **BYOD and IoT SSIDs:** treat any device, printer, or IoT SSID as its own source zone and test it against the CDE and corporate segments. These SSIDs are set up fast and reviewed rarely, and a camera or badge-reader VLAN with a path to the CDE is a real finding.

### Controller and Bridges
- [ ] **SSID-to-VLAN mapping:** confirm each SSID lands on the VLAN the design says it does, and that the wireless controller is not trunking an unexpected VLAN to the AP. A guest SSID mapped onto a corporate VLAN is a segmentation failure at the controller, not the firewall.
- [ ] **Rogue and bridged paths:** check for APs or wireless bridges that connect a wireless zone to a wired zone outside the controlled path. A test host that associates to the guest SSID and reaches a wired management interface has found a bridge.
- [ ] **AP management reachability:** confirm the AP and controller management interfaces are not reachable from the guest or user SSIDs they serve. An AP that manages from the same VLAN it hands to guests is a management-plane leak over the air.

---

## Recent Techniques (2024-2026)

Segmentation findings are config-driven, so the recurring issues are classes of misconfiguration rather than CVEs. Device CVEs apply to the firewalls and switches that enforce the boundaries; test those against the [Firewall and Network Device Review](Firewall%20and%20Network%20Device%20Review.md) checklist and the vendor advisories. The failure classes below are what to test for on a modern estate.

- [ ] **Shared management VLAN across zones:** one management network spanning corporate and CDE is still the most common real flattening. Test for: management addresses of CDE infrastructure reachable from a data zone.
- [ ] **Forgotten any-any firewall rule:** a temporary permit added during a migration or incident and never removed. Test for: a live wide-open flow across a boundary the diagram says is closed, then trace it to the rule.
- [ ] **Jump-host bypass:** the bastion is deployed but not the only path, so direct management reaches devices around it. Test for: direct SSH/RDP/HTTPS to a managed device from an admin segment without transiting the jump host.
- [ ] **Unpruned trunk carrying the CDE VLAN:** a trunk to a user-area switch or AP that still allows the CDE VLAN, extending its layer-2 reach. Test for: the CDE VLAN present on a trunk that serves a lower-trust area, then an access-port hop onto it.
- [ ] **Permissive DNS/ICMP egress:** the CDE blocks TCP but leaves recursive DNS and outbound ICMP open, giving a ready tunneling and C2 channel. Test for: a DNS or ICMP tunnel out of the CDE to a controlled collector.
- [ ] **Guest-WiFi-to-corp bleed:** a guest SSID that reaches internal hosts because of a VLAN-mapping or ACL slip at the controller. Test for: any internal host answering from the guest SSID.
- [ ] **Cloud-to-onprem VPN/peering flattening:** a transit gateway, VPC peering, or site-to-site VPN that lets a cloud subnet reach the on-prem CDE without a boundary control. Test for: reachability from a cloud subnet into the CDE across the link.
- [ ] **Dual-homed appliance bridging:** backup, monitoring, or hypervisor hosts with a NIC in two zones carrying traffic around the firewall. Test for: a path through the dual-homed host from the lower-trust side to the higher-trust side.
- [ ] **IPv6 parallel path left unfiltered:** IPv4-only segmentation policy on hosts that auto-configure IPv6. Test for: a blocked pair reachable over IPv6 where the IPv4 path is denied.
- [ ] **Asymmetric return path:** inbound is blocked but the documented outbound flow's return traffic, or a backup link, provides an uncontrolled path back. Test for: the reverse direction and any secondary path on every boundary.
- [ ] **Virtual-switch zone bridging:** a shared hypervisor places CDE and non-CDE VMs on the same virtual switch or a VM spans both. Test for: reachability between zones inside the host where no physical firewall sits in the path.
- [ ] **IPv4-only policy, IPv6-enabled hosts:** the segmentation ruleset covers IPv4 while hosts auto-configure IPv6, leaving an unfiltered parallel. Test for: the same blocked pairs reached over IPv6 link-local or global addresses.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Source and destination, exactly:** for every tested flow record the source zone and IP, the destination zone and IP, the port and protocol, and whether the flow succeeded. A segmentation finding is unreadable without all four; "the CDE is reachable" means nothing without from where and on what.
- [ ] **The capture that proves it:** save the scan output or packet capture showing the connection completing (or being dropped), captured at test time, tagged with the source host's confirmed position. A reachability claim without the from-position proof is not reproducible.
- [ ] **Pass results too:** record the boundaries that held, not only the failures. 11.4.5 validation is a statement about every pair tested; the passes are the evidence the segmentation works, and the matrix coverage is itself a deliverable.
- [ ] **Method and tooling stated:** record the exact scan commands, rates, and source positions used per pair so the test is reproducible by the next assessor. A result nobody can reproduce is an opinion, not evidence.
- [ ] **Map each finding to the documented-flows list:** state explicitly that the reachable flow is absent from the client's documented flows (or present but wrong-direction). That mapping is what turns "a port is open" into "an undocumented flow crosses the boundary."
- [ ] **Coverage statement:** report which zone pairs were tested and which were not, and why. 11.4.5 is a claim about the whole boundary set; an honest coverage statement, including pairs you could not reach a source position for, is part of the deliverable, not an admission.
- [ ] **Benign markers only:** where a flow succeeds, prove it with a benign probe or marker, never by reading or moving real cardholder data. The crossing is the finding; the payload should carry nothing sensitive, and the report says so.

### Severity Guidance
| Severity | Typical segmentation example |
| --- | --- |
| Critical | CDE reachable from an untrusted or guest zone on an undocumented flow; any-any rule flattening the CDE boundary; guest WiFi reaching the CDE |
| High | CDE reachable from the corporate zone on an undocumented port; shared management VLAN bridging a data zone and the CDE; unrestricted egress from the CDE enabling C2/exfil; VLAN hop into the CDE |
| Medium | Undocumented flow between two internal non-CDE zones; permissive DNS/ICMP egress from the CDE with no proven tunnel; jump-host bypass to infrastructure |
| Low | Diagram/reality mismatch with no proven reachable flow; stale or shadowed firewall rule with no live impact; missing deny-by-default that nothing currently exploits |
| Info | Hardening and documentation-hygiene observations with no reachability impact |

Rate by what actually crossed the boundary and from where. Reachability from a lower-trust zone to the CDE is the axis that sets severity; an undocumented flow between two equally trusted internal zones is not the same as one into the CDE.

### Common False Positives to Rule Out
- [ ] **Intentional documented flow:** a reachable host may be a documented, approved flow. Check the documented-flows list before reporting; a flow that is on the list and matches direction is a pass, not a finding.
- [ ] **Firewall interface vs flow through it:** a port answering on the firewall's own address is the device responding, not traffic reaching the zone behind it. Confirm the response came from a host inside the destination zone.
- [ ] **Asymmetric routing artifacts:** a half-open or RST-only result can be a routing or stateful-inspection artifact, not a real reachable service. Confirm a completed handshake and an actual service before calling a flow open.
- [ ] **Captive portal / inline interstitial:** an inline device can complete a TCP handshake or serve a redirect that looks like reachability. Confirm the expected service answered, not an interception layer.
- [ ] **Wrong source position:** a "reachable" result from a test host that drifted onto the wrong VLAN proves nothing. Re-confirm the source host's zone before reporting any crossing.
- [ ] **NAC quarantine mistaken for isolation:** a host parked in a NAC quarantine VLAN may show a zone sealed when the real access VLAN is open. Confirm the test host reached the intended zone, not a holding VLAN, before calling a boundary tight.
- [ ] **Scan-rate drops vs policy drops:** an aggressive sweep can trip rate-limiting or IPS that drops packets, mimicking a clean deny. Re-test a suspected pass at low rate before recording the boundary as enforced.

---

## Tools and References

| Tool | Use |
| --- | --- |
| nmap | Cross-segment TCP/UDP reachability sweeps; `--reason` to tell a drop from a reject |
| hping3 | Crafted single-packet probes across a boundary; firewall behavior and flag testing |
| scapy | Custom frames for 802.1Q double-tagging and arbitrary layer-2/3 probes |
| yersinia | DTP/VLAN and layer-2 protocol attacks for switch-spoofing hops |
| Firewalk | Inferring which ports a gateway ACL forwards to hosts behind it |
| egress-assess / dnscat2 / iodine | Egress-filter and DNS/ICMP tunneling tests from inside the CDE |
| tcpdump | Capturing the proof pair at source and destination; confirming what actually crossed |
| Nping | Controlled TCP/UDP/ICMP probe generation with precise flag and rate control |

References:
- PCI DSS v4.0 requirement 11.4.5: test segmentation controls at least every 12 months and after changes, confirming they isolate the CDE from out-of-scope systems.
- PCI DSS v4.0 requirement 1 (network security controls) and the PCI SSC guidance on scoping and network segmentation.
- NIST SP 800-115 for technical assessment methodology.
- Vendor hardening guides for the enforcing devices (switch VLAN/DTP hardening, firewall rule hygiene).

---

## Related

- Checklists: [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md), [External Network Penetration Test](External%20Network%20Penetration%20Test.md), [Firewall and Network Device Review](Firewall%20and%20Network%20Device%20Review.md)
- Cheatsheets: [Nmap](../Cheatsheets/Nmap.md), [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md), [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- Playbooks: [IPv6 mitm6 Relay to RBCD Takeover](../Playbooks/IPv6%20mitm6%20Relay%20to%20RBCD%20Takeover.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
