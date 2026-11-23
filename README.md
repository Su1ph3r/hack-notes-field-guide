# Pentest Field Guide

A practical, cross-linked reference kit for offensive security engagements, in three layers:

- **Cheatsheets** (21): command and payload references for tools and techniques.
- **Checklists** (31): phased, checkbox methodology guides (what to test, in order) per engagement type.
- **Playbooks** (18): end-to-end attack chains walked A to Z, with commands, decision branches, OPSEC, detection, and cleanup.

All techniques are for authorized security testing only. Content is current to 2024-2026.

Maintained by [Cairn Security](https://cairnsecurity.com), an independent penetration testing practice.

## How to use

Read top down: a **Cheatsheet** gives you the commands, the matching **Checklist** gives you the methodology, and a **Playbook** shows a specific chain end to end. Links between notes are relative and clickable on GitHub. The attack-graph diagram in `Playbooks/Attack Graph.md` renders natively on GitHub. For the full backlink graph and local search, clone and open the three folders as an Obsidian vault.

## Cheatsheets

- [API JWT and GraphQL](Cheatsheets/API%20JWT%20and%20GraphQL.md)
- [AWS Pentest](Cheatsheets/AWS%20Pentest.md)
- [Active Directory and Kerberos](Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [Azure and Entra ID](Cheatsheets/Azure%20and%20Entra%20ID.md)
- [CICD and Supply Chain](Cheatsheets/CICD%20and%20Supply%20Chain.md)
- [Hashcat](Cheatsheets/Hashcat.md)
- [Kubernetes and Container Breakout](Cheatsheets/Kubernetes%20and%20Container%20Breakout.md)
- [Linux Privilege Escalation](Cheatsheets/Linux%20Privilege%20Escalation.md)
- [MCP-Assisted Pentesting](Cheatsheets/MCP-Assisted%20Pentesting.md)
- [Mainframe Tooling](Cheatsheets/Mainframe%20Tooling.md)
- [Mobile App Testing](Cheatsheets/Mobile%20App%20Testing.md)
- [NetExec and Impacket](Cheatsheets/NetExec%20and%20Impacket.md)
- [Nmap](Cheatsheets/Nmap.md)
- [Nuclei Usage](Cheatsheets/Nuclei%20Usage.md)
- [OSINT and Recon](Cheatsheets/OSINT%20and%20Recon.md)
- [Phishing and Initial Access](Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [Pivoting and Tunneling](Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [Web App and Payloads](Cheatsheets/Web%20App%20and%20Payloads.md)
- [Windows Privilege Escalation](Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Wireless](Cheatsheets/Wireless.md)

## Checklists

- [AI and LLM Application](Checklists/AI%20and%20LLM%20Application.md)
- [API Security](Checklists/API%20Security.md)
- [AWS Cloud Penetration Test](Checklists/AWS%20Cloud%20Penetration%20Test.md)
- [Assumed Breach](Checklists/Assumed%20Breach.md)
- [Azure and M365 Entra ID](Checklists/Azure%20and%20M365%20Entra%20ID.md)
- [Build Review and VDI](Checklists/Build%20Review%20and%20VDI.md)
- [CICD Pipeline](Checklists/CICD%20Pipeline.md)
- [Cloud Configuration Review](Checklists/Cloud%20Configuration%20Review.md)
- [Compromise Assessment](Checklists/Compromise%20Assessment.md)
- [Database Security](Checklists/Database%20Security.md)
- [Email Security](Checklists/Email%20Security.md)
- [External Network Penetration Test](Checklists/External%20Network%20Penetration%20Test.md)
- [Firewall and Network Device Review](Checklists/Firewall%20and%20Network%20Device%20Review.md)
- [Firmware and Embedded Device](Checklists/Firmware%20and%20Embedded%20Device.md)
- [GCP Cloud Penetration Test](Checklists/GCP%20Cloud%20Penetration%20Test.md)
- [Internal Network and Active Directory](Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [IoT Device](Checklists/IoT%20Device.md)
- [Kubernetes and Containers](Checklists/Kubernetes%20and%20Containers.md)
- [Mobile Application](Checklists/Mobile%20Application.md)
- [Network Segmentation Test](Checklists/Network%20Segmentation%20Test.md)
- [OSINT and Reconnaissance](Checklists/OSINT%20and%20Reconnaissance.md)
- [OT and ICS](Checklists/OT%20and%20ICS.md)
- [Phishing and Social Engineering](Checklists/Phishing%20and%20Social%20Engineering.md)
- [Physical Security](Checklists/Physical%20Security.md)
- [Purple Team Exercise](Checklists/Purple%20Team%20Exercise.md)
- [Ransomware Readiness and Simulation](Checklists/Ransomware%20Readiness%20and%20Simulation.md)
- [Red Team Operation](Checklists/Red%20Team%20Operation.md)
- [Secure Code Review](Checklists/Secure%20Code%20Review.md)
- [Thick Client Application](Checklists/Thick%20Client%20Application.md)
- [Web Application](Checklists/Web%20Application.md)
- [Wireless Network Assessment](Checklists/Wireless%20Network%20Assessment.md)

## Playbooks

- [Attack Graph](Playbooks/Attack%20Graph.md) (map of how the playbooks chain together)
- [AWS IMDS SSRF to Account Takeover](Playbooks/AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)
- [AWS Leaked Key to IAM Privilege Escalation](Playbooks/AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md)
- [Azure AiTM Token Theft to Global Admin](Playbooks/Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md)
- [Blind SSRF to Cloud Metadata RCE](Playbooks/Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md)
- [Coercion to ADCS ESC8 to Domain Admin](Playbooks/Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md)
- [DCSync to Golden Ticket Persistence](Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md)
- [Device Code Phishing to M365 Takeover](Playbooks/Device%20Code%20Phishing%20to%20M365%20Takeover.md)
- [Edge Device Exploit to Internal Foothold](Playbooks/Edge%20Device%20Exploit%20to%20Internal%20Foothold.md)
- [File Upload to Web Shell to Foothold](Playbooks/File%20Upload%20to%20Web%20Shell%20to%20Foothold.md)
- [GCP Service Account Impersonation to Org Admin](Playbooks/GCP%20Service%20Account%20Impersonation%20to%20Org%20Admin.md)
- [IPv6 mitm6 Relay to RBCD Takeover](Playbooks/IPv6%20mitm6%20Relay%20to%20RBCD%20Takeover.md)
- [Indirect Prompt Injection to Data Exfiltration](Playbooks/Indirect%20Prompt%20Injection%20to%20Data%20Exfiltration.md)
- [Insecure Deserialization to RCE](Playbooks/Insecure%20Deserialization%20to%20RCE.md)
- [Kerberoasting to Domain Admin](Playbooks/Kerberoasting%20to%20Domain%20Admin.md)
- [Kubernetes Pod to Cluster to Cloud](Playbooks/Kubernetes%20Pod%20to%20Cluster%20to%20Cloud.md)
- [Poisoned CI Pipeline to Cloud Admin](Playbooks/Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md)
- [SQL Injection to RCE to Pivot](Playbooks/SQL%20Injection%20to%20RCE%20to%20Pivot.md)
- [badSuccessor dMSA to Domain Admin](Playbooks/badSuccessor%20dMSA%20to%20Domain%20Admin.md)


---

## About

Written and maintained by [Cairn Security](https://cairnsecurity.com), an independent penetration testing practice. These are the same methodologies we run on client engagements, kept current as the techniques change.

Want any of it run against your own environment, by the people who wrote it? That's the day job: **[cairnsecurity.com](https://cairnsecurity.com)**.
