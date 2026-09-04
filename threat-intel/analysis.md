# Threat Intelligence: Huntress "Vibe-Coded" AD Enumeration Incident

## Source

Huntress, "Analyzing AI-Augmented Network Enumeration" (Jevon Ang & Dray Agha, July 8, 2026): https://www.huntress.com/blog/ai-coded-malware-vibe-coding-active-directory

No PDF of the report exists; the recovered script was published as a GitHub Gist by Huntress.

## What happened

An attacker RDP'd into a domain-joined Windows server using pre-compromised credentials, staged tools in C:\ProgramData\, and ran an AI-generated ("vibe-coded") PowerShell script, Untitled1.ps1, to enumerate Active Directory. The script writes CSVs and an AD_Report.html into C:\AD_Reports_\<datetime\>\ and zips the folder. It performs enumeration only, no exfiltration logic is present in the script itself. Roughly 30 minutes after the enumeration finished, the attacker dropped two additional tools: s5cmd.exe (used to push data to S3-compatible storage) and SharpShares.exe (share enumeration).

## Why it's notable

The script bears hallmarks of AI-generated code rather than hand-written offensive tooling: verbose comments, a leftover placeholder value (Server1.HR.local) suggesting an LLM template, and a hard dependency on the RSAT Active Directory PowerShell module. A skilled human operator would more likely use ADSISearcher or DirectorySearcher directly against LDAP, which needs neither RSAT nor local admin to install it. That dependency becomes a genuine tell, and in this lab's threat model, a real liability: RSAT can't be installed by a standard domain user, so an attacker limited to one set of standard-user credentials could not have staged it themselves.

## Artifact reference

| Artifact | Purpose | Written to |
|---|---|---|
| Untitled1.ps1 | Vibe-coded enumeration script | C:\ProgramData\ |
| CSV exports | Per-object-class AD enumeration output | C:\AD_Reports_\<datetime\>\ |
| AD_Report.html | Rolled-up HTML report | C:\AD_Reports_\<datetime\>\ |
| Zip archive | Compressed report + CSVs | C:\AD_Reports_\<datetime\>\ |
| s5cmd.exe | S3-compatible exfil tool | C:\ProgramData\ (dropped ~30 min later) |
| SharpShares.exe | Share enumeration | C:\ProgramData\ (dropped ~30 min later) |

Per Huntress's own framing, the script is a one-off, so this table is a replication-validation checklist, not a durable indicator list. Detections in this repo key on behavior, not these filenames.

## ATT&CK mapping

| Technique | Tactic | How it maps here |
|---|---|---|
| T1078.002 - Valid Accounts: Domain Accounts | Initial Access | Pre-compromised standard domain user credentials |
| T1021.001 - Remote Desktop Protocol | Lateral Movement | RDP into the target host |
| T1074.001 - Local Data Staging | Collection | CSVs/HTML/zip staged under C:\ProgramData\ |
| T1018 - Remote System Discovery | Discovery | Enumeration includes computer objects |
| T1087.002 - Account Discovery: Domain Account | Discovery | Core behavior of Untitled1.ps1 |
| T1482 - Domain Trust Discovery | Discovery | Trust enumeration section of the script |
| T1135 - Network Share Discovery | Discovery | SharpShares.exe |
| T1560.001 - Archive via Utility | Collection | Compress-Archive zips the report folder |
| T1567.002 - Exfiltration to Cloud Storage | Exfiltration | s5cmd.exe pushes the archive to S3-compatible storage |

## Lab threat model

This repo's replica assumes the attacker holds only one set of standard domain-user credentials (famtech\Prush), not a privileged account. Two things that don't fit that model are handled as lab preconditions rather than attacker actions, so they don't read as inconsistencies: the RSAT Active Directory module is pre-installed on the endpoint before detonation, since a standard user can't self-install it (Add-WindowsCapability requires elevation); and the account used for the replica is a member of Remote Desktop Users, since RDP access isn't granted by default. Both are scoped as lab setup, not part of the attack chain being measured.
