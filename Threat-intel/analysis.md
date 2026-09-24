# Threat Intelligence: AI Augmented AD Enumeration

**Primary source:** Huntress, *"Analyzing AI-Augmented Network Enumeration"*, by Jevon Ang and
Dray Agha, July 2026.
https://www.huntress.com/blog/ai-coded-malware-vibe-coding-active-directory

Cite Huntress directly, not the news aggregators that repackaged it. No PDF exists; the
recovered script was published as a GitHub Gist.

## What happened

An attacker RDP'd into a domain joined Windows server using **already compromised
credentials**, staged tooling in `C:\ProgramData\`, and ran an AI generated ("vibe coded")
PowerShell script, `Untitled1.ps1`, to enumerate Active Directory. The script writes one CSV
per object class plus an `AD_Report.html` into `C:\AD_Reports_<datetime>\`, then zips the
directory.

`Untitled1.ps1` performs **enumeration only**. There is no exfiltration in the script itself.
Roughly 30 minutes later the attacker dropped two further binaries: 

| Binary | Purpose |
|---|---|
| `s5cmd.exe` | S3 client, exfiltration of the archive |
| `SharpShares.exe` | network share enumeration |

## Why it is interesting

Nothing about the *technique* is new. Directory enumeration by an authenticated user is as old
as Active Directory, and every tool used has legitimate equivalents.

What changed is the **economics of tooling**. The script is verbose, redundant, and clearly
generated rather than written, and it is disposable. An attacker can produce a fresh one for
every engagement at no cost, which means:

- **Hash based detection is worthless here.** The binary is unique per intrusion.
- **Filename and cmdlet signatures are worthless here.** They describe one generated artifact.
- **The behaviour is unchanged and unavoidable.** The directory still has to be read, the
output still has to be staged, the archive still has to leave.

This is the thesis the detection pack is built on: *the technique did not change, so detection
should not have gotten harder. It got harder only for people who were detecting tooling
instead of behaviour.*

## ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Lateral Movement | T1078.002, Valid Accounts: Domain Accounts | RDP with already compromised credentials |
| Lateral Movement | T1021.001, Remote Services: RDP | Logon Type 10 |
| Discovery | T1087.002, Account Discovery: Domain Account | LDAP reads of user objects |
| Discovery | T1018, Remote System Discovery | LDAP reads of computer objects |
| Discovery | T1482, Domain Trust Discovery | LDAP reads of trust objects |
| Collection | T1074.001, Local Data Staging | CSVs written to one directory |
| Collection | T1560.001, Archive Collected Data | the staging directory zipped |
| Exfiltration | T1567.002, Exfiltration to Cloud Storage | `s5cmd.exe` to an S3 endpoint |

## Artifacts from the original incident

Treat this table as a **replication checklist**, not as durable IOCs. Everything in it is
specific to one intrusion.

| Artifact | Type | Detection value |
|---|---|---|
| `Untitled1.ps1` | AI generated enumeration script | none, single use |
| `C:\AD_Reports_<datetime>\` | staging directory | low, pattern not path |
| `AD_Users.csv`, `AD_Computers.csv`, `AD_Groups.csv`, `AD_OUs.csv`, `AD_Trusts.csv`, `AD_Subnets.csv` | enumeration output | **the count and shared location matter, not the names** |
| `AD_Report.html` | formatted report | none |
| `*.zip` of the staging directory | archive | behaviour, not name |
| `s5cmd.exe` | S3 client | legitimate open source tool, presence in ProgramData is the signal |
| `SharpShares.exe` | share enumeration | not reproduced in this lab |

## What was reproduced, and what was not

**Reproduced faithfully:** RDP with valid domain credentials; the enumeration sweep; local
staging of one file per object class; archiving; exfiltration with **real `s5cmd`** against a
self hosted MinIO endpoint, so the network stage is genuine rather than simulated.

**Not reproduced:** `SharpShares.exe` share enumeration, and the initial credential
compromise. This project starts from the assumption of valid credentials, which is where the
Huntress incident effectively starts too.

**Out of scope, tracked separately:** detection validation across multiple tools (running the
same technique through RSAT, `net.exe` and `ADSISearcher` to prove the rule keys on behaviour)
is being done as its own project rather than folded in here.
