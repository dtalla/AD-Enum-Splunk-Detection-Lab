# AD Enumeration Detection Lab

Replicating and detecting the June 2026 Huntress "vibe coded" Active Directory enumeration
incident: attack chain, Splunk ES detections, SOAR response, and a full NIST SP 800-61
incident response cycle, built in a home SOC lab.

---

## Threat summary

In July 2026 Huntress published *"Analyzing AI-Augmented Network Enumeration"* (Jevon Ang &
Dray Agha), detailing an intrusion where an attacker RDP'd into a domain joined Windows server
with previously compromised credentials, staged tooling in `C:\ProgramData`, and ran an AI
generated ("vibe coded") PowerShell script called `Untitled1.ps1` to enumerate Active
Directory. The script only enumerates: it writes one CSV per object class plus an HTML report
into `C:\AD_Reports_<datetime>\` and zips it. Roughly 30 minutes later the attacker dropped
`s5cmd.exe` (S3 exfiltration) and `SharpShares.exe` (share enumeration).

**The interesting part is not the technique. It is the disposability of the tooling.** The
script is generated per intrusion, so its hash, its filenames and its cmdlet choices are
worthless as indicators. The behaviour underneath is unchanged and unavoidable. 

That is the thesis this repo is built to test: *detect the behaviour, not the tool.*

## Attack chain

```
RDP with valid domain creds T1078.002 / T1021.001 Lateral Movement
↓
Enumerate AD object classes T1087.002 / T1018 / T1482 Discovery
↓
Stage one CSV per object class T1074.001 Collection
↓
Archive the staging directory T1560.001 Collection
↓
Exfiltrate with s5cmd to S3 T1567.002 Exfiltration
```

## Detection approach

Five low severity risk rules, one per stage, write to `index=risk`. **None of them alert.**
One correlation search turns them into a single investigation when
`total_risk >= 60 AND tactic_count >= 4`, and forwards it to SOAR.

The Discovery rule keys on **4662 directory object reads at the domain controller**, not on
PowerShell cmdlet names. The enumeration has to read the directory; the tool used to do it is
interchangeable.

| Rule | ATT&CK | Score | Source |
|---|---|---|---|
| AD Object Class Enumeration | T1087.002, T1018, T1482 | 15 | `index=us_domain` 4662 |
| Bulk File Staging in ProgramData | T1074.001 | 25 | Sysmon 11 |
| Archive Creation via Compress-Archive | T1560.001 | 20 | Sysmon 11 (known gap, has never fired) |
| RDP Logon to Domain Asset | T1078.002, T1021.001 | 10 | `datamodel=Authentication` |
| Outbound to Nonstandard Destination | T1567.002 | 30 | `datamodel=Network_Traffic` |

## Response approach

Two SOAR playbooks, split by whether they change anything:

- **`AD_Enum_Enrichment`** fires automatically on artifact creation and is read only. Pulls the
risk history, lists sessions, and gets a VirusTotal verdict on the exfil binary's SHA256
**sourced from Sysmon data already in Splunk**, not by pulling the binary off the host.
- **`AD_Enum_Isolate_Endpoint_With_Prompt`** is manual, and blocked on a human approval prompt.
Applies a default deny firewall with three deliberate exceptions: WinRM in and out so the
responder keeps control, and **Splunk forwarder egress so the contained host stays visible.**

## Repo map

```
README.md this file
Threat-intel/
analysis.md the Huntress incident, ATT&CK mapping, artifact table
Attacks/
detonation-log.md both detonation runs, what fired, the ACL problem
Detections/
methodology.md how the rules were designed and why
macros.md the four macros, commented, read this one first
Risk-rules/README.md all five rules, as built, with reasoning
correlation-search.md the correlation search + the timing model
validation.md multi tool validation, split into its own project
Dashboards/
README.md investigation dashboard (in progress)
Soar/
playbook.md both playbooks, the generated Python explained
IR/
framework.md NIST 800-61 implementation, 19 tasks and exit criteria
nist-800-61-workbook.json the same, importable as a SOAR workbook template
case-79-report.md one real incident through all 19 tasks, with evidence
Docs/
lessons-learned.md ten findings, root causes, and what changed
```

## Where to start reading

- **For the detection engineering:** `Detections/macros.md`, then
`Detections/correlation-search.md`. The macros are where the real decisions live, and the
timing model is the part that is genuinely hard.
- **For the incident response:** `IR/framework.md`, then `IR/case-79-report.md`.
- **For the short version of everything that went wrong:** `Docs/lessons-learned.md`.

## The headline finding

Four separate components in this pipeline **reported success while doing nothing**:

1. A containment playbook returned `success` having never touched the endpoint. Its approval
prompt resolved to an empty recipient, and every downstream block was silently skipped.
2. An enrichment query returned `success` with zero events, because a Format block had
collapsed five duplicate artifact values into `"prush, prush, prush, prush, prush"`.
3. Splunk's Edit Alert modal saved a time range change and silently discarded the SPL edit in
the same save.
4. A documented containment rollback *looked* like a restore and left the host unreachable for
a different reason than before.

And the containment itself severed the responder's own access to the host. The SOAR service
account authenticates over NTLM as a **domain** account, so blocking outbound to the domain
controller killed the secure channel, and with it, the only way back in.

The detections worked. Everything that actually broke was the plumbing around them.

## Lab scope

This repo documents the incident, the detections and the response. It does **not** document
the lab build. Step by step VM and endpoint construction stays in a private reference; it
answers "can you build a lab," not "can you handle a threat," and it rots as soon as the
config changes.

The one exception is configuration that *is* the detection story. For example, the GPO that
enables PowerShell script block logging is what makes 4104 capture possible. Those get one
line each. Test: does this config choice change whether the detection works? Yes → one line.
No → omit.

## Out of scope

**Validating detection across multiple tools**, running the same technique through RSAT,
`net.exe` and `ADSISearcher` to prove the rules key on behaviour rather than on tooling, is
being done as a separate project rather than folded in here.

## Attribution

Scenario based on Huntress, *"Analyzing AI-Augmented Network Enumeration"* (Jevon Ang & Dray
Agha, July 2026):
https://www.huntress.com/blog/ai-coded-malware-vibe-coding-active-directory

## Status

| | |
|---|---|
| Repo scaffolding | done |
| Attack chain replica (RDP → enumeration → exfil) | done, two runs, two accounts |
| Splunk ES risk rules + correlation search | done, 4 of 5 rules proven firing |
| SOAR enrichment playbook | done, automatic, 4/4 actions |
| SOAR containment playbook | done, analyst gated, verified on the host |
| NIST 800-61 incident response cycle | done, 19/19 tasks closed with evidence |
| Lessons learned | done |
| Investigation dashboard | in progress |
| Detection validation across tools | separate project |

All internal IP addresses, hostnames and account names are lab only (RFC1918 / `famtech.local`).
No credentials, keys or tokens are published in this repo.
