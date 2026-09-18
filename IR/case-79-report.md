# Case 79: Incident Follow Up Report

**AD Enumeration Kill Chain: prush & ppitt on Endpoint-1 (FAMTECH)**
Severity High · TLP:AMBER · Framework NIST SP 800-61r2 · Workbook 19/19 tasks closed

This is the worked example for `framework.md`. Every claim below is backed by a SOAR action
run or a Splunk query attached to the case, and the action run IDs are cited so the evidence
can be found rather than taken on trust.

---

## 1. Executive summary

Two standard domain accounts, `prush` and `ppitt`, executed a scripted Active Directory
enumeration chain on a single workstation, staged the output locally, archived it, and moved
it to an external S3 compatible endpoint. Risk based alerting detected each stage
independently, correlated them across four MITRE tactics, and escalated to SOAR as two
events, which were promoted into this case.

The host was contained by network isolation under analyst approval. Scope was confirmed to
one host. The exfiltration destination was identified and blocked before containment was
lifted, artifacts were hashed and quarantined, and restoration was verified end to end.

**Neither account held elevated privileges at any point.** Everything in the Discovery stage
was available to any authenticated user, by design of Active Directory.

## 2. Timeline (UTC)

| When | What | Evidence |
|---|---|---|
| 2026-09-08 | First observed activity on Endpoint-1 | seven day sweep, action run 64 |
| 2026-09-13 | Two simulation runs, one per account | |
| 18:00 | Enrichment playbook fired automatically on artifact creation: Splunk risk lookup, session list, endpoint script, VirusTotal reputation on the s5cmd hash | playbook run 10 |
| 18:41 | **First containment attempt returned `success` having done nothing** | playbook run 12 |
| 18:42 | Last indicator event of the incident | action run 64 |
| ~19:36 | Containment relaunched after the prompt recipient was corrected; analyst approved | playbook run 13 |
| 19:41 | Containment verified on the host: all profiles Block/Block with three allow rules | action run 63 |
| ~19:52 | **Remote access to the host lost** | action runs 65, 66 |
| ~19:55 | Splunk confirms the forwarder is still reporting from the isolated host | action run 67 |
| ~20:00 | Root cause identified: NETLOGON secure channel severed | action run 70 |
| 20:10 | Exfiltration destination identified and blocked at the perimeter | action run 74 |
| 21:03 | Containment lifted at the VM console | analyst, console |
| 21:05 | Restoration verified: firewall state, secure channel, WinRM | action run 73 |
| 21:08 | Artifacts hashed, then quarantined; persistence checked | action runs 75, 76 |

<img width="2843" height="1539" alt="Image" src="https://github.com/user-attachments/assets/639f144b-f240-4ef3-b6c7-753b4a6c44ee" />

*The SOAR case timeline (Analyst view) for Case 79, spanning enrichment through isolation, eradication, and recovery validation.*

## 3. NIST 800-61 prioritisation

| Dimension | Rating | Reasoning |
|---|---|---|
| Functional impact | **MEDIUM** | One workstation, deliberately isolated. No production service degraded; the isolation itself removed the host from normal use. |
| Information impact | **PRIVACY BREACH (simulated)** | User objects, computer objects and trust relationships enumerated. Data left the host over a nonstandard outbound channel, so exfiltration is assumed rather than disproved. |
| Recoverability | **SUPPLEMENTED RESOURCES** | Recovery was achievable but not with the resources available to the response path: it required hypervisor console access, because containment had removed remote administration. |
| **Overall** | **HIGH** | |

The recoverability rating is the interesting one. On paper this is a single lab workstation
that could be reverted from a snapshot in minutes. It rates Supplemented because the rating
is about *the responder's actual reach*, not the theoretical difficulty, and the responder
had locked themselves out.

## 4. Attack chain observed

| Tactic | Technique | Evidence source | Rule score |
|---|---|---|---|
| Discovery | T1087.002, T1018, T1482 | 4662 directory object reads at the DC | 15 |
| Collection | T1074.001 | Sysmon 11: bulk CSV writes to one directory | 25 |
| Collection | T1560.001 | archive creation *(rule did not fire, see gaps)* | 20 |
| Lateral Movement | T1078.002, T1021.001 | CIM Authentication, `app=win:remote` | 10 |
| Exfiltration | T1567.002 | CIM Network_Traffic, port 9000 | 30 |

Correlation threshold: `total_risk >= 60 AND tactic_count >= 4`. Both were met.

## 5. Scope

Confined to **Endpoint-1 (10.0.0.102)** and the accounts `prush` and `ppitt`.

```spl
index=end-user earliest=-7d (CommandLine="*Get-ADObject*" OR CommandLine="*s5cmd*"
OR Image="*s5cmd.exe" OR CommandLine="*Compress-Archive*" OR CommandLine="*Untitled1_LAB*")
| eval acct=coalesce(user,User)
| stats count as events, values(acct) as accounts, values(EventCode) as eventcodes,
min(_time) as first_seen, max(_time) as last_seen by host
| sort - events
```

One row returned: `Endpoint-1`, 124 events, accounts `ppitt` and `prush`, Sysmon Event IDs
1, 3 and 7. *(action run 64)*

<img width="1751" height="680" alt="Image" src="https://github.com/user-attachments/assets/85aff50d-a961-4c7c-800a-7c4761149f12" />

*The actual scope-sweep result behind this query — 46 events across both accounts on Endpoint-1, not the 124 cited above; the two were captured from different runs of the lab.*

**Stated limits of that conclusion.** The sweep is indicator based, not behaviour based, so a
renamed binary or a different cmdlet would evade it. Coverage extends only as far as Sysmon is
deployed. A host with no forwarder is invisible to this query, which is itself a visibility
gap. And RDP is part of this chain, so a successful interactive logon on a destination host
would not necessarily produce any of these indicators there. A behaviour based authentication
sweep for both accounts is the recommended follow up.

## 6. Containment

| | Before | After |
|---|---|---|
| Domain / Private / Public profiles | `NotConfigured` / `NotConfigured` | **Block** / **Block**, all enabled |
| `Allow-WinRM-Inbound` | absent | present, enabled |
| `Allow-WinRM-Outbound` | absent | present, enabled |
| `Allow-SplunkUF-Outbound` | absent | present, enabled |

Executed as playbook run 13 against **a single artifact** rather than the whole case: the
case carries two artifacts for the same host, and running against both would have issued
duplicate firewall rules.

The forwarder egress exception was added deliberately before the run. It is the reason
`index=end-user host=Endpoint-1 earliest=-30m` still returned **32,009 events, the most
recent 24 seconds before the query** *(action run 55)*, and therefore the reason the failure
in the next section could be diagnosed at all rather than guessed at.

<img width="2849" height="1564" alt="Image" src="https://github.com/user-attachments/assets/2dafcaac-8d06-4a19-b272-1490da6aae4b" />

*SOAR action run 67 — the containment validation query confirming 32,009 Sysmon events still flowing from the isolated host, the evidence that made the lockout diagnosable.*


## 7. The containment lockout

About ten minutes after containment succeeded, every further SOAR action against the host
failed.

| # | Observation | Source |
|---|---|---|
| 1 | Verification action **succeeded** at 19:41: its session was already open | action run 63 |
| 2 | `the specified credentials were rejected by the server` | action run 65 |
| 3 | `HTTPConnectionPool(host='10.0.0.102', port=5985): Read timed out (read timeout=30)` | action run 66 |
| 4 | **Event 5719**: NETLOGON could not set up a secure session with a domain controller (×1) | action run 70 |
| 5 | **Event 4625**: failed logon (×2, one per failed SOAR action) | action run 70 |

<img width="2785" height="1321" alt="Image" src="https://github.com/user-attachments/assets/8b04341d-5609-4870-a349-cc95b2a8f673" />
<img width="2822" height="1504" alt="Image" src="https://github.com/user-attachments/assets/43b1fe4e-d332-49e9-a4c2-c2f75f4ee779" />

*Two of the lockout's own artifacts: the read-timeout failure on recovery validation (left) and the domain-auth-failure query — EventCode 5719/4625 — that traced it to the severed NETLOGON secure channel (right).*

**Root cause.** The SOAR endpoint asset authenticates as `famtech\svr_soar` **over NTLM**: a
*domain* account. NTLM pass through requires the member host to reach a domain controller. The
DC is 192.168.30.101, confirmed from pre incident Sysmon Event 3 traffic (341 connections to
389/LDAP, 58 to 445/SMB). The lockdown blocked all outbound except 5985 and 9997 to the
indexer, so the DC became unreachable, the secure channel dropped, and every subsequent
authentication failed.

The first verification succeeding is what made this dangerous. It used a session that was
already established, so the failure looked like success for one action longer than it should.

**The obvious fix is the wrong one.** Permanently allowing outbound to the domain controller
is self defeating here: the incident being contained *is* LDAP enumeration of that domain
controller. Reopening that path hands the attacker back the channel the containment was meant
to cut.

**Preferred fix:** a **local break glass administrator account** on each managed host for the
SOAR asset. Local NTLM is validated by the host's own SAM and needs no domain controller, so
the response channel survives full network isolation while the domain stays blocked. Accepted
cost: a privileged local account per host, which must carry a unique randomised password
(LAPS or equivalent) or it becomes a lateral movement path of its own.

## 8. Eradication and recovery

**Destination first.** Sysmon Event 3 identified the exfiltration target: **10.0.0.134 on TCP
9000**, reached by `C:\ProgramData\s5cmd.exe`, 84 connections across the incident window
*(action run 74)*. It was blocked at the perimeter **before** host containment was lifted, so
the rollback did not restore the attacker's egress path.

**Artifacts hashed before being touched** *(action run 75)*:

```
E2356C742C74CCE5C6B6100162D0071A3F71E2FED2ED895C2011061A95B3299A s5cmd.exe (18,185,728 bytes)
2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C Untitled1_LAB.ps1 (13,935 bytes)
2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C Untitled1_LAB_ppitt.ps1 (13,935 bytes)
```

The two scripts share a hash: confirming the `ppitt` copy is byte for byte identical, and
that the per user filename was a workaround for a file ACL, not a second variant of the tool.

**Quarantined, not deleted** *(action run 76)*: all three moved to `C:\Quarantine_Case79`;
files matching the incident indicators remaining in `C:\ProgramData`: **0**.

**No persistence** *(action run 73)*: non Microsoft scheduled tasks are Edge Update and
OneDrive Reporting only. Consistent with the threat model: this chain is hands on keyboard
with no persistence mechanism in the script.

<img width="2769" height="1513" alt="Image" src="https://github.com/user-attachments/assets/a373f2d2-b2c7-461a-b887-aee6754cc8fd" />
<img width="2823" height="1383" alt="image" src="https://github.com/user-attachments/assets/6ca2350b-8abe-4eb1-8aa9-f1325c7c1b1b" />


**Restoration, performed at the VM console** because SOAR had no path to the host:

```powershell
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
Set-NetFirewallProfile -All -Enabled False
```

An earlier attempt using `Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured` did
**not** restore service. The pre incident state had the firewall *disabled*, not merely
permissive; resetting the default actions left it enabled with Windows' own inbound Block,
while the cleanup had already removed the `Allow-WinRM-Inbound` rule. The symptom changed from
a credential rejection to a read timeout, which is what separated the two causes.

**Verified from SOAR** *(action run 73)*: all three profiles `Enabled False`;
`Test-ComputerSecureChannel` returns **True**; remote script execution succeeded, which is
itself the proof the response path is back.

<img width="2693" height="1029" alt="image" src="https://github.com/user-attachments/assets/8c5ded77-e1fb-4aa7-8d06-6f3c4f49a7c2" />


**Detection capability preserved throughout.** `EnableScriptBlockLogging = 1` confirmed at
`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`. Neither the lockdown
nor the rollback degraded the telemetry the detections depend on.

## 9. What worked

- Risk based alerting produced **one** finding across four tactics instead of five separate
alerts, which is the entire argument for the approach.
- Enrichment ran automatically on artifact creation and returned a usable reputation verdict
**without pulling the binary over WinRM**: sourcing the SHA256 from Sysmon data already in
Splunk. That design also kept working when the host became unreachable.
- The analyst approval gate held. No destructive action ran without a human answering, and it
cost about a minute.
- The forwarder egress exception preserved visibility into the contained host: the single
decision that made the lockout diagnosable.

## 10. What did not

- A playbook reported success while performing no action.
- Containment severed the responder's own access to the host.
- Lifting containment did not restore the pre containment state.
- One of the five detections (Archive Creation) has never fired and remains unproven: it was
masked by a second rule covering the same tactic.
- One SOAR action (`list processes`) fails on this host because a machine wide PowerShell
profile prints a banner that corrupts the connector's JSON parse.


