# Detonation Log

Two runs, one per account, on Endpoint-1 (10.0.0.102). The second run existed to prove the
detections key on behaviour and identity rather than on anything specific to the first user,
and it surfaced a Windows ACL problem worth documenting.

| | Run 1 | Run 2 |
|---|---|---|
| Account | `famtech\prush` | `famtech\ppitt` |
| Host | Endpoint-1 | Endpoint-1 |
| Result | full chain, correlation fired | full chain, correlation fired |
| SOAR container | 78 | 79 |

<img width="1889" height="458" alt="Image" src="https://github.com/user-attachments/assets/5b76a114-04a1-4447-8066-2b9528dfe7f5" />
Combined telemetry across both runs, 7 day window: **274 events** on one host, Sysmon Event
IDs 1 (process create), 3 (network connect) and 7 (image load), spanning 2026-09-08 to
2026-09-13 18:42 UTC.

## Chain executed

1. **RDP** to Endpoint-1 with valid domain credentials → 4624 Type 10, normalised by the
Windows TA to `app=win:remote`.
2. **Enumerate AD** with the sanitised `Untitled1_LAB.ps1` → 4662 directory object reads at
the DC, and 4104 script blocks on the endpoint.
3. **Stage** one CSV per object class into a single directory → Sysmon Event 11.
4. **Archive** the staging directory → Sysmon Event 11.
5. **Exfiltrate** with real `s5cmd.exe` to a self hosted MinIO endpoint on
**10.0.0.134:9000** → Sysmon Event 3. 84 connections recorded across the window.

Search showcasing the events chain. 

<img width="1886" height="800" alt="Image" src="https://github.com/user-attachments/assets/5375024d-0239-4d69-b433-ba09184ac63e" />

## Note on the archive (zip) step

During the archive stage, `Compress-Archive` intermittently threw an Access Denied error
against the FileStream handle for the target zip file. This traces back to the executing
account not holding sufficient permission on `C:\ProgramData` at that path and moment (the
same class of per file ACL issue described below for `Copy-Item`), not to a fault in the
script itself. The script's own catch block recovered from the error and the archive was
still written to disk in most runs.

Because the archive step could not be relied on to succeed cleanly, exfiltration was carried
out against the already staged CSV files in `C:\AD_Reports_<datetime>\` directly, rather than
against the zip. This is also the practical reason the Archive Creation risk rule (see
`Detections/Risk-rules/README.md`) has been difficult to validate: the archive is not
consistently the artifact that actually left the host.

## What fired

| Stage | Rule | Fired |
|---|---|---|
| RDP | RDP Logon to Domain Asset | yes |
| Enumeration | AD Object Class Enumeration | yes |
| Staging | Bulk File Staging in ProgramData | yes |
| Archiving | Archive Creation via Compress-Archive | **no, see below** |
| Exfiltration | Outbound to Nonstandard Destination | yes |

<img width="1900" height="542" alt="Image" src="https://github.com/user-attachments/assets/48d10eb3-23ec-4c50-af04-e532fa96909c" />

Four distinct tactics and a risk total above 60 were reached **without** the archive rule,
because the staging rule already contributes the Collection tactic. The correlation fired
correctly on both runs. That redundancy is also what hid the broken rule. See
`Docs/lessons-learned.md`, finding 9.



## Artifacts left on the host

| File | Size | SHA256 |
|---|---|---|
| `s5cmd.exe` | 18,185,728 | `E2356C742C74CCE5C6B6100162D0071A3F71E2FED2ED895C2011061A95B3299A` |
| `Untitled1_LAB.ps1` | 13,935 | `2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C` |
| `Untitled1_LAB_ppitt.ps1` | 13,935 | `2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C` |

*Note: `Untitled1_LAB_ppitt.ps1` is not a second artifact. It is `Untitled1_LAB.ps1` copied
under the `ppitt` account as the per user filename fix described above; the identical SHA256
confirms it.*

All three were hashed and then quarantined to `C:\Quarantine_Case79` during the incident
response. No attacker persistence was found. Non Microsoft scheduled tasks on the host are
Edge Update and OneDrive Reporting only, which matches the threat model: this chain is hands
on keyboard with no persistence mechanism in the script.

`(add screenshot of the quarantine folder listing and hash verification here)`

## Environment note that cost real time

`C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1` prints
`Atomic Red Team loaded. Type 'art-help'.` at the start of **every** PowerShell session,
including every WinRM session opened by SOAR. It breaks any connector action that parses
stdout as JSON. Guard machine wide profiles with `if ($Host.Name -eq 'ConsoleHost') { ... }`
before running response tooling against the host.
