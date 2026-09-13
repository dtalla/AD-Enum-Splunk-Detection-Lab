# Detonation Log

Two runs, one per account, on Endpoint-1 (10.0.0.102). The second run existed to prove the
detections key on behaviour and identity rather than on anything specific to the first user —
and it surfaced a Windows ACL problem worth documenting.

| | Run 1 | Run 2 |
|---|---|---|
| Account | `famtech\prush` | `famtech\ppitt` |
| Host | Endpoint-1 | Endpoint-1 |
| Result | full chain, correlation fired | full chain, correlation fired |
| SOAR container | 78 | 79 |

Combined telemetry across both runs, 7-day window: **274 events** on one host, Sysmon Event
IDs 1 (process create), 3 (network connect) and 7 (image load), spanning 2026-09-08 to
2026-09-13 18:42 UTC.

## Chain executed

1. **RDP** to Endpoint-1 with valid domain credentials → 4624 Type 10, normalised by the
   Windows TA to `app=win:remote`.
2. **Enumerate AD** with the sanitised `Untitled1_LAB.ps1` → 4662 directory-object reads at
   the DC, and 4104 script blocks on the endpoint.
3. **Stage** one CSV per object class into a single directory → Sysmon Event 11.
4. **Archive** the staging directory → Sysmon Event 11.
5. **Exfiltrate** with real `s5cmd.exe` to a self-hosted MinIO endpoint on
   **10.0.0.134:9000** → Sysmon Event 3. 84 connections recorded across the window.

## What fired

| Stage | Rule | Fired |
|---|---|---|
| RDP | RDP Logon to Domain Asset | yes |
| Enumeration | AD Object Class Enumeration | yes |
| Staging | Bulk File Staging in ProgramData | yes |
| Archiving | Archive Creation via Compress-Archive | **no — see below** |
| Exfiltration | Outbound to Non-Standard Destination | yes |

Four distinct tactics and a risk total above 60 were reached **without** the archive rule,
because the staging rule already contributes the Collection tactic. The correlation fired
correctly on both runs. That redundancy is also what hid the broken rule — see
`docs/lessons-learned.md`, finding 9.

## Issue: `Copy-Item` access denied for the second user

Run 2 failed at the staging step:

```
Copy-Item : Access to the path 'C:\ProgramData\Untitled1_LAB.ps1' is denied.
```

`prush` had no such problem, and both accounts sit in the same user OU with the same group
memberships.

**Root cause — a per-file ACL, not a rights problem.** `C:\ProgramData` carries an inheritable
**CREATOR OWNER** ACE. `prush` created the file first, so the resulting ACL is:

| Principal | Rights |
|---|---|
| `FAMTECH\prush` (owner) | FullControl |
| `BUILTIN\Users` | ReadAndExecute |

`ppitt` is in `Users`, so it can read and execute the file but cannot overwrite it. Identical
accounts, different outcome, decided entirely by who created the file first.

**Fix.** Write per-user filenames:

```powershell
-Destination "C:\ProgramData\Untitled1_LAB_$($env:USERNAME).ps1"
```

The two scripts were later confirmed byte-for-byte identical —
SHA256 `2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C` for both — so the
per-user filename is a workaround for the ACL, not a second variant of the tool.

**Related note.** `C:\` root grants `AppendData` (create folders) to Authenticated Users but
not file creation, which is a useful constraint to know when choosing staging paths for a
replication.

## Artifacts left on the host

| File | Size | SHA256 |
|---|---|---|
| `s5cmd.exe` | 18,185,728 | `E2356C742C74CCE5C6B6100162D0071A3F71E2FED2ED895C2011061A95B3299A` |
| `Untitled1_LAB.ps1` | 13,935 | `2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C` |
| `Untitled1_LAB_ppitt.ps1` | 13,935 | `2A4D6D9171661C26C217160C6E0AA057898C3CB1B62EB4D97E525A0D378C694C` |

All three were hashed and then quarantined to `C:\Quarantine_Case79` during the incident
response. No attacker persistence was found — non-Microsoft scheduled tasks on the host are
Edge Update and OneDrive Reporting only, which matches the threat model: this chain is
hands-on-keyboard with no persistence mechanism in the script.

## Environment note that cost real time

`C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1` prints
`Atomic Red Team loaded. Type 'art-help'.` at the start of **every** PowerShell session,
including every WinRM session opened by SOAR. It breaks any connector action that parses
stdout as JSON. Guard machine-wide profiles with `if ($Host.Name -eq 'ConsoleHost') { ... }`
before running response tooling against the host.
