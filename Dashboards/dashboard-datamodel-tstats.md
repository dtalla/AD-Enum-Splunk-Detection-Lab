# dashboard-datamodel-tstats.md: SOC Overview (Data Model / tstats)

Self contained reference for the **SOC Overview: Data Model (tstats)** dashboard.
Companion doc: [`dashboard-raw-spl.md`](./dashboard-raw-spl.md).

## What this dashboard is

Whole environment overview dashboard, built entirely on `tstats` against accelerated data
models (`Authentication`, `Network_Traffic`, plus a custom staging summary). It exists to
answer "what does the environment look like right now" fast, across every account and host at
once, without waiting on raw index searches. Use the companion **AD Enum Incident: Raw SPL
Investigation** dashboard when you already know which account and host to dig into.

Live at `10.0.0.225:8000`, Search & Reporting app, Classic (Simple XML) dashboard, private
sharing.



## Panel 1: Remote RDP Logons

`tstats` count of `Authentication` events where `action=success` and `app=win:remote`, by
`user` and `dest`, over the dashboard's time range. First panel on the board because a remote
interactive logon is the starting point of the attack chain this whole project is built
around.


```spl
| tstats summariesonly=true count from datamodel=Authentication
where Authentication.action=success Authentication.app=win:remote
by Authentication.user, Authentication.dest
| rename Authentication.user as user, Authentication.dest as dest
```
<img width="1864" height="289" alt="Image" src="https://github.com/user-attachments/assets/48f42ca3-6894-42c2-9be8-3c6c1453a5ad" />

## Panel 2: Top Processes by Distinct AD Object Classes Queried

Counts, per process, how many distinct AD object classes (`user`, `computer`, `group`, and so
on) were queried in 4662 directory reads at the domain controller, joined back to the process
that issued them. The idea: one process quietly touching many different object classes in a
short window is a stronger enumeration signal than raw event volume.

```spl
| tstats summariesonly=true dc(Change.object_category) as distinct_object_classes
from datamodel=Change
where Change.action=modified Change.object_category=*
by Change.user, _time span=1h
| rename Change.user as user
| where distinct_object_classes >= 3
```

<img width="1848" height="671" alt="Image" src="https://github.com/user-attachments/assets/5b6b5eb9-a996-445a-a0a0-f0f99bf6be54" />

## Panel 3: File Staging Activity by Host

Counts distinct CSV files created per host in a short window, meant to catch the "several
report files landing in one place" pattern regardless of which account or tool produced them.

```spl
| tstats summariesonly=true dc(Filesystem.file_name) as distinct_csv_files
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.csv" Filesystem.file_path="*AD_Reports_*"
by Filesystem.dest, _time span=15m
| rename Filesystem.dest as dest
| where distinct_csv_files >= 4
```
<img width="1852" height="272" alt="Image" src="https://github.com/user-attachments/assets/00d08b2a-de11-4ade-a363-de8235026294" />

## Panel 4: Live Risk Board, Open Risk Objects

Table of every account currently carrying summed risk, pulled straight from `index=risk`
rather than a data model, since risk events are a lab specific index and not part of any CIM
data model. Kept on this dashboard rather than moved to the raw SPL companion because it is
meant to be glanced at continuously, the same way the rest of this board is.

```spl
index=risk earliest=-24h
| stats sum(risk_score) as total_risk, dc(mitre_tactic) as tactic_count,
values(mitre_tactic) as tactics by risk_object
| where total_risk >= 60 AND tactic_count >= 4
| sort - total_risk
```
<img width="1858" height="648" alt="Image" src="https://github.com/user-attachments/assets/0f0763b5-7b71-47a1-95ab-3ce51ede8d77" />

## Investigation and fixes (Sep 13, 2026)

Four bugs found and fixed while validating this dashboard against a live detonation, in the
order they were found.

### 1. Data model acceleration was broken

**Observed.** Panels 1 and 2 returned zero results even though the underlying raw events were
present in `index=us_domain`.

**Root cause.** The `Authentication` and `Change` data models were either not accelerated, or
accelerated over a summary range that did not cover the detonation window. `tstats` against an
unaccelerated or stale summary range silently returns nothing; it does not error.

**Fix.** Reenabled acceleration on both data models with a summary range wide enough to cover
the lab's detonation windows, and added the verification searches from
`Detections/methodology.md` (dropping `summariesonly=true` to confirm the raw mapping first)
to the standing pre flight checklist before trusting any `tstats` panel.

### 2. Cmdlet name detection is not possible from this data model

**Observed.** An early draft of panel 2 tried to filter on `CommandLine="*Get-ADUser*"` inside
the `Change` data model and never matched anything.

**Root cause.** The `Change` data model's constraints do not carry `CommandLine`; that field
only exists on the `Endpoint.Processes` data model, and the two cannot be joined inside a
single `tstats` call. This is also a direct instance of the methodology's own rule: detecting
one AI generated script's specific cmdlet choices is not durable, so this was the wrong field
to key on even if it had been technically possible.

**Fix.** Rebuilt panel 2 around `Change.object_category`, the durable behavioural signal
(directory object classes actually read), described above.

### 3. Wrong path filter on the staging panel

**Observed.** Panel 3 returned zero results during a detonation that was known to have staged
four CSV files.

**Root cause.** The panel's original filter used `Filesystem.file_path="*ProgramData*"`, which
only catches where the attacker's tooling (`Untitled1_LAB.ps1`, `s5cmd.exe`) is staged, not
where the script's own CSV output lands, which is a separate `C:\AD_Reports_<timestamp>\`
folder. See `Detections/methodology.md` for the same distinction as it applies to the
detection rules themselves.

**Fix.** Changed the filter to `Filesystem.file_path="*AD_Reports_*"`. Noted in
`dashboard-raw-spl.md` that its own Panel 3 still carries the old `ProgramData` only filter and
has not yet been fixed the same way.

### 4. Splunk token parsing `$` 

**Observed.** A draft panel filter written as `Filesystem.file_name="*.csv$"`, intended as an
end of string anchor, matched nothing.

**Root cause.** Splunk Simple XML treats a bare `$` as the closing delimiter of a dashboard
token, not as regex syntax; SPL `LIKE` style field matching does not support regex anchors in
the first place. The `$` silently broke token substitution rather than raising a visible
error.

**Fix.** Dropped the anchor entirely and matched on `Filesystem.file_name="*.csv"`, which is
sufficient given the panel already scopes by `file_path`.

## Change log

| Date | Change |
|---|---|
| Sep 9, 2026 | Added `exclude_noise_accounts` style filtering to panel 1 to drop `DWM-n`/`UMFD-n` noise accounts from the RDP logon view. |
| Sep 13, 2026 | Fixed data model acceleration (#1); replaced cmdlet based filter with object class based filter on panel 2 (#2); corrected panel 3's path filter from `ProgramData` to `AD_Reports_` (#3); removed an invalid `$` regex anchor from panel 3 (#4). |

See `Detections/methodology.md` and `Detections/macros.md` for the detection side of the same
investigation.
