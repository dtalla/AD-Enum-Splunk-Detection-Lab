# dashboard-raw-spl.md: AD Enum Incident (Raw SPL Investigation)

Self contained reference for the **AD Enum Incident: Raw SPL Investigation** dashboard.
Companion doc: [`dashboard-datamodel-tstats.md`](./dashboard-datamodel-tstats.md).

## What this dashboard is

Analyst deep dive dashboard for one incident/account/host at a time. Every panel searches
raw indexes/sourcetypes directly: `index=us_domain` (DC auth) or `index=end-user`
(Endpoint-1's 4688 + Sysmon), with no data model and no acceleration involved. That means it
works even before a data model is built or accelerated, and every field the raw event
actually contains is visible for inspection, not just the CIM subset a normalized model
exposes. Use the companion **SOC Overview: Data Model (tstats)** dashboard instead for a
fast, always on, whole environment view.


**Inputs:**

| Token | Type | Default | Purpose |
|---|---|---|---|
| time_tok | time | -24h@h to now | Scopes every panel's time range |
| user_tok | text | Prush | Scopes every panel to one account |
| dest_tok | text (wildcard ok) | * | Optionally narrows to one host |


## Panel 1: Incident Timeline (All Raw Events for this Account)

Stacked column of RDP logon / process create / file create / network connect over time,
EventCode labeled into readable stage names. The first panel an analyst opens on a specific
account: answers "what order did this happen in" without needing every field normalized yet.
Deliberately queries both `index=us_domain` and `index=end-user` in one search and matches on
both `User=` and `user=`: the exact per sourcetype field name inconsistency (`User` vs `user`
vs, elsewhere, `Account_Name`) that the companion data model dashboard exists to normalize
away.

```spl
(index=us_domain OR index=end-user) (EventCode=4624 OR EventCode=4688 OR EventCode=1 OR EventCode=3 OR EventCode=11)
(User="$user_tok$" OR user="$user_tok$") dest="$dest_tok$"
| eval stage=case(
EventCode=4624, "1 - RDP Logon",
EventCode=4688, "2 - Process Create (4688)",
EventCode=1, "2 - Process Create (Sysmon)",
EventCode=11, "3 - File Staged (Sysmon)",
EventCode=3, "4 - Network Connect (Sysmon)",
1=1, "Other")
| timechart span=5m count by stage
```

## Panel 2: Process Execution Detail (full command lines)

Raw 4688/Sysmon EventCode 1, full unfiltered `CommandLine`, parent/child visible via
`ParentImage`/`Image`: what you'd paste into a writeup to show exactly which commands ran, in
order, under which parent process. No data model normalization here on purpose: the raw
`CommandLine` is the evidence.

```spl
index=end-user (EventCode=4688 OR EventCode=1) (User="$user_tok$" OR user="$user_tok$") dest="$dest_tok$"
| table _time, dest, User, ParentImage, Image, CommandLine
| sort - _time
```

## Panel 3: File Staging Detail (ProgramData writes)

Raw Sysmon EventCode 11 (FileCreate), kept as its own table since "what ran" (panel 2) and
"what did it leave behind" (this panel) are different triage questions.

```spl
index=end-user EventCode=11 (User="$user_tok$" OR user="$user_tok$") dest="$dest_tok$" TargetFilename="*ProgramData*"
| table _time, dest, User, Image, TargetFilename
| sort - _time
```

**Known limitation, carried over from before this pass:** this filters on
`TargetFilename="*ProgramData*"`, which only catches the *staging* of the attacker's tools
(`Untitled1_LAB.ps1`, `s5cmd.exe`) into `C:\ProgramData\`. It does **not** show the script's
actual CSV output, which lands in a separate `C:\AD_Reports_<timestamp>\` folder. This is the
exact same path bug that was just fixed on the companion tstats dashboard's "File Staging
Activity by Host" panel (see `dashboard-datamodel-tstats.md`, Investigation & fixes #3). It
just hasn't been carried over to this panel yet. **Recommended follow up:** either broaden the
filter to `TargetFilename="*ProgramData*" OR TargetFilename="*AD_Reports_*"`, or add a second
panel dedicated to the `AD_Reports_*` output, so an analyst pivoting on one account can see
both the staging and the actual data gathering output in one place.

<img width="1812" height="423" alt="Image" src="https://github.com/user-attachments/assets/1f48c3dc-c7d4-4b10-b5f3-1fbb5bae9969" />

## Panel 4: Risk Score Trend for this Account

`index=risk` timechart of individual risk events over time for the account in scope: not the
aggregate the correlation search thresholds on, but the raw event stream, so an analyst can
see exactly which rule fired when.

```spl
index=risk risk_object="$user_tok$"
| timechart span=5m sum(risk_score) as risk_score by risk_message useother=f
```

## Design notes

This dashboard was deliberately left unchanged during the Sep 13, 2026 investigation into the
companion tstats dashboard (see `dashboard-datamodel-tstats.md`). It doesn't share panels
2/3's acceleration related bugs since it never queries a data model. Its only carried over
issue is the ProgramData only path filter on panel 3, flagged above. It also wasn't touched
by the Sep 9, 2026 noise account fix, since it's already scoped to one account via `user_tok`
(default `Prush`) by design, so DWM-n/UMFD-n noise was never a problem here the way it was on
the whole environment overview dashboard.
