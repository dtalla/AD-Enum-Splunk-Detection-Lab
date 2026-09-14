# dashboard-datamodel-tstats.md — SOC Overview (Data Model / tstats)

Self-contained reference for the **SOC Overview - Data Model (tstats)** dashboard. Companion doc: [`dashboard-raw-spl.md`](./dashboard-raw-spl.md).

## What this dashboard is

Operational, always-on overview across the whole environment, not just one incident. Every panel queries an accelerated CIM data model via `tstats` (or, where acceleration turned out to be unreliable, the non-accelerated `| datamodel ... search` form of the same CIM model — see below) instead of raw indexes, so field names stay uniform (`user`, `dest`, `process`, `file_name`...) no matter which sourcetype produced the underlying event. This is the dashboard an analyst would leave open on a SOC monitor; for one incident's full raw detail, use the companion **AD Enum Incident - Raw SPL Investigation** dashboard instead.

Live at `10.0.0.225:8000`, Search & Reporting app, Classic (Simple XML) dashboard, private sharing, owner `dorian`.

**Input:** time range only (`time_tok`, default `-24h@h` to `now`) — no account/host scoping, this is a fleet-wide view.

## Panel 1 — Remote (RDP) Logons by User

`tstats` over `Authentication`, filtered `app=win:remote` (the CIM-normalized value the Windows TA maps Logon_Type 10 into). Confirmed working against live data from the start — the Authentication model is accelerated and populated in this environment.

```spl
| tstats summariesonly=true count
    from datamodel=Authentication
    where Authentication.action=success Authentication.app=win:remote
    `exclude_noise_accounts(Authentication.user)`
    by Authentication.user, _time span=1h
| rename Authentication.user as user
| timechart span=1h sum(count) as logons by user useother=f
```

Uses a reusable macro (Settings → Advanced Search → Search Macros, app `search`) to drop Windows virtual/service accounts (DWM-n, UMFD-n) that add noise without adding signal:

```
[exclude_noise_accounts(1)]
args = field
definition = NOT ($field$="UMFD-*" OR $field$="DWM-*")
```

## Panel 2 — Top Processes by Distinct AD Object Classes Queried

**Rewritten Sep 13, 2026 — see "Investigation & fixes" below for the full root-cause story.** Originally tried to detect AD enumeration by regex-matching cmdlet names (`get-aduser`, `get-adgroup`, ...) against the process command line. That can never match here: the attack script runs as `powershell.exe -File C:\ProgramData\Untitled1_LAB.ps1`, so the actual `Get-AD*` calls execute *inside* the script and never appear on the command line. Seeing them would need PowerShell Script Block Logging (EventCode 4104), which is confirmed **not enabled** anywhere on Endpoint-1 (0 events over the last 7 days).

The fix reuses the same "one process touched N distinct kinds of AD objects" signal, but grounds it in telemetry that actually exists: each enumeration run writes a distinct, fixed set of CSVs into a fresh `C:\AD_Reports_<timestamp>\` folder, and each filename maps 1:1 to an AD object class:

| Output file | Object class |
|---|---|
| AD_Users.csv / AD_Simple_Users.csv / AD_Users_With_Email.csv | user_accounts |
| AD_Computers.csv | computer_accounts |
| AD_Groups.csv | groups |
| AD_Trusts.csv | trusts |
| AD_OUs.csv / AD_Subnets.csv / Domain_Info.csv | topology |

```spl
| datamodel Endpoint Filesystem search
| search Filesystem.file_path="*AD_Reports_*" Filesystem.file_name="*.csv"
| rename Filesystem.* as *
| rex field=file_path "(?i)AD_Reports_(?<run_id>\d{8}_\d{6})"
| eval object_class=case(
    match(file_name, "(?i)AD_(Simple_)?Users(_With_Email)?\.csv"), "user_accounts",
    match(file_name, "(?i)AD_Computers\.csv"),                    "computer_accounts",
    match(file_name, "(?i)AD_Groups\.csv"),                       "groups",
    match(file_name, "(?i)AD_Trusts\.csv"),                       "trusts",
    match(file_name, "(?i)(AD_OUs|AD_Subnets|Domain_Info)\.csv"), "topology")
| where isnotnull(object_class)
| stats dc(object_class) as distinct_object_classes, values(object_class) as classes_seen,
        values(process_id) as process_id
    by user, dest, process_name, run_id
| sort - distinct_object_classes
| head 20
```

Note the `match()` patterns intentionally carry no `^`/`$` anchors — `match()` already implies a full-string match in SPL, and a stray literal `$` in a dashboard XML query gets misparsed by Splunk's `$token$` substitution (see gotcha #4 below).

Verified live: both attacker accounts (`prush`, `ppitt`) show `distinct_object_classes = 5` for their respective runs, with `classes_seen` = all five categories above.

## Panel 3 — File Staging Activity by Host (CSV bursts in AD_Reports_*)

**Rewritten Sep 13, 2026.** Originally titled "...(CSV bursts in ProgramData)" and filtered `file_path="*\\ProgramData\\*"` — but the script only *stages itself* there (`Untitled1_LAB.ps1`, `s5cmd.exe`); its actual CSV output goes to a freshly created `C:\AD_Reports_<timestamp>\` folder per run. Title and filter both corrected; also switched off `tstats` for the reason in gotcha #1 below.

```spl
| datamodel Endpoint Filesystem search
| search Filesystem.file_path="*AD_Reports_*" Filesystem.file_name="*.csv"
| rename Filesystem.dest as dest
| timechart span=1h count as csv_writes by dest useother=f
```

Verified live: clear burst columns (5-10 CSVs written within about a second, once per run) for `Endpoint-1.famtech.local`, lining up with the runs panel 2 found.

## Panel 4 — Live Risk Board - Open Risk Objects

This Splunk instance is plain Enterprise (dev license), not Enterprise Security, so there is no real ES Risk Analysis framework or `Risk.All_Risk` CIM data model. The risk pipeline (5 risk rules + 1 correlation search, documented under `detections/`) writes to `index=risk sourcetype=risk_event` by hand via `| collect`. This panel originally tried `tstats ... from datamodel=Risk.All_Risk` and errored ("Data model 'Risk' was not found"); rewritten as a plain search matching the correlation search's own approach:

```spl
index=risk sourcetype=risk_event project="famtech-ad-enum"
| stats sum(risk_score) as total_risk, values(tactic) as tactics, dc(tactic) as tactic_count,
        values(risk_message) as reasons by risk_object
| sort - total_risk
```

Corroborates panels 2 and 3 independently — its own `reasons` column already read "User prush wrote 9 CSV files into C:\AD_Reports_<timestamp> on Endpoint-1.famtech.local" and "User prush read N distinct AD object classes on Dom-Con.famtech.local" before panels 2/3 were fixed, which is what confirmed the file-diversity approach above matches how this environment's own risk engine already defines the ground truth for this attack.

## Investigation & fixes (Sep 13, 2026)

Three independent bugs were behind panels 2 and 3 showing no data, found in this order:

1. **`Endpoint.Filesystem` data model acceleration is stale/broken in this environment.** `tstats summariesonly=true` returned 0 rows for these events even though the base CIM tag matched (a bare `| tstats count from datamodel=Endpoint.Filesystem` returned 334k+ events). Re-running with `summariesonly=false` (which should fall back to a live, non-accelerated scan through the same tsidx-backed command) *still* returned 0 rows when grouping by `Endpoint.Filesystem.dest` or `.file_name` — meaning the data model's calculated field extraction is broken for this acceleration build, not merely out of date. Confirmed the underlying raw fields (`dest`, `file_name`, `file_path`) resolve fine outside the data model. Fix: dropped `tstats`/acceleration for these two panels entirely and used `| datamodel Endpoint Filesystem search`, which re-evaluates the CIM model live against raw data and resolved every field correctly. Trade-off: slower than an accelerated `tstats` call, acceptable here since this is a 24h-scoped dashboard, not a scheduled search over the whole retention window.
2. **Cmdlet-name detection is structurally impossible against this invocation style.** Documented under panel 2 above — the enumeration happens inside a `-File`-invoked script, invisible to process-command-line telemetry (Sysmon EventCode 1 / 4688). Confirmed via `index=end-user EventCode=4104` returning 0 events over 7 days that PowerShell Script Block Logging — the one data source that *would* see inside the script — is not enabled on Endpoint-1. **Open follow-up:** enabling 4104 (via the `EnableScriptBlockLogging` GPO setting) would let panel 2 go back to genuine cmdlet-level detection instead of the file-output proxy; not done in this pass.
3. **Wrong path filter.** Panel 3 (and originally panel 2, indirectly) filtered on `ProgramData`, which only holds the staged tools, not the script's actual output. Corrected to `AD_Reports_*` in both panels, confirmed against live `TargetFilename` values from Sysmon EventCode 11.
4. **Splunk dashboard token-parsing gotcha, found while fixing #2/#3:** the first corrected version of panel 2 used `^...\.csv$`-style regex anchors inside `match()`. Splunk's dashboard XML scans the whole query string for `$...$` pairs to resolve tokens — five *unpaired* literal `$` characters (one per `match()` call) got paired up arbitrarily across the query and treated as one bogus unresolved token, which silently put the panel into a permanent "search is pending input" state (no error, just never runs). Fix: dropped the `^`/`$` anchors — `match()` in SPL already implies a full-string match, so they were redundant anyway. Worth remembering for any future panel: **a literal, unescaped `$` in dashboard SPL is dangerous even when it's not meant as a token.**

## Change log

**Sep 13, 2026** — Panels 2 and 3 rewritten per the investigation above; both confirmed populating with real data (prush/ppitt runs, 5 distinct object classes each; CSV-burst timechart matching Sysmon EventCode 11 write timestamps). Saved via Modifier → Source in the dashboard editor.

**Sep 9, 2026** — Noise-account fix: added the `exclude_noise_accounts(1)` macro and applied it to panels 1 and 2's `where` clauses to drop `DWM-n`/`UMFD-n` virtual accounts from by-user panels.
