# Risk Rules: as built

Five rules, one per kill chain stage. **None of them alert.** Each only writes a low severity
entry to `index=risk` through the `risk_finding` macro. One `Get-ADUser` call, or a few CSVs
in ProgramData, happens on a real network for legitimate reasons. Alerting on any of them
individually is how a SOAR queue becomes permanently ignored. The *combination*, in a short
window, against the *same account*, is the signal. See `correlation-search.md`.

| # | Rule | ATT&CK | Tactic | Score | Source | Window |
|---|---|---|---|---|---|---|
| 1 | AD Object Class Enumeration | T1087.002, T1018, T1482 | Discovery | 15 | `index=us_domain` 4662 | `-30m` → `now` |
| 2 | Bulk File Staging in ProgramData | T1074.001 | Collection | 25 | `index=end-user` Sysmon 11 | `-30m` → `now` |
| 3 | Archive Creation via Compress-Archive | T1560.001 | Collection | 20 | `index=end-user` Sysmon 11 | `-30m` → `now` |
| 4 | RDP Logon to Domain Asset | T1078.002, T1021.001 | Lateral Movement | 10 | `datamodel=Authentication` | `-10m@m` → `-5m@m` |
| 5 | Outbound to Nonstandard Destination | T1567.002 | Exfiltration | 30 | `datamodel=Network_Traffic` | `-10m@m` → `-5m@m` |

All five on cron `*/5`. Maximum achievable total is 100; the correlation threshold is 60 and
4 distinct tactics, so no two rules alone can trip it, and the two Collection rules together
still only count as **one** tactic.

---

## 1. AD Object Class Enumeration: T1087.002 / T1018 / T1482

```spl
index=us_domain EventCode=4662 Object_Type!="SecretObject" `exclude_noise_accounts(Account_Name)`
| `new_events_only`
| stats dc(Object_Type) as distinct_object_classes, /* BREADTH of the sweep */
values(Object_Type) as classes_seen, /* what they actually read */
min(_time) as first_seen /* attack time, not run time */
by Account_Name, ComputerName
| where distinct_object_classes >= 3 /* 3+ classes = recon, not a lookup */
| eval risk_message="User ".Account_Name." read ".distinct_object_classes
." distinct AD object classes on ".ComputerName
| `risk_finding(Account_Name, "T1087.002,T1018,T1482", "Discovery", 15)`
```

**The design decision.** This keys on **4662 directory object reads at the DC**, not on
PowerShell cmdlets at the endpoint. That is the whole point of the project. Huntress' own
argument is that the script was a one time, AI generated artifact, so matching
`Get-ADUser|Get-ADComputer|Get-ADTrust` would detect *that script* and nothing else. LDAP
reads at the domain controller are what the attacker cannot avoid: whether the tool is RSAT,
`net user /domain`, `ADSISearcher`, BloodHound, or something that does not exist yet.

**Why `dc(Object_Type) >= 3`.** A help desk lookup touches one object class. A recon sweep
walks users, then computers, then groups, then trusts. Counting *distinct classes* rather
than event volume is what separates the two, and it is deliberately a low bar, because this
rule scores 15 and is not meant to be conclusive on its own.

**Why `Object_Type!="SecretObject"`.** SecretObject reads are LSA/DPAPI internals that fire
constantly from normal domain operation. Left in, they inflate `distinct_object_classes` for
every account on the network.

**Requires:** "Audit Directory Service Access" enabled on the DC. If 4662 is sparse, that is
a GPO tuning step, not a failed detection.

`(add screenshot of SPL results validating this rule fired here)`

---

## 2. Bulk File Staging in ProgramData: T1074.001

```spl
index=end-user tag=endpoint tag=filesystem TargetFilename="*.csv" `exclude_noise_accounts(user)`
| `new_events_only`
| rex field=TargetFilename "^(?<file_path>.*)\\\\(?<file_name>[^\\\\]+)$" /* split dir | file */
| stats dc(file_name) as distinct_csv_files,
min(_time) as first_seen
by user, dest, file_path /* group BY DIRECTORY, see below */
| where distinct_csv_files >= 4
| eval risk_message="User ".user." wrote ".distinct_csv_files." CSV files into "
.file_path." on ".dest
| `risk_finding(user, "T1074.001", "Collection", 25)`
```

**Why group by `file_path`.** Grouping by directory encodes the actual behaviour: one CSV
per enumerated object type, all landing in *the same* staging folder before being zipped.
Without it, four unrelated CSV writes scattered across four legitimate directories would
trip the rule. The `rex` exists purely to split the Sysmon `TargetFilename` into directory
and filename, because Sysmon gives you the full path as one string.

**Why `>= 4`.** The enumeration produces one CSV per object class: users, computers, groups,
OUs, trusts, subnets. Four is comfortably above routine export behaviour and comfortably
below what the attack produces.

**Not anchored on `C:\ProgramData`.** The path filter was deliberately dropped: staging
somewhere else is the obvious evasion, and the directory grouping already carries the
signal.

`(add screenshot of SPL results validating this rule fired here)`

---

## 3. Archive Creation via Compress-Archive: T1560.001

```spl
index=end-user tag=endpoint tag=filesystem
(TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*.rar" OR TargetFilename="*.cab")
`exclude_noise_accounts(user)`
| `new_events_only`
| stats count, min(_time) as first_seen by user, dest, TargetFilename, Image
| eval risk_message="User ".user." created archive ".TargetFilename." on ".dest
." using ".Image
| `risk_finding(user, "T1560.001", "Collection", 20)`
```

Deliberately the simplest rule: a presence check with no threshold. It is kept separate from
rule 2 rather than folded in, for one reason: it carries its own `risk_message` and its own
evidence (`Image` tells you *what* created the archive), so the analyst sees "PowerShell
zipped this" rather than inferring it.

Note it matches **any** archive extension and **any** creating process, not
`Compress-Archive` specifically. The name is historical; the logic is tool agnostic.

> ### KNOWN GAP: this rule has never fired
> Despite archive creation in every detonation, this rule has produced zero risk events.
> Leading hypothesis: the Sysmon config's FileCreate (Event ID 11) section excludes archive
> extensions, or includes only a specific directory set, so the event never reaches the
> index. To confirm:
> ```spl
> index=end-user tag=endpoint tag=filesystem TargetFilename="*.zip" earliest=-7d | head 20
> ```
> If that returns nothing, it is a telemetry gap, not a rule bug, and the fix is in
> `sysmonconfig.xml`, not in SPL.
>
> A second, contributing factor: the archive step itself has thrown Access Denied errors
> during detonation, traced to the executing account not holding sufficient permission on the
> target path at that moment rather than to the script. See `Attacks/detonation-log.md`. When
> that happens the archive is not reliably the artifact that leaves the host, since exfil was
> run against the already staged CSV files instead, which is a second reason this rule sees
> less consistent telemetry than rule 2.
>
> **It is listed as a coverage gap, not as coverage.** An untested detection is not a
> detection: this rule has been sitting in the pack appearing to provide Collection coverage
> while contributing nothing. Rule 2 covers the same tactic, which is why the correlation
> still reached four tactics. The gap was masked by redundancy, which is exactly how this
> kind of thing survives unnoticed.

`(add screenshot of the SPL query above and its result count here)`

---

## 4. RDP Logon to Domain Asset: T1078.002 / T1021.001

```spl
| tstats summariesonly=true count, min(_time) as first_seen
from datamodel=Authentication
where Authentication.action=success
Authentication.app=win:remote /* CIM's normalisation of Logon_Type 10 */
NOT Authentication.dest IN ("localhost","127.0.0.1","-")
by Authentication.user, Authentication.dest
| rename Authentication.* as *
| search `exclude_noise_accounts(user)` /* AFTER rename, fields are bare now */
| eval risk_message="Interactive remote (RDP) logon by ".user." to ".dest
| `risk_finding(user, "T1078.002,T1021.001", "Lateral Movement", 10)`
```

**Why `app=win:remote` and not `Logon_Type=10`.** `Logon_Type` is not a CIM field. The
Windows TA's `eventtypes.conf` already normalises Logon Type 10 into `app=win:remote`, so
filtering on the normalised value keeps the rule portable: if the endpoint later reports
through WEF instead of a local forwarder, or Sysmon is replaced by an EDR agent, this search
does not change. Only the TA's field extractions do.

**Lowest score of the five (10), and intentionally so.** Legitimate admin RDP fires this
every single time. It is a *presence* rule, not a threshold rule: its job is to contribute
one timestamped user/dest pair and one tactic toward the correlation, never to be
interesting alone.

**Note the `| search` before the macro.** After `rename`, the field is bare `user`, so the
macro has to be applied through a `search` command rather than inline in the `tstats where`
clause, because `tstats` cannot filter on a renamed field it has not produced yet.

`(add screenshot of SPL results validating this rule fired here)`

---

## 5. Outbound Connection to a Nonstandard Destination: T1567.002

```spl
| tstats summariesonly=true count, min(_time) as first_seen
from datamodel=Network_Traffic
where All_Traffic.action=allowed
All_Traffic.dest_port=9000 /* MinIO, the lab's S3 stand in */
NOT All_Traffic.dest_ip IN ("192.168.30.0/24","10.0.0.225","10.0.0.140")
by All_Traffic.user, All_Traffic.src, All_Traffic.dest_ip,
All_Traffic.dest_port, All_Traffic.app
| rename All_Traffic.* as *
| lookup famtech_assets src OUTPUT owner /* host -> owner, see below */
| eval user=if(isnull(user) OR user="unknown" OR user="-" OR user="", owner, user)
| eval risk_message="Host ".src." (".user.") sent data to ".dest_ip.":".dest_port
." using ".app
| `risk_finding(user, "T1567.002", "Exfiltration", 30)`
```

**Highest score (30), because this is the stage where data actually leaves.**

**The `famtech_assets` lookup is the load bearing part.** Sysmon Event 3 network events
frequently carry no usable user: the connection is attributed to a process, and for service
hosted or short lived processes the user field arrives as `unknown`, `-`, or empty. Without a
user there is **no `risk_object`**, so the risk event cannot be attributed to anyone, and the
correlation search, which groups by account, never sees this stage at all. The kill chain
would stop at three tactics and never fire.

The lookup maps `src` (host) to an `owner` account, and the `eval` falls back to it only when
the real user is missing. It is a lab scale answer to a real problem; in production the same
job is done by an asset/identity framework. The principle holds either way: **a risk rule
that cannot name the account contributes nothing to a correlation that groups by account.**

**Why `dest_port=9000` is a lab artifact, not a detection.** It stands in for the real
incident's cloud storage exfil. In production this should key on *destination reputation and
volume* rather than a port number, because there is nothing to pattern match inside an
outbound TLS session to an S3 compatible endpoint. The connection itself is the signal. The
exclusion list removes known good lab infrastructure so what remains is "this host talked to
something outside its normal blast radius."

This is also the rule that produced the evidence used during eradication: the destination it
flagged, `10.0.0.134:9000` reached by `C:\ProgramData\s5cmd.exe`, was blocked at the
perimeter before host containment was lifted.

`(add screenshot of SPL results validating this rule fired, and of the blocked destination, here)`
