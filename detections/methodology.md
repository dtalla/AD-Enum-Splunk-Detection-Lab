# Detection Methodology

## Start from the technique, not the log

Name the technique the attacker has to execute (T1087.002), ask which data source or CIM data
model that behaviour appears in, and only then write SPL. Writing SPL first produces rules
that detect *the sample you had*, which is exactly the failure mode this incident is about.

## Detect behaviour, not tooling

Huntress's central point about this intrusion is that `Untitled1.ps1` was a **one-off,
AI-generated artifact**. Its filenames, its cmdlet choices and its hash will never be seen
again. A detection built on them detects nothing but history.

So the Discovery rule keys on **4662 directory-object reads at the domain controller**, not on
`Get-ADUser`. The enumeration *has* to read the directory; whether the tool is RSAT,
`net user /domain`, `ADSISearcher`, BloodHound or something written next week, the DC sees the
reads. The filename list from the incident is a **replication checklist**, not a set of
durable IOCs.

The same logic elsewhere: the staging rule counts distinct CSV files landing in one directory
rather than matching `AD_Users.csv`; the archive rule matches any archive extension from any
process rather than `Compress-Archive`.

## Every rule answers five questions

| Question | Field | Why it exists |
|---|---|---|
| Who | `user` → `risk_object` | without a consistent identity the correlation has nothing to group on |
| Where | `dest` | SOAR needs an asset to act against — "AD enumeration detected" with no host is not actionable |
| What | process / file / dest_ip | the proof |
| When | `_time` (from `min(_time) as first_seen`) | attack time, not scheduler time |
| Which ATT&CK step | `mitre_tactic` | the correlation counts **distinct tactics** |

If a candidate search cannot produce all five, it is not ready to be a risk rule. The
Exfiltration rule nearly failed this test — Sysmon network events often carry no user — which
is why it carries an asset-to-owner lookup. See `risk-rules/README.md`.

## Why risk-based alerting instead of five alerts

One `Get-ADUser` call, or a few CSVs in ProgramData, happens on a real network for legitimate
reasons. Alerting on any of them individually is how a queue becomes permanently ignored. The
*combination*, in a short window, against the *same account*, is the signal.

So each rule writes a low-severity entry to `index=risk` and pages nobody. One correlation
search turns them into a single investigation. The threshold —
`total_risk >= 60 AND tactic_count >= 4` — is set so that no two rules alone can trip it.

## Mixed sourcing: raw index and data models, on purpose

Three rules search raw indexes; two use `tstats` against accelerated data models.

**`tstats` where the schema is stable and the volume is high** (Authentication,
Network_Traffic) — it is dramatically faster and portable across TA changes.

**Raw index where the detail matters** (4662 `Object_Type`, Sysmon `TargetFilename`) — the
fields these rules depend on are not all normalised into CIM, and forcing them through a data
model would lose the precision the thresholds need.

The cost of mixing is that the two families need **different deduplication mechanisms**:
`tstats` cannot read `_indextime`. That is not an inconsistency to tidy up; it is the correct
answer for each source. See `macros.md`.

## Verify the data before writing the rule

```spl
| tstats summariesonly=true count from datamodel=Authentication
| tstats summariesonly=true count from datamodel=Network_Traffic
index=us_domain EventCode=4662 earliest=-24h | head 5
index=end-user tag=endpoint tag=filesystem earliest=-24h | head 5
```

If a data model returns 0: it may not be accelerated, the sourcetype may not be tagged into
its constraints, or `summariesonly=true` is hiding un-summarised data — drop the flag to
confirm the raw mapping, then re-enable it for anything scheduled.

Running these first would have caught the Archive Creation gap before the rule was written
rather than months later.

## Exclude your own response tooling

The `exclude_noise_accounts` macro drops `svr_soar`, the SOAR WinRM service account. Without
it, the response tooling generates risk against itself on a schedule and can manufacture a
kill chain out of its own enrichment activity.

The accepted cost: an attacker who compromises that account is invisible to these five rules.
The mitigation is a separate detection watching for the service account doing anything outside
its known action set — listed as a follow-up rather than quietly ignored.
