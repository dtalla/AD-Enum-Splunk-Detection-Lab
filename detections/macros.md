# Search Macros

Four macros carry this detection pack. Each exists because something broke without it —
none are cosmetic. Macros were used instead of copy-pasted SPL for one reason:
**five rules had to agree on the same behaviour.** When the shared logic lives in one macro,
changing it changes all five at once and they cannot silently drift apart.

All four live in the `search` app, sharing `app`, read permission `*`, so every scheduled
search and every ad-hoc search can resolve them.

| Macro | Job | Used by |
|---|---|---|
| `risk_finding(4)` | write a normalised risk event | all 5 rules |
| `new_events_only` | count each event exactly once | the 3 raw-event rules |
| `exclude_noise_accounts(1)` | drop machine and service accounts | all 5 rules |
| `soar_export_flatten` | collapse multivalue fields before export | correlation search only |

---

## 1. `risk_finding(4)` — write a normalised risk event

**What it does:** takes a detection result and writes it into the risk index in exactly the
shape the correlation search expects.

**Why a macro:** the correlation search groups by `risk_object` and counts distinct
`mitre_tactic` values. If one rule spelled the field `risk_object` and another spelled it
`user`, that rule's contribution would silently vanish from the correlation — no error, just
a kill chain that never reaches four tactics. The macro makes the contract unbreakable:
there is exactly one place that decides what a risk event looks like.

```spl
[risk_finding(4)]
args = object, technique, tactic, score
definition = eval \
    risk_object      = $object$,             /* who the risk attaches to - always the account */ \
    risk_object_type = "user",               /* the correlation search filters on this        */ \
    risk_score       = $score$,              /* per-stage weight; SUMMED by the correlation   */ \
    mitre_technique  = "$technique$",        /* e.g. T1087.002 - context for the analyst      */ \
    mitre_tactic     = "$tactic$",           /* e.g. Discovery - counted as DISTINCT tactics  */ \
    project          = "famtech-ad-enum",    /* separates lab risk from any real risk data    */ \
    _time            = coalesce(first_seen, now()) \
                                             /* ^ THE IMPORTANT ONE - see below               */ \
  | collect index=risk sourcetype=risk_event
```

**Argument order is `object, technique, tactic, score`** — technique before tactic, score
last. Getting them the wrong way round produces a risk event with `mitre_tactic="T1087.002"`
that still writes successfully and still breaks the distinct-tactic count.

**Called as the last line of every rule:**

```spl
... | `risk_finding(user, "T1560.001", "Collection", 20)`
```

### The `_time` line is the one that matters

Without it, `collect` stamps the risk event with **the moment the scheduled search ran**,
not the moment the attacker acted. On a 5-minute cron that quantises the whole incident
timeline into buckets aligned to the scheduler, so an analyst reconstructing "what happened
when" is reading the *search schedule*, not the attack.

Every rule therefore computes `min(_time) as first_seen` over its own results, and the macro
stamps it. `coalesce(first_seen, now())` means: use the attack time when the rule produced
one, fall back to now when it did not, and never write a null `_time` — a null timestamp
puts the event at epoch 0, where it vanishes from every search.

This bug is easy to miss because nothing looks broken. All the events are there. They are
just in the wrong places.

---

## 2. `new_events_only` — count each event exactly once

```spl
[new_events_only]
definition = where _indextime >= relative_time(now(), "-5m@m") \
               AND _indextime <  relative_time(now(), "@m")
/* _indextime = when the INDEXER received the event                    */
/* _time      = when the event SAYS it happened                        */
/* Dedup must use _indextime: _time does not change between runs, so   */
/* filtering on _time would re-admit the same events forever.          */
```

### The problem it solves

Three rules run on a **5-minute cron over a 30-minute window**. The wide window is
deliberate — it tolerates a forwarder hiccup, clock skew, or a slow detonation. But it means
any single event falls inside **six consecutive search windows**, and each run wrote another
risk event for it. The risk score for `prush` inflated roughly six-fold.

> Think of a shop counting customers by photographing the floor every 5 minutes and counting
> everyone in shot. Someone who browses for half an hour is counted six times. The camera
> works fine; the counting method is the bug.

This matters more than it sounds. Risk-based alerting is arithmetic layered on detections.
If the arithmetic over-counts, `total_risk >= 60` stops meaning "four real stages happened"
and starts meaning "one stage happened and the scheduler ran a lot."

### Where `_indextime` comes from

It is **built into Splunk** — nothing to enable. Every event carries two timestamps:

| Field | Set by | Means |
|---|---|---|
| `_time` | the parser, from the event text | when the thing happened |
| `_indextime` | the indexer, on receipt | when Splunk first saw it |

`_indextime` is hidden from the field picker but always available in SPL. Because it is
assigned once and never changes, it is the natural answer to "have I already processed this
event?"

### Placement, and the trade-off it creates

In the current build the macro sits **immediately after the base search, before `stats`**:

```spl
index=end-user tag=endpoint tag=filesystem TargetFilename="*.csv" `exclude_noise_accounts(user)`
| `new_events_only`                       /* gate goes here, before aggregation */
| stats dc(file_name) as distinct_csv_files, min(_time) as first_seen by user, dest, file_path
| where distinct_csv_files >= 4
```

That placement guarantees no double counting, which was the bug being fixed. It has a known
cost worth stating plainly rather than hiding:

- **What the 30-minute window still buys:** late-arriving data. An event that happened at
  11:02 but only reached the indexer at 11:20 is still inside `-30m` *and* inside its own
  index-time block, so it is caught.
- **What it no longer buys:** burst-spanning aggregation. A threshold like
  `distinct_csv_files >= 4` only counts files whose events landed in the **same** 5-minute
  index block. A script writing four CSVs over a six-minute span could be split 2 and 2 and
  never trip the threshold.

For this attack chain the staging burst is sub-second, so it does not bite. In a slower
environment the correct fix is to widen the gate to match the expected burst duration
(`-15m@m` to `-10m@m` with the cron at `*/15`), not to remove it. **Keep the overlap, dedupe
on write** — that is the production answer, not "shrink the window until it stops double
counting."

`new_events_only` is **not** used by the two `tstats` rules. Accelerated data model summaries
do not carry `_indextime`, so the macro cannot resolve there; those rules use non-overlapping
lagged windows instead. See `correlation-search.md`.

---

## 3. `exclude_noise_accounts(1)` — drop machine and service accounts

```spl
[exclude_noise_accounts(1)]
args = field
definition = NOT ($field$="UMFD-*" OR $field$="DWM-*" OR $field$="SYSTEM" \
              OR $field$="NETWORK SERVICE" OR $field$="LOCAL SERVICE" \
              OR $field$="ANONYMOUS LOGON" OR $field$="svr_soar" \
              OR $field$="*$" OR $field$="*\\krbtgt")
```

**Why parameterised:** the account field is named differently in each source —
`Account_Name` in 4662, `user` in the Sysmon and CIM-normalised rules. One macro, one
argument, five call sites.

**Why each entry is there:**

| Pattern | What it removes |
|---|---|
| `UMFD-*`, `DWM-*` | Windows font driver host and desktop window manager logon sessions |
| `SYSTEM`, `NETWORK SERVICE`, `LOCAL SERVICE` | built-in service principals |
| `ANONYMOUS LOGON` | null sessions |
| `*$` | **computer accounts** — the single biggest noise source in 4662 |
| `*\krbtgt` | the KDC service account |
| `svr_soar` | **our own SOAR service account** |

That last one is the interesting one. SOAR authenticates to Endpoint-1 over WinRM for every
enrichment and containment action, generating logons and directory reads on a schedule.
Without the exclusion, **the response tooling generates risk against itself** and can
manufacture a kill chain out of its own activity. Any detection pack that also automates
response has to exclude its own service account, or it will eventually investigate itself.

The obvious counter-argument: excluding an account means an attacker who compromises
`svr_soar` becomes invisible to these five rules. That is a real, accepted gap. The
mitigation is a separate detection watching for `svr_soar` doing anything outside its known
action set, which is listed as a follow-up in `docs/lessons-learned.md`.

---

## 4. `soar_export_flatten` — collapse multivalue fields before export

```spl
[soar_export_flatten]
definition = eval \
    tactics    = mvjoin(tactics,    ", "),   /* short atoms, never contain a comma */ \
    dest       = mvjoin(dest,       ", "),   /* hostnames                          */ \
    techniques = mvjoin(techniques, " || "), /* free text - may contain commas     */ \
    reasons    = mvjoin(reasons,    " || "), /* risk messages - definitely do      */ \
    file_path  = mvjoin(file_path,  " || "), /* paths - may contain commas         */ \
    app        = mvjoin(app,        " || ")
```

### What `mvjoin` does

A Splunk multivalue field is a list. `mvjoin(field, delimiter)` concatenates that list into
one ordinary string separated by the delimiter — so downstream, there is no list left to
expand.

### Why two different delimiters

`", "` where values are short atoms that will never contain a comma — tactic names,
hostnames. `" || "` where a value can contain a comma — risk messages, file paths, technique
strings such as `"T1078.002,T1021.001"`. If you comma-join values that themselves contain
commas, the delimiter stops being a delimiter: nothing downstream can split the string back
apart correctly, and the field is quietly corrupted.

### The failure it prevents

The correlation search aggregates with `values()`, which produces genuine multivalue fields.
The **Splunk App for SOAR Export expands multivalue fields into the cartesian product** —
one artifact per value — and does it **per field independently**, destroying the pairing
between fields.

Observed on SOAR container 77:

- one correlation result row produced **five artifacts**
- artifact 172 attributed Collection activity **to the domain controller**, when the staging
  had happened on Endpoint-1

An analyst reading that artifact would have reached a false conclusion about where the attack
occurred. That is worse than a missed alert — it is a confidently wrong one.

**Second-order failure.** A SOAR Format block downstream joined all five artifact values and
produced:

```
risk_object="prush, prush, prush, prush, prush"
```

The resulting `run query` action returned **status: success with zero events**. No error
anywhere. The five duplicate artifacts also opened five simultaneous WinRM sessions, four of
which died with `Connection reset by peer`.

**After the fix:** containers 78 and 79 each arrived with exactly **one** artifact, fields
correctly paired.

### Why it must be the last line

It has to run after `stats` has produced the multivalue fields and after the `where` has
filtered, but before the alert action hands the result to the export app. Anything appended
after it that re-introduces a `values()` call puts the bug straight back.
