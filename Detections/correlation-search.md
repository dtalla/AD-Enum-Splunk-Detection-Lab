# Correlation Search: AD Enum Kill Chain

The only search in this pack that generates a notable and forwards to SOAR. The five risk
rules never page anyone on their own.

```spl
index=risk sourcetype=risk_event project="famtech-ad-enum"
| eval dest=coalesce(dest, ComputerName) /* rules disagree on the host field name */
| stats sum(risk_score) as total_risk, /* HOW MUCH evidence, severity weighted */
dc(mitre_tactic) as tactic_count, /* HOW BROAD the activity is */
values(mitre_tactic) as tactics,
values(mitre_technique) as techniques,
values(risk_message) as reasons, /* every contributing rule's one line summary */
values(src) as src,
values(dest) as dest,
values(dest_ip) as dest_ip,
values(dest_port) as dest_port,
values(file_path) as file_path,
values(app) as app
by risk_object /* the ACCOUNT is the story's spine */
| where total_risk >= 60 AND tactic_count >= 4 /* BOTH, never either alone, see below */
| eval user=risk_object /* SOAR artifact field naming */
| `soar_export_flatten` /* MUST be last, see macros.md */
```

**Schedule:** cron `*/15`, window `-60m@m` → `now`
**Throttle:** suppress on `risk_object`, 60 minutes
**Alert action:** `sendtophantom`

<img width="1651" height="658" alt="Image" src="https://github.com/user-attachments/assets/3f345dab-59e6-43f2-8ee2-579453737965" />

*The correlation search's alert configuration in Splunk — enabled, cron scheduled, two actions on trigger (add to Triggered Alerts, Send to SOAR), with a recent trigger visible in the history below.*

---

## Why both thresholds, never either alone

`total_risk >= 60` alone measures **volume**. A noisy but benign process accumulates score
over time and eventually crosses any fixed number.

`tactic_count >= 4` alone measures **breadth** but ignores severity. Four low severity,
individually normal signals can technically span four tactics and mean nothing.

Together they encode *kill chain, not coincidence*: the activity was broad enough to cross
four stages of ATT&CK **and** heavy enough that the higher severity stages actually
happened.

## Why key on the account, not the host

`risk_object` is the user. The account is the constant across the whole chain. Prush logs
in, prush's session enumerates, stages, archives and exfiltrates. In this single host lab the
destination is constant too, so either would work here. Identity is the choice that still
works after lateral movement in a real environment, which is the only reason to prefer it.

---

# Correlation timing: what we learned

This was the least obvious part of the build and it cost the most time. The short version:
**a correlation search does not fire when the attack finishes. It fires at the next tick of
a clock it does not share with the attacker.**

## The layers of delay

Six independent waits stack up between the last malicious command and the notable:

| # | Stage | Delay it adds |
|---|---|---|
| 1 | Sysmon writes → UF forwards → indexed | seconds |
| 2 | Risk rule cron `*/5`, the rule has to run | 0 to 5 min |
| 3 | `tstats` rules only look at `-10m@m` → `-5m@m` | +5 to 10 min for those two stages |
| 4 | Risk event written by `collect`, then indexed | seconds |
| 5 | Correlation cron `*/15`, it has to run | 0 to 15 min |
| 6 | Throttle, 60 min on `risk_object` | suppresses repeats, not the first |

Worst case from "last stage of the attack completes" to "notable exists" is roughly
**20 to 30 minutes**, and none of that is a fault. It is the sum of deliberate choices.

### The analogy that makes it click

You need to post a letter that must be signed by four people in four different offices.

- Each office **collects its outbound post every 5 minutes** (the risk rules).
- Two of those offices are cautious: they only process post that has been sitting in the
tray for at least 5 minutes, so nothing gets collected before it is fully written
(the `tstats` lag).
- The **central sorting office opens the bag every 15 minutes** (the correlation search)
and only acts if all four signatures are inside.
- Once it acts, it **ignores further copies of that same letter for an hour**
(the throttle).

The letter is complete the moment the fourth person signs. It still does not move until the
next fifteen minute collection. Nothing is broken. You are just watching a clock that was
never synchronised to the person signing.

### Worked example: why it fired at 11:15 and not before

```
11:02 prush completes the exfiltration stage (the 4th tactic)
11:05 the T1567.002 rule runs, but its lagged tstats window is -10m@m to -5m@m,
so at 11:05 it is looking at 10:55-11:00 - the 11:02 event is not in range yet
11:10 the rule runs again, window is now 11:00-11:05 - the event is in range,
the risk event is written
11:15 the correlation search runs, sees 4 distinct tactics for prush, fires
```
<img width="1722" height="817" alt="Image" src="https://github.com/user-attachments/assets/d586b079-4341-4218-bdb1-3632bb38c83a" />

*The actual risk index events behind this pattern — real timestamps snap to the rules' 5-minute cadence (10:55, 11:00, 11:05), the same staggered-arrival effect the illustrative 11:02→11:15 walkthrough above is modeling.*

Thirteen minutes from the last attacker action to the notable, and every minute of it was a
design decision rather than an accident.

## The choices behind each number

**`*/5` on the risk rules, not `*/1`.** Five searches per rule per hour is cheap; sixty is
not, and the extra resolution buys nothing when the correlation only wakes every 15 minutes
anyway. Matching the rule cadence to the consumer's cadence is the actual rule of thumb.

**A thirty minute window on a five minute cron.** The overlap is deliberate: a forwarder
hiccup, clock skew or a slow detonation would drop an event out of a tight non overlapping
window entirely. The overlap is insurance against missing data, and the price is the
overcounting that `new_events_only` then removes. **Keep the overlap, dedupe on write.** That
is the production answer, not "shrink the window until it stops double counting."

**`*/15` on the correlation, not `*/5`.** The correlation search reads the whole risk index
over 60 minutes and aggregates. Running it every 5 minutes triples the cost to shave an
average of 5 minutes off detection time for an attack whose own recon to exfil gap was
about 30 minutes. The scheduler should be faster than the attacker, not faster than
physics.

**`span`/window of 60 minutes.** Anchored on the real incident: Huntress observed roughly
30 minutes between enumeration and the exfiltration tooling being dropped. Sixty gives
headroom for a slower lab run without being so wide that unrelated risk events hours apart
on a busy service account get swept into one story.

**Throttle 60 minutes on `risk_object`.** Without it, the same kill chain produces a
notable every 15 minutes for the next hour, because the risk events stay inside the
sixty minute window. The throttle key is `risk_object`, not the whole result, so prush
being throttled does not suppress a genuinely new notable for ppitt.

## The three timing bugs I actually hit

**1. Overcounting (fixed by `new_events_only`).** Six overlapping windows meant six risk
events per real event. Symptom: a risk score far larger than the five rules could produce.
The correlation still fired, but the number on the notable was meaningless, and a
meaningless number erodes the threshold that everything else depends on.

**2. `tstats` cannot see `_indextime`.** Accelerated data model summaries do not carry it,
so the dedup macro will not resolve there. Those two rules were given non overlapping
**lagged snapped windows** instead: `earliest=-10m@m`, `latest=-5m@m`. Snapped to the minute
so consecutive runs tile exactly with no gap and no overlap; lagged by 5 minutes so
late arriving data has landed before the window closes over it. The cost is the extra 5 to
10 minutes of detection latency shown in the worked example above. That trade, a few minutes
of latency for correct arithmetic, is worth making every time.

**3. Risk events carried scheduler time, not attack time.** Fixed in `risk_finding` with
`_time=coalesce(first_seen, now())`. Before the fix, the incident timeline was a picture of
the cron schedule. This one is easy to miss because nothing looks broken. The events are
all there, just in the wrong places.

## What to check first when a correlation search "doesn't fire"

In order, because this is the order that finds it fastest:

1. Did the contributing rules actually write to the risk index?
`index=risk sourcetype=risk_event risk_object="<user>" earliest=-2h`
2. Is `tactic_count` really reaching the threshold, or are two rules emitting the **same**
tactic string, so four rules only produce three distinct tactics?
3. Is the correlation window wide enough to still contain the **earliest** risk event by
the time the **latest** one lands?
4. Is the throttle suppressing it because the same `risk_object` fired within the hour?
5. Only then look at the SPL.

Four of those five are timing, not logic. That ratio is the lesson.
