# Lessons Learned

Ten findings, ordered by how much they changed the way the pack is built. Each has the
observation, the root cause, and the change adopted.

The theme, stated up front: **the detections were the easy part.** The rules fired, correlated
and escalated correctly on the first real detonation. Almost everything that actually went
wrong was in the plumbing around them — and four separate components reported success while
doing nothing.

---

## 1. "Success" from an automation platform is a claim, not evidence

**Observed.** Containment playbook run 12 completed with status `success`. The endpoint's
firewall was untouched.

**Root cause.** The approval prompt's recipient was set to *Event owner*; the case had no
owner at launch, so the recipient evaluated to an empty string. `phantom.act()` rejected the
prompt, the callback never fired, every downstream block was skipped — and the run still
closed green. The rejection appears only in the debug log, never in the run status.

**Change.** Verify containment against the endpoint's own state, read back by something other
than the playbook that changed it. Every isolation playbook ends with a verification action
whose failure raises its own alert. And treat an *instant* success on a playbook containing a
human prompt as a red flag — a prompt that was actually delivered leaves the run in `running`.

## 2. Containment that ignores the responder's access path will remove it

**Observed.** Ten minutes after successful isolation, every SOAR action against the host
failed — first `credentials rejected`, then read timeouts.

**Root cause.** The SOAR asset authenticates as `famtech\svr_soar` over NTLM. NTLM
pass-through requires the member host to reach a domain controller; the lockdown blocked all
outbound except WinRM and the forwarder. Windows Event **5719** (NETLOGON secure channel lost)
and two Event **4625**s — one per failed action — confirmed it.

**Change.** Response tooling must not depend on infrastructure that containment cuts off. Use
a **local** break-glass account on managed hosts, validated by the host's own SAM.

The tempting alternative — permanently allowing outbound to the DC — is wrong *for this threat
model*, because LDAP enumeration of that DC is the incident. Containment that restores the
attacker's primary objective is not containment.

## 3. Keep telemetry alive through containment, deliberately

**Observed.** With all outbound blocked except an explicit forwarder exception, the isolated
host still delivered 32,009 events in 30 minutes.

**Why it mattered.** Events 5719 and 4625 — the entire root cause of finding 2 — arrived
through that exception. Without it the host would have gone silent at the same moment it
became unreachable, and the diagnosis would have been guesswork.

**Change.** Telemetry egress is a standing exception in every isolation action, and loss of
forwarder heartbeat is itself an alert. **An isolated host that goes silent is not contained,
it is unobservable.**

## 4. Lifting containment is not the same as restoring the prior state

**Observed.** After the documented rollback, the host was still unreachable — but with a
*different* error: a read timeout instead of a credential rejection.

**Root cause.** The pre-incident state had the firewall **disabled**, not merely permissive.
`Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured` left the firewall *enabled*
with Windows' own default inbound Block, while the cleanup had already removed the
`Allow-WinRM-Inbound` rule the containment added. Nothing was listening on 5985.

**Change.** A containment action must record the exact prior state it overwrites, and the
rollback must restore *that recorded state*, not a plausible-looking default. "Set it back to
normal" is not a rollback if nobody wrote down what normal was.

The changed error message was the only clue, which is a small lesson of its own: when a
failure persists but its *symptom* changes, the cause has changed too.

## 5. Identify and block the destination before lifting host isolation

**Observed.** The exfiltration target — `10.0.0.134:9000`, reached by `s5cmd.exe`, 84
connections — was recovered from Sysmon Event 3 and blocked at the perimeter before host
containment came off.

**Why the order matters.** Reversed, host isolation lifts first and the attacker's egress path
is live again for however long it takes to find the address.

**Change.** Destination containment precedes host restoration in the workbook's Recovery
phase, as an explicit exit criterion.

## 6. Detection plumbing fails silently by default

Three separate instances, none of which raised an error:

- **Multivalue expansion.** `values()` produced multivalue fields; the SOAR export app expands
  them into the cartesian product, per field independently. One result row became five
  artifacts with mismatched attributions — artifact 172 placed Collection activity on the
  domain controller when it happened on Endpoint-1. **A confidently wrong artifact is worse
  than a missing one.**
- **Format-block collapse.** Five artifact values were joined into
  `risk_object="prush, prush, prush, prush, prush"`. The resulting Splunk query returned
  **success with zero events.**
- **Duplicate sessions.** The same five artifacts opened five simultaneous WinRM sessions;
  four died with `Connection reset by peer`.

**Change.** Flatten multivalue fields before export (`soar_export_flatten`). Treat a
zero-result enrichment as a condition to surface, not a quiet pass. And put "does the artifact
count match the result rows?" in the first task of the Detection phase.

## 7. Overlapping search windows inflate risk scores

**Observed.** A risk score far larger than the five rules could produce.

**Root cause.** Rules on a 5-minute cron over a 30-minute window: every event fell inside six
consecutive windows and was scored six times.

**Change.** Gate raw-event rules on `_indextime` (`new_events_only`); use non-overlapping
lagged snapped windows for `tstats` rules, which cannot see `_indextime`. Stamp risk events
with the attack time, not the scheduler time.

**Keep the overlap, dedupe on write.** The wide window exists to tolerate late data; shrinking
it until the double counting stops trades a visible bug for an invisible one. Risk-based
alerting is arithmetic layered on detections — if the arithmetic over-counts, every threshold
built on it is meaningless.

## 8. Environment hygiene breaks tooling in ways that look like security findings

**Observed.** The SOAR `list processes` action fails on Endpoint-1 with
`Error parsing output: Expecting value: line 1 column 1 (char 0)`.

**Root cause.** `C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1` prints
`Atomic Red Team loaded. Type 'art-help'.` at the start of every PowerShell session, including
every WinRM session. The connector expects JSON on stdout; the banner arrives first. Routing to
stderr does not help — stderr over WinRM is CLIXML-wrapped. The same banner corrupted the
original SHA256 extraction.

**Change.** Guard machine-wide profiles: `if ($Host.Name -eq 'ConsoleHost') { ... }`. The real
cost was not the broken action — it was the time spent treating an automation failure as a
possible compromise symptom.

## 9. An untested detection is not a detection

**Observed.** The Archive Creation rule (T1560.001) has never fired, despite archive creation
in every detonation.

**Why it survived unnoticed.** A second rule covers the same tactic (Collection), so the
correlation still reached four distinct tactics. **Redundancy masked the gap** — which is
precisely how a dead rule sits in a pack for months while appearing to provide coverage.

**Change.** A rule counts toward coverage only after a proven firing. Until then it is tracked
as a gap, in writing. The leading hypothesis here is a Sysmon FileCreate filter excluding
archive extensions — a telemetry gap, not an SPL bug, and it would never have been found by
reading the rule.

## 10. Prompt gates worked, and should stay

No destructive change reached the host without a person answering. That is the control that
makes automated containment acceptable at all, and it cost roughly one minute of wall-clock
time.

Worth stating because the instinct after finding 1 is to distrust the prompt mechanism. The
prompt was not the failure — its *recipient resolution* was. The gate itself did exactly what
it was built to do.

---

## Two things worth saying about the detections themselves

**Behaviour over tooling held up.** Keying the Discovery rule on 4662 directory-object reads
at the DC rather than on PowerShell cmdlet names is the design decision the whole project
rests on, and it survived both detonations. The tool was a one-off AI-generated script; the
LDAP reads are what the attacker could not avoid.

**Risk-based alerting earned its complexity.** Five stages produced one investigation instead
of five alerts. The overhead — a risk index, a shared macro contract, a correlation search, a
timing model — is only worth it at that threshold. For a single high-confidence detection it
would be over-engineering.
