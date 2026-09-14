# NIST SP 800-61 Incident Response Framework: as implemented

This directory is the reusable part of the project. The detections are specific to one attack
chain; the framework is not.

| File | What it is |
|---|---|
| `framework.md` | this file: the 19 tasks, why each exists, and its exit criteria |
| `nist-800-61-workbook.json` | the same thing as a Splunk SOAR workbook template you can import |
| `case-79-report.md` | one real incident walked through all 19 tasks, with the evidence |

## Design decisions

**Five phases, not four.** NIST SP 800-61r2 defines four: Preparation; Detection and
Analysis; Containment, Eradication and Recovery; Post Incident Activity. This implementation
splits the third phase into **Eradicate** and **Recovery**, and folds impact assessment into
an **Analysis and Containment** phase. The reason is practical: containment, eradication and
recovery have different exit criteria and often different owners, and collapsing them into
one phase lets a case be marked "in containment" for days while nobody can say which part is
actually outstanding. Preparation is deliberately absent from the case workbook: preparation
is a program, not a task you complete during an incident.

**Every task requires a closing note.** This is enforced in the template
(`is_note_required: true`). The effect is that a completed workbook *is* the incident record:
there is no separate report to write afterwards from memory, and no task can be ticked
without stating what was actually done. It is the single highest value setting in the whole
template.

**Evidence is attached, not transcribed.** Where a task's conclusion comes from a query or a
command, it is run as a SOAR action against the case so the raw result is attached, and the
note references the action run ID. A note that says "confirmed no other hosts affected" is an
opinion. A note that says "action run 64, one row returned" is evidence.

**Tasks stay open when the work has not happened.** During this incident three tasks sat In
Progress for hours because containment had locked the responder out of the host. Closing them
would have put a false statement in the case record. A workbook is an evidence artifact, not
a progress bar.

---

## Phase 1: Detection

Purpose: establish that something real happened, and what.

| Task | Exit criterion |
|---|---|
| Determine if an incident has occurred | The contributing risk events are named and confirmed to reflect distinct real activity, not a detection artifact. |
| Analyze precursors and indicators | Rules, techniques, accounts, hosts, and true first/last seen recorded. |
| Look for correlating information | At least one supporting source outside the rules themselves. |
| Perform research | The external reference and the specific behavioural match recorded. |
| Confirmed incident | An explicit decision plus the strongest single piece of evidence for it. |

> **Check the plumbing here, not later.** The first task exists partly to catch detection
> artifacts. In this incident, one event arrived as five SOAR artifacts with mismatched
> fields because of multivalue expansion. An analyst who trusted artifact 172 would have
> concluded the staging happened on the domain controller. "Does the artifact count match the
> result rows?" belongs in task 1.

`(add screenshot of the correlation search result and the resulting SOAR artifact count here)`

## Phase 2: Analysis and Containment

Purpose: size the incident, decide priority, and stop it.

| Task | Exit criterion |
|---|---|
| Determine functional impact | None / Low / Medium / High, with the affected systems named. |
| Determine information impact | None / Privacy / Proprietary / Integrity, with the assumption stated when exfiltration cannot be disproved. |
| Determine recoverability effort | Regular / Supplemented / Extended / Not Recoverable, judged against the resources actually available. |
| Prioritize incident | Overall rating plus the reasoning that produced it. |
| Report incident | Who, when, how, and what they were told. |
| Contain incident | Prior state recorded, action taken, and resulting state **independently verified**. |

> **The containment task's exit criterion is the important one.** A SOAR playbook returning
> `success` is a claim about the platform, not evidence about the endpoint. In this incident a
> playbook reported success having done nothing at all, because its approval prompt resolved
> to an empty recipient and every downstream block was skipped. Containment is not complete
> until the host's own state has been read back by something other than the playbook that
> changed it.

## Phase 3: Eradicate

Purpose: remove the attacker's tooling and close what let them in.

| Task | Exit criterion |
|---|---|
| Identify and mitigate all vulnerabilities | Each kill chain stage has a named enabling condition and a mitigation, with fixable vs detectable only stated honestly. |
| Removal of malicious content | Hashes captured **before** removal; artifacts quarantined not deleted; absence verified by a second query; persistence checked. |
| Verify no other hosts are affected | An enterprise sweep attached as evidence, **with its limits stated**. |

> **Hash before you touch, quarantine before you delete.** Deletion destroys the evidence you
> need to reanalyse, and in a real incident belongs after forensic acquisition rather than
> before it. Quarantine takes the artifact off the execution path while keeping it.
>
> **State what your sweep cannot see.** An indicator based sweep does not catch renamed
> binaries, different tooling for the same technique, or hosts with no agent deployed. A scope
> conclusion without its limits is overconfident, and overconfidence about scope is how
> incidents get reopened.

## Phase 4: Recovery

Purpose: return to normal service without reopening the attack path.

| Task | Exit criterion |
|---|---|
| Restore affected systems | Malicious destination blocked **before** host containment is lifted; the recorded pre incident state restored. |
| Validate restoration | Every criterion evidenced by an attached result, including a detection regression test. |
| Implement additional monitoring | Changes made during the incident, plus new detections the incident justified. |

> **Sequence matters.** Identify and block the destination first, then lift host isolation.
> Reversed, you hand the attacker back their egress path for however long it takes to find the
> address.
>
> **Restore the recorded state, not a plausible default.** During this incident the rollback
> reset the firewall's default actions to `NotConfigured`, which *looked* like a restore. The
> original state had the firewall disabled outright, so the host came back with the firewall
> enabled, Windows' default inbound Block, and the WinRM allow rule already removed by the
> cleanup. Still unreachable, now for a different reason. A containment action must record
> the exact prior state it overwrites.
>
> **Regression test the detections.** The response changed firewall rules, accounts and
> possibly agent behaviour. Rerun the simulation and confirm the rules still fire. This is the
> step that gets skipped, and it is the one that tells you whether you still have detection
> coverage tomorrow.

## Phase 5: Post Incident Activity

| Task | Exit criterion |
|---|---|
| Create a follow up report | Summary, timeline, prioritisation, chain, scope, status with open items, what worked and what did not. |
| Lessons learned | One finding per lesson: observation, root cause, adopted change. |

> **Write down the things that reported success while doing nothing.** Those are the findings
> nobody else will discover for you, and they are worth more than the ones that failed loudly.

---

## Importing the workbook

`nist-800-61-workbook.json` is the template structure: phases, ordered tasks, descriptions,
and the note required flag. In Splunk SOAR: **Administration → Response Management →
Workbooks → Add Workbook**, then create the phases and tasks to match, or adapt the JSON to
your platform's import format (field names vary by version, which is why this is published as
a readable structure rather than a version pinned export blob).

Nothing in it is Splunk specific except the mechanics of loading it. The 19 tasks and their
exit criteria apply to any case management tool, or to a text file.
