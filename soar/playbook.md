# SOAR Playbook

Two phases, run in Splunk SOAR against the notable this repo's correlation search generates.

Auto-enrichment (no approval needed): asset lookup on the affected endpoint, a check for whether the account is privileged, the staging-directory listing plus any 4104 script blocks pulled over WinRM, and hashes of any dropped binaries.

Analyst-approval-gated containment: disable the domain account, isolate the endpoint, and kill the PowerShell process. Containment is gated behind human approval rather than automatic, and the writeup will explain why: enumeration alone is common enough (any authenticated user can read most of AD by default) that automatic account lockout on this signal risks disrupting legitimate work.

Not yet populated, pending the correlation search and dashboard this playbook triggers from. See the Status checklist in the repo README for current progress.
