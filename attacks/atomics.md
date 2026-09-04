# Detection Validation Commands

Exact Invoke-AtomicTest commands, with timestamps, used to prove the T1087.002 detection fires on behavior rather than on Untitled1.ps1's specific tooling.

Three variants, same technique, different tools:

Variant 1: T1087.002-2, Get-ADUser (mirrors what the script itself does).
Variant 2: T1087.002-1, net user /domain (no RSAT required).
Variant 3: T1087.002-12, ADSISearcher (no RSAT, raw LDAP).

If one behavioral detection rule fires on all three, the rule is keyed on behavior, not on this specific script's fingerprints.

Not yet populated, pending detection validation. See the Status checklist in the repo README for current progress.
