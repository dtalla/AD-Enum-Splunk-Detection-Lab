# Detection Validation: moved

Validation of T1087.002 across multiple tools, running the same enumeration through **RSAT**,
**`net.exe`**, and **`ADSISearcher`** to prove the Discovery rule keys on behaviour rather
than on tooling, is being carried out as its own project rather than folded in here.

**Why it was split.** Validation is a different argument from detection. This repo answers
*"can this kill chain be detected and responded to?"* Validation answers *"does the rule
survive a change of tool?"* This deserves its own detonations, its own controls, and its own
writeup rather than an appendix.

**What the rule is designed to survive.** The Discovery rule keys on **4662 directory object
reads at the domain controller**, not on PowerShell cmdlet names. Any tool that enumerates
the directory produces those reads:

| Tool | Requires RSAT | Produces 4662 at the DC |
|---|---|---|
| `Get-ADUser` / `Get-ADComputer` / `Get-ADTrust` | yes | yes |
| `net user /domain`, `net group /domain` | no | yes |
| `[adsisearcher]` | no | yes |
| BloodHound / SharpHound | no | yes |

The threshold is `dc(Object_Type) >= 3`: three or more distinct object classes read by the
same account. None of the four tools above can avoid that if they are doing reconnaissance.

**What would falsify the design.** A tool that enumerates AD without generating 4662 events,
for example by reading a replicated copy of the directory, or by using an API path not
covered by Directory Service Access auditing. That is the case the separate project is meant
to test, and it is the honest limit of this detection.

See `methodology.md` for the reasoning, and `Detections/Risk-rules/README.md` for the rule
itself.
