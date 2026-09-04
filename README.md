# famtech-ad-enum-detection

Replicating and detecting the June 2026 Huntress "vibe-coded" Active Directory enumeration incident: attack chain, Splunk ES detections, and SOAR response, built in a home SOC lab.

## Threat summary

In July 2026, Huntress published "Analyzing AI-Augmented Network Enumeration" (Jevon Ang & Dray Agha), detailing an intrusion where an attacker RDP'd into a domain-joined Windows server using pre-compromised credentials, staged tools in C:\ProgramData\, and ran an AI-generated ("vibe-coded") PowerShell script (Untitled1.ps1) to enumerate Active Directory. The script itself only performs enumeration, writing CSVs and an HTML report to C:\AD_Reports_\<datetime\>\ and zipping it, but roughly 30 minutes later the attacker dropped s5cmd.exe (S3 exfiltration) and SharpShares.exe (share enumeration).

This project reproduces that attack chain with real tooling in an isolated lab, builds detections for it in Splunk Enterprise Security, and automates response with Splunk SOAR.

## Planned repo structure

```
famtech-ad-enum-detection/
|-- README.md              # this file
|-- threat-intel/
|   `-- analysis.md        # Huntress incident breakdown, ATT&CK mapping
|-- attacks/
|   |-- detonation-log.md  # timeline: what ran, when, what fired
|   |-- atomics.md         # detection-validation commands
|   `-- Untitled1_LAB.ps1  # sanitized copy of the recovered script
|-- detections/
|   |-- risk-rules/        # one rule per attack stage
|   |-- correlation-search.md
|   `-- validation.md
|-- dashboards/
|   `-- ad-enum-investigation.xml
|-- soar/
|   `-- playbook.md
`-- docs/
    `-- lessons-learned.md
```

## Scope

This repo documents the incident, the detections, and the response, not the lab build. Lab architecture will be summarized here (diagram + component roles) once the detonation is complete; step-by-step build instructions and any real-world network details stay in a private reference and are not published here.

## Attribution

Scenario based on Huntress, "Analyzing AI-Augmented Network Enumeration" (Jevon Ang & Dray Agha, July 2026): https://www.huntress.com/blog/ai-coded-malware-vibe-coding-active-directory

## Status

Building this out incrementally as the project progresses.

- [x] Repo scaffolding
- [ ] Attack chain replica (RDP -> enumeration -> exfil)
- [ ] Detection validation (three T1087.002 tool variants, same behavior different tools)
- [ ] Splunk ES risk-based correlation search
- [ ] Investigation dashboard
- [ ] SOAR playbook
- [ ] Lessons learned
