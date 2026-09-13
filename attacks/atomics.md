# Atomic / multi-tool validation commands — moved

The T1087.002 validation commands (RSAT, `net.exe`, `ADSISearcher`) and their Atomic Red Team
equivalents now live in a **separate project**. See `detections/validation.md` for why the
split was made and what the rule is designed to survive.

## Lab hygiene note, kept here because it cost real time

If Atomic Red Team is installed on a host that SOAR also drives over WinRM, check the
machine-wide PowerShell profile:

```
C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1
```

If it prints a banner — `Atomic Red Team loaded. Type 'art-help'.` — that banner is emitted at
the start of **every** PowerShell session, including every WinRM session. Any SOAR connector
action that parses stdout as JSON then fails with:

```
Error parsing output: Expecting value: line 1 column 1 (char 0)
```

Routing to stderr does not help: stderr over WinRM is CLIXML-wrapped. Guard the profile
instead:

```powershell
if ($Host.Name -eq 'ConsoleHost') {
    # banner and Atomic Red Team helpers here
}
```

During this project that banner failed the `list processes` action in both containment runs
and corrupted the first attempt at extracting a SHA256 over WinRM. The real cost was not the
broken action — it was the time spent treating an automation failure as a possible compromise
symptom.
