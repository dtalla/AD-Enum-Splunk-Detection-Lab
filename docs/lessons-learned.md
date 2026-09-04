# Lessons Learned

Notes on what didn't fire on the first detonation attempt, configuration fights encountered along the way, and any deviations from the original detection design. This fills in as the project actually runs, not before.

Known open item going in: Endpoint-1 has two NICs and no default gateway on the bridged one, so NLA can't identify the network and the host falls back to the Public firewall profile, which blocks inbound WinRM from SOAR. Needs to be forced to Private. Will document the fix and confirmation once resolved during detonation.

Not yet populated otherwise. See the Status checklist in the repo README for current progress.
