# Detonation Log

Timeline of the incident replica: what ran, when, and what fired in Splunk during detonation.

Not yet populated, pending the lab detonation run. See the Status checklist in the repo README for current progress.

Planned contents once detonation runs:

Act 1: RDP from the Kali attacker box into Endpoint-1 as famtech\Prush.
Act 2: run the sanitized Untitled1_LAB.ps1 (enumeration, CSV staging, HTML report, zip archive).
Act 3: exfiltrate the archive from Endpoint-1 to Kali via s5cmd against a self-hosted MinIO endpoint.

Each act will list exact timestamps, the commands run, and the specific events each one is expected to generate.
