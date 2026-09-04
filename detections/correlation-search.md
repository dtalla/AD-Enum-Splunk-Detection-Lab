# Risk-Based Correlation Search

The single notable-generating search this detection design is built around: risk score above a threshold AND four or more distinct MITRE tactics for the same risk object within a 60-minute window.

The window is sized to the incident's roughly 30-minute recon-to-exfil gap. Rather than 8 separate alerts, this repo builds about 6 low-severity risk rules (one per attack stage), each writing to the Splunk risk index attributed to the compromised user or endpoint. This search is the one place those risk events get correlated into a single notable.

Not yet populated, pending the individual risk rules this search depends on. See the Status checklist in the repo README for current progress.
