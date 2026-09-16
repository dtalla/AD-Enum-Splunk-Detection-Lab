# Dashboards

Two Classic (Simple XML) dashboards, both live and built on the Splunk Search & Reporting
app. Companion detection logic lives under [`Detections/`](../Detections).

## Why two dashboards instead of one

Scheduled backend content (the risk rules and correlation search under `Detections/`) should
almost always run via `tstats` over accelerated data models for performance at scale. These
two dashboards illustrate that split side by side: one for deep investigative work on a
specific incident, one as the always on operational view.

| | Raw SPL dashboard | Data model dashboard |
|---|---|---|
| Source | `search index=...` directly | `tstats` / `datamodel` over CIM models |
| Scope | One incident / account / host | Whole environment |
| Field names | Per sourcetype (`User` vs `user` vs `Account_Name`) | Uniform CIM names (`user`, `dest`, `process`) |
| Use case | Analyst pivot during an investigation | SOC monitor, standing overview |

## AD Enum Incident: Raw SPL Investigation

Analyst deep dive, scoped to one account/host via `user`/`dest` tokens (default `Prush`, `*`).
Every panel searches `index=us_domain` or `index=end-user` directly, no data model, no
acceleration. Full panel by panel writeup: [`dashboard-raw-spl.md`](./dashboard-raw-spl.md).

<img width="1878" height="917" alt="Image" src="https://github.com/user-attachments/assets/b15ad3ad-7839-4fa3-8212-229f7b91a240" /> <img width="1869" height="882" alt="Image" src="https://github.com/user-attachments/assets/c5ae65f0-009b-4ce8-8724-0092eeff99d0" />

## SOC Overview: Data Model (tstats)

Operational, always on, environment wide. Every panel queries a CIM data model
(`Authentication`, `Endpoint.Filesystem`, plus a plain `index=risk` search standing in for
`Risk.All_Risk` since this is Enterprise, not ES). Full panel by panel writeup:
[`dashboard-datamodel-tstats.md`](./dashboard-datamodel-tstats.md).

<img width="1891" height="918" alt="Image" src="https://github.com/user-attachments/assets/2c5be5c6-3331-4eb6-911e-af09bad03d4c" /><img width="1877" height="832" alt="Image" src="https://github.com/user-attachments/assets/418dcc5f-c22a-4e47-b7a7-edbadb72b457" />

## Status

Both dashboards are built, deployed, and confirmed populating with real data as of Sep 13,
2026. Source XML for both is exported alongside these docs.
