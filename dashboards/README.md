# Dashboards

Two Classic (Simple XML) dashboards, both live and built on the Splunk Search & Reporting app, owner `dorian`. Companion detection logic lives under [`detections/`](../detections).

## Why two dashboards instead of one

Scheduled backend content (the risk rules and correlation search under `detections/`) should almost always run via `tstats` over accelerated data models for performance at scale. These two dashboards illustrate that split side by side: one for deep investigative work on a specific incident, one as the always-on operational view.

| | Raw SPL dashboard | Data model dashboard |
|---|---|---|
| Source | `search index=...` directly | `tstats` / `datamodel` over CIM models |
| Scope | One incident / account / host | Whole environment |
| Field names | Per-sourcetype (`User` vs `user` vs `Account_Name`) | Uniform CIM names (`user`, `dest`, `process`) |
| Use case | Analyst pivot during an investigation | SOC monitor, standing overview |

## AD Enum Incident - Raw SPL Investigation

Analyst deep-dive, scoped to one account/host via `user`/`dest` tokens (default `Prush`, `*`). Every panel searches `index=us_domain` or `index=end-user` directly - no data model, no acceleration. Full panel-by-panel writeup: [`dashboard-raw-spl.md`](./dashboard-raw-spl.md).

## SOC Overview - Data Model (tstats)

Operational, always-on, environment-wide. Every panel queries a CIM data model (`Authentication`, `Endpoint.Filesystem`, plus a plain `index=risk` search standing in for `Risk.All_Risk` since this is Enterprise, not ES). Full panel-by-panel writeup: [`dashboard-datamodel-tstats.md`](./dashboard-datamodel-tstats.md).

## Status

Both dashboards are built, deployed, and confirmed populating with real data as of Sep 13, 2026. Source XML for both is exported alongside these docs.
