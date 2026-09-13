# SOAR Playbooks

Two playbooks. One runs automatically and only reads; the other runs manually, changes the
host, and cannot proceed without a human. That split is the whole design.

| | `AD_Enum_Enrichment` | `AD_Enum_Isolate_Endpoint_With_Prompt` |
|---|---|---|
| Trigger | **Artifact created** (automatic) | manual |
| Category | Investigation | Containment |
| Effect on the host | read-only | changes firewall state |
| Human in the loop | no | **yes — blocking prompt** |

---

## 1. `AD_Enum_Enrichment`

```
Start → run query (splunk-es) → list sessions (endpoint-1) → run script (endpoint-1)
      → file reputation (virustotal) → End
```

Fires the moment the correlation search's artifact lands, so by the time an analyst opens the
event the enrichment is already attached.

### The Splunk query block

```spl
index=risk sourcetype=risk_event project="famtech-ad-enum" risk_object="{0}" earliest=-24h
| stats sum(risk_score) as risk_score, count as events, values(risk_message) as reasons,
        min(_time) as first_seen, max(_time) as last_seen
    by mitre_tactic, mitre_technique
| sort - risk_score
| appendcols
    [ search index=end-user EventCode=1 Image="C:\\ProgramData\\s5cmd.exe" earliest=-24h
      | rex field=Hashes "SHA256=(?<sha256>[A-F0-9]+)"
      | stats latest(sha256) as sha256 ]
| eventstats values(sha256) as sha256
```

`{0}` is substituted with `artifact:*.cef.destinationUserName`.

**Why the hash comes from Splunk and not from the endpoint.** The original design pulled
`s5cmd.exe` over WinRM with the `get file` action, hashed it, and submitted the hash. It
failed:

```
Read timed out (read timeout=30)
```

An 18 MB binary base64-encoded over WinRM does not finish in 30 seconds, and the WinRM app
exposes no configurable timeout — there was nothing to raise. But Sysmon Event 1 already
records the SHA256 at execution time, and that data is already indexed. Sourcing it from the
telemetry pipeline is faster, puts no load on a possibly-compromised host, and — as this
incident proved — **still works when the host is unreachable**.

> ### Gotcha: `phantom.format()` and regex quantifiers
> The regex originally read `SHA256=(?<sha256>[A-F0-9]{64})` and the action failed with:
> ```
> IndexError: Replacement index 64 out of range
> ```
> SOAR Format-mode fields are Python `str.format()` templates, where `{0}` is the first
> datapath. Python parsed `{64}` as a format placeholder and went looking for a 65th argument.
> Fixed by using `[A-F0-9]+`. **Any regex containing a `{n}` quantifier will break the same
> way inside a SOAR format field.**

### The reputation block

`file_reputation_1` takes its hash from the datapath
`run_query_1:action_result.action_result.data.*.sha256` — the output of one block feeding the
input of the next, which is the entire point of a playbook rather than five separate actions.

---

## 2. `AD_Enum_Isolate_Endpoint_With_Prompt`

```
Start → list processes → list connections → prompt_1 → analyst_approved_isolation
      → run script → End
```

### The Python, block by block

SOAR's visual editor generates Python. Reading it is how you find out what the boxes actually
do.

**`on_start` — the entry point.** Every playbook has one. It receives the `container` (the
event or case) and kicks off the first blocks. Think of it as `main()`.

**`phantom.collect2(...)` — pull values out of the container.**

```python
container_data = phantom.collect2(
    container=container,
    datapath=["artifact:*.cef.destinationAddress", "artifact:*.id"]
)
```

`collect2` walks the container's artifacts and returns the values at the datapaths you asked
for, as a list of `[value, artifact_id]` pairs. It is the playbook equivalent of *"go and look
in the case file for the host address."* The `*` means "every artifact" — which is exactly why
the multivalue artifact explosion mattered so much: five duplicate artifacts meant `collect2`
returned five hosts and every downstream action ran five times.

**`phantom.act(...)` — run a connector action.**

```python
phantom.act("run script",
            parameters=parameters,
            assets=["endpoint-1"],
            callback=next_block_name,
            name="run_script_1")
```

`act` is asynchronous. It hands the action to the connector and returns immediately; the
`callback` is the function SOAR calls when the result comes back. Like posting a letter with
a return address rather than waiting at the counter — which is why a broken block does not
raise an exception, it just never calls back.

**`phantom.prompt2(...)` — block until a human answers.**

```python
user = phantom.collect2(container=container,
                        datapath=["playbook:launching_user.name"])[0][0]
phantom.prompt2(container=container,
                user=user,
                role=None,
                message="Isolate Endpoint-1? This will block all traffic except WinRM and Splunk UF.",
                respond_in_mins=30,
                name="prompt_1",
                callback=analyst_approved_isolation)
```

This is the human gate. Nothing downstream executes until someone answers or the 30-minute
timer expires.

> ### The silent failure — the most important finding in the project
> The recipient was originally set to **Event owner**. The case had no owner assigned when the
> playbook launched, so `user` resolved to an empty string. The debug log said:
> ```
> phantom.act() 'prompt_1' has an invalid 'to' parameter value.
> User or role is not specified or has evaluated to empty string.
> callback 'analyst_approved_isolation' will not be called
> ```
> The prompt was dropped, the callback never fired, every downstream block was skipped — and
> **the playbook run still closed with status `success`.**
>
> Fixed by changing the recipient to **Playbook run owner**, which resolves to
> `playbook:launching_user.name` — whoever pressed the button, which is by definition someone
> who exists and is present.
>
> The observable difference after the fix: run 13 entered status `running` and stayed there
> until answered. Run 12 had returned `success` instantly. **An instant success on a playbook
> containing a human prompt is the tell.**

**`phantom.decision(...)` — branch on the answer.**

```python
phantom.decision(container=container,
                 conditions=[["prompt_1:action_result.summary.responses.0", "==", "Yes"]],
                 name="analyst_approved_isolation")
```

`responses.0` is the first answer to the first question in the prompt. Only the `Yes` branch
reaches the `run script` block.

### The isolation script

```powershell
New-NetFirewallRule -DisplayName Allow-WinRM-Inbound   -Direction Inbound  -LocalPort 5985  -Protocol TCP -Action Allow;
New-NetFirewallRule -DisplayName Allow-WinRM-Outbound  -Direction Outbound -RemotePort 5985 -Protocol TCP -Action Allow;
New-NetFirewallRule -DisplayName Allow-SplunkUF-Outbound -Direction Outbound -RemoteAddress 10.0.0.225 -RemotePort 9997 -Protocol TCP -Action Allow;
Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block
```

**Allow rules are created before the default-deny is applied.** Reverse the order and the
command that creates the allow rules is itself cut off mid-execution.

**The Splunk UF exception is not optional.** The first version blocked all outbound including
the forwarder, which would have blinded detection on the contained host at exactly the moment
visibility matters most. With it in place the host kept shipping 32,009 events in the
following 30 minutes — and that telemetry is the only reason the lockout described below could
be root-caused.

**What is still missing from this playbook.** It has no post-isolation reachability probe. It
should end with a read-only action against the host whose failure raises its own alert,
because this containment severed the responder's own access and nothing noticed for ten
minutes. See `docs/lessons-learned.md`.

---

## Reading action results

Every SOAR action result has four sections, and the UI shows the least useful one by default:

| Section | Contains |
|---|---|
| `parameter` | the **request** — what you asked for, including `script_str` and `ip_hostname` |
| `data[]` | the **response** — `std_out`, `std_err`, `status_code` |
| `summary` | a connector-computed rollup |
| `status` / `message` | success/failure and the human-readable reason |

Command output lives in `data[].std_out`. The action card shows `summary`, which is why a
`Get-Acl` result can look empty when it is not.

**Why `ip_hostname` appears on every action:** it is a required parameter of the WinRM app
itself, not of your command. Every action has to say which host to open a session against, so
the connector injects it into `parameter` on every call.

## Asset configuration

| Field | Value | Note |
|---|---|---|
| Asset | `endpoint-1` | WinRM app |
| Endpoint | `10.0.0.102` | |
| Transport | `ntlm` | |
| Domain | `famtech` | |
| Username | `svr_soar` | **a domain account — this is the lockout root cause** |
| Verify server cert | false | lab only; use 5986 + a CA-issued cert in production |

The recommended change is a **local** break-glass administrator per host instead of a domain
account, so authentication is validated by the host's own SAM and survives full isolation.
