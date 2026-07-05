# SentryLog

A minimal **SIEM** (Security Information and Event Management) tool, built in
phases.

> **Phase 1: ingestion & normalization. Phase 2: detection. Both live here.**
> SentryLog reads raw logs from different sources and converts every one of
> them into a single, strict, normalized event schema (Phase 1), then runs
> detection rules over that normalized stream and emits severity-tiered alerts
> (Phase 2). Because rules only ever see normalized events, one brute-force
> rule fires identically on an SSH attack and an RDP attack — get the
> normalization right and every rule works across every source for free.

---

## Why this design

A SIEM's whole value is **normalization**: a hundred log formats in, one clean
event shape out. So Phase 1 is built around one idea —

```
raw log file ──▶ source-specific parser ──▶ normalized Event ──▶ summary/output
                 (sentrylog/parsers/*)       (sentrylog/event.py)   (sentrylog/cli.py)
```

Every parser emits the **same** `Event` and nothing else. A Phase-2 rule such as
"many failed logins from one IP in 60 seconds" will then fire identically on an
SSH brute force *and* an RDP brute force, because by the time the rule sees the
data, "SSH" and "RDP" have both become `action=login, outcome=failure`.

---

## Project layout

```
SentryLog/
├── sentrylog/
│   ├── __init__.py            # package API (re-exports Event, enums)
│   ├── __main__.py            # enables `python -m sentrylog`
│   ├── event.py               # the normalized Event schema (the contract)
│   ├── detect.py              # --type auto source detection
│   ├── analysis.py            # failed-login extraction, brute-force detection, summaries
│   ├── table.py               # dependency-free terminal table renderer
│   ├── cli.py                 # argparse CLI: `sentrylog ingest ...`
│   ├── parsers/
│   │   ├── __init__.py        # parser registry (SourceType -> parse_file)
│   │   ├── base.py            # ParseResult / ParseStats / UnparseableLine
│   │   ├── linux_auth.py      # /var/log/auth.log parser (sshd, sudo)
│   │   └── windows_evtx.py    # Windows .evtx parser (python-evtx)
│   └── detection/             # Phase 2: the detection layer
│       ├── __init__.py        # rule registry (default_rules factory)
│       ├── alert.py           # Alert dataclass + Severity tiers (the contract)
│       ├── base.py            # Rule interface (analyze(events) -> Alerts)
│       ├── engine.py          # sorts the stream, runs rules, ranks alerts
│       ├── brute_force.py     # sliding-window failed-login bursts per IP
│       ├── privilege_escalation.py  # sudo + Win 4672/4720/4732, tiered
│       └── compromise.py      # failed logins then a success from the same IP
├── sentrylog_mcp.py           # MCP server exposing analysis + detection as tools
├── samples/
│   └── auth.log               # demo sample: every rule fires (all 4 severities)
├── sample_logs/
│   └── auth.log               # realistic mixed-outcome sample (runs OOTB)
├── tests/
│   ├── test_linux_auth.py     # unit + end-to-end tests for the Linux parser
│   └── test_detection.py      # rule unit tests incl. window edges, cross-OS firing
├── requirements.txt
├── pyproject.toml             # installs the `sentrylog` console script
├── .gitignore
└── README.md
```

---

## The normalized event schema

Defined once in [`sentrylog/event.py`](sentrylog/event.py). Every source maps
into this:

| Field         | Type                     | Notes                                                            |
|---------------|--------------------------|------------------------------------------------------------------|
| `timestamp`   | `datetime` (tz-aware UTC)| Strictly enforced — naive datetimes are rejected at construction.|
| `source_type` | `SourceType` enum        | `linux_auth` / `windows_evtx`.                                   |
| `event_id`    | `str` or `None`          | **Source-native** id. Win: `"4625"`. Linux: synthetic mnemonic.  |
| `host`        | `str` or `None`          | Machine the event was seen on.                                   |
| `user`        | `str` or `None`          | The principal the event concerns.                                |
| `source_ip`   | `str` or `None`          | Remote IP for network actions; `None` for local.                 |
| `action`      | `Action` enum            | **Normalized** category: `login`, `privilege_escalation`, …      |
| `outcome`     | `Outcome` enum           | `success` / `failure` / `unknown`.                               |
| `raw`         | `str`                    | The original line/record — kept verbatim for audit.              |
| `metadata`    | `dict`                   | Source-specific extras (auth method, logon type, command, …).    |

**`event_id` vs `action` is the key distinction.** `event_id` preserves what the
source called it; `action` is the cross-platform bucket a rule matches on. They
are intentionally separate.

---

## Install & run

Requires **Python 3.9+**. The core path is **standard-library only** — no
install needed to parse Linux logs.

### Quickest start (no install)

```powershell
# from the SentryLog/ directory
python -m sentrylog ingest sample_logs/auth.log
```

### Install the `sentrylog` command

```powershell
pip install -e .            # core only
pip install -e ".[evtx]"    # + Windows .evtx support (python-evtx)

sentrylog ingest sample_logs/auth.log
```

### Usage

```
sentrylog ingest <path> [--type auto|linux_auth|windows_evtx] [--show N] [-v]

  path            log file to ingest (.log/.txt for Linux, .evtx for Windows)
  --type          source type; 'auto' (default) detects by extension + content
  --show N        also print the first N normalized events
  -v, --verbose   show DEBUG (skipped lines) and WARNING (unparseable lines)
```

### Example

```powershell
python -m sentrylog ingest sample_logs/auth.log --show 4
```

produces a summary table of counts by source type × outcome, a breakdown by
action, the parsed/skipped/error stats, and (with `--show`) a peek at the
normalized events themselves.

---

## Parsers

### Linux `auth.log` (`sentrylog/parsers/linux_auth.py`)

Handles the auth events that matter most:

- **SSH accepted** (`password`, `publickey`, …) → `login` / `success`
- **SSH failed** (incl. `invalid user`) → `login` / `failure`
- **SSH invalid user** notices → `login` / `failure` (`ssh_invalid_user`)
- **sudo** success (command run) → `privilege_escalation` / `success`
- **sudo** failure (`user NOT in sudoers`, bad password) → `privilege_escalation` / `failure`

It parses in two layers: a **syslog skeleton** regex (timestamp/host/program)
then **program-specific** regexes with named groups. Lines that don't match the
skeleton are logged as warnings and skipped — **the parser never crashes on bad
input**. Lines that are valid syslog but from programs we don't model (CRON,
systemd) are silently skipped (visible with `-v`).

> **Timestamp caveat (worth knowing):** classic syslog timestamps carry no year
> and no timezone. SentryLog assumes UTC and the current year, with a guard that
> rolls back a year if the date would otherwise be in the future. The assumption
> is explicit and isolated in one method.

### Windows `.evtx` (`sentrylog/parsers/windows_evtx.py`)

Uses [`python-evtx`](https://pypi.org/project/python-evtx/) to read the binary
EVTX format, renders each record to XML, and maps four core security IDs:

| Event ID | Meaning                       | action                 | outcome   |
|----------|-------------------------------|------------------------|-----------|
| 4624     | An account logged on          | `login`                | `success` |
| 4625     | An account failed to log on   | `login`                | `failure` |
| 4672     | Special privileges assigned   | `privilege_escalation` | `success` |
| 4688     | A new process was created     | `process_creation`     | `unknown` |

It extracts user, source IP, and logon type (mapping e.g. type `10` →
`RemoteInteractive`/RDP) from the event XML. The `python-evtx` import is **lazy**
— you only need the package installed if you actually ingest a `.evtx` file.

**Trying the Windows parser:** there's no `.evtx` in the repo (they're binary).
On a Windows host you can copy one out and ingest it:

```powershell
pip install -e ".[evtx]"
Copy-Item C:\Windows\System32\winevt\Logs\Security.evtx .\sample.evtx
python -m sentrylog ingest .\sample.evtx
```

(Reading the live `Security.evtx` in place needs admin; copying it first avoids
a sharing-violation.)

---

## Tests

```powershell
pytest tests/                       # if pytest is installed
python tests/test_linux_auth.py     # zero-dependency fallback runner
```

The suite covers each Linux pattern (accepted/failed/invalid-user/sudo), the
strict tz-aware timestamp guarantee, graceful handling of malformed lines, and
an end-to-end count check against the shipped sample.

---

## Detection (Phase 2)

Detection runs **only** on normalized `Event` objects — never raw logs. The
engine ([`detection/engine.py`](sentrylog/detection/engine.py)) sorts the
stream once and fans it out to rules; each rule is a single-pass state machine
implementing `analyze(events) -> Iterator[Alert]`. Adding a rule is one module
plus one line in `default_rules()` ([`detection/__init__.py`](sentrylog/detection/__init__.py))
— the engine, CLI, and MCP server never change.

### The rules

| Rule | Fires on | Severity |
|------|----------|----------|
| `brute_force` | ≥ X failed logins from one IP in a Y-second **sliding** window (default 5 in 60s). One alert **per burst**, not per event. | medium; **high** on ≥3× volume or a multi-user spray |
| `privilege_escalation` | sudo failures/successes, Win 4672 / 4720 / 4732 | failed sudo & 4720: **medium**; 4732 into an admin-equivalent group: **high**; routine sudo/4672 successes: **low**, aggregated per user+host |
| `compromise` | ≥ N failed logins from an IP followed by a **success** from that same IP within a window (default 3 in 600s) | **critical** — the attack worked |

Design notes worth reading in the module docstrings: why the window slides
instead of tumbling, why the boundary is inclusive, why bursts emit one alert
(alert fatigue), why routine elevation aggregates to a single low-severity
audit entry instead of paging, and why only realized compromise earns
`critical`.

Every alert carries `rule_name`, `severity`, `timestamp`, `source_ip`, `user`,
`description`, and the full `matched_events` evidence chain (each event still
holding its raw log line — the pivot back to ground truth is never lost).

### Run it

```powershell
python -m sentrylog detect samples/auth.log --show-events
```

The shipped sample trips **all four severity tiers**: a critical compromise
(192.0.2.146 fails three times then gets in), a high password spray
(45.155.205.233, 12 failures across 5 users), a medium sudo denial (`intern`),
and a low audit trail (`deploy`'s sudo).

Multiple files — even mixed OSes — merge into one chronological stream, so a
single rule correlates across sources:

```powershell
python -m sentrylog detect auth.log security.evtx
```

Tunables: `--bf-threshold/--bf-window` (brute force), `--cf-min-failures/--cf-window`
(compromise), `--min-severity` to filter output, `--show-events` for evidence.

---

## MCP Server

SentryLog also ships as an **MCP server** — a bridge that lets an AI assistant
(e.g. Claude Desktop) call SentryLog's log-analysis functions as tools, so you
can investigate an `auth.log` conversationally ("who's brute-forcing this box?").

The server is [`sentrylog_mcp.py`](sentrylog_mcp.py) in the repo root and
builds on [`sentrylog/analysis.py`](sentrylog/analysis.py). All tools are
**read-only** (declared via `readOnlyHint` annotations) and validate inputs
with Pydantic.

### Tools

All tools accept Linux `auth.log` **or** Windows `.evtx` paths (format is
sniffed; EVTX needs `pip install python-evtx`).

| Tool | Arguments | What it returns |
|------|-----------|-----------------|
| `list_failed_logins` | `log_path`, `limit` (default 20) | Failed login attempts (incl. `Invalid user` notices) with timestamp, user, source IP, port, and raw line. |
| `summarize_log` | `log_path` | Top source IPs, top targeted users (by *failed* logins), event counts by action/outcome, time range, parse stats. |
| `detect_bruteforce` | `log_path`, `threshold` (5), `window_seconds` (60) | Sliding-window brute-force alerts, one per burst, with severity and the evidence chain. |
| `detect_privesc` | `log_path` | Privilege-escalation alerts: sudo denials, account creation (4720), privileged-group additions (4732), aggregated routine elevation. |
| `list_alerts` | `log_path`, `min_severity` (`low`) | Runs **all** rules (incl. the critical failed-then-success compromise rule); triage-ordered alerts plus counts per severity. |

Every response includes the parse statistics, and errors are actionable — a
missing file reports the exact path that was tried and points at the shipped
sample (`samples/auth.log`).

### Install

```powershell
pip install "mcp[cli]"
```

That's the only dependency — the analysis itself is standard-library only.

### Try it without a client

```powershell
# from the SentryLog/ directory
python -c "from sentrylog_mcp import summarize_log; import json; print(json.dumps(summarize_log(r'samples\auth.log'), indent=2))"
```

### Connect it to Claude Desktop

Add the server to `claude_desktop_config.json`
(**Settings → Developer → Edit Config**, or directly at
`%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "sentrylog": {
      "command": "python",
      "args": ["C:\\Cyber Security Projects\\SentryLog\\sentrylog_mcp.py"]
    }
  }
}
```

If `python` isn't on Claude Desktop's PATH, use the full interpreter path as
`command` (find yours with `(Get-Command python).Source` in PowerShell).
Restart Claude Desktop and the three tools appear under the **sentrylog**
server. Ask something like:

> *Summarize C:\Cyber Security Projects\SentryLog\samples\auth.log — any brute-force activity?*

---

## Roadmap

- **Phase 1 — ingestion & normalization** ✅
- **Phase 2 — detection** ✅ — rule engine + brute-force, privilege-escalation,
  and compromise rules over the normalized stream, with severity-tiered alerts
  (`sentrylog detect`, MCP tools).
- Later — more rules (impossible travel, beaconing), more sources, persistent
  storage, alert routing.
