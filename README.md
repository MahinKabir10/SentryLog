# SentryLog

A minimal **SIEM** (Security Information and Event Management) tool, built in
phases.

> **Phase 1 (this repo): ingestion & normalization only.**
> SentryLog reads raw logs from different sources and converts every one of them
> into a single, strict, normalized event schema. **There is no detection logic
> yet** — alerting and correlation rules are Phase 2. Phase 1 is the foundation
> everything else stands on: get the normalization right and every future rule
> works across every source for free.

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
│   ├── table.py               # dependency-free terminal table renderer
│   ├── cli.py                 # argparse CLI: `sentrylog ingest ...`
│   └── parsers/
│       ├── __init__.py        # parser registry (SourceType -> parse_file)
│       ├── base.py            # ParseResult / ParseStats / UnparseableLine
│       ├── linux_auth.py      # /var/log/auth.log parser (sshd, sudo)
│       └── windows_evtx.py    # Windows .evtx parser (python-evtx)
├── sample_logs/
│   └── auth.log               # realistic mixed-outcome sample (runs OOTB)
├── tests/
│   └── test_linux_auth.py     # unit + end-to-end tests for the Linux parser
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

## Roadmap

- **Phase 1 — ingestion & normalization** ✅ *(this repo)*
- **Phase 2 — detection** — correlation rules over the normalized stream
  (brute-force, impossible-travel, privilege-escalation chains).
- Later — more sources, persistent storage, alert routing.
