# Agent report format

An agent is a POSIX shell script streamed to the target over `ssh host sh -s`.
It prints a report to stdout and exits; nothing is installed on the host and
nothing is left behind.

The format is line-based and tab-separated — deliberately not JSON, because the
agents must run under BusyBox with no `jq` and no Python, and quoting JSON by
hand in shell is how you get a parser that breaks on the first quotation mark in
a service description.

## Lines

**Scalar** — `key<TAB>value`:

```
kind	linux
hostname	box
uptime	5736.11
mem_total	8162078720
```

**List entry** — `@kind<TAB>field<TAB>field…`. Fields are positional; their
names live in `LIST_FIELDS` in `collector/probe.py`:

```
@disk	/	/dev/nvme0n1p2	249792131072	154116878336
@service	zoneminder.service	active/running	enabled	5710660325	0	/lib/systemd/system/zoneminder.service	ZoneMinder
```

Trailing fields may be omitted when a value is unavailable; the parser fills
them with empty strings. A short row is normal, not an error.

**Terminator** — every successful report ends with:

```
ok	1
```

The collector treats a report without this line as a failure, which is what
distinguishes "the agent ran and found nothing" from "ssh died halfway through".

## Rules for agents

- **POSIX sh only.** No bashisms, no `jq`, no Python on the target. The same
  script runs on Ubuntu's dash, Synology's BusyBox and OpenWrt's ash.
- **Never print credentials.** Connection strings are reduced to `host:port`
  before they leave the machine (see the ZoneMinder section of `linux.sh`);
  configuration files that hold tokens are read for structure, never echoed.
- **Be cheap.** These run every poll cycle on weak hardware. Batch calls rather
  than forking per unit: an early version shelled out to `systemctl` once per
  service and ran `du` over a video archive, costing 44 seconds per host on a
  Celeron N5105 — the batched version takes under two.
- **Prefer an honest gap to a guess.** Where a fact needs privileges the agent
  does not have (SMART on Synology, the Surveillance Station database), emit
  nothing. A missing section renders as "not reported"; a fabricated one
  renders as a healthy green card.

## Kinds currently emitted

| Kind | Meaning |
|---|---|
| `@disk` | mount, device, total bytes, used bytes |
| `@temp` | sensor label, °C |
| `@update` | package, old version, new version, security flag, suite |
| `@service` | unit, state, enabled, start (monotonic µs), restarts, path, description |
| `@timer` | timer unit, state, next elapse, description |
| `@unitpkg` | unit, owning package, package version |
| `@container` | name, image, state, status |
| `@repo` | path, branch, commit, describe, commit time |
| `@camera` | id, name, enabled, address, resolution, status, fps, analysis fps, bandwidth, last event, retention days |
| `@camlink` | address of a camera this host has an open RTSP session with |
| `@smart` | device, health, °C, power-on hours, reallocated, pending, wear %, model |
| `@listen` | port, process, scope (`any` or `local`) |
| `@raid` | array, level, state (`UU`, `U_`, …) |
| `@backup` | task, name, last run |
| `@iface` | name, status, rx, tx, comment |

Adding a kind means adding one entry to `LIST_FIELDS` and emitting the rows;
nothing else in the pipeline needs to know about it.

## Non-shell agents

RouterOS and Meshtastic do not run a shell for us:

- **RouterOS** is driven by a scripted command list (`ROUTEROS_CMD`) whose
  output is parsed in `probe.py`. Its `print` tables are *not* parsed — flags
  are optional and space-separated, columns align differently per type, and
  values contain spaces. Scripted `:put a."|".b` avoids all of it.
- **Meshtastic** firmware serves `/json/report` over plain HTTP, which is read
  directly. No protobuf, no `meshtastic` package, and it works on nodes that
  are too busy to complete a TCP API handshake.
