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
@service	zoneminder.service	active/running	enabled	5710660325	0	/lib/systemd/system/zoneminder.service	ZoneMinder	user
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
| `@service` | unit, state, enabled, start (monotonic µs), restarts, path, description, scope |
| `@timer` | timer unit, state, next elapse, description, scope |

`scope` is `user` or `system`: whose service this is, the operator's or the
distribution's. Only the card and the alerting rules care — the detail view
lists both. An agent that cannot tell leaves it empty, which reads as `user`.
| `@unitpkg` | unit, owning package, package version |
| `@container` | name, image, state, status |
| `@repo` | path, branch, commit, describe, commit time |
| `@camera` | id, name, enabled, address, resolution, status, fps, analysis fps, bandwidth, last event, retention days |
| `@camlink` | address of a camera this host has an open RTSP session with |
| `@smart` | device, health, °C, power-on hours, reallocated, pending, wear %, model |
| `@proc` | pid, % of the whole machine, short name, command line |
| `@diskio` | device, operations a second, ms per operation, % of time busy, rotating flag, operations counted, window in ms |
| `@stuck` | pid, short name, command line, kernel call it is stuck in |
| `@netio` | interface, bits/s in, bits/s out, packets/s in, packets/s out, window in seconds |
| `@wgpeer` | interface, peer name, tunnel address, endpoint address, bits/s from the peer, bits/s to it, seconds since the last handshake |
| `@listen` | port, process, scope (`any` or `local`) |
| `@raid` | array, level, state (`UU`, `U_`, …) |
| `@backup` | task, name, last run |
| `@iface` | name, status, rx, tx, comment |

`@proc` answers "who is using the processor" for the `cpu_load_pct` reported in
the same report. The agent samples every process across the same fraction of a
second it measures the total over, so the percentages are shares of the whole
machine and add up under it — they are not the per-core figures `top` prints.
Rows come biggest first, at most four of them, and only when the host is at
least half busy: on an idle machine the question has no answer worth sending.
The command line is flattened to one line, because an argument may contain a
newline and a row that spans two lines is not a row.

`@diskio` is measured from the previous poll, not over the fraction of a second
the processor is measured over: a disk finishes nothing at all in a third of a
second, and "no operations" does not answer "how fast does it answer". The
agent keeps the previous counters in `$TMPDIR/health-zoo-diskstats` and falls
back to the short window on the first poll after a reboot. Latency times rate
gives the average queue depth, which is what separates storage that is slow
from storage that is merely busy with our own work.

`@stuck` rows are sent only while something is actually waiting on storage.
They cost nothing to collect — the process table has already been read twice
for `@proc` — and they are the only evidence of a machine that feels slow with
no processor load at all: a task in uninterruptible sleep uses none.

Two scalars come with them: `io_stall_pct` and `io_stall_full_pct`, the share
of the last ten seconds in which at least one task, or every runnable task, was
waiting for storage. They come from `/proc/pressure/io`, where the kernel keeps
it; iowait answers the same question only on a machine with nothing else to do.

`@netio` and `@wgpeer` are the same idea applied to the wires: a service that
pegs a core is explained by the throughput next to it, and on a tunnel the
question "whose traffic" has an answer the kernel already knows. Both are
measured from the previous poll and both keep the two directions apart — a
tunnel or a proxy carries the same bytes twice, once in each, and adding them
up reports double the traffic.

Peer names come from the `# name` comments in the server config, looked up by
public key. Two traps live in `wg show all dump`: its first line per interface
carries the **private** key, and with AmneziaWG that line is *longer* than a
peer line rather than shorter, so it cannot be told apart by counting fields.
Allowed-ips in the fifth column is what only a peer has.

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
