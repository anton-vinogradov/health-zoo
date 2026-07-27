# Specification

A living document: it states what health-zoo is meant to do and why it is built
this way, and it is updated together with the code. A requirement that is not
here is not implemented — or is implemented and forgotten, which is worse.
Русская версия: [SPEC.ru.md](SPEC.ru.md).

## 1. Why

A fleet of ~26 devices: servers, routers, NAS units, cameras, access points,
Meshtastic nodes, speakers, two Raspberry Pis. Their state can only be learned
by logging into each one in turn — which means a failure is discovered when it
is already in the way.

The dashboard answers three questions, in this order:

1. What is broken right now?
2. What is not broken yet but heading there?
3. Which of that is already known and accepted, and which is news?

Everything else is subordinate to those three.

## 2. Scope

**In.** Polling state, health rules, history and trends, alerting, actions on
hosts (package updates, reboots, restarting and removing services), suppressing
findings, editing thresholds.

**Out.** High-resolution metrics (that is Prometheus), logs (journald, Loki),
configuration management (Ansible), inventory as an end in itself. health-zoo
looks, and acts where asked — it does not store per-second time series and does
not describe a desired state of systems.

## 3. Invariants

Rules that must not be broken. Each was paid for with a mistake.

1. **Nothing is installed on the targets.** Agents are POSIX sh scripts streamed
   through `ssh host sh -s` and executed in memory. The fleet has no single OS,
   and an installed agent is one more thing that breaks and needs upgrading.
2. **All rules live on the server.** The banner, the card colours and the
   Telegram alerts read one list of findings. When the rules lived in the
   browser, the alerting layer would have had to re-implement every threshold,
   and the two copies would drift the first time one was tuned.
3. **No host whitelists.** A newly installed service appears on the dashboard by
   itself. Lists in the code are allowed for classification (whose service is
   this) and never for hiding anything.
4. **Whatever the card shows, the detail view explains.** Every chip, badge and
   bar has a full explanation behind it. A glyph with no explanation is a riddle,
   not a signal.
5. **A check either runs or says plainly that it did not.** The Checks tab lists
   everything watched on that host, including what was skipped and why. A
   dashboard that shows only findings leaves "is this fine, or simply not
   watched?" unanswered.
6. **There is exactly one way to accept a known state: a suppression with a
   reason.** No config flag quietly demotes a finding. The reason is mandatory,
   the expiry optional, and suppressions are reviewed fleet-wide.
7. **Secrets are never stored in the clear.** Passwords and tokens go through
   systemd-creds (`LoadCredentialEncrypted`) or a 600 file; the config holds a
   reference, not a value. The public repository contains no real address.
8. **An action reports its own outcome.** An update names what it could not
   install; a reboot waits for the host to come back; after any action the host
   is re-polled immediately rather than at the next cycle.
9. **Python standard library only.** No venv, no pip on the target machine.
10. **Bilingual docs, English code.** README and SPEC exist in both languages;
    commits and comments are English, the interface is Russian.

## 4. Requirements

Marked: **✓** done, **▶** in progress, **○** deliberately not done.

### 4.1 Polling and inventory

| | Requirement |
|---|---|
| ✓ | Poll every device over SSH with no agent installed |
| ✓ | Support Ubuntu/Debian, Synology DSM, OpenWrt, RouterOS, Meshtastic, UniFi, Sonos, cameras |
| ✓ | Draw the topology by subnet, mirroring the real uplinks |
| ✓ | Group devices by type within a subnet |
| ✓ | Discover services automatically, with nothing declared in the config |
| ✓ | Separate the operator's services from the distribution's; the card counts only the former |
| ✓ | Find unmanaged devices from DHCP leases |
| ✓ | Poll hosts reachable only through another site (`probe_via`) |
| ✓ | List every web resource of a host, linked by domain name; loopback marked, not hidden |
| ✓ | Report what RouterOS has open (`/ip service` plus socks/UPnP/RoMON/bandwidth-test) |

### 4.2 Checks

| | Requirement |
|---|---|
| ✓ | Disks, memory, swap, temperature, load — thresholds per role |
| ✓ | SMART and RAID state where available |
| ✓ | Failed and not-running services; base-OS units weigh less |
| ✓ | Docker containers |
| ✓ | Pending updates; security updates are a problem, not a note |
| ✓ | Reboot required — naming what is waiting for it |
| ✓ | Backups: freshness, share coverage, hosts with no backup at all |
| ✓ | Cameras: stream state, silent detection, archive depth |
| ✓ | Wi-Fi: radios on air, airtime (own and foreign), channel choice, per-SSID quality |
| ✓ | TLS certificate expiry |
| ✓ | Reachability from outside (measured from an external host) |
| ✓ | Port forwards that lead nowhere; IPsec policies that never came up |
| ✓ | Packages nothing depends on any more (autoremove candidates) |
| ✓ | Auto power-on after a power cut (declared by the operator) |
| ○ | Verifying backups by restoring them — needs access this tool does not hold |

### 4.3 Actions

| | Requirement |
|---|---|
| ✓ | Update packages on one host and on the whole fleet |
| ✓ | The host running the dashboard updates last |
| ✓ | Hosts update in parallel, a tab each, with a highlighted log |
| ✓ | Updates go all the way (`--with-new-pkgs`); what is left is named |
| ✓ | Reboot any kind of device, cameras and mesh nodes included |
| ✓ | A reboot waits for the host to return and says how long it was gone |
| ✓ | Restart and remove a service from the interface |
| ✓ | Automatic reboots when required — within a window, with exclusions, off by default |
| ✓ | Automatic cleanup of orphaned packages as part of an update, on by default |

### 4.4 Interface

| | Requirement |
|---|---|
| ✓ | One banner for the fleet, coloured by the worst finding |
| ✓ | "Problems only" filter and search |
| ✓ | Explicit stale-snapshot status |
| ✓ | Second tab in the detail view: every check, by category |
| ✓ | Suppressions: mandatory reason, fleet-wide list for review |
| ✓ | Settings: thresholds, per-camera thresholds, automatic reboots |
| ✓ | Mobile layout |
| ✓ | Dark and light themes |

### 4.5 Alerting

| | Requirement |
|---|---|
| ✓ | Telegram; a message only when something changed |
| ✓ | One digest a day while a problem stands |
| ✓ | Flapping is debounced, and the counters survive a service restart |
| ✓ | Every message links to the dashboard |
| ✓ | A host is muted for the duration of a planned reboot |

## 5. Decisions worth remembering

- **Service classification needs three signals at once.** Package priority,
  `apt-mark showmanual` and the unit path each fail somewhere: priority is
  `optional` for almost everything now, the base system is flagged manual on VPS
  images and Raspberry Pi OS, and a provider ships `serial-getty@ttyS0`
  hand-written under `/etc`.
- **RouterOS is queried with scripted `:put a."|".b`, not by parsing tables.**
  `print` columns cannot be parsed reliably: flags are optional and values
  contain spaces.
- **Thresholds live outside the config** (`/var/lib/health-zoo/settings.json`)
  and only when they differ from the default — otherwise today's defaults are
  pinned forever.
- **Camera silence is a per-camera threshold.** One fleet-wide number is
  guaranteed to be wrong for one camera, and wrong in the quiet direction.
- **Cleanup runs between two upgrade passes.** A package is often held back
  only because it conflicts with something nothing needs any more: the
  `libgl1-amber-dri` security update on watchcats was stuck behind
  `libglapi-mesa`, which was itself on the autoremove list. Upgrade, clean,
  ask again — and the question answers itself, with nothing forced.
- **History is optional by design.** If the database cannot be opened the
  dashboard runs without trends rather than failing.

## 6. Still open

- Firewall rules referring to interfaces and address lists that no longer exist.
- DHCP reservations for devices long gone from the network.
- Show what the neighbours are doing to the 2.4 GHz band, not just the percentage.
