# health-zoo

**English** | [Русский](README.ru.md)

A single page showing whether every box on your network is healthy — servers, NAS
units, routers, cameras and mesh radios — drawn as the network tree they actually
form, with a button to install pending OS updates.

No agents to install, no database, no dependencies beyond `python3`. The hub logs
into each host over SSH, runs a small shell script there, and renders what comes
back.

![dashboard](docs/screenshot.png)

## What it shows

Devices are grouped by subnet, and subnets nest by their real topology — uplink
router → site router → the camera segment behind it.

| Device | Collected |
|---|---|
| Debian/Ubuntu | uptime, load, RAM/swap, disks, temperatures, pending `apt` updates (security flagged separately), reboot-required, services, containers, git checkouts, ZoneMinder monitors |
| Synology DSM | DSM version, volumes, RAID state, swap pressure, temperatures, installed packages and versions, HyperBackup freshness, Surveillance Station cameras |
| MikroTik RouterOS | version, RouterBOARD firmware (and whether a reboot is pending), CPU/RAM/flash, temperature and voltage, management services, installed packages, interface link state |
| OpenWrt | release, model, overlay/flash usage, temperatures, init scripts, interfaces |
| Meshtastic nodes | uptime, channel utilisation, heap and filesystem, reboot counter, wifi RSSI, battery |
| Cameras | reachability, and — more usefully — whether the host recording them says the stream is alive, at what frame rate |

**Services are discovered, never configured.** The agents enumerate whatever is
running on each host; installing something new makes it appear on the dashboard
by itself. Only the host list lives in the config file.

Each unit's version is resolved through the package that owns its unit file, so
"which ZoneMinder is this" is answered without the collector knowing anything
about ZoneMinder.

## Updating packages

Hosts marked `updatable` get an update button, plus a global **Update everything**
that walks them in order and streams the log into the page.

The machine hosting the dashboard is always updated **last** — otherwise it
restarts its own service mid-run — and its upgrade is detached with `setsid` so
it survives that restart.

Only Debian-family hosts are updatable. NAS units and routers are reported but
never touched: upgrading OpenWrt packages in place is a known way to brick a
router, and DSM updates need credentials this tool deliberately does not hold.

## Removing a service

Each service in the host detail view has a remove button: it stops the unit,
disables it and deletes its unit file. Units belonging to a package are stopped
and masked instead, since deleting their files would only invite the next
upgrade to restore them.

Units that would cut off access to the host — `ssh`, `network`, `firewall`,
`systemd-*` and friends — are refused by the server, not merely hidden in the UI.
Removal asks you to type the service name to confirm.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/anton-vinogradov/health-zoo/main/install.sh | sudo bash
```

This installs to `/opt/health-zoo`, creates a systemd unit, generates an SSH key
and prints its public half. Then:

1. Install that public key on every host you want polled.
2. Edit `/etc/health-zoo.json` — the host list, subnets and their parents.
3. `sudo systemctl restart health-zoo`

The dashboard listens on port 8816. Re-running the installer is the upgrade path;
it never overwrites your config.

### Access needed per host type

| Host | Needs |
|---|---|
| Debian/Ubuntu | SSH key; passwordless `sudo` only for the update button and ZoneMinder queries |
| Synology | SSH key. Works entirely unprivileged — anything requiring root is left unreported rather than guessed |
| RouterOS | a user with the `read` group and your key imported (`/user ssh-keys import`) |
| OpenWrt | key in `/etc/dropbear/authorized_keys` |
| Meshtastic | nothing — the firmware serves `/json/report` over HTTP |
| Cameras | nothing — status comes from whoever records them |

## Configuration

```json
{
  "poll_interval": 180,
  "ssh_key": "~/.ssh/id_health_zoo",
  "port": 8816,
  "subnets": [
    { "cidr": "0.0.0.0/0",     "name": "Internet", "parent": null },
    { "cidr": "10.0.0.0/24",   "name": "Uplink",   "parent": "0.0.0.0/0",   "router": "10.0.0.1" },
    { "cidr": "10.0.10.0/24",  "name": "Site",     "parent": "10.0.0.0/24", "router": "10.0.10.1" }
  ],
  "hosts": [
    { "id": "box", "name": "box", "addr": "10.0.10.5", "user": "admin",
      "agent": "linux", "role": "server", "subnet": "10.0.10.0/24",
      "local": true, "updatable": true, "update_last": true }
  ]
}
```

`agent` is one of `linux`, `synology`, `routeros`, `openwrt`, `meshtastic`, or
`none` for ping/port probing only. `role` (`server`, `nas`, `router`, `camera`,
`mesh`) picks the icon and the grouping inside a subnet.

The config file holds every address; the repository holds none.

## How it works

```
hub.py      HTTP server + poll loop + update/removal jobs
probe.py    per-host probing, report parsing, camera↔recorder linking
agents/*.sh streamed to the host over `ssh host sh -s`, emit a TSV report
```

Agents are POSIX shell with no dependencies on the target — not even `jq`. They
are written to be cheap: an early version shelled out per systemd unit and ran
`du` over a ZoneMinder archive, which took 44 seconds per host on a Celeron
N5105; batching those calls brought it to under 2.

Hosts are polled in parallel, so a whole fleet takes about as long as its slowest
member. The browser is only ever served the last completed snapshot.

## Licence

MIT.
