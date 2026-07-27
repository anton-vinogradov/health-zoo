# health-zoo

**English** | [Русский](README.ru.md)

A single page showing whether every box on your network is healthy — servers, NAS
units, routers, cameras and mesh radios — drawn as the network tree they actually
form, with a button to install pending OS updates.

No agents to install, no database, no dependencies beyond `python3`. The hub logs
into each host over SSH, runs a small shell script there, and renders what comes
back.



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

## Suppressing a finding

Any monitoring system eventually shows something known, understood and not
being fixed today. Left alone it trains the operator to ignore an amber
dashboard; turned off, the check is forgotten entirely.

A suppression is neither. The check keeps running and its verdict stays
visible, but it stops colouring the host and stops alerting, and the reason
sits next to it. A reason is mandatory — a suppression with no explanation is
indistinguishable from a check nobody understood — and an optional expiry
makes it come back for review.

The **Исключения** view lists them fleet-wide, with age, remaining time, and
whether the underlying finding still occurs at all. That last column is the
useful one: a suppression hiding nothing can simply be dropped.

## Removing a service

Each service in the host detail view has a remove button: it stops the unit,
disables it and deletes its unit file. Units belonging to a package are stopped
and masked instead, since deleting their files would only invite the next
upgrade to restore them.

Units that would cut off access to the host — `ssh`, `network`, `firewall`,
`systemd-*` and friends — are refused by the server, not merely hidden in the UI.
Removal asks you to type the service name to confirm.

### Secrets

Passwords do not belong in the config file: it ends up in backups, in `cat`
output and on shared screens. Two of them are needed — the Telegram bot token
and the UniFi controller password — and both are referenced rather than
stored:

```bash
printf %s 'the-secret' | sudo systemd-creds encrypt --name=telegram-token - \
    /etc/health-zoo.d/telegram-token.cred
```

`systemd-creds` encrypts with a key held by the machine. Add
`--with-key=host+tpm2` to bind it to the TPM as well: without that the host
key sits in `/var/lib/systemd/credential.secret` and travels with any full
backup, so a copied credential plus a copied backup is a readable secret.
(systemd reports "TPM2 support is not installed" until `libtss2-rc0` is
present — the one library it dlopens for TPM, easy to miss when every other
libtss2 package is already there.) systemd
decrypts it at service start into a tmpfs directory that only this service can
read. The config then names it instead of holding it:

```json
"telegram":         { "token_credential":    "telegram-token" },
"unifi_controller": { "password_credential": "unifi-password" }
```

`<field>_file` is also accepted for hosts without systemd credentials, and a
plain `<field>` still works so existing setups keep running.

One honest limit: the decrypted value is readable by the account the service
runs as. This protects the config, backups and anyone looking over your
shoulder — not someone already logged in as that user. Run the service as its
own account if that matters.

### Access points

UniFi Network 10 removed per-device SSH authentication from the standalone
application, so access points are read through the controller's API instead —
which is the better route anyway: one login returns every AP's radios, client
counts, airtime and firmware state without touching the access points at all.

Configure it with an account that can also act, not a view-only one: reading
statistics and rebooting a radio go through the same endpoint, so a read-only
account means the reboot and firmware buttons cannot work.

```json
"unifi_controller": {
  "url": "https://10.0.10.13:8443",
  "site": "default",
  "username": "health-zoo",
  "password": "…"
}
```

A router that is also an access point simply declares both roles:
`"roles": ["router", "ap"]`.

### Rebooting

Every device type can be rebooted from its card, each by the only mechanism it
actually offers:

| Type | How |
|---|---|
| Debian/Ubuntu, OpenWrt | `shutdown -r`, detached so the dying ssh session does not kill it |
| RouterOS | `/system reboot` |
| Meshtastic | the `meshtastic` CLI from the hub — the node speaks protobuf, not shell |
| Cameras | ISAPI, issued **from the host recording them**, using credentials that stay on that machine |
| Synology | `sudo reboot`, which DSM refuses without a password (see below) |

A reboot mutes alerting for that host while it comes back, so a planned
restart is not reported as an outage.

DSM grants no passwordless sudo, and health-zoo deliberately stores no DSM
password. To allow reboots — and SMART, which is also root-only — add one line
with `visudo` on the NAS:

```
your-user ALL=(root) NOPASSWD: /sbin/reboot, /usr/bin/smartctl
```

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
