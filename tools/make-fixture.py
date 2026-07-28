#!/usr/bin/env python3
"""Turn a live snapshot into an anonymous fixture the rules can be tested on.

The rules were the only part of this project with no tests, and the reason was
that testing them needs a whole fleet: a rule is wrong when it fires on a
healthy Synology or stays quiet on a broken port, and neither case fits in a
hand-written dict. A real snapshot does fit — once it stops naming the network
it came from.

Addresses, names, MAC addresses, SSIDs and URLs are replaced consistently, so
"the forward points at the host that listens on that port" survives the
translation while the address itself does not. Numbers, states and verdicts are
kept exactly: those are what the rules read.

    ./tools/make-fixture.py http://dashboard:8816 tests/fixtures/fleet.json
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import issues  # noqa: E402

MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
# Names that are the whole point of a finding stay: a rule keyed on "ether10"
# reads differently from one keyed on "port-3".
KEEP_NAMES = {"lo", "eth0", "wan", "lan"}


class Anonymiser:
    """Stable, reversible-looking replacements: same input, same output."""

    def __init__(self) -> None:
        self.addresses: dict[str, str] = {}
        self.macs: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.essids: dict[str, str] = {}

    def address(self, value: str) -> str:
        if value in self.addresses:
            return self.addresses[value]
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return value
        index = len(self.addresses) + 1
        # Private stays private and public stays public: several rules turn on
        # exactly that distinction.
        replacement = (f"10.0.{index // 250}.{index % 250 + 1}" if parsed.is_private
                       else f"203.0.113.{index % 250 + 1}")
        self.addresses[value] = replacement
        return replacement

    def mac(self, value: str) -> str:
        if value not in self.macs:
            self.macs[value] = "02:00:00:%02x:%02x:%02x" % (
                len(self.macs) // 65536, len(self.macs) // 256 % 256, len(self.macs) % 256)
        return self.macs[value]

    def name(self, value: str, prefix: str = "host") -> str:
        if not value or value in KEEP_NAMES:
            return value
        if value not in self.names:
            self.names[value] = f"{prefix}-{len(self.names) + 1}"
        return self.names[value]

    def essid(self, value: str) -> str:
        if not value:
            return value
        if value not in self.essids:
            self.essids[value] = f"net-{len(self.essids) + 1}"
        return self.essids[value]


def walk(node, anon: Anonymiser, key: str = ""):
    if isinstance(node, dict):
        # "name" means a host only where there is an address next to it. On a
        # port, a radio, a unit or a container it is the thing the rules key on
        # — rewriting enp1s0 to host-83 makes the fixture disagree with itself.
        host_like = "addr" in node
        return {k: walk(v, anon, "_asis" if k == "name" and not host_like else k)
                for k, v in node.items()}
    if isinstance(node, list):
        return [walk(v, anon, key) for v in node]
    if not isinstance(node, str):
        return node

    if key == "_asis":
        return node
    if key in ("essid", "ssid", "loudest"):
        return anon.essid(node)
    if key in ("name", "host_name", "to_name", "recorded_by", "camera_name",
               "firmware_source", "verified_from", "via"):
        return " → ".join(anon.name(part.strip(), "host") for part in node.split("→"))
    if key in ("id", "host"):
        return anon.name(node, "id")
    if key in ("addr", "address", "to", "public_addr", "wan_addr", "egress_addr",
               "ssh_peer", "gateway"):
        return anon.address(node.split(":")[0]) if node else node
    if key in ("mac", "bssid", "unifi_mac", "ap_mac"):
        return anon.mac(node)
    # Free text: comments, notes, reasons, URLs. Scrub what looks like an
    # address or a MAC and leave the wording, which is what makes a fixture
    # readable a year later.
    text = MAC.sub(lambda m: anon.mac(m.group(0)), node)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                  lambda m: anon.address(m.group(0)), text)
    return re.sub(r"https?://[^\s\"']+", "https://example.invalid/", text)


# Structural strings: an issue key is what the rules and the suppressions match
# on, so rewriting a host name inside "no_backup" would break the fixture in a
# way that looks like a rule bug.
STRUCTURAL = {"key", "keys", "category", "status", "level", "verdict", "state",
              "proto", "action", "chain", "agent", "role"}


def scrub(node, replacements: list, key: str = ""):
    """Second pass: the names again, this time wherever they were written."""
    if isinstance(node, dict):
        return {k: scrub(v, replacements, k) for k, v in node.items()}
    if isinstance(node, list):
        return [scrub(v, replacements, key) for v in node]
    if not isinstance(node, str) or key in STRUCTURAL:
        return node
    for original, replacement in replacements:
        # Whole words only, and nothing shorter than four characters: "cam" or
        # "s0" as a substring rule turns port names and identifiers into
        # nonsense that reads like a parser fault later.
        if len(original) < 4:
            continue
        node = re.sub(rf"(?<!\w){re.escape(original)}(?!\w)",
                      replacement, node, flags=re.IGNORECASE)
    return node


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    source, target = sys.argv[1], sys.argv[2]
    with urllib.request.urlopen(f"{source}/api/state", timeout=30) as response:
        state = json.load(response)

    anon = Anonymiser()
    hosts = walk(state.get("hosts", []), anon, "hosts")
    subnets = walk(state.get("subnets", []), anon, "subnets")
    # Structured fields are replaced by key, but the same names turn up inside
    # free text nobody keyed: service descriptions, suppression reasons, notes,
    # window titles. A second pass over every string catches those — over the
    # values, not over the serialised document, which a name containing a quote
    # would tear in half. Longest first, so "cam-nas" is not half-replaced by
    # the rule for "cam".
    replacements = sorted({**anon.names, **anon.essids}.items(),
                          key=lambda item: -len(item[0]))
    hosts = scrub(hosts, replacements)
    subnets = scrub(subnets, replacements)
    # What each host is expected to produce, recorded now and asserted later:
    # a rule that starts firing on a host nobody touched is a regression, and
    # so is one that goes quiet.
    # The live hub runs with thresholds an operator has tuned; replaying the
    # findings without them compares two different dashboards. Only the
    # differences from the defaults are kept, per host, which is also a readable
    # record of what was tuned and where.
    defaults = issues.DEFAULT_THRESHOLDS
    tuned = {}
    for host in hosts:
        limits = host.get("thresholds") or {}
        role = issues.ROLE_THRESHOLDS.get(host.get("role", ""), {})
        diff = {k: v for k, v in limits.items()
                if v != role.get(k, defaults.get(k))}
        if diff:
            tuned[host["id"]] = diff

    fixture = {
        "note": "Anonymised snapshot of a live fleet — see tools/make-fixture.py",
        "cfg": {"thresholds_by_host": tuned},
        "subnets": subnets,
        "hosts": hosts,
        "expect": {host["id"]: sorted(i["key"] for i in host.get("issues", []))
                   for host in hosts},
    }
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(fixture, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"{target}: {len(hosts)} хостов, "
          f"{sum(len(v) for v in fixture['expect'].values())} ожидаемых замечаний")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
