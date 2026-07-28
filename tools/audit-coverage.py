#!/usr/bin/env python3
"""What the fleet reports that nothing ever reads.

`cpu_warn` and `cpu_bad` sat in the threshold table from the first commit with
no rule reading either of them, so a machine pinned at 100% was as green as an
idle one. The restart counter was collected for months and never compared
against anything; so was the carrier-change counter. None of that is visible by
reading the code — the collector and the rules are far apart, and a field that
goes nowhere looks exactly like a field that goes somewhere.

Three questions, answered against the live fleet or a fixture:

  * which fields the agents report and no rule and no view reads
  * which thresholds are defined and never consulted
  * which checks are not answering for anybody right now

The first list is advisory: plenty of fields exist for the detail view alone.
The second is not — a threshold nobody reads is a promise the dashboard does
not keep.

    ./tools/audit-coverage.py                       # from the fixture
    ./tools/audit-coverage.py http://dashboard:8816 # from the live fleet
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collector"))

import issues  # noqa: E402

# Bookkeeping the rules have no business reading.
PLUMBING = {"id", "name", "addr", "issues", "checks", "level", "thresholds",
            "agent", "role", "roles", "note", "probe_ms", "rtt_ms", "subnet",
            "web", "web_host", "endpoints_probed", "unifi_state", "unifi_mac"}


def readers() -> str:
    """Everything that could plausibly consume a field."""
    # probe.py counts as a reader: plenty of what the agents send is consumed
    # there — camera firmware, RTSP links, listener lists — and calling that
    # unread would bury the fields that genuinely go nowhere.
    parts = [(ROOT / "collector" / name).read_text(encoding="utf-8")
             for name in ("issues.py", "alerts.py", "history.py", "hub.py",
                          "probe.py")]
    parts += [path.read_text(encoding="utf-8") for path in (ROOT / "ui").glob("*.js")]
    return "\n".join(parts)


def fields(hosts: list[dict]) -> dict[str, int]:
    """Field name -> how many hosts report it, including inside lists."""
    seen: dict[str, int] = {}
    for host in hosts:
        for key, value in host.items():
            seen[key] = seen.get(key, 0) + 1
            items = value if isinstance(value, list) else []
            for item in items:
                if isinstance(item, dict):
                    for inner in item:
                        name = f"{key}[].{inner}"
                        seen[name] = seen.get(name, 0) + 1
    return seen


def main() -> int:
    if len(sys.argv) > 1:
        with urllib.request.urlopen(f"{sys.argv[1]}/api/state", timeout=30) as response:
            state = json.load(response)
        hosts = state["hosts"]
        source = sys.argv[1]
    else:
        fixture = json.loads((ROOT / "tests" / "fixtures" / "fleet.json")
                             .read_text(encoding="utf-8"))
        hosts, source = fixture["hosts"], "корпус тестов"

    code = readers()

    print(f"источник: {source}, хостов: {len(hosts)}\n")

    unread = []
    for field, count in sorted(fields(hosts).items()):
        bare = field.split("[].")[-1]
        if bare in PLUMBING:
            continue
        if re.search(rf'["\'\.]{re.escape(bare)}\b', code):
            continue
        unread.append((field, count))
    print(f"поля, которые собираются и нигде не читаются ({len(unread)}):")
    for field, count in unread:
        print(f"   {field:34} на {count} хостах")
    if not unread:
        print("   нет")

    print()
    # Named once means named only where it is defined. The dashboard also looks
    # thresholds up dynamically — `limits[kind + '_warn']` — so a suffix that is
    # composed at runtime counts as a reader too, or this list would be a lie in
    # the other direction.
    dynamic = re.findall(r"['\"]_(\w+)['\"]", code)
    forgotten = [name for name in issues.DEFAULT_THRESHOLDS
                 if code.count(f'"{name}"') + code.count(f"'{name}'") <= 1
                 and name.split("_")[-1] not in dynamic]
    print(f"пороги, объявленные и ни разу не прочитанные ({len(forgotten)}):")
    for name in forgotten:
        print(f"   {name} = {issues.DEFAULT_THRESHOLDS[name]}")
    if not forgotten:
        print("   нет")

    print()
    issues.annotate(hosts, {}, None)
    issues.annotate_checks(hosts, {})
    silent: dict[str, set] = {}
    for host in hosts:
        for check in host.get("checks", []):
            silent.setdefault(check["name"], set()).add(check["status"])
    never = sorted(name for name, statuses in silent.items()
                   if statuses <= {"n/a"})
    print(f"проверки, не применимые сейчас ни к кому ({len(never)}):")
    for name in never:
        print(f"   {name}")
    if not never:
        print("   нет")
    return 1 if forgotten else 0


if __name__ == "__main__":
    raise SystemExit(main())
