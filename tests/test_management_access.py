"""Management access regressions; requests use fake sockets and never act on hosts."""
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
import configuration
import hub


def handler(*, peer="192.0.2.60", local="192.0.2.8", port=8816,
            host="192.0.2.8:8816", networks=None, configured_token="secret"):
    request = hub.Handler.__new__(hub.Handler)
    request.client_address = (peer, 42310)
    request.connection = SimpleNamespace(
        getsockname=lambda: (local, port), settimeout=lambda seconds: None)
    request.headers = {
        "Host": host,
        "Origin": "http://" + host,
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": "2",
        "X-Health-Zoo-Request": "dashboard",
        "Sec-Fetch-Site": "same-origin",
    }
    request.rfile = io.BytesIO(b"{}")
    request.path = "/api/state"
    store = SimpleNamespace(storage_error="")
    request.fleet = SimpleNamespace(
        cfg={"trusted_management_networks": ["192.0.2.0/24"] if networks is None else networks,
             "action_token": configured_token},
        version="test-version", get=lambda: {"hosts": []},
        settings=store, suppressions=store, acks=store, alerts=store,
    )
    request.response = None
    request._json = lambda payload, code=200: setattr(request, "response", (code, payload))
    return request


def test_explicit_lan_browser_manages_without_a_secret():
    request = handler(configured_token="")
    assert request._trusted_management_client()
    assert request._authorized() == ""


@pytest.mark.parametrize("networks,peer", [
    ([], "192.0.2.60"),
    (["192.0.2.0/24"], "198.51.100.60"),
    (["192.0.2.60/32"], "192.0.2.61"),
    (["192.0.2.0/24"], "127.0.0.1"),
])
def test_trust_is_opt_in_and_uses_only_explicit_cidr(networks, peer):
    request = handler(networks=networks, peer=peer)
    assert not request._trusted_management_client()
    assert request._authorized() == "token_required"
    request.headers["X-Health-Zoo-Token"] = "secret"
    assert request._authorized() == ""


def test_forwarded_headers_cannot_establish_lan_trust():
    request = handler(peer="198.51.100.42")
    request.headers.update({"X-Forwarded-For": "192.0.2.60",
                            "Forwarded": "for=192.0.2.60;host=192.0.2.8:8816",
                            "X-Real-IP": "192.0.2.60"})
    assert not request._trusted_management_client()
    assert request._authorized() == "token_required"


@pytest.mark.parametrize("host", [
    "evil.example:8816",  # Equal Host and Origin must not enable DNS rebinding.
    "192.0.2.9:8816", "192.0.2.8:80", "192.0.2.8", "",
    "name@192.0.2.8:8816", "192.0.2.8:8816/path",
    "192.0.2.8:8816?query", "192.0.2.8:8816#fragment",
    "192.0.2.8:invalid", "192.0.2.8:99999", "[broken:8816",
])
def test_host_must_be_actual_local_ip_and_port(host):
    request = handler(host=host)
    assert not request._trusted_management_client()
    assert request._authorized()


def test_hostname_reverse_proxy_keeps_token_authentication():
    request = handler(host="dashboard.example:8816")
    assert not request._trusted_management_client()
    assert request._authorized() == "token_required"
    request.headers["X-Health-Zoo-Token"] = "secret"
    assert request._authorized() == ""


@pytest.mark.parametrize("origin", [
    "https://evil.example", "http://192.0.2.9:8816",
    "http://192.0.2.8:80", "null", "http://[broken",
])
def test_origin_mismatch_denies_both_lan_and_token_requests(origin):
    request = handler()
    request.headers["Origin"] = origin
    request.headers["X-Health-Zoo-Token"] = "secret"
    assert request._authorized().startswith("cross-origin")


def test_referer_is_checked_when_origin_is_missing():
    request = handler()
    request.headers.pop("Origin")
    request.headers["Referer"] = "http://192.0.2.8:8816/dashboard"
    assert request._authorized() == ""
    request.headers["Referer"] = "https://evil.example/dashboard"
    assert request._authorized().startswith("cross-origin")


@pytest.mark.parametrize("key,value", [
    ("Content-Type", None), ("Content-Type", "text/plain"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("X-Health-Zoo-Request", None), ("X-Health-Zoo-Request", "other"),
])
def test_tokenless_lan_write_requires_json_and_custom_header(key, value):
    request = handler()
    if value is None:
        request.headers.pop(key)
    else:
        request.headers[key] = value
    assert request._authorized() == "dashboard_header_required"


@pytest.mark.parametrize("fetch_site", ["same-site", "cross-site"])
def test_browser_cross_origin_context_cannot_use_lan_shortcut(fetch_site):
    request = handler()
    request.headers["Sec-Fetch-Site"] = fetch_site
    assert request._authorized().startswith("cross-origin")


def test_non_browser_json_client_can_use_lan_shortcut_without_origin():
    request = handler()
    request.headers.pop("Origin")
    request.headers.pop("Sec-Fetch-Site")
    assert request._authorized() == ""


@pytest.mark.parametrize("peer", ["192.0.2.60", "198.51.100.42"])
def test_legacy_token_scripts_need_no_browser_specific_headers(peer):
    request = handler(peer=peer)
    request.headers = {"Host": "192.0.2.8:8816", "X-Health-Zoo-Token": "secret"}
    assert request._authorized() == ""


def test_no_token_and_no_trusted_network_keeps_actions_disabled():
    request = handler(networks=[], configured_token="")
    assert request._authorized() == "actions_disabled"


@pytest.mark.parametrize("peer,local,host,networks", [
    ("2001:db8:1::60", "2001:db8:1::8", "[2001:db8:1::8]:8816", ["2001:db8:1::/64"]),
    ("::ffff:192.0.2.60", "::ffff:192.0.2.8", "192.0.2.8:8816", ["192.0.2.0/24"]),
    ("::ffff:192.0.2.60", "::ffff:192.0.2.8", "[::ffff:192.0.2.8]:8816", ["192.0.2.0/24"]),
    ("127.0.0.1", "127.0.0.1", "localhost:8816", ["127.0.0.1/32"]),
])
def test_ipv6_mapped_ipv4_and_explicit_loopback_access(peer, local, host, networks):
    request = handler(peer=peer, local=local, host=host, networks=networks)
    assert request._trusted_management_client()
    assert request._authorized() == ""


def test_localhost_name_cannot_identify_a_non_loopback_socket():
    request = handler(host="localhost:8816")
    assert not request._trusted_management_client()


def test_port_80_host_can_omit_default_port():
    request = handler(host="192.0.2.8", port=80)
    assert request._trusted_management_client()


@pytest.mark.parametrize("peer,host,token,enabled,needs_token", [
    ("192.0.2.60", "192.0.2.8:8816", "secret", True, False),
    ("192.0.2.60", "192.0.2.8:8816", "", True, False),
    ("198.51.100.42", "192.0.2.8:8816", "secret", True, True),
    ("198.51.100.42", "192.0.2.8:8816", "", False, False),
    ("192.0.2.60", "evil.example:8816", "secret", True, True),
])
def test_state_access_flags_are_per_request_and_get_needs_no_origin(peer, host, token, enabled, needs_token):
    request = handler(peer=peer, host=host, configured_token=token)
    request.headers = {"Host": host}
    request.do_GET()
    code, state = request.response
    assert code == 200
    assert state["actions_enabled"] is enabled
    assert state["needs_token"] is needs_token
    assert "secret" not in json.dumps(state)


def test_post_guard_denies_before_mutation_dispatch():
    request = handler()
    request.path = "/api/settings"
    request.headers.pop("X-Health-Zoo-Request")
    request.do_POST()
    assert request.response == (403, {"error": "dashboard_header_required",
                                      "code": "dashboard_header_required"})


@pytest.mark.parametrize("networks", [None, "192.0.2.0/24", {}, [42], ["invalid"], ["192.0.2.0/99"]])
def test_invalid_trust_configuration_is_rejected(networks):
    with pytest.raises(ValueError):
        configuration.validate({"trusted_management_networks": networks})


def test_existing_configuration_needs_no_new_trust_setting():
    configuration.validate({})
    configuration.validate({"trusted_management_networks": ["192.0.2.0/24", "2001:db8::/64"]})


def open_handler(**kwargs):
    request = handler(**dict({"peer": "198.51.100.42", "networks": []}, **kwargs))
    request.fleet.cfg["require_action_token"] = False
    return request


@pytest.mark.parametrize("peer", ["192.0.2.60", "198.51.100.42", "2001:db8:2::42"])
def test_global_opt_out_accepts_any_peer_without_configured_key(peer):
    request = open_handler(peer=peer, configured_token="")
    assert not request._trusted_management_client()
    assert request._authorized() == ""


def test_global_opt_out_never_loads_key_for_write_or_state(monkeypatch):
    request = open_handler()
    request.headers["X-Health-Zoo-Token"] = "incorrect-unused-token"
    monkeypatch.setattr(hub.secrets_mod, "load", lambda *args: pytest.fail("key lookup in open mode"))
    assert request._authorized() == ""
    request.do_GET()
    assert request.response[1]["actions_enabled"] is True
    assert request.response[1]["needs_token"] is False


@pytest.mark.parametrize("host", ["192.0.2.8:8816", "dashboard.example:8816"])
def test_global_opt_out_state_never_prompts_for_a_key(host):
    request = open_handler(host=host, configured_token="")
    request.headers = {"Host": host}
    request.do_GET()
    assert request.response[0] == 200
    assert request.response[1]["actions_enabled"] is True
    assert request.response[1]["needs_token"] is False


@pytest.mark.parametrize("key,value", [
    ("Content-Type", None), ("Content-Type", "text/plain"),
    ("X-Health-Zoo-Request", None), ("X-Health-Zoo-Request", "other"),
])
def test_global_opt_out_still_requires_dashboard_headers_even_with_valid_key(key, value):
    request = open_handler()
    request.headers["X-Health-Zoo-Token"] = "secret"
    if value is None:
        request.headers.pop(key)
    else:
        request.headers[key] = value
    assert request._authorized() == "dashboard_header_required"


@pytest.mark.parametrize("header,value", [
    ("Origin", "https://evil.example"), ("Origin", "null"),
    ("Referer", "https://evil.example/dashboard"),
])
def test_global_opt_out_keeps_origin_and_referer_guard(header, value):
    request = open_handler()
    request.headers.pop("Origin")
    request.headers[header] = value
    assert request._authorized().startswith("cross-origin")


@pytest.mark.parametrize("fetch_site", ["same-site", "cross-site"])
def test_global_opt_out_keeps_browser_cross_origin_guard(fetch_site):
    request = open_handler()
    request.headers["Sec-Fetch-Site"] = fetch_site
    assert request._authorized().startswith("cross-origin")


@pytest.mark.parametrize("host", ["evil.example:8816", "192.0.2.9:8816", "192.0.2.8:80"])
def test_global_opt_out_rejects_rebinding_without_token_fallback(host):
    request = open_handler(host=host)
    request.headers["X-Health-Zoo-Token"] = "secret"
    assert request._authorized() == "management_host_required"


@pytest.mark.parametrize("peer,local,host", [
    ("2001:db8:2::60", "2001:db8:1::8", "[2001:db8:1::8]:8816"),
    ("::ffff:198.51.100.42", "::ffff:192.0.2.8", "192.0.2.8:8816"),
    ("127.0.0.1", "127.0.0.1", "localhost:8816"),
])
def test_global_opt_out_retains_ipv6_and_loopback_host_support(peer, local, host):
    request = open_handler(peer=peer, local=local, host=host)
    assert request._authorized() == ""


def test_global_opt_out_dispatches_refresh_from_external_peer_without_key():
    request = open_handler(configured_token="")
    request.path = "/api/refresh"
    wake_calls = []
    request.fleet.wake = SimpleNamespace(set=lambda: wake_calls.append(True))
    request.do_POST()
    assert request.response == (200, {"ok": True})
    assert wake_calls == [True]


def test_explicit_token_requirement_keeps_existing_external_client_policy():
    request = handler(peer="198.51.100.42", networks=[])
    request.fleet.cfg["require_action_token"] = True
    assert request._authorized() == "token_required"
    request.headers["X-Health-Zoo-Token"] = "secret"
    assert request._authorized() == ""


@pytest.mark.parametrize("value", [True, False])
def test_global_token_policy_accepts_boolean_values(value):
    configuration.validate({"require_action_token": value})


@pytest.mark.parametrize("value", [None, "false", "true", 0, 1, [], {}])
def test_global_token_policy_rejects_ambiguous_values(value):
    with pytest.raises(ValueError):
        configuration.validate({"require_action_token": value})


@pytest.mark.parametrize("existing_key", [False, True])
def test_migration_in_open_mode_never_provisions_a_key(tmp_path, monkeypatch, existing_key):
    import migrate

    monkeypatch.setattr(migrate.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1234, pw_gid=5678))
    monkeypatch.setattr(migrate.os, "chown", lambda *args: None)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"require_action_token": False}))
    original_config = config.read_bytes()
    state = tmp_path / "state"
    state.mkdir()
    key = state / "action-token"
    if existing_key:
        key.write_text("unused-existing-test-key\n")
    for _ in range(2):
        result = migrate.prepare(config, "service-account", state_dir=state)
        assert result["require_action_token"] is False
        assert not any(name.startswith("action_token") for name in result)
        assert config.read_bytes() == original_config
        if existing_key:
            assert key.read_text() == "unused-existing-test-key\n"
        else:
            assert not key.exists()
    assert json.loads((state / "settings.json").read_text())["auto_security"]["enabled"] is False
