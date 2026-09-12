"""HTTP measurements use the displayed endpoint and never reuse title health."""
from pathlib import Path
import sys
import threading
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import probe  # noqa: E402


@pytest.fixture(autouse=True)
def clear_web_caches(monkeypatch):
    monkeypatch.setattr(probe, "_HTTP_CACHE", {})
    monkeypatch.setattr(probe, "_TITLE_CACHE", {})
    monkeypatch.setattr(probe, "_CERT_CACHE", {})


class Response:
    def __init__(self, status=200, read_error=None):
        self.status = status
        self.read_error = read_error
        self.reads = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def read(self, size):
        self.reads.append(size)
        if self.read_error:
            raise self.read_error
        return b"OK"


def test_get_is_bounded_and_does_not_claim_certificate_trust(monkeypatch):
    response = Response()
    calls = []

    def open_url(request, *, timeout, context):
        calls.append((request.full_url, request.get_method(), timeout, context))
        return response

    monkeypatch.setattr(probe.urllib.request, "urlopen", open_url)
    result = probe.fetch_http_health("https://console.example.test/admin/")
    assert result["status"] == 200
    assert result["checked_at"] > 0
    assert "error" not in result
    assert calls[0][:3] == ("https://console.example.test/admin/", "GET", 4)
    assert response.reads == [1024]
    assert response.closed
    assert not calls[0][3].check_hostname
    assert not any(key.startswith("trust") for key in result)


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_http_error_codes_remain_measurements_without_leaking_message(monkeypatch, status):
    def open_url(*args, **kwargs):
        raise urllib.error.HTTPError("https://user:secret@example.test/?token=secret", status,
                                     "private server details", {}, None)

    monkeypatch.setattr(probe.urllib.request, "urlopen", open_url)
    result = probe.fetch_http_health("https://console.example.test/admin/")
    assert result["status"] == status
    assert "error" not in result
    assert "secret" not in str(result)
    assert "private" not in str(result)


@pytest.mark.parametrize("error, expected", [
    (TimeoutError("secret-url"), "timeout"),
    (urllib.error.URLError(TimeoutError("secret-url")), "timeout"),
    (urllib.error.URLError("https://user:secret@example.test"), "connection_failed"),
    (OSError("credential=secret"), "connection_failed"),
])
def test_network_failures_are_short_and_sanitized(monkeypatch, error, expected):
    def open_url(*args, **kwargs):
        raise error

    monkeypatch.setattr(probe.urllib.request, "urlopen", open_url)
    result = probe.fetch_http_health("https://console.example.test")
    assert result["status"] is None
    assert result["error"] == expected
    assert "secret" not in str(result)


def test_stalled_body_does_not_report_healthy_status(monkeypatch):
    monkeypatch.setattr(probe.urllib.request, "urlopen",
                        lambda *args, **kwargs: Response(read_error=TimeoutError()))
    result = probe.fetch_http_health("https://console.example.test")
    assert result["status"] is None
    assert result["error"] == "timeout"


def test_health_cache_expires_before_title_cache_and_returns_independent_copies(monkeypatch):
    clock = [1000.0]
    calls = []
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.time, "time", lambda: clock[0])

    def open_url(*args, **kwargs):
        calls.append(1)
        if len(calls) > 1:
            raise urllib.error.HTTPError("https://panel.example.test", 503, "unavailable", {}, None)
        return Response()

    monkeypatch.setattr(probe.urllib.request, "urlopen", open_url)
    url = "https://panel.example.test"
    first = probe.fetch_http_health(url)
    first["status"] = 999
    clock[0] += 179
    assert probe.fetch_http_health(url) == {"status": 200, "checked_at": 1000}
    clock[0] += 1
    assert probe.fetch_http_health(url) == {"status": 503, "checked_at": 1180}
    assert len(calls) == 2


def test_health_cache_has_a_capacity_limit(monkeypatch):
    monkeypatch.setattr(probe, "_HTTP_CACHE_MAX", 2)
    monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    for name in ("one", "two", "three"):
        probe.fetch_http_health(f"https://{name}.example.test")
    assert len(probe._HTTP_CACHE) == 2


@pytest.mark.parametrize("address, expected", [
    ("2001:db8::1", "http://[2001:db8::1]:8080/admin/"),
    ("[2001:db8::1]", "http://[2001:db8::1]:8080/admin/"),
])
def test_ipv6_url_uses_brackets(address, expected):
    assert probe._web_url({"addr": address}, {"scheme": "http", "port": 8080, "path": "/admin/"}) == expected


@pytest.mark.parametrize("address", ["127.0.0.1", "127.0.0.2", "::1", "[::1]", "localhost", "localhost."])
def test_loopback_urls_are_not_measured(address):
    assert probe._web_url({"addr": address}, {"scheme": "http", "port": 80}) == ""


def test_annotate_uses_vhosts_paths_and_separate_http_measurements(monkeypatch):
    http_urls, title_urls, cert_names = [], [], []
    links = [
        {"scheme": "https", "port": 443, "host_name": "one.example.test", "path": "/admin/"},
        {"scheme": "https", "port": 443, "host_name": "two.example.test", "path": "/status"},
        {"scheme": "http", "port": 8080, "label": "nginx"},
        {"scheme": "http", "port": 80, "local": True, "http": {"status": 200}},
    ]

    def title(url, *args):
        title_urls.append(url)
        return ("Old cached title", "/admin/") if ":8080" in url else ("Cached title", "")

    def health(url):
        http_urls.append(url)
        return {"status": 503, "checked_at": 123}

    def cert(addr, port, name):
        cert_names.append(name)
        return {"days_left": 10}

    monkeypatch.setattr(probe, "fetch_title", title)
    monkeypatch.setattr(probe, "fetch_http_health", health)
    monkeypatch.setattr(probe, "fetch_cert", cert)
    probe.annotate_web([{"addr": "192.0.2.1", "web": links}])
    assert set(http_urls) == {"https://one.example.test/admin/", "https://two.example.test/status",
                             "http://192.0.2.1:8080/admin/"}
    assert "https://one.example.test/admin/" in title_urls
    assert set(cert_names) == {"one.example.test", "two.example.test"}
    assert all(link["http"]["status"] == 503 for link in links[:3])
    assert "http" not in links[3]


def test_distinct_web_links_are_probed_concurrently(monkeypatch):
    barrier = threading.Barrier(2, timeout=2)
    monkeypatch.setattr(probe, "fetch_title", lambda *args: ("Panel", ""))

    def health(url):
        barrier.wait()
        return {"status": 200, "checked_at": 123}

    monkeypatch.setattr(probe, "fetch_http_health", health)
    links = [{"scheme": "http", "port": port} for port in (8080, 8081)]
    probe.annotate_web([{"addr": "192.0.2.1", "web": links}], workers=2)
    assert all(link["http"]["status"] == 200 for link in links)


def test_titles_of_virtual_hosts_do_not_share_cache(monkeypatch):
    monkeypatch.setattr(probe, "_page_title", lambda url: url)
    first = probe.fetch_title("https://one.example.test", "192.0.2.1", 443)
    second = probe.fetch_title("https://two.example.test", "192.0.2.1", 443)
    assert first[0] == "https://one.example.test"
    assert second[0] == "https://two.example.test"


def test_explicit_console_path_is_not_replaced_by_title_fallback(monkeypatch):
    calls = []
    monkeypatch.setattr(probe, "_page_title", lambda url: calls.append(url) or "")
    assert probe.fetch_title("https://one.example.test/console/", "192.0.2.1", 443) == ("", "")
    assert calls == ["https://one.example.test/console/"]
