from __future__ import annotations

from favhunt import FetchResult, ScanConfig, _should_retry, probe_page


class _FakeFetcher:
    """Minimal HttpFetcher stand-in that records requested URLs."""

    config = ScanConfig()

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, max_bytes=0):
        self.calls.append(url)
        return self.responses.get(url, FetchResult(url=url, error="connection refused"))


def test_probe_page_prefers_https():
    https = FetchResult(url="https://example.com/", status=200, data=b"<html></html>")
    fetcher = _FakeFetcher({"https://example.com/": https})

    scheme, page = probe_page("example.com", fetcher)

    assert scheme == "https"
    assert page is https
    assert fetcher.calls == ["https://example.com/"]


def test_probe_page_falls_back_to_http():
    http = FetchResult(url="http://example.com/", status=200, data=b"<html></html>")
    fetcher = _FakeFetcher({"http://example.com/": http})

    scheme, page = probe_page("example.com", fetcher)

    assert scheme == "http"
    assert page is http
    assert fetcher.calls == ["https://example.com/", "http://example.com/"]


def test_probe_page_returns_none_when_nothing_answers():
    fetcher = _FakeFetcher({})
    scheme, page = probe_page("example.com", fetcher)
    assert scheme == "https"
    assert page is None
    assert len(fetcher.calls) == 2


def test_should_retry_transient_failures_only():
    assert _should_retry(FetchResult(url="u", error="dns failure"))
    assert _should_retry(FetchResult(url="u", status=503, error="HTTP 503"))
    assert _should_retry(FetchResult(url="u", status=429, error="HTTP 429"))
    assert not _should_retry(FetchResult(url="u", status=404, error="HTTP 404"))
    assert not _should_retry(FetchResult(url="u", status=200, data=b"icon"))
