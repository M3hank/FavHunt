from __future__ import annotations

import pytest

from favhunt import format_url, normalize_host, normalize_targets


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Example.COM/path?q=1#frag", "example.com"),
        ("http://example.com:8080/admin", "example.com:8080"),
        ("example.com", "example.com"),
        ("example.com/path", "example.com"),
        ("https://example.com:443/", "example.com"),
        ("http://example.com:80/", "example.com"),
        ("EXAMPLE.com.", "example.com"),
        ("http://user:pass@example.com/", "example.com"),
        ("http://[::1]:8080/", "[::1]:8080"),
        ("http://[::1]/", "[::1]"),
        ("  example.com  ", "example.com"),
        ("//example.com/x", "example.com"),
        ("", None),
        ("   ", None),
        ("# just a comment", None),
        ("http://", None),
        ("example.com:notaport", None),
        ("http://exa mple.com", None),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_normalize_targets_dedupes_scheme_variants():
    values = [
        "http://a.example",
        "https://A.example/path",
        "a.example",
        "b.example:8443",
        "http://b.example:8443/",
        "https://b.example:8443/other",
    ]
    assert normalize_targets(values) == ["a.example", "b.example:8443"]


def test_normalize_targets_skips_invalid_and_preserves_order():
    values = ["z.example", "not a host", "a.example", "", "z.example"]
    assert normalize_targets(values) == ["z.example", "a.example"]


def test_format_url_prefers_https():
    assert format_url("example.com") == "https://example.com/favicon.ico"
    assert format_url("http://example.com/deep/path") == "https://example.com/favicon.ico"
    assert format_url("example.com", "/favicon.png") == "https://example.com/favicon.png"
    assert format_url("example.com", "icon.png") == "https://example.com/icon.png"


def test_format_url_rejects_invalid_targets():
    with pytest.raises(ValueError):
        format_url("http://")
