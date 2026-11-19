from __future__ import annotations

from favhunt import (
    FetchResult,
    collect_icon_candidates,
    extract_icon_links,
    icon_rejection_reason,
)

HTML = b"""
<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="/style.css">
    <link rel="icon" href="/static/favicon.png">
    <link rel="shortcut icon" href="legacy.ico">
    <link rel="apple-touch-icon" href="//cdn.example.com/touch.png">
    <link rel="icon" href="/static/favicon.png">
    <link rel="icon" href="data:image/png;base64,AAAA">
  </head>
</html>
"""


def test_extract_icon_links_handles_rel_variants_relative_urls_and_dedupes():
    links = extract_icon_links(HTML.decode(), "https://example.com/app/page")
    assert links == [
        "https://example.com/static/favicon.png",
        "https://example.com/app/legacy.ico",
        "https://cdn.example.com/touch.png",
    ]


def test_extract_icon_links_respects_base_href():
    html = '<head><base href="https://cdn.example.com/assets/">\n<link rel="icon" href="icon.svg"></head>'
    assert extract_icon_links(html, "https://example.com/") == [
        "https://cdn.example.com/assets/icon.svg"
    ]


def test_extract_icon_links_handles_uppercase_attributes_and_limit():
    html = '<LINK REL="ICON" HREF="/one.ico"><link rel="icon" href="/two.ico">'
    assert extract_icon_links(html, "http://example.com/") == [
        "http://example.com/one.ico",
        "http://example.com/two.ico",
    ]
    assert extract_icon_links(html, "http://example.com/", limit=1) == [
        "http://example.com/one.ico"
    ]


def test_extract_icon_links_ignores_non_icon_links_and_data_urls():
    html = """
    <link rel="preload" href="/app.js">
    <link rel="mask-icon" href="/mask.svg">
    <link rel="icon" href="data:image/x-icon;base64,AAAA">
    <link rel="icon" href="">
    """
    assert extract_icon_links(html, "https://example.com/") == [
        "https://example.com/mask.svg"
    ]


def test_collect_icon_candidates_orders_html_links_then_fallbacks():
    page = FetchResult(url="https://example.com/", status=200, data=HTML)
    candidates = collect_icon_candidates("example.com", page, "https")
    assert candidates[:4] == [
        "https://example.com/static/favicon.png",
        "https://example.com/legacy.ico",
        "https://cdn.example.com/touch.png",
        "https://example.com/favicon.ico",
    ]
    assert candidates[4:7] == [
        "https://example.com/favicon.png",
        "https://example.com/apple-touch-icon.png",
        "http://example.com/favicon.ico",
    ]


def test_collect_icon_candidates_without_page_uses_fallbacks():
    assert collect_icon_candidates("example.com", None, "https")[:3] == [
        "https://example.com/favicon.ico",
        "https://example.com/favicon.png",
        "https://example.com/apple-touch-icon.png",
    ]


def test_icon_rejection_reason_accepts_valid_icon():
    result = FetchResult(
        url="https://example.com/favicon.ico",
        status=200,
        content_type="image/x-icon",
        data=b"\x00\x00\x01\x00",
    )
    assert icon_rejection_reason(result) == ""


def test_icon_rejection_reason_flags_common_failure_modes():
    assert icon_rejection_reason(FetchResult(url="u", status=404)) == "HTTP 404"
    assert icon_rejection_reason(FetchResult(url="u", error="boom")) == "boom"
    assert (
        icon_rejection_reason(FetchResult(url="u", status=200, data=b""))
        == "empty response"
    )
    assert (
        icon_rejection_reason(
            FetchResult(
                url="u",
                status=200,
                content_type="text/html; charset=utf-8",
                data=b"ok",
            )
        )
        == "HTML content-type"
    )
    assert (
        icon_rejection_reason(
            FetchResult(url="u", status=200, content_type="", data=b"<!DOCTYPE html><html>")
        )
        == "HTML response body"
    )
    assert (
        icon_rejection_reason(
            FetchResult(url="u", status=200, content_type="image/png", data=b"x" * 11),
            max_bytes=10,
        )
        == "icon too large"
    )
