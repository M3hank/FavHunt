from __future__ import annotations

import csv
import io
import json

import pytest

import favhunt
from favhunt import InputError, build_parser, read_targets

ICON = b"\x89PNG\r\n\x1a\nfake-icon-bytes"
SHODAN_HASH = -1768129442
RAW_HASH = 794015155
HOST_LINK_HTML = (
    b'<html><head><link rel="icon" href="/static/icon.png"></head>'
    b"<body>hello</body></html>"
)


def _link_routes():
    return {
        "/": (200, "text/html; charset=utf-8", HOST_LINK_HTML),
        "/static/icon.png": (200, "image/png", ICON),
    }


def _host(server):
    return f"127.0.0.1:{server.server_address[1]}"


def _run(server, tmp_path, extra_args=None):
    """Run a full scan against a local server and return parsed artifacts."""
    host = _host(server)
    output_dir = tmp_path / "out"
    argv = [
        "-u",
        f"http://{host}/some/deep/path",
        "-t",
        "2",
        "--timeout",
        "2",
        "--retries",
        "0",
        "-o",
        str(output_dir / "icons"),
        "--json",
        str(output_dir / "report.json"),
        "--csv",
        str(output_dir / "report.csv"),
        "--queries",
    ]
    if extra_args:
        argv.extend(extra_args)

    code = favhunt.main(argv)
    payload = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    return code, host, output_dir, payload


def test_end_to_end_scan_with_html_icon_link(make_server, tmp_path, capsys):
    server = make_server(_link_routes())
    code, host, output_dir, payload = _run(server, tmp_path)

    assert code == 0
    assert payload["tool"] == "favhunt"
    assert payload["version"] == favhunt.__version__
    assert len(payload["results"]) == 1

    record = payload["results"][0]
    assert list(record) == list(favhunt.JSON_RESULT_COLUMNS)
    assert record["host"] == host
    assert record["icon_url"] == f"http://{host}/static/icon.png"
    assert record["mmh3"] == SHODAN_HASH
    assert record["mmh3_raw"] == RAW_HASH
    assert record["tech"] == "Unknown"
    assert record["content_type"] == "image/png"
    assert record["size"] == len(ICON)

    assert len(payload["clusters"]) == 1
    assert payload["clusters"][0]["mmh3"] == SHODAN_HASH
    assert payload["clusters"][0]["hosts"] == [host]
    assert payload["clusters"][0]["count"] == 1

    rows = list(csv.reader((output_dir / "report.csv").open(encoding="utf-8", newline="")))
    assert rows[0] == list(favhunt.CSV_COLUMNS)
    assert rows[1][0] == host
    assert rows[1][2] == str(SHODAN_HASH)

    hash_file = output_dir / "icons" / f"{SHODAN_HASH}.txt"
    assert hash_file.read_text(encoding="utf-8").splitlines() == [host]

    output = capsys.readouterr().out
    assert "\033[" not in output
    assert f"http.favicon.hash:{SHODAN_HASH}" in output
    assert "services.http.response.favicons.md5_hash:" in output
    assert f'icon_hash="{SHODAN_HASH}"' in output


def test_fallback_to_favicon_png(make_server, tmp_path):
    routes = {
        "/": (200, "text/html; charset=utf-8", b"<html><body>no icons here</body></html>"),
        "/favicon.png": (200, "image/png", ICON),
    }
    server = make_server(routes)
    code, host, _output_dir, payload = _run(server, tmp_path)

    assert code == 0
    assert len(payload["results"]) == 1
    assert payload["results"][0]["icon_url"] == f"http://{host}/favicon.png"
    assert payload["results"][0]["mmh3"] == SHODAN_HASH


def test_fallback_when_root_is_not_found(make_server, tmp_path):
    server = make_server({"/favicon.ico": (200, "image/x-icon", ICON)})
    code, host, _output_dir, payload = _run(server, tmp_path)

    assert code == 0
    assert len(payload["results"]) == 1
    assert payload["results"][0]["icon_url"] == f"http://{host}/favicon.ico"


def test_failed_target_is_reported_but_does_not_abort_scan(make_server, tmp_path):
    server = make_server({"/": (500, "text/plain", b"down")})
    code, _host_name, _output_dir, payload = _run(server, tmp_path)

    assert code == 0
    assert payload["results"] == []
    assert payload["clusters"] == []


def test_scheme_variants_are_deduped(make_server, tmp_path):
    server = make_server(_link_routes())
    host = _host(server)
    report = tmp_path / "dedupe.json"
    argv = [
        "-u",
        f"http://{host}/a",
        "-u",
        f"https://{host.upper()}/b",
        "-u",
        host,
        "--timeout",
        "2",
        "--retries",
        "0",
        "-t",
        "2",
        "--json",
        str(report),
    ]
    assert favhunt.main(argv) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert len(payload["results"]) == 1
    assert payload["results"][0]["host"] == host


def test_list_file_comments_and_blank_lines(make_server, tmp_path):
    server = make_server(_link_routes())
    host = _host(server)
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        f"# comment\n\nhttp://{host}/one\nhttps://{host}/two\n{host}\n", encoding="utf-8"
    )
    report = tmp_path / "list.json"

    code = favhunt.main(
        ["-l", str(target_file), "--timeout", "2", "--retries", "0", "--json", str(report)]
    )
    assert code == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert len(payload["results"]) == 1


def test_quiet_mode_prints_nothing(make_server, tmp_path, capsys):
    server = make_server(_link_routes())
    _code, _host_name, _output_dir, _payload = _run(
        server, tmp_path, ["-q", "--shodan"]
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_shodan_only_flag(make_server, tmp_path, capsys):
    server = make_server(_link_routes())
    host = _host(server)
    code = favhunt.main(
        [
            "-u",
            f"http://{host}",
            "--timeout",
            "2",
            "--retries",
            "0",
            "--json",
            str(tmp_path / "shodan.json"),
            "--shodan",
        ]
    )
    assert code == 0
    output = capsys.readouterr().out
    assert f"http.favicon.hash:{SHODAN_HASH}" in output
    assert "Censys" not in output


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        favhunt.main(["-V"])
    assert excinfo.value.code == 0
    assert favhunt.__version__ in capsys.readouterr().out


def test_missing_list_file_returns_usage_error(tmp_path, capsys):
    code = favhunt.main(["-l", str(tmp_path / "does-not-exist.txt")])
    assert code == 2
    assert "cannot read" in capsys.readouterr().err


def test_read_targets_from_stdin():
    args = build_parser().parse_args([])
    targets = read_targets(
        args, stdin=io.StringIO("HTTP://Example.com/x\nexample.com\nhttps://other.test/\n")
    )
    assert targets == ["example.com", "other.test"]


def test_read_targets_from_dash_list():
    args = build_parser().parse_args(["-l", "-"])
    assert read_targets(args, stdin=io.StringIO("example.com\n")) == ["example.com"]


def test_read_targets_errors_when_interactive_and_empty():
    class _FakeTty(io.StringIO):
        def isatty(self):
            return True

    args = build_parser().parse_args([])
    with pytest.raises(InputError):
        read_targets(args, stdin=_FakeTty())


def test_read_targets_errors_on_empty_input():
    args = build_parser().parse_args([])
    with pytest.raises(InputError):
        read_targets(args, stdin=io.StringIO(""))
