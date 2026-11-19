from __future__ import annotations

import csv
import json

from favhunt import (
    CSV_COLUMNS,
    HostResult,
    build_clusters,
    query_lines,
    result_to_dict,
    write_csv,
    write_json,
    write_text_output,
)


def _results():
    return [
        HostResult(
            host="b.example",
            icon_url="https://b.example/favicon.ico",
            mmh3=111,
            mmh3_raw=222,
            tech="wordpress",
            content_type="image/x-icon",
            size=10,
            md5="a" * 32,
        ),
        HostResult(
            host="a.example",
            icon_url="https://a.example/favicon.ico",
            mmh3=111,
            mmh3_raw=222,
            tech="wordpress",
            content_type="image/x-icon",
            size=10,
            md5="a" * 32,
        ),
        HostResult(
            host="c.example",
            icon_url="https://c.example/favicon.ico",
            mmh3=333,
            mmh3_raw=444,
            tech="Unknown",
            content_type="image/png",
            size=20,
            md5="b" * 32,
        ),
    ]


def test_build_clusters_groups_sorts_and_counts():
    clusters = build_clusters(_results())
    assert [cluster["mmh3"] for cluster in clusters] == [111, 333]
    assert clusters[0]["count"] == 2
    assert clusters[0]["hosts"] == ["a.example", "b.example"]
    assert clusters[0]["tech"] == "wordpress"
    assert clusters[0]["mmh3_raw"] == 222
    assert clusters[1]["count"] == 1
    assert clusters[1]["tech"] == "Unknown"


def test_result_to_dict_matches_documented_columns():
    record = result_to_dict(_results()[0])
    assert list(record) == list(CSV_COLUMNS)
    assert record["host"] == "b.example"
    assert record["mmh3"] == 111
    assert record["mmh3_raw"] == 222
    assert record["size"] == 10


def test_write_json_schema_and_ordering(tmp_path):
    destination = tmp_path / "reports" / "scan.json"
    written = write_json(destination, _results(), build_clusters(_results()), "2026-11-19T00:00:00Z")

    assert written == destination
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert list(payload) == ["tool", "version", "generated_at", "results", "clusters"]
    assert payload["tool"] == "favhunt"
    assert payload["version"] == "2.0.0"
    assert payload["generated_at"] == "2026-11-19T00:00:00Z"
    assert [record["host"] for record in payload["results"]] == [
        "a.example",
        "b.example",
        "c.example",
    ]
    assert list(payload["results"][0]) == list(CSV_COLUMNS)
    assert payload["clusters"][0]["hosts"] == ["a.example", "b.example"]


def test_write_json_with_empty_results(tmp_path):
    destination = tmp_path / "empty.json"
    write_json(destination, [], [])
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["results"] == []
    assert payload["clusters"] == []


def test_write_csv_header_and_rows(tmp_path):
    destination = tmp_path / "scan.csv"
    write_csv(destination, _results())

    with destination.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))

    assert rows[0] == list(CSV_COLUMNS)
    assert [row[0] for row in rows[1:]] == ["a.example", "b.example", "c.example"]
    assert rows[1][2] == "111"
    assert rows[1][3] == "222"
    assert len(rows) == 4


def test_write_text_output_one_file_per_hash(tmp_path):
    written = write_text_output(tmp_path / "icons", _results())
    names = sorted(path.name for path in written)
    assert names == ["111.txt", "333.txt"]
    assert (tmp_path / "icons" / "111.txt").read_text(encoding="utf-8").splitlines() == [
        "a.example",
        "b.example",
    ]
    assert (tmp_path / "icons" / "333.txt").read_text(encoding="utf-8").splitlines() == [
        "c.example"
    ]


def test_query_lines_cover_shodan_censys_and_fofa():
    cluster = build_clusters(_results())[0]
    queries = dict(query_lines(cluster))
    assert queries["Shodan"] == "http.favicon.hash:111"
    assert queries["Censys"] == "services.http.response.favicons.md5_hash:" + "a" * 32
    assert queries["Fofa"] == 'icon_hash="111"'
