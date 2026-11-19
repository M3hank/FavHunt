from __future__ import annotations

import json

from favhunt import (
    BUILTIN_FINGERPRINTS,
    default_fingerprint_path,
    load_fingerprints,
    lookup_tech,
)


def test_repository_database_loads_and_merges_builtins():
    fingerprints = load_fingerprints(default_fingerprint_path())
    assert len(fingerprints) > len(BUILTIN_FINGERPRINTS)
    assert fingerprints[1884422630] == "wordpress"
    assert fingerprints[81586312] == "jenkins"


def test_database_is_resolved_next_to_module():
    path = default_fingerprint_path()
    assert path.name == "fingerprints.json"
    assert path.is_file()


def test_temp_database_accepts_string_keys_and_dict_values(tmp_path):
    database = tmp_path / "fingerprints.json"
    database.write_text(
        json.dumps(
            {
                "123": "Acme Panel",
                " -456 ": {"name": "Other App"},
                "789": {"tech": "Third App"},
                "not-a-hash": "ignored",
                "999": "",
                "1000": {"unknown": "shape"},
            }
        ),
        encoding="utf-8",
    )

    fingerprints = load_fingerprints(database)
    assert fingerprints[123] == "Acme Panel"
    assert fingerprints[-456] == "Other App"
    assert fingerprints[789] == "Third App"
    assert 999 not in fingerprints
    assert 1000 not in fingerprints
    assert "ignored" not in fingerprints.values()


def test_database_overrides_builtin_entries(tmp_path):
    database = tmp_path / "fingerprints.json"
    database.write_text('{"81586312": "custom-jenkins"}', encoding="utf-8")
    fingerprints = load_fingerprints(database)
    assert fingerprints[81586312] == "custom-jenkins"


def test_missing_database_falls_back_to_builtins(tmp_path):
    warnings = []
    fingerprints = load_fingerprints(tmp_path / "missing.json", warn=warnings.append)
    assert fingerprints[81586312] == "jenkins"
    assert warnings and "built-in" in warnings[0]


def test_default_database_is_found_from_another_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fingerprints = load_fingerprints()
    assert len(fingerprints) > len(BUILTIN_FINGERPRINTS)
    assert fingerprints[1884422630] == "wordpress"


def test_malformed_database_falls_back_to_builtins(tmp_path):
    database = tmp_path / "fingerprints.json"
    database.write_text("{not json", encoding="utf-8")
    warnings = []
    fingerprints = load_fingerprints(database, warn=warnings.append)
    assert fingerprints[1884422630] == "wordpress"
    assert warnings and "could not read" in warnings[0]


def test_lookup_prefers_shodan_hash_then_raw_hash():
    fingerprints = {1: "by-shodan", 2: "by-raw"}
    assert lookup_tech(fingerprints, 1, 2) == "by-shodan"
    assert lookup_tech(fingerprints, 999, 2) == "by-raw"
    assert lookup_tech(fingerprints, None, None) == "Unknown"
    assert lookup_tech(fingerprints, 999, 998) == "Unknown"
