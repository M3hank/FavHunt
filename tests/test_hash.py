from __future__ import annotations

import base64

import pytest

mmh3 = pytest.importorskip("mmh3")

from favhunt import compute_hashes  # noqa: E402

ICON = b"\x89PNG\r\n\x1a\nfake-icon-bytes"


def test_known_vectors():
    """Pinned values computed with mmh3 4.x (seed=0, signed output)."""
    shodan_hash, raw_hash = compute_hashes(ICON)
    assert shodan_hash == -1768129442
    assert raw_hash == 794015155


def test_shodan_hash_uses_base64_with_newlines():
    encoded = base64.encodebytes(ICON)
    assert encoded.endswith(b"\n")
    assert compute_hashes(ICON)[0] == mmh3.hash(encoded)


def test_raw_hash_does_not_match_shodan_hash():
    shodan_hash, raw_hash = compute_hashes(ICON)
    assert shodan_hash != raw_hash
    assert raw_hash == mmh3.hash(ICON)


def test_empty_icon_hashes_to_zero():
    assert compute_hashes(b"") == (0, 0)


def test_large_icon_base64_wrapping_is_consistent():
    data = bytes(range(256)) * 4
    encoded = base64.encodebytes(data)
    assert encoded.count(b"\n") > 1
    assert compute_hashes(data)[0] == mmh3.hash(encoded)
