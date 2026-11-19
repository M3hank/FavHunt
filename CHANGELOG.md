# Changelog

All notable changes to FavHunt are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-19

### Added

- Icon discovery from HTML (`<link rel="icon">`, `shortcut icon`,
  `apple-touch-icon`, `apple-touch-icon-precomposed`, `mask-icon`, `<base href>`),
  with fallbacks to `/favicon.ico`, `/favicon.png` and `/apple-touch-icon.png`.
- HTTPS-first probing with an HTTP fallback per target.
- Raw-content hash (`mmh3.hash(data)`) alongside the Shodan-compatible
  `mmh3.hash(base64.encodebytes(data))` hash, in results, JSON and CSV.
- Structured output: `--json PATH` (documented schema) and `--csv PATH`, while
  `-o DIR` keeps writing one `<hash>.txt` file per cluster.
- `--queries` for Shodan, Censys and Fofa pivot strings; `--shodan` remains.
- `-u/--url` (repeatable), multiple `-l/--list` files, `-` for stdin, and a
  plain stdin fallback.
- `--timeout`, `--retries`, `--rate` (requests/second), `-q/--quiet`,
  `-v/--verbose` and `-V/--version`.
- Bounded redirects, response size limits, content-type/HTML sniffing, transient
  error retries and an optional global rate limiter.
- Built-in fingerprint fallback map and support for string keys / dict values in
  `fingerprints.json`.
- Typed-ish, testable modules: `fetch`, `parse`, `report` and `main` sections.
- Offline pytest suite (local `ThreadingHTTPServer`, no internet required),
  `pyproject.toml`, GitHub Actions CI (Python 3.10-3.13, ruff + pytest).

### Changed

- Target input is normalised to lowercase `host[:port]`: schemes, paths,
  credentials, fragments and default ports (80/443) are stripped.
- `fingerprints.json` is resolved relative to `favhunt.py`, not the current
  working directory.
- Per-target failures are summarised; details are only shown with `-v`.
- The fingerprint database is always merged over the built-in map, so a missing
  or malformed file degrades gracefully instead of disabling identification.
- Terminal output is colourless and banner-free when stdout is not a TTY.
- Shodan dorks are printed for every cluster (including hash `0`).

### Fixed

- `format_url()` no longer forces `http://`; HTTPS is tried first.
- Removed the meaningless `icon_hash != 0` filter.
- Duplicate targets supplied as `http://`, `https://` and bare hostnames are
  de-duplicated before scanning.
- Redirects no longer follow non-HTTP(S) schemes and are capped at five hops.

### Removed

- The `FavHunt` class and `display_banner()` helper; the public entry point is
  `favhunt.main()` (the CLI is unchanged apart from the additions above).

## [1.0.0]

- Initial public release: single `/favicon.ico` fetch, MurmurHash3, Shodan dorks
  and one text file per hash.
