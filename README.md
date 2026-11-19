# FavHunt

Fast favicon-based asset mapping and technology fingerprinting for bug bounty,
OSINT and red team reconnaissance.

FavHunt takes a list of targets, finds each site's real icon (not just
`/favicon.ico`), computes MurmurHash3 fingerprints, and groups assets that share
the same icon. Shared icons instantly reveal related infrastructure: the same
product, the same admin panel, or the same forgotten staging cluster.
Identification uses a bundled database of **1,400+ known favicon hashes**.

## Features

- **Smart icon discovery** - parses the HTML of `/` for `<link rel="icon">`,
  `shortcut icon`, `apple-touch-icon`, `apple-touch-icon-precomposed` and
  `mask-icon` (including `<base href>`), then falls back to `/favicon.ico`,
  `/favicon.png` and `/apple-touch-icon.png`.
- **HTTPS first** - every target is probed over HTTPS and falls back to HTTP
  only when needed.
- **Two hashes per icon** - Shodan-compatible `mmh3(base64(icon))` and the raw
  `mmh3(icon)`, so you can pivot on either convention.
- **Clustering** - assets are grouped by Shodan hash; one text file per cluster.
- **Structured reports** - `--json` and `--csv` for pipelines, plus the original
  per-hash text files via `-o`.
- **Pivot queries** - one flag prints ready-to-paste Shodan, Censys and Fofa
  queries per cluster.
- **Production hygiene** - bounded redirects, timeouts, retries, response size
  limits, HTML/error-page rejection, optional rate limiting, quiet/verbose modes
  and TTY-aware colour output.
- **Offline tests** - the pytest suite uses a local HTTP server; no internet
  access is required.

## Installation

```bash
git clone https://github.com/M3hank/FavHunt.git
cd FavHunt
pip3 install -r requirements.txt
```

Optional, for the `favhunt` command and development tooling:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Original v1 invocation still works
python3 favhunt.py -l urls.txt -t 20 -o outdir --shodan

# Single target / repeated targets
python3 favhunt.py -u https://example.com -u 10.0.0.5

# stdin fallback
cat targets.txt | python3 favhunt.py

# Machine-readable reports
python3 favhunt.py -l urls.txt --json report.json --csv report.csv

# Shodan + Censys + Fofa pivot strings
python3 favhunt.py -l urls.txt --queries

# Throttled, quiet scan of several lists
python3 favhunt.py -l in-scope.txt -l extra.txt -t 10 --rate 5 -q -o out/
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-l, --list FILE` | Target list file; repeatable, `-` reads stdin | None |
| `-u, --url URL` | Single target; repeatable | None |
| `-t, --threads N` | Concurrent workers | 20 |
| `--timeout SECONDS` | Per-request timeout | 8 |
| `--retries N` | Retries on transient errors (network, 429, 5xx) | 1 |
| `--rate N` | Global requests per second, `0` disables | 0 |
| `-o, --output DIR` | Write grouped `<hash>.txt` files | None |
| `--json PATH` | Write a JSON report | None |
| `--csv PATH` | Write a CSV report | None |
| `--shodan` | Print Shodan dorks per cluster | Off |
| `--queries` | Print Shodan, Censys and Fofa queries | Off |
| `-q, --quiet` | Suppress all non-error output | Off |
| `-v, --verbose` | Show failures and every icon URL tried | Off |
| `-V, --version` | Print version and exit | - |

If no `-u` or `-l` is supplied, targets are read from stdin.

### Input format

One target per line. Schemes, paths, queries, fragments, credentials and default
ports are stripped; the host is lower-cased and duplicates are removed.

```
https://example.com
https://sub.target.com/admin
http://192.168.1.1:8080
test.example.com
```

All four forms above are valid; `http://example.com`, `https://example.com/x`
and `EXAMPLE.com` collapse into a single scan of `example.com`.

## How it works

1. **Normalise** the target to `host[:port]` and de-duplicate.
2. **Probe** `https://host/`, falling back to `http://host/`.
3. **Discover** icon candidates in this order:
   - `<link>` icons parsed from the HTML (absolute, relative and protocol-relative
     URLs, resolved against `<base href>` when present);
   - `/favicon.ico`, `/favicon.png`, `/apple-touch-icon.png`.
4. **Validate** each response: HTTP 200, non-empty, at most 2 MiB, not an HTML
   document or `text/html` error page. The first valid icon wins.
5. **Hash** the icon twice:
   - `mmh3` (Shodan): `mmh3.hash(base64.encodebytes(data))` - note that
     `encodebytes` inserts newlines, which is exactly what Shodan indexes;
   - `mmh3_raw`: `mmh3.hash(data)`.
6. **Identify** by looking up the Shodan hash first, then the raw hash as a
   fallback, in `fingerprints.json` (merged over a small built-in map).
7. **Cluster and report**.

## Output

### Per-hash text files (`-o DIR`)

One file per Shodan hash, named `<hash>.txt`, containing one normalised host per
line. This is the same layout as v1 but with normalised hosts.

### JSON (`--json PATH`)

```json
{
  "tool": "favhunt",
  "version": "2.0.0",
  "generated_at": "2026-11-19T12:34:56Z",
  "results": [
    {
      "host": "example.com",
      "icon_url": "https://example.com/static/favicon.png",
      "mmh3": 1884422630,
      "mmh3_raw": 794015155,
      "tech": "wordpress",
      "content_type": "image/png",
      "size": 1150
    }
  ],
  "clusters": [
    {
      "mmh3": 1884422630,
      "mmh3_raw": 794015155,
      "tech": "wordpress",
      "count": 1,
      "hosts": ["example.com"],
      "md5": "9e107d9d372bb6826bd81d3542a419d6"
    }
  ]
}
```

Results are sorted by host; clusters are sorted by size (largest first) and then
by hash. `md5` is the MD5 of the representative icon, used for Censys queries.

### CSV (`--csv PATH`)

```
host,icon_url,mmh3,mmh3_raw,tech,content_type,size
example.com,https://example.com/static/favicon.png,1884422630,794015155,wordpress,image/png,1150
```

### Pivot queries (`--queries`)

```
Shodan : http.favicon.hash:1884422630
Censys : services.http.response.favicons.md5_hash:9e107d9d372bb6826bd81d3542a419d6
Fofa   : icon_hash="1884422630"
```

`--shodan` prints only the Shodan line, preserving v1 behaviour.

## Development

```bash
python3 -m pytest -q      # offline test suite
ruff check .              # lint
```

Tests cover target normalisation and de-duplication, HTML icon parsing, hashing
(including pinned vectors), fingerprint loading, JSON/CSV writers and a full
end-to-end scan against a local `ThreadingHTTPServer`.

## Known limitations

- TLS certificates are **not** verified (matching v1 behaviour for scan targets).
- `fingerprints.json` is resolved next to `favhunt.py`. When the module is
  installed as a wheel without the data file, the built-in fallback map is used.
- The Shodan hash convention is the base64-of-icon form; favicons that Shodan
  indexed differently (for example with a different redirect chain) may not
  match even though the raw hash does.
- Large HTML pages are truncated at 1 MiB for icon discovery; an icon list at
  the very end of a huge page may be missed.
- Only the first valid icon is hashed. Sites that serve different icons per
  path or per user agent will collapse to the discovered icon.
- `--rate` is a global cap across workers, not a per-host limit.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed (even when some or all targets failed) |
| `1` | `mmh3` is not installed |
| `2` | Invalid input: unreadable list file, no targets, or no valid targets |
| `130` | Interrupted with Ctrl-C |

Failures are counted in the summary and detailed with `-v`.

## Credits

Inspired by [FavFreak](https://github.com/devanshbatham/FavFreak) by Devansh
Batham.

## License

MIT - see [LICENSE.txt](LICENSE.txt).
