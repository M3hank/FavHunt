#!/usr/bin/env python3
"""FavHunt - fast favicon-based asset mapping and technology fingerprinting.

The tool normalises targets to a host (no scheme), discovers the best available
favicon (HTML <link> hints first, then well-known fallback paths), computes both
the Shodan-compatible MurmurHash3 (base64 of the icon) and the raw-content hash,
and groups assets that share the same icon.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence
from urllib.parse import urljoin, urlparse

try:  # pragma: no cover - exercised implicitly by every scan
    import mmh3
except ImportError:  # pragma: no cover - allows --help / --version without mmh3
    mmh3 = None  # type: ignore[assignment]

APP_NAME = "favhunt"
__version__ = "2.0.0"

DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 8.0
DEFAULT_RETRIES = 1
DEFAULT_RATE = 0.0
REDIRECT_LIMIT = 5
MAX_ICON_BYTES = 2 * 1024 * 1024
MAX_PAGE_BYTES = 1024 * 1024
MAX_HTML_ICONS = 8
MAX_ICON_CANDIDATES = 16
MAX_RETRY_SLEEP = 2.0
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
ICON_FALLBACK_PATHS = ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

#: Small offline safety net used when ``fingerprints.json`` cannot be loaded.
#: Keys are Shodan-compatible favicon hashes (mmh3 of base64-encoded icon bytes).
BUILTIN_FINGERPRINTS = {
    81586312: "jenkins",
    116323821: "spring",
    236809709: "atlassian",
    -38580010: "magento",
    -297069493: "tomcat",
    -949618468: "facebook",
    -1010568750: "phpmyadmin",
    -1038557304: "webmin",
    -1082845244: "rabbitmq",
    -1200737715: "kibana",
    -1399433489: "prometheus",
    -1610980956: "drupal",
    -1950415971: "joomla",
    1265477436: "gitlab",
    1485257654: "sonarqube",
    1848946384: "github",
    1884422630: "wordpress",
    1900658278: "cloudflare",
    2123863676: "grafana",
    2130463260: "kubernetes",
}

CSV_COLUMNS = ("host", "icon_url", "mmh3", "mmh3_raw", "tech", "content_type", "size")
JSON_RESULT_COLUMNS = CSV_COLUMNS

_HOSTNAME_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?$")
_ICON_REL_TOKENS = frozenset(
    {"icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"}
)
_COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

_BANNER = r"""
    ______              __  __             __
   / ____/___ __   __  / / / /__  ______  / /_
  / /_  / __ `/ | / / / /_/ / / / / __ \/ __/
 / __/ / /_/ /| |/ / / __  / /_/ / / / / /_
/_/    \__,_/ |___/ /_/ /_/\__,_/_/ /_/\__/
"""


class InputError(Exception):
    """Raised when targets cannot be read from the requested sources."""


# ---------------------------------------------------------------------------
# Target normalisation
# ---------------------------------------------------------------------------


def normalize_host(raw: str) -> Optional[str]:
    """Return ``host[:port]`` for an arbitrary target string, or ``None``.

    Schemes, paths, queries, fragments and credentials are stripped, the host is
    lower-cased, default ports (80/443) are removed and IPv6 literals are
    bracketed again so the value can be embedded in a URL safely.
    """
    value = (raw or "").strip()
    if not value or value.startswith("#"):
        return None

    if value.startswith("//"):
        value = "http:" + value
    elif "://" not in value:
        value = "//" + value

    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not hostname:
        return None

    host = hostname.strip().rstrip(".").lower()
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not host or any(char in host for char in "/\\@ "):
        return None

    if ":" in host:
        # IPv6 literal (urlparse strips the brackets).
        if not _is_ipv6(host):
            return None
        host = f"[{host}]"
    elif not _HOSTNAME_RE.match(host):
        return None

    if port is not None and port not in (80, 443):
        host = f"{host}:{port}"
    return host


def _is_ipv6(value: str) -> bool:
    try:
        return ":" in value and isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def normalize_targets(values: Iterable[str]) -> list[str]:
    """Normalise and de-duplicate targets while preserving input order."""
    seen: set[str] = set()
    targets: list[str] = []
    for value in values:
        host = normalize_host(value)
        if host and host not in seen:
            seen.add(host)
            targets.append(host)
    return targets


def format_url(target: str, path: str = "/favicon.ico") -> str:
    """Return an HTTPS URL for ``target`` (HTTPS is always preferred)."""
    host = normalize_host(target)
    if host is None:
        raise ValueError(f"invalid target: {target!r}")
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{host}{path}"


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


@dataclass
class FetchResult:
    """Outcome of a single HTTP GET (after retries)."""

    url: str
    status: Optional[int] = None
    content_type: str = ""
    data: bytes = b""
    final_url: str = ""
    error: str = ""
    attempts: int = 0

    @property
    def ok(self) -> bool:
        """True when the response is a usable 200 with a non-empty body."""
        return self.status == 200 and not self.error and bool(self.data)

    @property
    def effective_url(self) -> str:
        return self.final_url or self.url

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    """Bounded redirects restricted to HTTP(S)."""

    max_redirections = REDIRECT_LIMIT

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        if urlparse(newurl).scheme.lower() not in ("http", "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RateLimiter:
    """Simple thread-safe requests-per-second limiter (0 disables it)."""

    def __init__(self, rate: float) -> None:
        self._interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(now, self._next_slot) + self._interval
        if wait > 0:
            time.sleep(wait)


@dataclass(frozen=True)
class ScanConfig:
    """Network behaviour shared by every worker."""

    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    rate: float = DEFAULT_RATE
    retry_backoff: float = 0.25
    max_icon_bytes: int = MAX_ICON_BYTES
    max_page_bytes: int = MAX_PAGE_BYTES
    verify_tls: bool = False
    user_agent: str = USER_AGENT


class HttpFetcher:
    """HTTP client with timeouts, bounded retries, redirects and rate limiting."""

    def __init__(self, config: ScanConfig, limiter: Optional[RateLimiter] = None) -> None:
        self.config = config
        self.limiter = limiter
        context = ssl.create_default_context()
        if not config.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _RedirectHandler(),
        )
        self._headers = {
            "User-Agent": config.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def get(self, url: str, max_bytes: int = MAX_PAGE_BYTES) -> FetchResult:
        result = FetchResult(url=url)
        for attempt in range(self.config.retries + 1):
            if self.limiter is not None:
                self.limiter.acquire()
            result = self._get_once(url, max_bytes)
            result.attempts = attempt + 1
            if not _should_retry(result) or attempt >= self.config.retries:
                break
            time.sleep(min(self.config.retry_backoff * (attempt + 1), MAX_RETRY_SLEEP))
        return result

    def _get_once(self, url: str, max_bytes: int) -> FetchResult:
        request = urllib.request.Request(url, headers=self._headers, method="GET")
        try:
            with self._opener.open(request, timeout=self.config.timeout) as response:
                status = int(getattr(response, "status", 200) or 200)
                content_type = (response.headers.get("Content-Type") or "")
                content_type = content_type.split(";")[0].strip().lower()
                final_url = response.geturl() or url
                length = (response.headers.get("Content-Length") or "").strip()
                if length.isdigit() and int(length) > max_bytes:
                    return FetchResult(
                        url=url,
                        status=status,
                        content_type=content_type,
                        final_url=final_url,
                        error=f"response too large ({length} bytes)",
                    )
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    return FetchResult(
                        url=url,
                        status=status,
                        content_type=content_type,
                        final_url=final_url,
                        error=f"response larger than {max_bytes} bytes",
                    )
                return FetchResult(
                    url=url,
                    status=status,
                    content_type=content_type,
                    data=data,
                    final_url=final_url,
                )
        except urllib.error.HTTPError as exc:
            content_type = (exc.headers.get("Content-Type") if exc.headers else "") or ""
            return FetchResult(
                url=url,
                status=exc.code,
                content_type=content_type.split(";")[0].strip().lower(),
                final_url=exc.geturl() or url,
                error=f"HTTP {exc.code}",
            )
        except (OSError, ValueError) as exc:  # URLError, timeouts, TLS and DNS errors
            reason = getattr(exc, "reason", None) or str(exc) or exc.__class__.__name__
            return FetchResult(url=url, error=str(reason))
        except Exception as exc:  # pragma: no cover - defensive catch-all
            return FetchResult(url=url, error=f"{exc.__class__.__name__}: {exc}")


def _should_retry(result: FetchResult) -> bool:
    if result.error and result.status is None:
        return True
    return result.status in RETRY_STATUS


# ---------------------------------------------------------------------------
# Parsing / icon discovery
# ---------------------------------------------------------------------------


class _IconLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.icons: list[str] = []
        self.base_href: Optional[str] = None

    def handle_starttag(self, tag, attrs):  # noqa: D102
        attributes = {name.lower(): (value or "") for name, value in attrs}
        tag = tag.lower()
        if tag == "base":
            if self.base_href is None and attributes.get("href"):
                self.base_href = attributes["href"]
            return
        if tag != "link":
            return
        tokens = set(attributes.get("rel", "").lower().split())
        if not tokens & _ICON_REL_TOKENS:
            return
        href = attributes.get("href", "").strip()
        if href:
            self.icons.append(href)


def extract_icon_links(html: str, page_url: str, limit: int = MAX_HTML_ICONS) -> list[str]:
    """Extract absolute icon URLs from ``<link rel="...icon...">`` tags."""
    parser = _IconLinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # pragma: no cover - malformed markup must not abort a scan
        pass

    base = urljoin(page_url, parser.base_href.strip()) if parser.base_href else page_url
    links: list[str] = []
    for href in parser.icons:
        candidate = href.strip()
        if not candidate or candidate.lower().startswith(("data:", "javascript:", "mailto:")):
            continue
        absolute = urljoin(base, candidate)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue
        if absolute not in links:
            links.append(absolute)
        if len(links) >= limit:
            break
    return links


def _looks_like_html(data: bytes) -> bool:
    prefix = data[:512].lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def icon_rejection_reason(result: FetchResult, max_bytes: int = MAX_ICON_BYTES) -> str:
    """Return an empty string when ``result`` is a valid icon, else the reason."""
    if result.status is None:
        return result.error or "request failed"
    if result.error:
        return result.error
    if result.status != 200:
        return f"HTTP {result.status}"
    if not result.data:
        return "empty response"
    if len(result.data) > max_bytes:
        return "icon too large"
    if result.content_type.startswith("text/html"):
        return "HTML content-type"
    if _looks_like_html(result.data):
        return "HTML response body"
    return ""


def probe_page(host: str, fetcher: HttpFetcher) -> tuple[str, Optional[FetchResult]]:
    """Fetch ``/`` over HTTPS first, falling back to HTTP.

    Returns the scheme that should be preferred for icon lookups plus the page
    response (``None`` when no scheme answered at all).
    """
    responded: Optional[tuple[str, FetchResult]] = None
    for scheme in ("https", "http"):
        result = fetcher.get(f"{scheme}://{host}/", fetcher.config.max_page_bytes)
        if result.ok:
            return scheme, result
        if result.status is not None and responded is None:
            responded = (scheme, result)
    return responded if responded is not None else ("https", None)


def page_scheme(page: Optional[FetchResult], fallback: str = "https") -> str:
    if page is not None:
        scheme = urlparse(page.effective_url).scheme.lower()
        if scheme in ("http", "https"):
            return scheme
    return fallback


def collect_icon_candidates(
    host: str,
    page: Optional[FetchResult],
    preferred_scheme: str = "https",
) -> list[str]:
    """Build the ordered icon candidate list: HTML hints, then fallback paths."""
    candidates: list[str] = []
    if page is not None and page.ok:
        candidates.extend(extract_icon_links(page.text, page.effective_url))

    schemes = [preferred_scheme] + [
        scheme for scheme in ("https", "http") if scheme != preferred_scheme
    ]
    for scheme in schemes:
        for path in ICON_FALLBACK_PATHS:
            candidates.append(f"{scheme}://{host}{path}")

    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return ordered[:MAX_ICON_CANDIDATES]


# ---------------------------------------------------------------------------
# Hashing / fingerprinting
# ---------------------------------------------------------------------------


def compute_hashes(data: bytes) -> tuple[int, int]:
    """Return ``(shodan_hash, raw_hash)`` for icon ``data``.

    The Shodan-compatible value is ``mmh3.hash(base64.encodebytes(data))`` with
    the default seed and signed output; ``base64.encodebytes`` inserts newlines,
    which is exactly what Shodan indexes.
    """
    if mmh3 is None:
        raise RuntimeError("the 'mmh3' package is required: pip install mmh3")
    shodan_hash = int(mmh3.hash(base64.encodebytes(data)))
    raw_hash = int(mmh3.hash(data))
    return shodan_hash, raw_hash


def default_fingerprint_path() -> Path:
    """Resolve ``fingerprints.json`` next to this module (not the CWD)."""
    return Path(__file__).resolve().parent / "fingerprints.json"


def _coerce_tech(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("name", "tech", "technology", "product"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return ""


def load_fingerprints(
    path: Optional[Path] = None,
    warn: Optional[Callable[[str], None]] = None,
) -> dict[int, str]:
    """Load the fingerprint database, always keeping the built-in fallback map.

    Accepts integer-like string keys (including negative hashes) and values that
    are either strings or dicts with a ``name``/``tech`` field.
    """
    fingerprints: dict[int, str] = dict(BUILTIN_FINGERPRINTS)
    database = Path(path) if path is not None else default_fingerprint_path()
    notifier = warn if callable(warn) else None

    if not database.is_file():
        if notifier:
            notifier(
                f"fingerprint database not found at {database}; "
                f"using built-in map ({len(fingerprints)} entries)"
            )
        return fingerprints

    try:
        raw = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        if notifier:
            notifier(f"could not read {database}: {exc}; using built-in map")
        return fingerprints

    if not isinstance(raw, dict):
        if notifier:
            notifier(f"{database} does not contain a JSON object; using built-in map")
        return fingerprints

    loaded = 0
    for key, value in raw.items():
        tech = _coerce_tech(value)
        if not tech:
            continue
        try:
            icon_hash = int(str(key).strip())
        except ValueError:
            continue
        fingerprints[icon_hash] = tech
        loaded += 1

    if notifier and loaded == 0:
        notifier(f"no usable entries in {database}; using built-in map")
    return fingerprints


def lookup_tech(
    fingerprints: dict[int, str],
    shodan_hash: Optional[int],
    raw_hash: Optional[int] = None,
) -> str:
    """Look up a technology by Shodan hash, then by raw hash as a fallback."""
    if shodan_hash is not None:
        tech = fingerprints.get(int(shodan_hash))
        if tech:
            return tech
    if raw_hash is not None:
        tech = fingerprints.get(int(raw_hash))
        if tech:
            return tech
    return "Unknown"


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


@dataclass
class HostResult:
    host: str
    icon_url: str = ""
    mmh3: Optional[int] = None
    mmh3_raw: Optional[int] = None
    tech: str = "Unknown"
    content_type: str = ""
    size: int = 0
    md5: str = ""
    error: str = ""
    tried: list[tuple[str, str]] = field(default_factory=list)


def scan_host(
    host: str,
    config: ScanConfig,
    fetcher: HttpFetcher,
    fingerprints: dict[int, str],
) -> HostResult:
    """Discover and hash a single host's icon."""
    scheme, page = probe_page(host, fetcher)
    candidates = collect_icon_candidates(host, page, page_scheme(page, scheme))

    tried: list[tuple[str, str]] = []
    for url in candidates:
        result = fetcher.get(url, config.max_icon_bytes)
        reason = icon_rejection_reason(result, config.max_icon_bytes)
        if reason:
            tried.append((url, reason))
            continue
        try:
            shodan_hash, raw_hash = compute_hashes(result.data)
        except RuntimeError as exc:
            return HostResult(host=host, error=str(exc), tried=tried)
        return HostResult(
            host=host,
            icon_url=result.effective_url,
            mmh3=shodan_hash,
            mmh3_raw=raw_hash,
            tech=lookup_tech(fingerprints, shodan_hash, raw_hash),
            content_type=result.content_type,
            size=len(result.data),
            md5=hashlib.md5(result.data).hexdigest(),
            tried=tried,
        )

    detail = tried[-1][1] if tried else "no candidates"
    return HostResult(host=host, error=f"no usable favicon ({detail})", tried=tried)


def scan_targets(
    targets: Sequence[str],
    config: ScanConfig,
    fingerprints: dict[int, str],
    threads: int,
    console: "Console",
) -> tuple[list[HostResult], list[HostResult], float]:
    """Scan every target concurrently and return successes, failures, elapsed."""
    fetcher = HttpFetcher(config, RateLimiter(config.rate))
    started = time.monotonic()
    results: list[HostResult] = []
    failures: list[HostResult] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_host, host, config, fetcher, fingerprints): host
            for host in targets
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                outcome = HostResult(host=host, error=f"unexpected error: {exc}")

            if outcome.mmh3 is not None and not outcome.error:
                results.append(outcome)
                tech = f" ({outcome.tech})" if outcome.tech != "Unknown" else ""
                console.out(f" [+] {host} -> {outcome.mmh3}{tech}")
            else:
                failures.append(outcome)
                console.debug(f" [-] {host} -> {outcome.error}")
                for url, reason in outcome.tried:
                    console.debug(f"       {url}: {reason}")

    return results, failures, time.monotonic() - started


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def result_to_dict(result: HostResult) -> dict[str, object]:
    """Project a result onto the documented JSON/CSV column set."""
    return {column: getattr(result, column) for column in JSON_RESULT_COLUMNS}


def build_clusters(results: Sequence[HostResult]) -> list[dict[str, object]]:
    """Group results by Shodan hash, largest clusters first."""
    grouped: dict[int, list[HostResult]] = {}
    for result in results:
        if result.mmh3 is None:
            continue
        grouped.setdefault(int(result.mmh3), []).append(result)

    clusters: list[dict[str, object]] = []
    for shodan_hash, members in grouped.items():
        members = sorted(members, key=lambda item: item.host.lower())
        clusters.append(
            {
                "mmh3": shodan_hash,
                "mmh3_raw": members[0].mmh3_raw,
                "tech": members[0].tech,
                "count": len(members),
                "hosts": [member.host for member in members],
                "md5": members[0].md5,
            }
        )
    clusters.sort(key=lambda cluster: (-int(cluster["count"]), int(cluster["mmh3"])))
    return clusters


def shodan_query(shodan_hash: int) -> str:
    return f"http.favicon.hash:{shodan_hash}"


def censys_query(md5_digest: str) -> str:
    return f"services.http.response.favicons.md5_hash:{md5_digest}"


def fofa_query(shodan_hash: int) -> str:
    return f'icon_hash="{shodan_hash}"'


def query_lines(cluster: dict[str, object]) -> list[tuple[str, str]]:
    """Return labelled pivot queries for a cluster (Shodan, Censys, Fofa)."""
    return [
        ("Shodan", shodan_query(int(cluster["mmh3"]))),
        ("Censys", censys_query(str(cluster.get("md5") or ""))),
        ("Fofa", fofa_query(int(cluster["mmh3"]))),
    ]


def write_json(
    path: Path,
    results: Sequence[HostResult],
    clusters: Sequence[dict[str, object]],
    generated_at: Optional[str] = None,
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": APP_NAME,
        "version": __version__,
        "generated_at": generated_at or utc_now_iso(),
        "results": [
            result_to_dict(result)
            for result in sorted(results, key=lambda item: item.host.lower())
        ],
        "clusters": list(clusters),
    }
    destination.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return destination


def write_csv(path: Path, results: Sequence[HostResult]) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for result in sorted(results, key=lambda item: item.host.lower()):
            writer.writerow(result_to_dict(result))
    return destination


def write_text_output(output_dir: Path, results: Sequence[HostResult]) -> list[Path]:
    """Write one ``<shodan_hash>.txt`` file per cluster, as in v1."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    clusters = build_clusters(results)
    written: list[Path] = []
    for cluster in clusters:
        file_path = destination / f"{cluster['mmh3']}.txt"
        file_path.write_text(
            "".join(f"{host}\n" for host in cluster["hosts"]),  # type: ignore[union-attr]
            encoding="utf-8",
        )
        written.append(file_path)
    return written


class Console:
    """Tiny output helper: quiet/verbose levels and TTY-aware colours."""

    def __init__(
        self,
        quiet: bool = False,
        verbose: bool = False,
        color: Optional[bool] = None,
    ) -> None:
        self.quiet = quiet
        self.verbose = verbose
        if color is None:
            color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.color = bool(color)

    def paint(self, text: str, color: str) -> str:
        if not self.color:
            return text
        code = _COLORS.get(color)
        return f"{code}{text}{_COLORS['reset']}" if code else text

    def out(self, text: str = "") -> None:
        if not self.quiet:
            print(text)

    def always(self, text: str = "") -> None:
        print(text)

    def debug(self, text: str = "") -> None:
        if self.verbose and not self.quiet:
            print(text)

    def warn(self, text: str) -> None:
        if not self.quiet:
            print(self.paint(text, "yellow"))

    def error(self, text: str) -> None:
        print(self.paint(text, "red"), file=sys.stderr)


def print_banner(console: Console) -> None:
    """Print the ASCII banner only on a colour-capable (interactive) terminal."""
    if console.quiet or not console.color:
        return
    console.always(console.paint(_BANNER, "cyan"))
    console.always(
        console.paint(
            f"    v{__version__} | Fast, modern asset mapping via favicon DNA\n",
            "cyan",
        )
    )


def print_report(
    console: Console,
    results: Sequence[HostResult],
    failures: Sequence[HostResult],
    clusters: Sequence[dict[str, object]],
    elapsed: float,
) -> None:
    console.out("")
    console.out(
        console.paint(
            "=================[ FINGERPRINT INTELLIGENCE ]=================",
            "bold",
        )
    )

    if not clusters:
        console.warn("[!] No favicons could be retrieved.")
    for cluster in clusters:
        tech = str(cluster["tech"])
        color = "magenta" if tech != "Unknown" else "blue"
        header = console.paint(f"[Hash: {cluster['mmh3']}]", color)
        console.out(
            f"\n{header} | Tech: {console.paint(tech, 'bold')} | Count: {cluster['count']}"
        )
        console.debug(f"      mmh3_raw: {cluster['mmh3_raw']}")
        for host in cluster["hosts"]:  # type: ignore[union-attr]
            console.out(f"  -> {host}")

    identified = sum(1 for cluster in clusters if cluster["tech"] != "Unknown")
    console.out("")
    console.out(
        console.paint("====================[ STATS & EXPORT ]========================", "bold")
    )
    console.out(f"Targets   : {len(results) + len(failures)}")
    console.out(f"Clusters  : {len(clusters)}")
    console.out(f"Identified: {identified}")
    console.out(f"Failures  : {len(failures)}")
    console.out(f"Elapsed   : {elapsed:.2f}s")
    if failures:
        console.debug("[!] Failures:")
        for failure in failures:
            console.debug(f"  {failure.host}: {failure.error}")


def print_queries(
    console: Console,
    clusters: Sequence[dict[str, object]],
    shodan_only: bool,
) -> None:
    if not clusters:
        return
    console.out("")
    console.out(console.paint("[!] Pivot queries:", "yellow"))
    for cluster in clusters:
        hosts = ", ".join(cluster["hosts"])  # type: ignore[arg-type]
        if shodan_only:
            entries = query_lines(cluster)[:1]
        else:
            entries = query_lines(cluster)
        for label, query in entries:
            console.out(f"  {label:<7}: {console.paint(query, 'cyan')}  ({hosts})")


def export_results(
    console: Console,
    results: Sequence[HostResult],
    clusters: Sequence[dict[str, object]],
    output_dir: Optional[str],
    json_path: Optional[str],
    csv_path: Optional[str],
) -> None:
    if output_dir:
        if results:
            files = write_text_output(Path(output_dir), results)
            console.out(f"[+] Wrote {len(files)} hash file(s) to {output_dir}")
        else:
            console.warn("[!] No results to write to the output directory.")

    if json_path:
        destination = write_json(Path(json_path), results, clusters)
        console.out(f"[+] JSON report: {destination}")

    if csv_path:
        destination = write_csv(Path(csv_path), results)
        console.out(f"[+] CSV report : {destination}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="FavHunt - favicon-based asset mapping and technology fingerprinting.",
        epilog="Example: python3 favhunt.py -l urls.txt -t 20 -o outdir --shodan",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="append",
        metavar="FILE",
        help="file with target URLs (repeatable, '-' reads stdin)",
    )
    parser.add_argument(
        "-u",
        "--url",
        action="append",
        metavar="URL",
        help="single target (repeatable)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=_positive_int,
        default=DEFAULT_THREADS,
        help=f"number of concurrent workers (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--retries",
        type=_non_negative_int,
        default=DEFAULT_RETRIES,
        help=f"retries per request on transient failures (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--rate",
        type=_non_negative_float,
        default=DEFAULT_RATE,
        help="global requests per second, 0 = unlimited (default: 0)",
    )
    parser.add_argument("-o", "--output", metavar="DIR", help="write grouped <hash>.txt files here")
    parser.add_argument("--json", metavar="PATH", help="write a JSON report to PATH")
    parser.add_argument("--csv", metavar="PATH", help="write a CSV report to PATH")
    parser.add_argument("--shodan", action="store_true", help="print Shodan dorks per cluster")
    parser.add_argument(
        "--queries",
        action="store_true",
        help="print Shodan, Censys and Fofa queries per cluster",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress non-error output")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show per-target failures and every icon URL that was tried",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _read_target_file(name: str, stdin) -> list[str]:
    if name == "-":
        return stdin.read().splitlines()
    try:
        return Path(name).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise InputError(f"cannot read '{name}': {exc}") from exc


def read_targets(args: argparse.Namespace, stdin=None) -> list[str]:
    """Collect raw targets from ``-u``, ``-l`` or stdin (in that order)."""
    stream = stdin if stdin is not None else sys.stdin
    raw: list[str] = list(args.url or [])

    for name in args.list or []:
        raw.extend(_read_target_file(name, stream))

    if not raw and not args.list and not args.url:
        if stream.isatty():
            raise InputError(
                "no targets provided. Use -l FILE, -u URL or pipe a list on stdin."
            )
        raw.extend(stream.read().splitlines())

    targets = normalize_targets(raw)
    if not targets:
        raise InputError("no valid targets found in the provided input")
    return targets


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    console = Console(quiet=args.quiet, verbose=args.verbose)
    print_banner(console)

    if mmh3 is None:
        console.error("[!] 'mmh3' is required: pip install mmh3")
        return 1

    try:
        targets = read_targets(args)
    except InputError as exc:
        console.error(f"[!] {exc}")
        return 2

    config = ScanConfig(timeout=args.timeout, retries=args.retries, rate=args.rate)
    fingerprints = load_fingerprints(warn=console.warn)

    console.out(
        f"[*] Scanning {len(targets)} target(s) with {args.threads} threads "
        f"(timeout {config.timeout:g}s, retries {config.retries})"
    )
    results, failures, elapsed = scan_targets(
        targets, config, fingerprints, args.threads, console
    )
    clusters = build_clusters(results)

    print_report(console, results, failures, clusters, elapsed)

    if args.queries:
        print_queries(console, clusters, shodan_only=False)
    elif args.shodan:
        print_queries(console, clusters, shodan_only=True)

    export_results(console, results, clusters, args.output, args.json, args.csv)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Execution aborted by user.")
        raise SystemExit(130) from None
