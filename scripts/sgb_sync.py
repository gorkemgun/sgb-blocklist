#!/usr/bin/env python3
"""
Sync the malicious address list published by the Turkish Cyber Security
Presidency (T.C. Siber Guvenlik Baskanligi).

Source API : https://siberguvenlik.gov.tr/api/address/index  (no authentication)
API docs   : https://siberguvenlik.gov.tr/api/

The plain-text feed that used to live at usom.gov.tr/url-list.txt was retired
on 1 June 2026. The API is now the only way to get the data. This script walks
the API and writes plain-text lists.

Output files (into the directory given by --out):
  domains.txt            -> type=domain
  urls.txt               -> type=url
  ipv4.txt               -> type=ip
  ipv6.txt               -> type=ip6
  ipv6net.txt            -> type=ip6net
  url-list.txt           -> drop-in for the old url-list.txt: everything, no header
  domains-from-urls.txt  -> hostnames extracted from URL records
  categories/<type>-<CODE>.txt -> one list per malicious category (desc code)
  state.json             -> sync state (required by delta mode)

Modes:
  full   -> page through everything from scratch (also drops de-listed records)
  delta  -> fetch only records newer than the last run recorded in state.json
            and merge them into the existing lists (1 request per type)
  auto   -> full when state.json is missing, when the output layout version
            changed, or when the last full run is older than --full-interval.
            Delta otherwise. This is the default.

Standard library only.
"""

from __future__ import annotations

import argparse
import gzip
import io
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

API_URL = "https://siberguvenlik.gov.tr/api/address/index"
USER_AGENT = "sgb-url-list-sync/2.0 (+https://github.com/)"

# Server-side maximum: per-page 1..9999 (anything above returns HTTP 429)
PER_PAGE = 9999
# Politeness delay between pages, in seconds
PAGE_DELAY = 0.7
# HTTP retries
MAX_RETRIES = 5
RETRY_BACKOFF = (5, 10, 20, 40, 60)
TIMEOUT = 120

# Output layout version. Bumping it forces auto mode into a full run so new
# files can never be left missing or inconsistent.
LAYOUT = 3

# API type -> main output file / category-file prefix
TYPE_FILES = {
    "domain": "domains.txt",
    "url": "urls.txt",
    "ip": "ipv4.txt",
    "ip6": "ipv6.txt",
    "ip6net": "ipv6net.txt",
}
TYPE_PREFIX = {
    "domain": "domains",
    "url": "urls",
    "ip": "ipv4",
    "ip6": "ipv6",
    "ip6net": "ipv6net",
}
PREFIX_TYPE = {v: k for k, v in TYPE_PREFIX.items()}
TYPES = tuple(TYPE_FILES)

TYPE_LABELS = {
    "domain": "Domain",
    "url": "Full URL",
    "ip": "IPv4 address",
    "ip6": "IPv6 address",
    "ip6net": "IPv6 network block",
}

# Category codes and titles as published by /api/address-description/index
DESC_LABELS = {
    "PH": "Phishing",
    "BP": "Financial Phishing",
    "MD": "Malware Distribution Domain",
    "MI": "Malware Distribution IP",
    "MU": "Malware Distribution URL",
    "MC": "Malware Command Center",
    "CA": "Cyber Attack (Port Scan, Brute Force etc.)",
}
# Bucket for records whose desc field is empty or unrecognised
DESC_UNKNOWN = "UNKNOWN"

CATEGORY_DIR = "categories"
CATEGORY_FILE_RE = re.compile(
    r"^(domains|urls|ipv4|ipv6|ipv6net)-([A-Z0-9_-]{1,16})\.txt$"
)
DESC_CODE_RE = re.compile(r"^[A-Z0-9_-]{1,16}$")

# The API 'date' field looks like UTC, but delta queries still reach this many
# hours back to absorb clock skew and delayed inserts.
DELTA_OVERLAP_HOURS = 6

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9_-]{1,63}(?<!-))+$"
)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

DATE_FMT = "%Y-%m-%d %H:%M:%S"


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def http_get_json(url: str) -> dict:
    """GET + JSON, retrying with backoff on 429/5xx and network errors."""
    last_err: Exception | None = None
    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code not in (429, 500, 502, 503, 504):
                raise
            wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
            log(f"  HTTP {exc.code}, retrying in {wait}s "
                f"({attempt + 1}/{MAX_RETRIES})")
            time.sleep(wait)
        except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as exc:
            last_err = exc
            wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
            log(f"  Error: {exc} -> retrying in {wait}s "
                f"({attempt + 1}/{MAX_RETRIES})")
            time.sleep(wait)
    raise RuntimeError(f"Giving up after {MAX_RETRIES} attempts: {url} ({last_err})")


def fetch_records(addr_type: str, date_gte: str | None = None,
                  max_pages: int | None = None):
    """Yield every record from address/index, one page at a time.

    The 'page' query parameter is 1-based (page=0 and page=1 return the same
    first page). Records come back ordered by descending id and new records are
    prepended, so the same row can show up on two consecutive pages during a
    long crawl. Callers de-duplicate through a set.
    """
    page = 1
    page_count = None
    total = 0
    while True:
        params = {"type": addr_type, "per-page": str(PER_PAGE), "page": str(page)}
        if date_gte:
            params["date_gte"] = date_gte
        url = f"{API_URL}?{urllib.parse.urlencode(params)}"
        data = http_get_json(url)

        models = data.get("models") or []
        if page_count is None:
            page_count = int(data.get("pageCount") or 0)
            log(f"  type={addr_type}: totalCount={data.get('totalCount')} "
                f"pageCount={page_count}")
        total += len(models)
        for rec in models:
            yield rec
        log(f"  type={addr_type} page {page}/{page_count or '?'} "
            f"({len(models)} records, {total} so far)")

        if not models or page >= (page_count or 0):
            break
        if max_pages and page >= max_pages:
            log(f"  stopped at --max-pages={max_pages}")
            break
        page += 1
        time.sleep(PAGE_DELAY)


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def normalize_host(value: str) -> str | None:
    """Extract a resolvable hostname from a free-form address string.

    Strips scheme, userinfo, port, path, query and wildcard prefixes, and
    converts IDN labels to punycode. Returns None when no valid domain comes
    out, IP addresses included, since those live in their own files.
    """
    if not value:
        return None
    s = value.strip().strip('"\'').lower()
    if not s:
        return None

    # scheme
    if "://" in s:
        s = s.split("://", 1)[1]
    elif s.startswith("//"):
        s = s[2:]
    # path / query / fragment
    for sep in ("/", "?", "#", "\\"):
        s = s.split(sep, 1)[0]
    # userinfo
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    # bracketed IPv6 literal -> not a domain
    if s.startswith("["):
        return None
    # port
    if ":" in s:
        s = s.split(":", 1)[0]
    # wildcards and stray dots
    s = s.strip().strip(".")
    while s.startswith("*."):
        s = s[2:]
    if not s or "." not in s:
        return None
    if any(c.isspace() for c in s) or "," in s:
        return None

    # IDN -> punycode
    if not s.isascii():
        try:
            s = ".".join(
                lbl if lbl.isascii() else lbl.encode("idna").decode("ascii")
                for lbl in s.split(".")
            )
        except (UnicodeError, UnicodeDecodeError):
            return None

    if IPV4_RE.match(s):
        return None
    if not DOMAIN_RE.match(s):
        return None
    if s.split(".")[-1].isdigit():
        return None
    return s


def normalize_url(value: str) -> str | None:
    """Keep a URL record usable in a line-based file.

    The API serves URLs without a scheme, for example "example.com/bad/path".
    The value is preserved as-is and only trimmed. Records containing
    whitespace would break line-based parsing, so they are dropped.
    """
    if not value:
        return None
    s = value.strip().strip('"\'')
    if not s or any(c.isspace() for c in s):
        return None
    return s


def normalize_ip(value: str, version: int) -> str | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(addr) if addr.version == version else None


def normalize_net(value: str, version: int) -> str | None:
    if not value:
        return None
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    return str(net) if net.version == version else None


def normalize_value(addr_type: str, raw: str) -> str | None:
    if addr_type == "domain":
        return normalize_host(raw)
    if addr_type == "url":
        return normalize_url(raw)
    if addr_type == "ip":
        return normalize_ip(raw, 4)
    if addr_type == "ip6":
        return normalize_ip(raw, 6)
    if addr_type == "ip6net":
        return normalize_net(raw, 6)
    return None


def sort_values(addr_type: str, values) -> list[str]:
    """Sort IP types numerically, everything else lexicographically."""
    vals = list(values)
    if addr_type in ("ip", "ip6"):
        return sorted(vals, key=lambda v: int(ipaddress.ip_address(v)))
    if addr_type == "ip6net":
        return sorted(vals, key=lambda v: (int(ipaddress.ip_network(v).network_address),
                                           ipaddress.ip_network(v).prefixlen))
    return sorted(vals)


def clean_desc(value) -> str:
    code = (value or "").strip().upper()
    return code if DESC_CODE_RE.match(code) else DESC_UNKNOWN


# --------------------------------------------------------------------------- #
# File I/O
# --------------------------------------------------------------------------- #
def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        log("state.json is unreadable, assuming full mode")
        return {}


def file_header(addr_type: str, desc: str | None, count: int, ts: str,
                mode: str) -> str:
    if desc:
        title = (f"{TYPE_LABELS[addr_type]} - "
                 f"{DESC_LABELS.get(desc, 'Unknown category')} ({desc})")
    else:
        title = f"{TYPE_LABELS[addr_type]} - all categories"
    return (
        f"# T.C. Siber Guvenlik Baskanligi - {title}\n"
        f"# Source : {API_URL}?type={addr_type}"
        + (f"&desc={desc}\n" if desc else "\n")
        + f"# Records: {count}\n"
        f"# Last change: {ts} (sync mode: {mode})\n"
    )


# Header lines that carry a timestamp, so they must be ignored when deciding
# whether a file actually changed. "# Updated:" is the pre-LAYOUT-4 spelling.
TIMESTAMP_HEADERS = ("# Last change:", "# Updated:")


def _stable_header(lines: list[str]) -> list[str]:
    return [ln for ln in lines
            if ln.startswith("#") and not ln.startswith(TIMESTAMP_HEADERS)]


def write_if_changed(path: Path, values: list[str], header: str = "",
                     force: bool = False) -> bool:
    """Write a list file only when something other than the clock changed.

    Records and the non-timestamp header lines are compared against what is on
    disk. Leaving an untouched file alone keeps its timestamp honest, since it
    then marks the last actual content change, and stops an hourly run that
    found nothing new from producing a diff in every single file.

    Pass force=True to rewrite regardless, which is what migrates existing
    files after a change to the header layout.
    """
    if path.exists() and not force:
        existing = path.read_text(encoding="utf-8", errors="replace").splitlines()
        body = [ln.strip() for ln in existing
                if ln.strip() and not ln.startswith("#")]
        if body == values and _stable_header(existing) == _stable_header(
                header.splitlines()):
            return False
    write_atomic(path, header + ("\n".join(values) + "\n" if values else ""))
    return True


# --------------------------------------------------------------------------- #
# Previous state (needed by delta mode)
# --------------------------------------------------------------------------- #
def load_previous(out_dir: Path) -> dict[tuple[str, str], set[str]]:
    """Rebuild (type, category) -> values from the category files on disk."""
    buckets: dict[tuple[str, str], set[str]] = defaultdict(set)
    cat_dir = out_dir / CATEGORY_DIR
    if not cat_dir.is_dir():
        return buckets
    for path in sorted(cat_dir.glob("*.txt")):
        m = CATEGORY_FILE_RE.match(path.name)
        if not m:
            continue
        addr_type = PREFIX_TYPE[m.group(1)]
        buckets[(addr_type, m.group(2))].update(read_lines(path))
    return buckets


def prune_category_files(cat_dir: Path, keep: set[str]) -> list[str]:
    """Delete category files a full run no longer produces."""
    removed = []
    if not cat_dir.is_dir():
        return removed
    for path in sorted(cat_dir.glob("*.txt")):
        if CATEGORY_FILE_RE.match(path.name) and path.name not in keep:
            path.unlink()
            removed.append(path.name)
    return removed


# --------------------------------------------------------------------------- #
# Mode selection
# --------------------------------------------------------------------------- #
def decide_mode(args, state: dict, out_dir: Path) -> tuple[str, str | None]:
    """Return (mode, date_gte)."""
    if args.mode == "full":
        return "full", None

    last_run = state.get("last_run")
    last_full = state.get("last_full")

    if args.mode == "auto":
        if not last_run or not last_full:
            log("state.json missing/incomplete -> full")
            return "full", None
        if state.get("layout") != LAYOUT:
            log(f"output layout changed (state={state.get('layout')} "
                f"expected={LAYOUT}) -> full")
            return "full", None
        if not (out_dir / CATEGORY_DIR).is_dir():
            log(f"{CATEGORY_DIR}/ directory is missing -> full")
            return "full", None
        try:
            full_dt = datetime.strptime(last_full, DATE_FMT).replace(tzinfo=timezone.utc)
        except ValueError:
            return "full", None
        age_h = (datetime.now(timezone.utc) - full_dt).total_seconds() / 3600
        if age_h >= args.full_interval:
            log(f"last full run was {age_h:.1f}h ago "
                f"(>= {args.full_interval}) -> full")
            return "full", None

    if not last_run:
        log("no last_run for a delta -> full")
        return "full", None
    try:
        since = datetime.strptime(last_run, DATE_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return "full", None
    since -= timedelta(hours=args.overlap)
    return "delta", since.strftime(DATE_FMT)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("auto", "full", "delta"), default="auto")
    ap.add_argument("--out", default=".", help="output directory (default: .)")
    ap.add_argument("--full-interval", type=float, default=24.0,
                    help="hours between full crawls in auto mode (default 24)")
    ap.add_argument("--overlap", type=float, default=DELTA_OVERLAP_HOURS,
                    help="hours a delta query reaches back beyond the last run "
                         f"(default {DELTA_OVERLAP_HOURS})")
    ap.add_argument("--include-url-hosts", action="store_true",
                    help="also merge hostnames extracted from type=url records "
                         "into domains.txt (covers the whole domain, which can "
                         "be too broad for legitimate sites where only one page "
                         "is malicious)")
    ap.add_argument("--force-write", action="store_true",
                    help="rewrite every list even when nothing changed, which "
                         "is how a change to the file header format gets "
                         "applied to lists that are otherwise static")
    ap.add_argument("--max-pages", type=int, default=None,
                    help="cap pages per type (for quick tests)")
    args = ap.parse_args(argv)

    out_dir = Path(args.out).resolve()
    cat_dir = out_dir / CATEGORY_DIR
    state_path = out_dir / "state.json"
    urllist_path = out_dir / "url-list.txt"
    urlhosts_path = out_dir / "domains-from-urls.txt"

    state = load_state(state_path)
    mode, date_gte = decide_mode(args, state, out_dir)
    started = datetime.now(timezone.utc)
    log(f"mode={mode}" + (f" date_gte={date_gte}" if date_gte else "")
        + f" out={out_dir}")

    prev_buckets = load_previous(out_dir)
    prev_domains = {v for (t, _), vals in prev_buckets.items() if t == "domain"
                    for v in vals}
    prev_url_hosts = set(read_lines(urlhosts_path))

    if mode == "full":
        buckets: dict[tuple[str, str], set[str]] = defaultdict(set)
        url_hosts: set[str] = set()
    else:
        buckets = defaultdict(set, {k: set(v) for k, v in prev_buckets.items()})
        url_hosts = set(prev_url_hosts)

    fetched = {t: 0 for t in TYPES}
    skipped: dict[str, list[str]] = defaultdict(list)
    newest_date = ""

    for addr_type in TYPES:
        log(f"[{addr_type}] fetching...")
        for rec in fetch_records(addr_type, date_gte, args.max_pages):
            fetched[addr_type] += 1
            raw = (rec.get("url") or "").strip()
            if not raw:
                continue
            d = rec.get("date") or ""
            if d > newest_date:
                newest_date = d

            value = normalize_value(addr_type, raw)
            if value is None:
                if len(skipped[addr_type]) < 20:
                    skipped[addr_type].append(raw)
                continue
            buckets[(addr_type, clean_desc(rec.get("desc")))].add(value)

            if addr_type == "url":
                host = normalize_host(raw)
                if host:
                    url_hosts.add(host)

    # ---- outputs ----
    ts = started.strftime("%Y-%m-%d %H:%M:%S UTC")
    per_type: dict[str, set[str]] = {t: set() for t in TYPES}
    for (addr_type, _desc), vals in buckets.items():
        per_type[addr_type] |= vals

    if args.include_url_hosts:
        per_type["domain"] |= url_hosts

    counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    changed_files: list[str] = []

    # one list per type
    sorted_by_type: dict[str, list[str]] = {}
    for addr_type in TYPES:
        vals = sort_values(addr_type, per_type[addr_type])
        sorted_by_type[addr_type] = vals
        counts[TYPE_FILES[addr_type]] = len(vals)
        if write_if_changed(out_dir / TYPE_FILES[addr_type], vals,
                            file_header(addr_type, None, len(vals), ts, mode),
                            args.force_write):
            changed_files.append(TYPE_FILES[addr_type])

    # one list per (type, category)
    written: set[str] = set()
    for (addr_type, desc) in sorted(buckets):
        vals = sort_values(addr_type, buckets[(addr_type, desc)])
        if not vals:
            continue
        name = f"{TYPE_PREFIX[addr_type]}-{desc}.txt"
        written.add(name)
        category_counts[f"{CATEGORY_DIR}/{name}"] = len(vals)
        if write_if_changed(cat_dir / name, vals,
                            file_header(addr_type, desc, len(vals), ts, mode),
                            args.force_write):
            changed_files.append(f"{CATEGORY_DIR}/{name}")
    removed_files = prune_category_files(cat_dir, written) if mode == "full" else []
    if removed_files:
        log("removed now-empty category files: " + ", ".join(removed_files))

    # Human-readable index for the category directory. No timestamp here, so
    # the file only changes when the counts do.
    idx = ["# Lists by category", "",
           "| File | Type | Category | Records |", "|---|---|---|---|"]
    for name in sorted(written):
        m = CATEGORY_FILE_RE.match(name)
        addr_type = PREFIX_TYPE[m.group(1)]
        desc = m.group(2)
        idx.append(f"| [{name}]({name}) | {TYPE_LABELS[addr_type]} | "
                   f"{DESC_LABELS.get(desc, 'Unknown')} ({desc}) | "
                   f"{category_counts[f'{CATEGORY_DIR}/{name}']} |")
    idx += ["", "Record counts and sync timestamps live in ../state.json.", ""]
    write_atomic(cat_dir / "README.md", "\n".join(idx))

    # drop-in for the old url-list.txt: no header, every type in one file
    combined: list[str] = []
    for addr_type in TYPES:
        combined.extend(sorted_by_type[addr_type])
    if write_if_changed(urllist_path, combined, "", args.force_write):
        changed_files.append("url-list.txt")
    counts["url-list.txt"] = len(combined)

    sorted_url_hosts = sorted(url_hosts)
    if write_if_changed(
        urlhosts_path,
        sorted_url_hosts,
        "# Hostnames extracted from type=url records\n"
        "# NOTE: these cover the whole domain, while the source records may\n"
        "# only be malicious on one specific URL path.\n"
        f"# Records: {len(sorted_url_hosts)}\n"
        f"# Last change: {ts} (sync mode: {mode})\n",
        args.force_write,
    ):
        changed_files.append("domains-from-urls.txt")
    counts["domains-from-urls.txt"] = len(sorted_url_hosts)

    domains_now = set(sorted_by_type["domain"])
    new_state = {
        "layout": LAYOUT,
        "last_run": started.strftime(DATE_FMT),
        "last_full": started.strftime(DATE_FMT) if mode == "full"
                     else state.get("last_full"),
        "last_mode": mode,
        "date_gte": date_gte,
        "newest_record_date": newest_date or state.get("newest_record_date", ""),
        "fetched": fetched,
        "counts": counts,
        "category_counts": dict(sorted(category_counts.items())),
        "delta_vs_previous": {
            "domains_added": len(domains_now - prev_domains),
            "domains_removed": len(prev_domains - domains_now),
        },
        "changed_files": sorted(changed_files),
        "skipped": {t: len(v) for t, v in skipped.items() if v},
        "api": API_URL,
        "generator": "scripts/sgb_sync.py",
    }
    write_atomic(state_path, json.dumps(new_state, indent=2, ensure_ascii=False) + "\n")

    added = new_state["delta_vs_previous"]["domains_added"]
    removed = new_state["delta_vs_previous"]["domains_removed"]
    log("done: " + ", ".join(f"{TYPE_FILES[t]}={counts[TYPE_FILES[t]]}"
                             for t in TYPES))
    log(f"  domain delta: +{added} / -{removed}, "
        f"category files: {len(written)}, "
        f"rewritten: {len(changed_files)}")
    for t, vals in skipped.items():
        log(f"  skipped ({t}): {len(vals)} samples -> {', '.join(vals[:5])}")

    # GitHub Actions step outputs
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"mode={mode}\n")
            fh.write(f"domains={counts['domains.txt']}\n")
            fh.write(f"urls={counts['urls.txt']}\n")
            fh.write(f"ipv4={counts['ipv4.txt']}\n")
            fh.write(f"ipv6={counts['ipv6.txt']}\n")
            fh.write(f"ipv6net={counts['ipv6net.txt']}\n")
            fh.write(f"total={counts['url-list.txt']}\n")
            fh.write(f"categories={len(written)}\n")
            fh.write(f"rewritten={len(changed_files)}\n")
            fh.write(f"added={added}\n")
            fh.write(f"removed={removed}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
