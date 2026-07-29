# Malicious address lists (T.C. Siber Güvenlik Başkanlığı)

Hourly mirror of the malicious address data published by the Turkish Cyber
Security Presidency, pulled from their API and written out as plain-text lists
split by address type (domain, URL, IPv4, IPv6) and by malicious category.

The plain-text feed that used to live at `usom.gov.tr/url-list.txt` was retired
on **1 June 2026**. That URL now serves a Swagger page. The API is the only
remaining way to get the data: <https://siberguvenlik.gov.tr/api/>

## Lists

### By type

| File | API type | Contents |
|---|---|---|
| [domains.txt](domains.txt) | `domain` | Malicious domains, one per line |
| [urls.txt](urls.txt) | `url` | Full URL records, schemeless, such as `example.com/bad/path` |
| [ipv4.txt](ipv4.txt) | `ip` | IPv4 addresses, numerically sorted |
| [ipv6.txt](ipv6.txt) | `ip6` | IPv6 addresses, numerically sorted |
| [ipv6net.txt](ipv6net.txt) | `ip6net` | IPv6 network blocks, currently empty upstream |
| [url-list.txt](url-list.txt) | all | Drop-in for the old `url-list.txt`. No header, every type in one file |
| [domains-from-urls.txt](domains-from-urls.txt) | `url` hosts | Hostnames extracted from URL records. See the caveat below |
| [state.json](state.json) | n/a | Sync state and record counts for every file |

Type files start with `#` comment lines. If your consumer does not skip comment
lines, use `url-list.txt`, which has none.

The `Last change` line in a header is the last time that list's records
actually changed, not the last time the sync ran. A file whose records are
unchanged is left untouched, so an hourly run that finds nothing new produces
no diff at all. `state.json` is where the timestamp of the most recent sync
lives.

### By category

[categories/](categories/) holds one file per `<type>-<CODE>` pair. The current
file list with record counts lives in
[categories/README.md](categories/README.md).

| Code | Category |
|---|---|
| `PH` | Phishing |
| `BP` | Financial Phishing |
| `MD` | Malware Distribution Domain |
| `MI` | Malware Distribution IP |
| `MU` | Malware Distribution URL |
| `MC` | Malware Command Center (C&C) |
| `CA` | Cyber Attack (port scan, brute force etc.) |

Financial-phishing domains only are in
[categories/domains-BP.txt](categories/domains-BP.txt). C&C IPv4 addresses only
are in [categories/ipv4-MC.txt](categories/ipv4-MC.txt).

Codes come from the record's `desc` field. If the API adds a new code its file
appears automatically, and a category that runs out of records has its file
deleted on the next full crawl. Records with an empty or unrecognised `desc`
land in the `UNKNOWN` bucket.

### Raw URLs

```
https://raw.githubusercontent.com/gorkemgun/sgb-blocklist/main/domains.txt
https://raw.githubusercontent.com/gorkemgun/sgb-blocklist/main/ipv4.txt
https://raw.githubusercontent.com/gorkemgun/sgb-blocklist/main/categories/domains-PH.txt
```

### Things worth knowing

- `raw.githubusercontent.com` caches for roughly 5 minutes, which is not an
  issue at an hourly update cadence.
- The domain list holds **over 462,000** records. On low-memory devices, list
  compilation can take a while. Pick individual category files if you need a
  smaller set.
- IDN domains are converted to punycode (`xn--...`), since that is the form
  that resolves in DNS.
- IP addresses never leak into the domain lists. IPv4 records mis-filed under
  `type=domain` upstream are skipped.
- `domains-from-urls.txt` entries cover the **entire domain**, whereas the
  source records were listed because one specific URL path was malicious, such
  as a single compromised page on an otherwise legitimate site. Using that file
  risks blocking legitimate sites, which is why it is not merged into
  `domains.txt` by default.

## How the API works

No authentication, API key or quota. One endpoint does everything:

```
GET https://siberguvenlik.gov.tr/api/address/index
```

| Parameter | Description |
|---|---|
| `type` | `domain`, `url`, `ip`, `ip6`, `ip6net` |
| `q` | free-text search |
| `desc` | malicious category code (table above) |
| `source` | `US` USOM/TR-CERT, `SO` CERT, `RS` RSA, `IH` public report, `SB` SGB |
| `connectiontype` | `AC` APT C&C, `BC` Botnet C&C, `EK` Exploit Kit, `MC` Mobile C&C, `MF` Malware download, `MM` Mining malware, `PH` Phishing, `OT` Other |
| `criticality_level` | 1 (highest) to 10 (lowest) |
| `date_gte`, `date_lte` | `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` |
| `page` | **1-based**. `page=0` and `page=1` both return the first page |
| `per-page` | 1 to 9999. Anything above 9999 returns **HTTP 429** |

Response:

```json
{
  "totalCount": 462318,
  "count": 9999,
  "models": [
    {
      "id": 1147406,
      "url": "uyari-detaylar-tr.ink",
      "type": "domain",
      "desc": "PH",
      "source": "IH",
      "date": "2026-07-29 16:13:35.809423",
      "criticality_level": 4,
      "connectiontype": "PH"
    }
  ],
  "page": 0,
  "pageCount": 47
}
```

Gotchas found while building this:

- The `page` parameter is 1-based but the `page` field in the response is
  0-based.
- Records are ordered by descending `id` and new records are prepended, so the
  same row can appear on two consecutive pages during a long crawl. That
  produces duplicates rather than gaps, and the script de-duplicates through
  sets.
- The `date` field appears to be UTC, since record timestamps line up with the
  HTTP `Date` header. Delta queries still reach 6 hours further back.
- The API does not report removals. That is why a full crawl runs once a day
  and rebuilds every list from scratch.

Lookup endpoints for the code to title mappings:
`/api/address-description/index`, `/api/address-source/index`,
`/api/address-connection-type/index`

## Sync strategy

[.github/workflows/update.yml](.github/workflows/update.yml) runs
[scripts/sgb_sync.py](scripts/sgb_sync.py) at 17 minutes past every hour:

- **delta** (hourly default): queries `date_gte = last run - 6h`, so one request
  per type and a few dozen records total, merged into the existing lists.
- **full** (every 24h, decided from `last_full` in `state.json`): walks all 52
  pages in about 4 minutes and rebuilds every list, which is what clears out
  de-listed records. A change to the output layout version also forces a full
  run.

Running a full crawl every hour would mean pulling about 90 MB from the API
each time, so it is deliberately avoided. Delta plus a daily full gives the
same result.

Only files whose records changed are rewritten, so a quiet hour touches nothing
but `state.json`, and nothing is committed when even that matches.

### Running it manually

On GitHub: **Actions -> Update malicious address lists -> Run workflow**. The
mode is selectable.

Locally:

```bash
python scripts/sgb_sync.py --mode full --out .          # rebuild everything
python scripts/sgb_sync.py --mode delta --out .         # only add what is new
python scripts/sgb_sync.py --mode full --max-pages 1    # quick smoke test
python scripts/sgb_sync.py --mode delta --force-write   # rewrite files after a header format change
python scripts/sgb_sync.py --mode full --include-url-hosts   # merge URL hosts into domains.txt
```

Standard library only, no dependencies (Python 3.9+).

Want files split by `connectiontype` or `criticality_level` instead? The
`clean_desc(rec.get("desc"))` call in `scripts/sgb_sync.py` is the single place
that decides which category file a record goes to.

## Running your own copy

Consuming the lists needs nothing installed. To run your own mirror:

1. Fork or clone this repo.
2. Under **Settings -> Actions -> General -> Workflow permissions**, enable
   *Read and write permissions*.
3. Trigger the workflow once from the Actions tab with mode `full`, or wait for
   the hourly schedule to pick it up.

### About repository size

The lists total about 30 MB and are committed hourly. Git compresses similar
text well, but the repo does grow over time. If that becomes annoying, collapse
the history:

```bash
git checkout --orphan clean && git add -A && git commit -m "reset history"
git branch -D main && git branch -m main && git push -f origin main
```

## License

The code in this repository, meaning `scripts/`, `.github/` and the
documentation, is MIT licensed. See [LICENSE](LICENSE).

The address data is not covered by that license. It is produced and owned by
T.C. Siber Güvenlik Başkanlığı and only fetched and reformatted here. Terms of
use are set by the publisher: <https://siberguvenlik.gov.tr/yasal-uyarilar>

Upstream: <https://siberguvenlik.gov.tr/zararli-baglantilar>
