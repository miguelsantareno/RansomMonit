#!/usr/bin/env python3
"""
deepdark_monitor.py — Collect dark/deep web data from the deepdarkCTI lists
(https://github.com/fastfire/deepdarkCTI).

What it does:
  1) Loads a deepdarkCTI list (e.g. ransomware_gang.md) from a local file OR
     directly from GitHub (raw).
  2) Parses the Markdown table into structured records
     (name, url, status, channel, is_onion).
  3) Fetches ONLY the .onion targets (deep/dark web) through the Tor network,
     with circuit verification, rate limiting and retries.
  4) Exports everything to JSON and CSV.

Responsible use:
  This is a defensive threat-intelligence tool. It is meant for monitoring
  ransomware leak sites (checking whether an organization is listed as a
  victim, tracking group activity). Follow the law in your jurisdiction, do
  not access illegal content, and do not download victim data.

Requirements:
  - Tor running:  sudo service tor start   (SOCKS at 127.0.0.1:9050)
  - pip install "requests[socks]" beautifulsoup4

Examples:
  # Only list the ONLINE .onion targets (no fetching):
  python3 deepdark_monitor.py --list ransomware_gang --dry-run --only-online

  # Fetch the ONLINE .onion pages through Tor:
  python3 deepdark_monitor.py --list ransomware_gang --only-online -o out/

  # Use a local file instead of GitHub:
  python3 deepdark_monitor.py --file ./ransomware_gang.md -o out/
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050  # use 9150 if you run the Tor Browser
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

RAW_BASE = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"

# Repo files that share the same Markdown table format.
KNOWN_LISTS = {
    "ransomware_gang": "ransomware_gang.md",
    "forum": "forum.md",
    "telegram": "telegram.md",
    "stealer": "stealer_logs.md",
    "markets": "markets.md",
}

# Markdown link:  [Name](URL)
LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
ONION_RE = re.compile(r"\.onion(?:[:/]|$)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Loading and parsing the deepdarkCTI list
# --------------------------------------------------------------------------- #
def load_markdown(list_name: str | None, file_path: Path | None) -> str:
    """Read the Markdown from a local file or from GitHub raw."""
    if file_path:
        return file_path.read_text(encoding="utf-8", errors="replace")
    if list_name not in KNOWN_LISTS:
        raise ValueError(
            f"Unknown list '{list_name}'. Options: {', '.join(KNOWN_LISTS)} "
            "(or use --file with a local path)."
        )
    url = f"{RAW_BASE}/{KNOWN_LISTS[list_name]}"
    resp = requests.get(url, timeout=30)  # clearnet; does NOT need Tor
    resp.raise_for_status()
    return resp.text


def parse_entries(markdown: str) -> list[dict]:
    """Convert the Markdown table rows into structured records.

    Each row looks like:  |[Name](URL)|STATUS|user:pass|channel|rss|
    Returns dicts with name, url, status, channel, is_onion.
    """
    entries: list[dict] = []
    for line in markdown.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        # table cells
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells:
            continue
        m = LINK_RE.search(cells[0])
        if not m:
            continue  # header/separator row or no link
        name, url = m.group(1).strip(), m.group(2).strip()
        status = cells[1].upper() if len(cells) > 1 else ""
        channel = cells[3] if len(cells) > 3 else ""
        entries.append({
            "name": name,
            "url": url,
            "status": status,
            "channel": channel,
            "is_onion": bool(ONION_RE.search(url)),
        })
    return entries


# --------------------------------------------------------------------------- #
# Tor layer
# --------------------------------------------------------------------------- #
def build_tor_session(host: str, port: int) -> requests.Session:
    session = requests.Session()
    proxy = f"socks5h://{host}:{port}"  # socks5h => DNS resolved by Tor
    session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({"User-Agent": DEFAULT_UA})
    return session


def verify_tor(session: requests.Session, timeout: int = 30) -> dict:
    """Confirm traffic actually exits through the Tor network."""
    resp = session.get("https://check.torproject.org/api/ip", timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("IsTor"):
        raise RuntimeError(
            f"Traffic is NOT going through Tor (visible IP: {data.get('IP')}). "
            "Make sure Tor is running on the given SOCKS port."
        )
    return data


def fetch(session: requests.Session, url: str, timeout: int = 90,
          retries: int = 3, backoff: float = 5.0) -> requests.Response:
    """GET with retries and backoff; Tor circuits are slow and flaky."""
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last = exc
            if attempt < retries:
                wait = backoff * attempt
                print(f"    attempt {attempt}/{retries} failed ({exc}); "
                      f"retry in {wait:.0f}s", file=sys.stderr)
                time.sleep(wait)
    raise RuntimeError(f"{url}: {last}")


def extract(html: str) -> dict:
    """Pull title, visible text (capped) and links from an HTML page."""
    if not _HAS_BS4:
        text = html
        return {"title": None, "text_len": len(text), "text": text[:20000],
                "links": [], "_fulltext": text}
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    text = " ".join(soup.get_text(" ").split())
    links = sorted({a["href"] for a in soup.find_all("a", href=True)})
    return {"title": title, "text_len": len(text), "text": text[:20000],
            "links": links[:200], "_fulltext": text}


def match_keywords(text: str, keywords: list[str]) -> list[str]:
    """Return the keywords (case-insensitive) found in the page text."""
    if not keywords or not text:
        return []
    low = text.lower()
    return [kw for kw in keywords if kw.lower() in low]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run(entries: list[dict], session: requests.Session, delay: float,
        out_dir: Path, keywords: list[str] | None = None) -> list[dict]:
    keywords = keywords or []
    out_dir.mkdir(parents=True, exist_ok=True)
    pages_dir = out_dir / "pages"
    pages_dir.mkdir(exist_ok=True)
    results = []
    for i, e in enumerate(entries, 1):
        print(f"[{i}/{len(entries)}] {e['name']}  ({e['url']})", file=sys.stderr)
        rec = dict(e)
        try:
            resp = fetch(session, e["url"])
            host = (urlparse(e["url"]).netloc or f"n{i}").replace(":", "_")
            raw_path = pages_dir / f"{i:03d}_{host[:40]}.html"
            raw_path.write_text(resp.text, encoding="utf-8", errors="replace")
            info = extract(resp.text)
            fulltext = info.pop("_fulltext", "")
            hits = match_keywords(fulltext, keywords)
            rec.update({"fetched": True, "http_status": resp.status_code,
                        "raw_file": str(raw_path), "matched_keywords": hits,
                        **info})
            if hits:
                print(f"    *** MATCH: {', '.join(hits)}", file=sys.stderr)
        except RuntimeError as exc:
            rec.update({"fetched": False, "error": str(exc),
                        "matched_keywords": []})
        results.append(rec)
        if i < len(entries):
            time.sleep(delay)  # be polite: don't hammer the service
    return results


def export(records: list[dict], out_dir: Path) -> None:
    # JSON: drop the bulky raw text to keep the index light; the full HTML is
    # already saved under pages/.
    slim = [{k: v for k, v in r.items() if k != "text"} for r in records]
    (out_dir / "results.json").write_text(
        json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")

    cols = ["name", "url", "status", "is_onion", "fetched",
            "http_status", "title", "text_len", "matched_keywords", "error"]
    with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            row = dict(r)
            row["matched_keywords"] = ";".join(r.get("matched_keywords") or [])
            w.writerow(row)

    # Separate alerts file: only pages where a keyword matched.
    alerts = [{"name": r["name"], "url": r["url"],
               "matched_keywords": r.get("matched_keywords", []),
               "raw_file": r.get("raw_file")}
              for r in records if r.get("matched_keywords")]
    if alerts:
        (out_dir / "alerts.json").write_text(
            json.dumps(alerts, ensure_ascii=False, indent=2), encoding="utf-8")
    return None


def main() -> int:
    p = argparse.ArgumentParser(
        description="Monitor .onion targets from the deepdarkCTI lists.")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--list", choices=sorted(KNOWN_LISTS),
                        help="list to fetch from the deepdarkCTI GitHub repo")
    source.add_argument("--file", type=Path,
                        help="local deepdarkCTI .md file")
    p.add_argument("--only-online", action="store_true",
                   help="only targets marked ONLINE in the list")
    p.add_argument("--include-clearnet", action="store_true",
                   help="also include clearnet URLs (default: .onion only)")
    p.add_argument("--dry-run", action="store_true",
                   help="parse and list targets only, fetch nothing")
    p.add_argument("--limit", type=int, help="cap the number of targets (testing)")
    p.add_argument("--keywords", help="comma-separated terms to flag in page "
                   "text (e.g. your org name, domains)")
    p.add_argument("--keywords-file", type=Path,
                   help="file with one keyword per line")
    p.add_argument("--delay", type=float, default=4.0,
                   help="pause between requests in seconds (default 4)")
    p.add_argument("--socks-host", default=DEFAULT_SOCKS_HOST)
    p.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT)
    p.add_argument("-o", "--out-dir", type=Path, default=Path("deepdark_out"))
    args = p.parse_args()

    # 1) load + parse
    try:
        md = load_markdown(args.list, args.file)
    except Exception as exc:
        print(f"ERROR loading the list: {exc}", file=sys.stderr)
        return 1
    entries = parse_entries(md)

    # 2) filter targets: by default ONLY dark/deep web (.onion)
    targets = entries
    if not args.include_clearnet:
        targets = [e for e in targets if e["is_onion"]]
    if args.only_online:
        targets = [e for e in targets if e["status"] == "ONLINE"]
    if args.limit:
        targets = targets[:args.limit]

    n_onion = sum(1 for e in entries if e["is_onion"])
    print(f"List: {len(entries)} entries ({n_onion} .onion). "
          f"Selected targets: {len(targets)}.", file=sys.stderr)

    if args.dry_run:
        for e in targets:
            flag = "onion" if e["is_onion"] else "clear"
            try:
                print(f"  [{flag}|{e['status'] or '?':7}] {e['name']}: {e['url']}")
            except BrokenPipeError:
                break
        return 0

    if not targets:
        print("No targets left after filtering.", file=sys.stderr)
        return 1

    # 3) Tor session + verification
    session = build_tor_session(args.socks_host, args.socks_port)
    print("Verifying the Tor circuit...", file=sys.stderr)
    try:
        info = verify_tor(session)
        print(f"  OK — exiting through Tor (exit IP: {info.get('IP')})",
              file=sys.stderr)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # 4) collect + export
    keywords: list[str] = []
    if args.keywords:
        keywords += [k.strip() for k in args.keywords.split(",") if k.strip()]
    if args.keywords_file:
        keywords += [ln.strip() for ln in args.keywords_file.read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")]
    if keywords:
        print(f"Watching for {len(keywords)} keyword(s): "
              f"{', '.join(keywords)}", file=sys.stderr)

    records = run(targets, session, args.delay, args.out_dir, keywords)
    export(records, args.out_dir)
    ok = sum(1 for r in records if r.get("fetched"))
    n_alerts = sum(1 for r in records if r.get("matched_keywords"))
    print(f"\nDone: {ok}/{len(records)} pages collected. "
          f"Results in {args.out_dir}/ (results.json, results.csv)",
          file=sys.stderr)
    if keywords:
        where = f" -> {args.out_dir}/alerts.json" if n_alerts else ""
        print(f"Keyword matches: {n_alerts} page(s){where}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
