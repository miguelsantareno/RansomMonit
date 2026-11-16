#!/usr/bin/env python3
"""
ransommonit.py — Monitor dark/deep web ransomware leak sites from the
deepdarkCTI lists (https://github.com/fastfire/deepdarkCTI).

Pipeline:
  1) Load a deepdarkCTI list (local file OR GitHub raw).
  2) Parse the Markdown table into structured records.
  3) Filter to .onion targets (optionally ONLINE only) and deduplicate.
  4) Fetch each target through Tor (circuit verification, retries, rate limit,
     optional NEWNYM circuit rotation).
  5) Scan pages for watchlist keywords.
  6) Diff against the previous run (change detection) and, optionally, push a
     summary to a webhook (Slack/Discord compatible).
  7) Export JSON + CSV + raw HTML + changes/alerts.

Responsible use:
  Defensive threat-intelligence tool for lawful monitoring (e.g. checking
  whether an organization appears on a leak site). Follow the law in your
  jurisdiction, do not access illegal content, and do not download victim data.

Requirements:
  - Tor running:  sudo service tor start   (SOCKS at 127.0.0.1:9050)
  - pip install "requests[socks]" beautifulsoup4

Examples:
  # First run: establish a baseline (no change report yet).
  python3 ransommonit.py --list ransomware_gang --only-online -o out/

  # Subsequent runs: only what changed since last time + Slack alert.
  python3 ransommonit.py --list ransomware_gang --only-online -o out/ \
      --keywords "Your Company,yourcompany.com" \
      --notify-webhook https://hooks.slack.com/services/XXX --notify-on changes

  # Rotate the Tor circuit every 25 requests (needs the control port open).
  python3 ransommonit.py --list ransomware_gang -o out/ \
      --tor-control-port 9051 --renew-every 25
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
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

LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")  # [Name](URL)
ONION_RE = re.compile(r"\.onion(?:[:/]|$)", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    """Convert Markdown table rows into records.

    Each row:  |[Name](URL)|STATUS|user:pass|channel|rss|
    Returns dicts with name, url, status, channel, is_onion.
    """
    entries: list[dict] = []
    for line in markdown.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
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


def dedup_entries(entries: list[dict]) -> list[dict]:
    """Drop repeated URLs (the list often lists the same site many times).
    Keeps the first occurrence, which carries the canonical name."""
    seen: set[str] = set()
    out: list[dict] = []
    for e in entries:
        key = e["url"].rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


# --------------------------------------------------------------------------- #
# Tor layer
# --------------------------------------------------------------------------- #
def build_tor_session(host: str, port: int) -> requests.Session:
    session = requests.Session()
    proxy = f"socks5h://{host}:{port}"  # socks5h => DNS resolved Tor-side
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


def renew_circuit(host: str, control_port: int, password: str = "",
                  settle: float = 5.0) -> None:
    """Ask Tor for a fresh circuit via the control port (SIGNAL NEWNYM).

    Implemented over a raw socket to avoid a hard dependency on `stem`.
    Requires Tor's ControlPort to be enabled (e.g. `ControlPort 9051`) and an
    auth method configured (CookieAuthentication or a HashedControlPassword).
    """
    with socket.create_connection((host, control_port), timeout=10) as s:
        def cmd(line: str) -> str:
            s.sendall((line + "\r\n").encode())
            return s.recv(1024).decode(errors="replace")

        auth = f'AUTHENTICATE "{password}"' if password else "AUTHENTICATE"
        reply = cmd(auth)
        if not reply.startswith("250"):
            raise RuntimeError(f"Tor control auth failed: {reply.strip()}")
        reply = cmd("SIGNAL NEWNYM")
        if not reply.startswith("250"):
            raise RuntimeError(f"NEWNYM failed: {reply.strip()}")
    time.sleep(settle)  # give Tor a moment to build the new circuit


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


# --------------------------------------------------------------------------- #
# Content extraction + matching
# --------------------------------------------------------------------------- #
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


def content_hash(text: str) -> str:
    """Stable hash of the visible text — used to detect page changes."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def match_keywords(text: str, keywords: list[str]) -> list[str]:
    """Return the keywords (case-insensitive) found in the page text."""
    if not keywords or not text:
        return []
    low = text.lower()
    return [kw for kw in keywords if kw.lower() in low]


# --------------------------------------------------------------------------- #
# State + change detection
# --------------------------------------------------------------------------- #
def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_state(path: Path, records: list[dict]) -> None:
    """Persist a compact per-URL snapshot for the next run's diff."""
    state = {
        r["url"]: {
            "name": r.get("name"),
            "list_status": r.get("status"),
            "fetched": r.get("fetched", False),
            "http_status": r.get("http_status"),
            "title": r.get("title"),
            "content_hash": r.get("content_hash"),
            "matched_keywords": r.get("matched_keywords", []),
            "last_seen": _now(),
        }
        for r in records
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2),
                    encoding="utf-8")


def diff_states(prev: dict, records: list[dict]) -> list[dict]:
    """Compare the current run against the previous snapshot.

    Emits change events of type:
      NEW_TARGET      — URL never seen before
      BACK_ONLINE     — previously unreachable, now fetched
      WENT_OFFLINE    — previously fetched, now unreachable
      CONTENT_CHANGED — page text hash differs (likely new victims/posts)
      KEYWORD_MATCH   — a keyword matched that did not match last time
    """
    changes: list[dict] = []
    for r in records:
        url = r["url"]
        p = prev.get(url)
        fetched = r.get("fetched", False)
        if p is None:
            if fetched:
                changes.append({"type": "NEW_TARGET", "name": r["name"],
                                "url": url})
        else:
            if fetched and not p.get("fetched"):
                changes.append({"type": "BACK_ONLINE", "name": r["name"],
                                "url": url})
            elif not fetched and p.get("fetched"):
                changes.append({"type": "WENT_OFFLINE", "name": r["name"],
                                "url": url})
            if (fetched and p.get("fetched")
                    and r.get("content_hash") and p.get("content_hash")
                    and r["content_hash"] != p["content_hash"]):
                changes.append({"type": "CONTENT_CHANGED", "name": r["name"],
                                "url": url})
        new_hits = set(r.get("matched_keywords") or []) - set(
            (p or {}).get("matched_keywords") or [])
        if new_hits:
            changes.append({"type": "KEYWORD_MATCH", "name": r["name"],
                            "url": url, "keywords": sorted(new_hits)})
    return changes


# --------------------------------------------------------------------------- #
# Notifications
# --------------------------------------------------------------------------- #
def format_notification(changes: list[dict], matches: list[dict]) -> str:
    lines = ["*RansomMonit* report — " + _now()]
    if matches:
        lines.append(f"\n:rotating_light: *{len(matches)} keyword match(es):*")
        for m in matches[:15]:
            kws = ", ".join(m.get("matched_keywords", []))
            lines.append(f"  • {m['name']} ({kws}) — {m['url']}")
    if changes:
        lines.append(f"\n*{len(changes)} change(s) since last run:*")
        for c in changes[:20]:
            extra = ""
            if c.get("keywords"):
                extra = f" [{', '.join(c['keywords'])}]"
            lines.append(f"  • {c['type']}: {c['name']}{extra} — {c['url']}")
    if not matches and not changes:
        lines.append("\nNo matches or changes.")
    return "\n".join(lines)


def notify(webhook: str, text: str, timeout: int = 15) -> bool:
    """POST to a Slack/Discord-compatible incoming webhook (clearnet, no Tor)."""
    try:
        r = requests.post(webhook, json={"text": text,
                                         "content": text},  # Slack / Discord
                          timeout=timeout)
        r.raise_for_status()
        return True
    except requests.RequestException as exc:
        print(f"notify failed: {exc}", file=sys.stderr)
        return False


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run(entries: list[dict], session: requests.Session, delay: float,
        out_dir: Path, keywords: list[str] | None = None,
        renew_every: int = 0, renew_fn=None) -> list[dict]:
    keywords = keywords or []
    out_dir.mkdir(parents=True, exist_ok=True)
    pages_dir = out_dir / "pages"
    pages_dir.mkdir(exist_ok=True)
    results = []
    for i, e in enumerate(entries, 1):
        if renew_every and renew_fn and i > 1 and (i - 1) % renew_every == 0:
            try:
                print("  rotating Tor circuit (NEWNYM)...", file=sys.stderr)
                renew_fn()
            except Exception as exc:
                print(f"  circuit rotation failed: {exc}", file=sys.stderr)
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
                        "raw_file": str(raw_path),
                        "content_hash": content_hash(fulltext),
                        "matched_keywords": hits, **info})
            if hits:
                print(f"    *** MATCH: {', '.join(hits)}", file=sys.stderr)
        except RuntimeError as exc:
            rec.update({"fetched": False, "error": str(exc),
                        "content_hash": None, "matched_keywords": []})
        results.append(rec)
        if i < len(entries):
            time.sleep(delay)  # be polite: don't hammer the service
    return results


def export(records: list[dict], out_dir: Path, changes: list[dict]) -> None:
    slim = [{k: v for k, v in r.items() if k != "text"} for r in records]
    (out_dir / "results.json").write_text(
        json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")

    cols = ["name", "url", "status", "is_onion", "fetched", "http_status",
            "title", "text_len", "matched_keywords", "content_hash", "error"]
    with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            row = dict(r)
            row["matched_keywords"] = ";".join(r.get("matched_keywords") or [])
            w.writerow(row)

    alerts = [{"name": r["name"], "url": r["url"],
               "matched_keywords": r.get("matched_keywords", []),
               "raw_file": r.get("raw_file")}
              for r in records if r.get("matched_keywords")]
    if alerts:
        (out_dir / "alerts.json").write_text(
            json.dumps(alerts, ensure_ascii=False, indent=2), encoding="utf-8")
    if changes:
        (out_dir / "changes.json").write_text(
            json.dumps(changes, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Monitor .onion ransomware leak sites from deepdarkCTI.")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--list", choices=sorted(KNOWN_LISTS),
                        help="list to fetch from the deepdarkCTI GitHub repo")
    source.add_argument("--file", type=Path, help="local deepdarkCTI .md file")

    p.add_argument("--only-online", action="store_true",
                   help="only targets marked ONLINE in the list")
    p.add_argument("--include-clearnet", action="store_true",
                   help="also include clearnet URLs (default: .onion only)")
    p.add_argument("--no-dedup", action="store_true",
                   help="do not deduplicate repeated URLs")
    p.add_argument("--dry-run", action="store_true",
                   help="parse and list targets only, fetch nothing")
    p.add_argument("--limit", type=int, help="cap the number of targets")
    p.add_argument("--delay", type=float, default=4.0,
                   help="pause between requests in seconds (default 4)")

    # keywords
    p.add_argument("--keywords", help="comma-separated terms to flag in pages")
    p.add_argument("--keywords-file", type=Path,
                   help="file with one keyword per line")

    # Tor
    p.add_argument("--socks-host", default=DEFAULT_SOCKS_HOST)
    p.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT)
    p.add_argument("--tor-control-port", type=int,
                   help="Tor control port for circuit rotation (e.g. 9051)")
    p.add_argument("--tor-control-password", default="",
                   help="Tor control password (if configured)")
    p.add_argument("--renew-every", type=int, default=0,
                   help="rotate the Tor circuit every N requests (needs "
                        "--tor-control-port)")

    # change detection + notifications
    p.add_argument("--state-file", type=Path,
                   help="state file for change detection "
                        "(default: <out-dir>/state.json)")
    p.add_argument("--no-state", action="store_true",
                   help="disable change detection / state tracking")
    p.add_argument("--notify-webhook",
                   help="Slack/Discord-compatible webhook URL for alerts")
    p.add_argument("--notify-on", choices=["matches", "changes", "all"],
                   default="matches", help="when to send a webhook notification")

    p.add_argument("-o", "--out-dir", type=Path, default=Path("deepdark_out"))
    args = p.parse_args()

    # 1) load + parse
    try:
        md = load_markdown(args.list, args.file)
    except Exception as exc:
        print(f"ERROR loading the list: {exc}", file=sys.stderr)
        return 1
    entries = parse_entries(md)

    # 2) filter + dedup
    targets = entries
    if not args.include_clearnet:
        targets = [e for e in targets if e["is_onion"]]
    if args.only_online:
        targets = [e for e in targets if e["status"] == "ONLINE"]
    if not args.no_dedup:
        before = len(targets)
        targets = dedup_entries(targets)
        print(f"Deduplicated: {before} -> {len(targets)} unique URLs.",
              file=sys.stderr)
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

    # circuit rotation hook
    renew_fn = None
    if args.renew_every:
        if not args.tor_control_port:
            print("--renew-every needs --tor-control-port; ignoring rotation.",
                  file=sys.stderr)
        else:
            renew_fn = lambda: renew_circuit(  # noqa: E731
                args.socks_host, args.tor_control_port,
                args.tor_control_password)

    # keywords
    keywords: list[str] = []
    if args.keywords:
        keywords += [k.strip() for k in args.keywords.split(",") if k.strip()]
    if args.keywords_file:
        keywords += [ln.strip() for ln in args.keywords_file.read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")]
    if keywords:
        print(f"Watching for {len(keywords)} keyword(s): {', '.join(keywords)}",
              file=sys.stderr)

    # 4) collect
    records = run(targets, session, args.delay, args.out_dir, keywords,
                  renew_every=args.renew_every, renew_fn=renew_fn)

    # 5) change detection
    changes: list[dict] = []
    state_file = args.state_file or (args.out_dir / "state.json")
    if not args.no_state:
        prev = load_state(state_file)
        baseline = not prev
        changes = diff_states(prev, records)
        save_state(state_file, records)
        if baseline:
            print(f"Baseline established ({len(records)} targets) — change "
                  f"reporting starts next run.", file=sys.stderr)

    # 6) export
    export(records, args.out_dir, changes)

    ok = sum(1 for r in records if r.get("fetched"))
    matches = [r for r in records if r.get("matched_keywords")]
    print(f"\nDone: {ok}/{len(records)} pages collected. "
          f"Results in {args.out_dir}/", file=sys.stderr)
    if keywords:
        print(f"Keyword matches: {len(matches)} page(s)", file=sys.stderr)
    if not args.no_state:
        print(f"Changes since last run: {len(changes)}", file=sys.stderr)

    # 7) notify
    if args.notify_webhook:
        want = (
            args.notify_on == "all"
            or (args.notify_on == "matches" and matches)
            or (args.notify_on == "changes" and changes)
        )
        if want:
            text = format_notification(changes, matches)
            print("Sending webhook notification...", file=sys.stderr)
            notify(args.notify_webhook, text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
