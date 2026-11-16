# deepdarkCTI Monitor

A small, defensive **threat-intelligence** tool that collects dark/deep web data
from the curated lists in [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI).

It loads a deepdarkCTI list (e.g. `ransomware_gang.md`), parses the Markdown table
into structured records, and fetches **only the `.onion` targets** through the Tor
network — with circuit verification, rate limiting and retries — then exports the
results to JSON and CSV.

Typical use cases: checking whether an organization appears on a ransomware leak
site, tracking group activity, and building a time series of changes.

---

## ⚠️ Legal & ethical notice

This tool is intended for **lawful, defensive security research** only
(threat intelligence, OSINT, brand/leak monitoring).

- Follow the laws of your jurisdiction and the terms of the services you access.
- Do **not** use it to access illegal content or to download victim data.
- Many `.onion` services are honeypots, law-enforcement controlled, or hostile.
  Run it from an isolated environment and never log into personal accounts over
  the same Tor session.

You are solely responsible for how you use this software. See [DISCLAIMER](DISCLAIMER.md).

---

## Requirements

- Python 3.10+
- Tor running locally (SOCKS5 proxy)
- Python packages: see [`requirements.txt`](requirements.txt)

### Install

```bash
# 1. Tor
sudo apt install tor && sudo service tor start      # Debian/Ubuntu
# brew install tor && brew services start tor       # macOS

# 2. Python deps (a virtualenv is recommended)
pip install -r requirements.txt
```

Tor exposes a SOCKS5 proxy at `127.0.0.1:9050` (the `tor` daemon) or
`127.0.0.1:9150` (the Tor Browser — pass `--socks-port 9150`).

---

## Usage

```bash
# List the ONLINE .onion targets without fetching anything (no Tor needed):
python3 deepdark_monitor.py --list ransomware_gang --dry-run --only-online

# Fetch the first 10 ONLINE .onion pages through Tor (good for a first test):
python3 deepdark_monitor.py --list ransomware_gang --only-online --limit 10 -o out/

# Use a local copy of the list instead of GitHub:
python3 deepdark_monitor.py --file ./ransomware_gang.md -o out/
```

### Options

| Flag | Description |
| ---- | ----------- |
| `--list {ransomware_gang,forum,telegram,stealer,markets}` | Fetch a known list from the deepdarkCTI repo |
| `--file PATH` | Use a local `.md` file instead |
| `--only-online` | Keep only targets marked `ONLINE` |
| `--include-clearnet` | Also include clearnet URLs (default: `.onion` only) |
| `--dry-run` | Parse and print targets; fetch nothing |
| `--limit N` | Cap the number of targets (testing) |
| `--delay SECONDS` | Pause between requests (default `4`) |
| `--socks-host` / `--socks-port` | Tor SOCKS endpoint (default `127.0.0.1:9050`) |
| `-o, --out-dir DIR` | Output directory (default `deepdark_out/`) |

### Output

- `out/pages/NNN_host.html` — raw HTML of each fetched page
- `out/results.json` — structured records (name, url, status, title, text, links…)
- `out/results.csv` — flat summary for spreadsheets

---

## How it works

1. **Load** — reads the Markdown list from GitHub raw or a local file.
2. **Parse** — each table row `|[Name](URL)|STATUS|...|` becomes a record, and
   `.onion` URLs are flagged.
3. **Filter** — by default only `.onion`; optionally only `ONLINE`.
4. **Verify Tor** — queries `check.torproject.org`; aborts if traffic is not
   actually exiting through Tor (no false sense of anonymity).
5. **Fetch** — routes every request through the Tor SOCKS5 proxy (`socks5h://`,
   so DNS is resolved Tor-side and `.onion` names resolve correctly), with
   retries, backoff and a polite delay.
6. **Export** — writes JSON + CSV and the raw pages.

---

## Credits

Target lists are maintained by the [deepdarkCTI](https://github.com/fastfire/deepdarkCTI)
project. This tool only reads those lists; it does not redistribute them.

## License

[MIT](LICENSE)
