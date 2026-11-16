"""Unit tests for RansomMonit — pure logic only (no Tor / no network)."""

import importlib.util
from pathlib import Path

import pytest

# Load the single-file module by path.
_SPEC = importlib.util.spec_from_file_location(
    "ransommonit", Path(__file__).resolve().parent.parent / "ransommonit.py")
rm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rm)


SAMPLE_MD = """|Name|Status|User:Password|Tox ID|RSS|
| ------ | ------ | ------ | ------ | ------ |
|[ACME-Leaks](http://abcdefghij234567abcdefghij234567abcdefghij234567aa.onion)|ONLINE||tox:1||
|[ACME-Leaks dup](http://abcdefghij234567abcdefghij234567abcdefghij234567aa.onion/)|ONLINE||||
|[SomeBlog](https://example.com)|OFFLINE||||
|[Gang2](http://zyxwvu234567zyxwvu234567zyxwvu234567zyxwvu234567bb.onion)|ONLINE||||
not a table row
"""


def test_parse_entries_counts_and_flags():
    entries = rm.parse_entries(SAMPLE_MD)
    # 4 linked rows (header/separator and the non-table line are ignored)
    assert len(entries) == 4
    names = [e["name"] for e in entries]
    assert names == ["ACME-Leaks", "ACME-Leaks dup", "SomeBlog", "Gang2"]
    assert entries[0]["is_onion"] is True
    assert entries[2]["is_onion"] is False  # clearnet
    assert entries[0]["status"] == "ONLINE"
    assert entries[2]["status"] == "OFFLINE"


def test_dedup_collapses_same_url_ignoring_trailing_slash_and_case():
    entries = rm.parse_entries(SAMPLE_MD)
    onion = [e for e in entries if e["is_onion"]]
    deduped = rm.dedup_entries(onion)
    # the two ACME-Leaks entries collapse into one -> 2 unique onion URLs
    assert len(deduped) == 2
    assert deduped[0]["name"] == "ACME-Leaks"


def test_match_keywords_case_insensitive():
    text = "Leaked data from ACME Corp and nomad-ttc.pt listed here"
    hits = rm.match_keywords(text, ["acme corp", "NOMAD-TTC.PT", "absent"])
    assert hits == ["acme corp", "NOMAD-TTC.PT"]
    assert rm.match_keywords("", ["x"]) == []
    assert rm.match_keywords("text", []) == []


def test_content_hash_is_stable_and_sensitive():
    assert rm.content_hash("abc") == rm.content_hash("abc")
    assert rm.content_hash("abc") != rm.content_hash("abd")


def _rec(url, name="n", fetched=True, chash="h", kw=None):
    return {"url": url, "name": name, "fetched": fetched,
            "content_hash": chash, "matched_keywords": kw or []}


def test_diff_new_target_on_empty_prev():
    recs = [_rec("http://a.onion")]
    changes = rm.diff_states({}, recs)
    assert [c["type"] for c in changes] == ["NEW_TARGET"]


def test_diff_content_changed():
    prev = {"http://a.onion": {"fetched": True, "content_hash": "old",
                               "matched_keywords": []}}
    recs = [_rec("http://a.onion", chash="new")]
    types = [c["type"] for c in rm.diff_states(prev, recs)]
    assert types == ["CONTENT_CHANGED"]


def test_diff_back_online_and_went_offline():
    prev = {
        "http://a.onion": {"fetched": False, "content_hash": None,
                           "matched_keywords": []},
        "http://b.onion": {"fetched": True, "content_hash": "h",
                           "matched_keywords": []},
    }
    recs = [_rec("http://a.onion", chash="h"),
            _rec("http://b.onion", fetched=False, chash=None)]
    types = {c["type"] for c in rm.diff_states(prev, recs)}
    assert "BACK_ONLINE" in types
    assert "WENT_OFFLINE" in types


def test_diff_new_keyword_match_only_when_new():
    prev = {"http://a.onion": {"fetched": True, "content_hash": "h",
                               "matched_keywords": ["old"]}}
    recs = [_rec("http://a.onion", chash="h", kw=["old", "new"])]
    changes = rm.diff_states(prev, recs)
    kw_changes = [c for c in changes if c["type"] == "KEYWORD_MATCH"]
    assert len(kw_changes) == 1
    assert kw_changes[0]["keywords"] == ["new"]  # "old" not re-reported


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
