"""AUDIT.md is the project's schema for what may be written and why.

These tests parse its tables and hold the three scripts to them, the same
way test_slimbrave.py holds the three scripts to each other. A failure here
means the document and the code disagree; the source they both cite decides
which one is wrong.
"""

import re

from test_slimbrave import LINUX_MOD, MAC_MOD, ROOT

AUDIT = (ROOT / "AUDIT.md").read_text(encoding="utf-8")
GLYPHS = ("✅", "⚠️", "⛔", "❌", "💀", "🕓")
LIVE = ("✅", "⚠️")


def _section(title):
    """Text of one H2 section, up to the next H2."""
    marker = f"\n## {title}\n"
    start = AUDIT.index(marker)
    body = AUDIT[start + len(marker):]
    end = body.find("\n## ")
    return body if end < 0 else body[:end]


def _tables(text):
    """Every markdown table in `text` as (header, [row dict, ...])."""
    blocks, current = [], []
    for line in text.split("\n"):
        if line.startswith("|"):
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    tables = []
    for block in blocks:
        header = [c.strip() for c in block[0].strip().strip("|").split("|")]
        rows = []
        for line in block[2:]:
            cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip())[1:-1]]
            rows.append(dict(zip(header, cells)))
        tables.append((header, rows))
    return tables


def _keys_in(cell):
    """Policy key names named in a table cell: bare or back-ticked."""
    bare = re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", cell)
    if bare:
        return {cell}
    found = set()
    for name in re.findall(r"`([A-Za-z][A-Za-z0-9/]*\*?)`", cell):
        found.add(name.split("/")[-1])
    return found


BRAVE_TABLES = _tables(_section("Brave-specific keys"))
CHROMIUM_TABLES = _tables(_section("Chromium-inherited keys"))
REJECTED_TABLES = _tables(_section("Considered and rejected — do not add"))
ORIGIN_TEXT = _section("Brave Origin on Linux")

KEY_ROWS = {}
for _header, _rows in BRAVE_TABLES + CHROMIUM_TABLES:
    for _row in _rows:
        KEY_ROWS[_row["Key"]] = _row

REJECTED = set()
for _header, _rows in REJECTED_TABLES:
    for _row in _rows:
        REJECTED |= _keys_in(_row["Key(s)"])


def _written(mod):
    rows = mod.build_rows()
    keys = {r["key"] for r in rows if r["type"] in (mod.ROW_FEATURE, mod.ROW_CHOICE)}
    return keys | {"DnsOverHttpsMode", "DnsOverHttpsTemplates"}


WRITTEN = _written(LINUX_MOD) | _written(MAC_MOD)


def _rejected_match(key):
    for rejected in REJECTED:
        if rejected.endswith("*"):
            if key.startswith(rejected[:-1]):
                return rejected
        elif rejected == key:
            return rejected
    return None


def test_every_written_key_is_audited_as_live():
    missing = sorted(k for k in WRITTEN if k not in KEY_ROWS)
    assert missing == [], f"written but not in a key table: {missing}"
    not_live = sorted(k for k in WRITTEN if not KEY_ROWS[k]["Status"].startswith(LIVE))
    assert not_live == [], f"written but not marked live: {not_live}"


def test_nothing_rejected_is_written():
    hits = sorted(f"{k} (matches {_rejected_match(k)})" for k in WRITTEN if _rejected_match(k))
    assert hits == [], hits
    dead_in_tables = sorted(k for k, row in KEY_ROWS.items()
                            if not row["Status"].startswith(LIVE) and k in WRITTEN)
    assert dead_in_tables == []


def test_status_cells_use_the_vocabulary():
    for header, rows in BRAVE_TABLES + CHROMIUM_TABLES + REJECTED_TABLES:
        assert "Status" in header, header
        for row in rows:
            assert row["Status"].startswith(GLYPHS), (row.get("Key") or row.get("Key(s)"), row["Status"])


def test_origin_builtin_keys_are_exactly_the_guarded_brave_rows():
    guarded = {k for k, row in KEY_ROWS.items()
               if k in WRITTEN and re.search(r"map, `ENABLE_", row.get("Dispatch", ""))}
    for mod in (LINUX_MOD, MAC_MOD):
        assert set(mod.ORIGIN_BUILTIN_KEYS) == guarded, (
            sorted(set(mod.ORIGIN_BUILTIN_KEYS) ^ guarded))
        for key in mod.ORIGIN_BUILTIN_KEYS:
            assert f"`{key}`" in ORIGIN_TEXT, f"{key} not named in the Origin section"
    unguarded_brave = {k for k, row in KEY_ROWS.items()
                       if k in WRITTEN and row.get("Dispatch", "").startswith("map, unguarded")}
    assert not unguarded_brave & set(LINUX_MOD.ORIGIN_BUILTIN_KEYS)


def test_inventory_counts_match_the_scripts():
    m = re.search(r"\*\*Inventory: (\d+) rows over (\d+) distinct keys\*\*", AUDIT)
    assert m, "inventory line missing"
    rows = [r for r in LINUX_MOD.build_rows()
            if r["type"] in (LINUX_MOD.ROW_FEATURE, LINUX_MOD.ROW_CHOICE)]
    assert (int(m.group(1)), int(m.group(2))) == (len(rows), len({r["key"] for r in rows}))


def test_ledger_names_the_key_sections():
    ledger = next((rows for header, rows in _tables(AUDIT) if header[:2] == ["Section", "Last verified"]), None)
    assert ledger is not None, "verification ledger missing"
    sections = {row["Section"] for row in ledger}
    for needed in ("Brave-specific keys", "Chromium-inherited keys",
                   "Brave Origin on Linux", "Considered and rejected"):
        assert needed in sections, needed
    for row in ledger:
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", row["Last verified"]), row


def test_no_diary_markers():
    assert not re.search(r"Stale as of|^### 20\d\d|Read at:", AUDIT, re.MULTILINE)
