"""Import names everything it leaves out, matches names in exact letter case,
and shows what it copies from the file safely.

What a config holds that no row takes falls into one of these, named in
this order and in the same words in all three scripts: a name in the wrong
letter case, a value outside its policy's JSON type (or an unknown
DnsMode), a value of the right type that no row writes, a retired key, a
key SlimBrave Neo does not offer, an unknown top-level field; then the
Python scripts' Brave Origin count and the exclusion groups. Nothing named
is written. Names and values from the file are shown in printable ASCII,
quoted unless plain, cut to 64 characters, five per clause.

Both scripts are loaded here as in test_slimbrave.py, and slimbrave-mac.py a
second time with sys.platform faked as Darwin, where BackgroundModeEnabled
has no row. Nothing here touches /etc, the registry or a real Brave profile.
"""

import ast
import curses
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(alias, filename, platform=None):
    """Load a script as a module, with sys.platform faked if asked."""
    real_platform = sys.platform
    if platform is not None:
        sys.platform = platform
    try:
        spec = importlib.util.spec_from_file_location(alias, ROOT / filename)
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.platform = real_platform


LINUX_MOD = _load("slimbrave_linux_naming", "slimbrave-linux.py")
MAC_MOD = _load("slimbrave_mac_naming", "slimbrave-mac.py")
MAC_DARWIN = _load("slimbrave_mac_darwin_naming", "slimbrave-mac.py", "darwin")
MODULES = [LINUX_MOD, MAC_MOD, MAC_DARWIN]
MODULE_IDS = ["linux", "mac", "darwin"]

PRESETS = sorted((ROOT / "Presets").glob("*.json"))

# The clause leads, written out: a change of wording has to show up here
# (and in SlimBrave.ps1, whose reasons are the same words).
CASE = "; left unmanaged because names are case-sensitive: "
TYPE = "; left unmanaged because the value is not one this policy accepts: "
VALUE = "; left unmanaged because no row sets that value: "
RETIRED = "; left unmanaged because SlimBrave Neo no longer offers it: "
UNKNOWN = "; left unmanaged because SlimBrave Neo does not offer it: "
FIELD = "; ignored because it is not a SlimBrave Neo setting: "
EXCLUSIVE = "; left unmanaged because it is mutually exclusive with another imported row: "

SHIELDS_WILDCARDS = ["https://*", "http://*"]


@pytest.fixture(params=MODULES, ids=MODULE_IDS)
def mod(request):
    return request.param


def _row_keys(mod, rows=None):
    rows = mod.build_rows() if rows is None else rows
    return {r["key"] for r in rows if r["type"] in (mod.ROW_FEATURE, mod.ROW_CHOICE)}


def _origin_installs(mod):
    chan = next(c for c in mod.LINUX_CHANNELS if c["id"] == "origin")
    return [mod._make_installation(chan, plist_path="/x/slimbrave.json", prefs_path=None)]


def _write(tmp_path, config, name="cfg.json"):
    """`config` (an object, or JSON text as it is) written to tmp_path."""
    path = tmp_path / name
    text = config if isinstance(config, str) else json.dumps(config)
    path.write_text(text, encoding="utf-8")
    return path


def _import(mod, tmp_path, config, rows=None, name="cfg.json"):
    """Import `config` into `rows` (fresh ones by default).

    Returns (rows, the policy they build, the message after its lead).
    """
    path = _write(tmp_path, config, name)
    rows = mod.build_rows() if rows is None else rows
    ok, msg = mod.import_settings(rows, str(path))
    assert ok, msg
    lead = f"Imported from {name}"
    assert msg.startswith(lead), msg
    policy, err = mod._build_policy(rows)
    assert err == ""
    return rows, policy, msg[len(lead):]


def _ps1_text():
    return (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")


def _esc(text):
    """How Import echoes a file name or path, written out again here: each
    UTF-16 code unit outside printable ASCII as \\uXXXX in uppercase hex."""
    units = text.encode("utf-16-le", "surrogatepass")
    out = []
    for i in range(0, len(units), 2):
        unit = int.from_bytes(units[i:i + 2], "little")
        out.append(chr(unit) if 0x20 <= unit <= 0x7E else "\\u%04X" % unit)
    return "".join(out)


# What a file name echoed by Import keeps out of the message: the control
# and bidi characters a template may not hold and the zero-width format
# characters (any lone surrogate too).
NAME_UNSAFE = {*range(0x20), *range(0x7F, 0xA0), 0x2028, 0x2029, 0x061C, 0x200E, 0x200F,
               *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200B, 0x200C, 0x200D,
               0x2060, 0xFEFF}


def _esc_name(text):
    """How Import echoes a file name or path, written out again here: an
    unsafe character (NAME_UNSAFE, or a lone surrogate) as \\uXXXX in
    uppercase hex, any other character as it is."""
    return "".join("\\u%04X" % ord(ch) if ord(ch) in NAME_UNSAFE or 0xD800 <= ord(ch) <= 0xDFFF
                   else ch for ch in text)


# A file name holding what Import has to escape when it echoes one: a
# non-ASCII letter and a bidi override, and where file names may hold them
# (not on Windows) an ESC and a newline.
ODD_NAME = "café ‮" + ("" if os.name == "nt" else "\x1b[31m\n") + ".json"


def _write_named(tmp_path, config, name):
    """_write, skipped where the file system cannot hold `name`."""
    try:
        return _write(tmp_path, config, name)
    except (OSError, UnicodeEncodeError) as e:
        pytest.skip(f"this file system cannot hold the name: {e!r}")


# ---------------------------------------------------------------------------
# The known names and the shared code
# ---------------------------------------------------------------------------


def test_the_known_names_and_the_reasons_are_the_specified_ones(mod):
    assert mod.CONFIG_FIELDS == ("Features", "DnsMode", "DnsTemplates")
    assert mod.PLATFORM_LIMITED_KEYS == frozenset({"BackgroundModeEnabled", "DynamicCodeSettings"})
    assert mod.FEATURES_NAME_HINTS == {
        "DnsOverHttpsMode": "use DnsMode",
        "DnsOverHttpsTemplates": "use DnsTemplates",
        "DnsMode": "a top-level field",
        "DnsTemplates": "a top-level field",
    }
    assert [reason for _, _, reason in mod.IMPORT_NOTES] == [
        "names are case-sensitive",
        "the value is not one this policy accepts",
        "no row sets that value",
        "SlimBrave Neo no longer offers it",
        "SlimBrave Neo does not offer it",
        "it is not a SlimBrave Neo setting",
    ]
    assert [verb for _, verb, _ in mod.IMPORT_NOTES] == ["left unmanaged"] * 5 + ["ignored"]
    assert mod.EXCLUSIVE_REASON == "it is mutually exclusive with another imported row"
    assert (mod.SHOWN_MAX, mod.MAX_SHOWN_ITEMS, mod.STATUS_MAX_LINES) == (64, 5, 4)
    # What a template may not hold: C0, DEL and C1, the line and paragraph
    # separators, and the twelve bidi controls (Unicode's Bidi_Control),
    # which the template field also masks.
    assert mod._CONTROL_CHARS == frozenset(
        chr(c) for c in list(range(0x00, 0x20)) + list(range(0x7F, 0xA0)) + [0x2028, 0x2029])
    assert mod._BIDI_CONTROLS == frozenset(
        chr(c) for c in [0x061C, 0x200E, 0x200F] + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)))
    assert len(mod._CONTROL_CHARS) == 67 and len(mod._BIDI_CONTROLS) == 12


def _ps1_retired_names():
    block = re.search(r"\$script:retiredPolicies = \[ordered\]@\{(.*?)\n\}", _ps1_text(), re.S)
    return set(re.findall(r'"(\w+)"\s*=', block.group(1)))


def test_the_retired_keys_are_the_same_ten_in_all_three_scripts():
    ps1 = _ps1_retired_names()
    assert len(ps1) == 10
    assert LINUX_MOD.RETIRED_KEYS == ps1
    for module in (MAC_MOD, MAC_DARWIN):
        assert module.RETIRED_KEYS == ps1 == set(module.RETIRED_POLICIES)
    # The mac script derives its set; the Linux one carries the literal.
    mac_src = (ROOT / "slimbrave-mac.py").read_text(encoding="utf-8")
    assert "RETIRED_KEYS = frozenset(RETIRED_POLICIES)" in mac_src


def test_retired_and_platform_limited_keys_are_no_row_of_any_python_script(mod):
    keys = _row_keys(mod)
    lowered = {k.lower() for k in keys}
    assert not mod.RETIRED_KEYS & keys
    assert not {k.lower() for k in mod.RETIRED_KEYS} & lowered
    assert not mod.RETIRED_KEYS & mod.PLATFORM_LIMITED_KEYS
    # A DNS hint never shadows a row either.
    assert not set(mod.FEATURES_NAME_HINTS) & keys


def test_platform_limited_keys_are_the_rows_some_platform_lacks():
    """Every row one script offers and another lacks is platform-limited,
    so a preset never carries a note for it; and SlimBrave.ps1, the one
    script on Windows, where both policies exist, has both rows."""
    ps1_keys = set(re.findall(r'Key = "(\w+)"', _ps1_text()))
    every = ps1_keys.union(*(_row_keys(m) for m in MODULES))
    for module in MODULES:
        assert every - _row_keys(module) <= module.PLATFORM_LIMITED_KEYS, module.__name__
    assert LINUX_MOD.PLATFORM_LIMITED_KEYS <= ps1_keys
    assert "DynamicCodeSettings" not in _row_keys(LINUX_MOD)
    assert "BackgroundModeEnabled" in _row_keys(LINUX_MOD)
    assert "BackgroundModeEnabled" not in _row_keys(MAC_DARWIN)


# The import path is one copy per script and must not drift: compared as
# syntax trees, docstrings included, so the wording is held too.
SHARED_DEFS = [
    "_is_json_int", "_value_fits_row", "_value_matches_row",
    "_fold_case", "_KeysDifferInCase", "_EmptyKey", "_refuse_unreadable_keys",
    "read_json_file",
    "CONFIG_FIELDS", "PLATFORM_LIMITED_KEYS", "FEATURES_NAME_HINTS",
    "IMPORT_NOTES", "EXCLUSIVE_REASON", "SHOWN_MAX", "MAX_SHOWN_ITEMS",
    "_PLAIN_NAME_CHARS", "_CONTROL_CHARS", "_BIDI_CONTROLS", "_escaped",
    "_shown_path", "_quoted", "_shown_name", "_shown_value", "_shown_item",
    "_note_clause", "import_settings", "_import_config", "_take_config",
    "STATUS_MAX_LINES", "status_lines", "layout", "viewport_rows",
    "_field_text", "draw",
]


def _top_level_defs(filename):
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            out[node.name] = ast.dump(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = ast.dump(node.value)
    return out


def test_the_import_code_is_the_same_in_both_scripts():
    linux = _top_level_defs("slimbrave-linux.py")
    mac = _top_level_defs("slimbrave-mac.py")
    for name in SHARED_DEFS:
        assert name in linux and name in mac, name
        assert linux[name] == mac[name], f"{name} differs between the two scripts"


def _exit_rule(filename):
    src = (ROOT / filename).read_text(encoding="utf-8")
    start = src.index("    # A Features block that names entries")
    return src[start:src.index("        return 1\n", start)]


def test_both_clis_refuse_to_apply_a_file_with_nothing_taken_the_same_way():
    assert _exit_rule("slimbrave-linux.py") == _exit_rule("slimbrave-mac.py")


# ---------------------------------------------------------------------------
# Rendering: one rule for every name and value the message copies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "MetricsReportingEnabled", "a.b-c_d", "x", "0", "x" * 64,
], ids=["policy", "punctuation", "one-char", "digit", "64-chars"])
def test_a_plain_name_is_shown_as_it_is(mod, name):
    assert mod._shown_name(name) == name


QUOTED_NAMES = [
    ("", '""'),
    ("Foo Bar", '"Foo Bar"'),
    ("A, B", '"A, B"'),
    ("x; y", '"x; y"'),
    ('say "hi"', '"say \\"hi\\""'),
    ("back\\slash", '"back\\\\slash"'),
    ("\x00", '"\\u0000"'),
    ("a\x1b[2Jb", '"a\\u001B[2Jb"'),
    ("line\nbreak", '"line\\u000Abreak"'),
    ("tab\t", '"tab\\u0009"'),
    ("\x7f", '"\\u007F"'),
    ("\x9b", '"\\u009B"'),
    ("café", '"caf\\u00E9"'),
    ("‮dcba", '"\\u202Edcba"'),
    ("\U0001F600", '"\\uD83D\\uDE00"'),
    ("\ud800", '"\\uD800"'),
    ("<>&'", '"<>&\'"'),
    ("x" * 65, '"' + "x" * 61 + '..."'),
]


@pytest.mark.parametrize("name,shown", QUOTED_NAMES, ids=[
    "empty", "space", "comma", "semicolon", "quote", "backslash", "nul", "esc",
    "newline", "tab", "del", "c1", "latin1", "bidi", "astral", "lone-surrogate",
    "html-chars", "65-chars"])
def test_any_other_name_is_quoted_with_every_non_printable_escaped(mod, name, shown):
    """Uppercase \\uXXXX for each UTF-16 code unit outside 0x20-0x7E, `"`
    and `\\` escaped; json.dumps would leave DEL raw, write lowercase hex
    and \\n, and SlimBrave.ps1's ConvertTo-Json would escape <>&' too."""
    assert mod._shown_name(name) == shown
    assert all(" " <= c <= "~" for c in mod._shown_name(name))


def test_the_cut_falls_on_the_escaped_text(mod):
    # 20 NULs escape to 120 characters: 61 of them, then '...'
    shown = mod._shown_name("\x00" * 20)
    assert shown == '"' + ("\\u0000" * 11)[:61] + '..."'
    assert len(shown) == 64 + 2
    # A body of exactly 64 is kept whole.
    assert mod._quoted("y" * 64) == '"' + "y" * 64 + '"'
    assert mod._quoted("y" * 63 + "\x01") == '"' + "y" * 61 + '..."'
    # A megabyte-long name costs no more than a short one.
    assert mod._shown_name("z" * 1_000_000) == '"' + "z" * 61 + '..."'


@pytest.mark.parametrize("value,shown", [
    (True, "true"), (False, "false"), (None, "null"), (3, "3"), (-7, "-7"),
    (0, "0"), (3000000000, "3000000000"),
    (2 ** 63 - 1, "9223372036854775807"), (-2 ** 63, "-9223372036854775808"),
    # Windows PowerShell 5.1 reads a larger integer as a [decimal] or a
    # [double], so it is no integer there and is not shown.
    (2 ** 63, None), (-2 ** 63 - 1, None), (10 ** 70, None),
    ("x", '"x"'), ("", '""'), ("DISABLE_NON_PROXIED_UDP", '"DISABLE_NON_PROXIED_UDP"'),
    ("\x00", '"\\u0000"'),
    (2.0, None), (2.5, None), (float("inf"), None), ([], None), ([1], None), ({}, None),
], ids=["true", "false", "null", "int", "negative", "zero", "big-int", "int64-max",
        "int64-min", "past-int64", "below-int64", "huge-int",
        "str", "empty-str", "enum-str", "nul-str", "float-integral", "float",
        "infinity", "empty-list", "list", "object"])
def test_values_are_shown_by_one_rule(mod, value, shown):
    assert mod._shown_value(value) == shown
    item = mod._shown_item("Key", value)
    assert item == ("Key" if shown is None else f"Key={shown}")


def test_a_clause_lists_five_items_then_counts_the_rest(mod):
    items = [f"K{i}" for i in range(8)]
    assert mod._note_clause("left unmanaged", "r", items[:5]) == (
        "; left unmanaged because r: K0, K1, K2, K3, K4")
    assert mod._note_clause("left unmanaged", "r", items[:6]) == (
        "; left unmanaged because r: K0, K1, K2, K3, K4 and 1 more")
    assert mod._note_clause("ignored", "r", items) == (
        "; ignored because r: K0, K1, K2, K3, K4 and 3 more")


# ---------------------------------------------------------------------------
# The lead and each clause
# ---------------------------------------------------------------------------


def test_the_lead_names_the_file_not_its_path(mod, tmp_path):
    folder = tmp_path / "some" / "folder"
    folder.mkdir(parents=True)
    path = _write(folder, {"Features": {"BraveRewardsDisabled": True}}, "My Preset.json")
    ok, msg = mod.import_settings(mod.build_rows(), str(path))
    assert ok and msg == "Imported from My Preset.json"


def test_a_path_is_echoed_with_only_unsafe_characters_escaped(mod):
    assert mod._shown_path("My Preset.json") == "My Preset.json"
    assert mod._shown_path('/tmp/a "b" \\c.json') == '/tmp/a "b" \\c.json'
    name = "caf\u00e9\n\x1b[2J\u202e\U0001F600\u200b\udcff.json"
    assert mod._shown_path(name) == (
        "caf\u00e9\\u000A\\u001B[2J\\u202E\U0001F600\\u200B\\uDCFF.json") == _esc_name(name)
    # A Cyrillic or CJK name reads as it is.
    assert mod._shown_path("\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438.json") == (
        "\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438.json")
    assert mod._shown_path("\u8a2d\u5b9a.json") == "\u8a2d\u5b9a.json"
    assert mod._shown_path("y" * 300) == "y" * 300    # no cut


def test_import_echoes_the_file_name_and_path_escaped(mod, tmp_path):
    """The lead and every refusal that names the file: a newline, an ESC or
    a bidi control in a name never reaches the status line or the terminal."""
    path = _write_named(tmp_path, {"Features": {"BraveRewardsDisabled": True}}, ODD_NAME)
    assert mod.import_settings(mod.build_rows(), str(path)) == (
        True, "Imported from " + _esc_name(ODD_NAME))
    assert _esc_name(ODD_NAME).startswith("caf\u00e9 \\u202E")   # the letter as it is
    missing = tmp_path / ("gone " + ODD_NAME)
    assert mod.import_settings(mod.build_rows(), str(missing)) == (
        False, "File not found: " + _esc_name(str(missing)))
    folder = tmp_path / ("dir " + ODD_NAME)
    folder.mkdir()
    # The OSError's own text, its repr() of the path included, escaped.
    ok, msg = mod.import_settings(mod.build_rows(), str(folder))
    assert ok is False and msg.startswith("Read error: "), msg
    assert not any(ord(c) in NAME_UNSAFE or 0xD800 <= ord(c) <= 0xDFFF for c in msg), repr(msg)
    assert "dir caf\u00e9 " in msg


@pytest.mark.parametrize("config,items", [
    ({"Features": {"metricsReportingEnabled": False}},
     "metricsReportingEnabled (use MetricsReportingEnabled)"),
    ({"Features": {"INCOGNITOMODEAVAILABILITY": 1}},
     "INCOGNITOMODEAVAILABILITY (use IncognitoModeAvailability)"),
    ({"Features": {"defaultnotificationssetting": 2}},
     "defaultnotificationssetting (use DefaultNotificationsSetting)"),
    ({"Features": {"backgroundmodeenabled": False, "dynamiccodesettings": 1}},
     "backgroundmodeenabled (use BackgroundModeEnabled), "
     "dynamiccodesettings (use DynamicCodeSettings)"),
    ({"Features": ["braverewardsdisabled"]},
     "braverewardsdisabled (use BraveRewardsDisabled)"),
    ({"Features": {}, "dnsmode": "off", "DNSTEMPLATES": "https://dns.example/dns-query"},
     "dnsmode (use DnsMode), DNSTEMPLATES (use DnsTemplates)"),
], ids=["camel", "upper", "choice", "platform-limited", "legacy", "top-level"])
def test_a_name_in_the_wrong_letter_case_is_named_with_its_spelling(mod, tmp_path, config, items):
    """The spelling comes from the row keys and the platform-limited keys,
    so every script words a mis-cased BackgroundModeEnabled the same way,
    whether or not it has the row."""
    rows, policy, tail = _import(mod, tmp_path, config)
    assert tail == CASE + items
    assert policy == {}
    assert mod.get_dns_mode(rows) == "unmanaged"


@pytest.mark.parametrize("name", [
    "shoppinglistenabled",            # a retired key's spelling
    "dnsoverhttpsmode",               # a DNS policy name's spelling
    "MetricsReportingEnabled ",       # a blank: not a letter-case slip
    "MetrıcsReportingEnabled",   # dotless i: Python and .NET disagree
    "Kelvin",                    # Kelvin sign folds to k in Python
], ids=["retired", "dns", "trailing-blank", "dotless-i", "kelvin"])
def test_only_an_ascii_case_slip_of_a_row_key_gets_a_spelling(mod, tmp_path, name):
    _, _, tail = _import(mod, tmp_path, {"Features": {name: 1}})
    assert tail == UNKNOWN + mod._shown_name(name)


TYPE_CASES = [
    ("ChromeVariations", True, "ChromeVariations=true"),
    ("ChromeVariations", "2", 'ChromeVariations="2"'),
    ("ChromeVariations", 2.0, "ChromeVariations"),
    ("SafeBrowsingProtectionLevel", False, "SafeBrowsingProtectionLevel=false"),
    ("MetricsReportingEnabled", "0", 'MetricsReportingEnabled="0"'),
    ("MetricsReportingEnabled", None, "MetricsReportingEnabled=null"),
    ("MetricsReportingEnabled", [False], "MetricsReportingEnabled"),
    ("ExtensionInstallBlocklist", "*", 'ExtensionInstallBlocklist="*"'),
    ("WebRtcIPHandling", 1, "WebRtcIPHandling=1"),
    ("BrowserSignin", {"a": 1}, "BrowserSignin"),
    ("DefaultNotificationsSetting", "3", 'DefaultNotificationsSetting="3"'),
    ("DefaultNotificationsSetting", True, "DefaultNotificationsSetting=true"),
    ("DefaultWebUsbGuardSetting", 2.0, "DefaultWebUsbGuardSetting"),
    ("DefaultGeolocationSetting", [2], "DefaultGeolocationSetting"),
]


@pytest.mark.parametrize("key,value,item", TYPE_CASES,
                         ids=[f"{k}-{v!r}" for k, v, _ in TYPE_CASES])
def test_a_value_outside_the_policys_json_type_is_named_with_its_value(mod, tmp_path, key, value, item):
    _, policy, tail = _import(mod, tmp_path, {"Features": {key: value}})
    assert key not in policy
    assert tail == TYPE + item


@pytest.mark.parametrize("mode,item", [
    ("bogus", 'DnsMode="bogus"'), (5, "DnsMode=5"), (True, "DnsMode=true"),
    (2.5, "DnsMode"), ([1], "DnsMode"), ({"a": 1}, "DnsMode"),
    ("\x00", 'DnsMode="\\u0000"'), ("\x1b]52;c;eA==\x07", 'DnsMode="\\u001B]52;c;eA==\\u0007"'),
], ids=["word", "number", "true", "float", "list", "object", "nul", "osc52"])
def test_an_unknown_dns_mode_is_named_through_the_same_rule(mod, tmp_path, mode, item):
    rows, policy, tail = _import(mod, tmp_path, {"Features": {}, "DnsMode": mode})
    assert tail == TYPE + item
    assert mod.get_dns_mode(rows) == "unmanaged" and "DnsOverHttpsMode" not in policy


@pytest.mark.parametrize("mode", ["OFF", "Secure", "automatic"])
def test_the_dns_mode_word_itself_stays_case_insensitive(mod, tmp_path, mode):
    config = {"Features": {}, "DnsMode": mode, "DnsTemplates": "https://dns.example/dns-query"}
    rows, _, tail = _import(mod, tmp_path, config)
    assert tail == ""
    assert mod.get_dns_mode(rows) == mode.lower()


@pytest.mark.parametrize("mode,item", [
    (False, "DnsMode=false"), (0, "DnsMode=0"), ([], "DnsMode"), ({}, "DnsMode"),
    ([0], "DnsMode"), ("of\u00adf", 'DnsMode="of\\u00ADf"'),
    ("\u017fecure", 'DnsMode="\\u017Fecure"'),    # casefold() would make it "secure"
], ids=["false", "zero", "empty-list", "empty-object", "list-of-zero", "soft-hyphen",
        "long-s"])
def test_a_dns_mode_that_is_there_but_names_no_mode_is_named(mod, tmp_path, mode, item):
    """Only a missing, null or "" DnsMode is no DnsMode, so a template next
    to it does not make DNS custom; any other value names a mode in printable
    ASCII, in any letter case, or is named. Python used to read false, 0, []
    and {} as no DnsMode, and SlimBrave.ps1 reads [0] that way."""
    config = {"Features": {}, "DnsMode": mode, "DnsTemplates": "https://dns.example/dns-query"}
    rows, policy, tail = _import(mod, tmp_path, config)
    assert tail == TYPE + item
    assert mod.get_dns_mode(rows) == "unmanaged" and "DnsOverHttpsMode" not in policy


@pytest.mark.parametrize("config", [
    {"Features": {}}, {"Features": {}, "DnsMode": None}, {"Features": {}, "DnsMode": ""},
], ids=["missing", "null", "empty-string"])
@pytest.mark.parametrize("template", ["", "https://dns.example/dns-query"], ids=["alone", "with-template"])
def test_a_missing_null_or_empty_dns_mode_is_no_dns_mode(mod, tmp_path, config, template):
    if template:
        config = {**config, "DnsTemplates": template}
    rows, _, tail = _import(mod, tmp_path, config)
    assert tail == ""
    assert mod.get_dns_mode(rows) == ("custom" if template else "unmanaged")


@pytest.mark.parametrize("tmpl", [
    "https://dns.example/dns-query\n", "https://a.example/\rdns-query",
    "\x00https://dns.example/dns-query", "https://dns.example/\tdns-query",
    "https://dns.example/dns-query\x1b[2J", "https://dns.example/\x1f", "https://dns.example/\x7f",
    "https://dns.example/\x85", "https://dns.example/\x9f", "https://dns.example/\u2028",
    "https://dns.example/\u2029", ["https://a.example/dns-query", "https://b.example/\ndns-query"],
], ids=["lf", "cr", "nul", "tab", "esc", "unit-separator", "del", "nel", "c1-last",
        "line-separator", "paragraph-separator", "in-a-list"])
def test_a_template_with_a_control_character_refuses_the_file(mod, tmp_path, tmpl):
    """Never stripped: what would be left is a resolver the file did not
    name, and the TUI painted a newline in the field as a new line."""
    rows = _preticked(mod)
    path = _write(tmp_path, {"Features": {"BraveRewardsDisabled": True}, "DnsMode": "custom",
                             "DnsTemplates": tmpl})
    assert mod.import_settings(rows, str(path)) == (
        False, "Invalid config: DnsTemplates contains a control character")
    assert _untouched(mod, rows)


@pytest.mark.parametrize("tmpl", [
    "https://r\u00e9solveur.example/dns-query",
    "https://\u4f8b\u3048.example/dns-query{?dns}",
    "https://dns.example/~ \u00a0\u2027\u202f/dns-query",
], ids=["idn-host", "cjk-host", "next-to-the-controls"])
def test_a_template_with_printable_non_ascii_imports_and_round_trips(mod, tmp_path, tmpl):
    """An IDN host is a template, not a corrupted one: taken as written,
    applied as written, and exported and imported back unchanged."""
    rows, policy, tail = _import(mod, tmp_path, {"Features": {}, "DnsMode": "custom",
                                                 "DnsTemplates": tmpl})
    assert tail == ""
    assert policy == {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": tmpl}
    out = tmp_path / "exported.json"
    ok, msg = mod.export_settings(rows, str(out))
    assert ok, msg
    again = mod.build_rows()
    assert mod.import_settings(again, str(out)) == (True, "Imported from exported.json")
    assert (mod.get_dns_mode(again), mod.get_dns_template(again)) == ("custom", tmpl)


VALUE_CASES = [
    ("IncognitoModeAvailability", 0, "IncognitoModeAvailability=0"),
    ("ChromeVariations", 0, "ChromeVariations=0"),
    ("SafeBrowsingProtectionLevel", 2, "SafeBrowsingProtectionLevel=2"),
    ("DefaultBraveReferrersSetting", 0, "DefaultBraveReferrersSetting=0"),
    ("BrowserSignin", 1, "BrowserSignin=1"),
    ("MetricsReportingEnabled", True, "MetricsReportingEnabled=true"),
    ("MetricsReportingEnabled", 1, "MetricsReportingEnabled=1"),
    ("MetricsReportingEnabled", 5, "MetricsReportingEnabled=5"),
    ("BraveRewardsDisabled", False, "BraveRewardsDisabled=false"),
    ("WebRtcIPHandling", "default", 'WebRtcIPHandling="default"'),
    ("WebRtcIPHandling", "DISABLE_NON_PROXIED_UDP", 'WebRtcIPHandling="DISABLE_NON_PROXIED_UDP"'),
    ("BraveShieldsDisabledForUrls", ["https://intranet.example"], "BraveShieldsDisabledForUrls"),
    ("BraveShieldsEnabledForUrls", ["HTTPS://*", "HTTP://*"], "BraveShieldsEnabledForUrls"),
    ("ExtensionInstallTypeBlocklist", ["COMMAND_LINE"], "ExtensionInstallTypeBlocklist"),
    ("ExtensionInstallTypeBlocklist", [], "ExtensionInstallTypeBlocklist"),
    ("DefaultNotificationsSetting", 3, "DefaultNotificationsSetting=3"),
    ("DefaultNotificationsSetting", 3000000000, "DefaultNotificationsSetting=3000000000"),
    ("DefaultWebUsbGuardSetting", 1, "DefaultWebUsbGuardSetting=1"),
]


@pytest.mark.parametrize("key,value,item", VALUE_CASES,
                         ids=[f"{k}-{v!r}" for k, v, _ in VALUE_CASES])
def test_a_value_no_row_sets_is_named_once_and_not_written(mod, tmp_path, key, value, item):
    """Legal or not, in its policy's JSON type: a value SlimBrave does not
    offer, a mis-cased string or list entry, a foreign list. Two rows can
    share a key; it is named once."""
    _, policy, tail = _import(mod, tmp_path, {"Features": {key: value}})
    assert key not in policy
    assert tail == VALUE + item


def test_every_boolean_no_row_writes_is_named(mod, tmp_path):
    """Generated from the table, so a new boolean row is covered too."""
    written = {}
    for row in mod.build_rows():
        if row["type"] == mod.ROW_FEATURE and isinstance(row["value"], bool):
            written.setdefault(row["key"], set()).add(row["value"])
    assert written
    for key, values in sorted(written.items()):
        for other in sorted({True, False} - values):
            _, policy, tail = _import(mod, tmp_path, {"Features": {key: other}})
            assert key not in policy
            assert tail == VALUE + f"{key}={json.dumps(other)}"


@pytest.mark.parametrize("features", [
    {"IncognitoModeAvailability": 2, "HardwareAccelerationModeEnabled": True},
    {"IncognitoModeAvailability": 1, "HardwareAccelerationModeEnabled": False},
    {"ChromeVariations": 2, "SafeBrowsingProtectionLevel": 1, "DefaultBraveReferrersSetting": 1},
], ids=["second-rows", "first-rows", "other-pairs"])
def test_a_value_one_of_two_rows_takes_is_not_named(mod, tmp_path, features):
    _, policy, tail = _import(mod, tmp_path, {"Features": features})
    assert policy == features
    assert tail == ""


def test_an_integer_past_64_bits_is_no_integer(mod, tmp_path):
    """Windows PowerShell 5.1 reads one as a [decimal] or a [double]: not a
    value an integer or boolean policy accepts, and not shown, there or here."""
    _, policy, tail = _import(mod, tmp_path, {"Features": {
        "ChromeVariations": 2 ** 63,
        "MetricsReportingEnabled": 2 ** 64,
        "DefaultNotificationsSetting": -2 ** 63 - 1,
        "IncognitoModeAvailability": 2 ** 63 - 1,
        "BrowserSignin": -2 ** 63,
    }, "DnsMode": 10 ** 30})
    assert policy == {}
    assert tail == (TYPE + "ChromeVariations, MetricsReportingEnabled, "
                    "DefaultNotificationsSetting, DnsMode"
                    + VALUE + "IncognitoModeAvailability=9223372036854775807, "
                    "BrowserSignin=-9223372036854775808")
    # In a legacy array such an entry has no rendering, so it is not listed.
    _, policy, tail = _import(mod, tmp_path, {"Features": [
        "BraveRewardsDisabled", 2 ** 63, 2 ** 63 - 1, -2 ** 63 - 1]})
    assert policy == {"BraveRewardsDisabled": True}
    assert tail == UNKNOWN + "9223372036854775807"


def _row(mod, key, rows=None):
    rows = mod.build_rows() if rows is None else rows
    return next(r for r in rows if r["type"] == mod.ROW_FEATURE and r["key"] == key)


def _deep_list(depth):
    """["https://*"] inside `depth` more lists, built without recursing."""
    value = ["https://*"]
    for _ in range(depth):
        value = [value]
    return value


def test_a_list_row_takes_only_json_strings_and_never_walks_an_entry(mod):
    row = _row(mod, "BraveShieldsDisabledForUrls")
    assert mod._value_matches_row(row, ["http://*", "https://*"])
    assert not mod._value_matches_row(row, ["https://*", ["http://*"]])
    assert not mod._value_matches_row(row, ["https://*", 5])
    assert not mod._value_matches_row(row, ["https://*"])
    # sorted(key=str) printed this entry, which raised RecursionError: past
    # the stack on Python 3.14, past the recursion limit before it.
    assert not mod._value_matches_row(row, ["http://*", _deep_list(200_000)])


def test_a_deeply_nested_list_value_is_named_not_raised(mod, tmp_path, monkeypatch):
    """A list-row value nested ~50,000 deep, a 95 KB file that json reads
    on an 8 MB stack, ended the TUI and printed a traceback from --import.
    How deep json reads depends on the stack, so the reader is stood in for."""
    config = {"Features": {"BraveShieldsDisabledForUrls": ["http://*", _deep_list(200_000)]}}
    monkeypatch.setattr(mod, "read_json_file", lambda path: config)
    rows = mod.build_rows()
    assert mod.import_settings(rows, str(tmp_path / "deep.json")) == (
        True, "Imported from deep.json" + VALUE + "BraveShieldsDisabledForUrls")
    assert mod._build_policy(rows) == ({}, "")


def _recursion_error(*args, **kwargs):
    raise RecursionError("maximum recursion depth exceeded")


def test_a_recursion_error_while_taking_a_file_refuses_it_and_restores_the_rows(
        mod, tmp_path, monkeypatch, applied, capsys):
    """Nothing in the import walks a value's depth now; should anything
    raise RecursionError all the same, the rows go back to what they were
    and the import is refused, in the TUI's import_settings and in --import."""
    path = _write(tmp_path, {"Features": {"BraveRewardsDisabled": True}, "DnsMode": "off"})
    rows = _preticked(mod)
    monkeypatch.setattr(mod, "_enforce_groups", _recursion_error)   # after every row is set
    assert mod.import_settings(rows, str(path)) == (False, "Invalid config: nesting too deep")
    assert _untouched(mod, rows)
    assert mod.cli_import(str(path), None) == 1
    assert applied == []
    assert capsys.readouterr() == ("", "Error: Invalid config: nesting too deep\n")


# RETIRED_POLICIES, the table RETIRED_KEYS is held equal to above.
@pytest.mark.parametrize("key", sorted(MAC_MOD.RETIRED_POLICIES))
@pytest.mark.parametrize("value", [False, True, 1])
def test_a_retired_key_is_named_whatever_its_value(mod, tmp_path, key, value):
    _, policy, tail = _import(mod, tmp_path, {"Features": {key: value, "BraveRewardsDisabled": True}})
    assert policy == {"BraveRewardsDisabled": True}
    assert tail == RETIRED + key


def test_keys_slimbrave_does_not_offer_are_named_and_dns_names_hinted(mod, tmp_path):
    rows, policy, tail = _import(mod, tmp_path, {"Features": {
        "HomepageLocation": "https://example.com",
        "DnsOverHttpsMode": "secure",
        "DnsOverHttpsTemplates": "https://dns.example/dns-query",
        "DnsMode": "custom",
        "DnsTemplates": "https://dns.example/dns-query",
    }})
    assert policy == {}
    assert mod.get_dns_mode(rows) == "unmanaged"
    assert tail == UNKNOWN + (
        "HomepageLocation, DnsOverHttpsMode (use DnsMode), "
        "DnsOverHttpsTemplates (use DnsTemplates), DnsMode (a top-level field), "
        "DnsTemplates (a top-level field)")


def test_a_legacy_array_names_what_no_row_takes(mod, tmp_path):
    """Names in the wrong case, retired and unknown ones, and entries that
    are no name: shown as values where the rule shows one (5, null, true);
    a float, list or object entry has no rendering and is not listed. A
    repeated name is named once."""
    _, policy, tail = _import(mod, tmp_path, {"Features": [
        "BraveRewardsDisabled", "NotAPolicy", "metricsreportingenabled", 5, None, True,
        2.5, [1], {"a": 1}, "NotAPolicy", "DynamicCodeSettings", "IPFSEnabled"]})
    assert policy == {"BraveRewardsDisabled": True}
    assert tail == (CASE + "metricsreportingenabled (use MetricsReportingEnabled)"
                    + RETIRED + "IPFSEnabled"
                    + UNKNOWN + "NotAPolicy, 5, null, true")


def test_unknown_top_level_fields_are_ignored_and_named(mod, tmp_path):
    """The DNS hints are for Features only: at the top level the policy
    file's names are just fields a config does not have."""
    rows, _, tail = _import(mod, tmp_path, {
        "Comment": "mine", "Features": {"BraveRewardsDisabled": True},
        "DnsOverHttpsMode": "secure", "Version": 2, "MetricsReportingEnabled": False})
    assert tail == FIELD + "Comment, DnsOverHttpsMode, Version, MetricsReportingEnabled"
    assert mod.get_dns_mode(rows) == "unmanaged"


def test_a_group_loser_is_named_only_as_mutually_exclusive(mod, tmp_path):
    _, policy, tail = _import(mod, tmp_path, {"Features": {
        "SpellCheckServiceEnabled": False, "SpellcheckEnabled": False,
        "BraveShieldsDisabledForUrls": SHIELDS_WILDCARDS,
        "BraveShieldsEnabledForUrls": SHIELDS_WILDCARDS}})
    assert policy == {"SpellcheckEnabled": False, "BraveShieldsEnabledForUrls": SHIELDS_WILDCARDS}
    # sorted, as SlimBrave.ps1 lists them: not in file order, not table order
    assert tail == EXCLUSIVE + "BraveShieldsDisabledForUrls, SpellCheckServiceEnabled"


def test_the_exclusion_clause_is_sorted_in_any_letter_case_and_never_cut(mod, tmp_path, monkeypatch):
    """SlimBrave.ps1 lists the losers through Sort-Object -Unique, which
    ignores letter case and has no cap. Two keys at most can lose to a group
    today, so a stand-in _enforce_groups drops every key the file names."""
    rows = mod.build_rows()
    features = {"SpellCheckServiceEnabled": False, "SpellcheckEnabled": False}
    for row in rows:
        if (row["type"] == mod.ROW_FEATURE and isinstance(row["value"], bool)
                and not row.get("group") and len(features) < 8):
            features.setdefault(row["key"], row["value"])
    monkeypatch.setattr(mod, "_enforce_groups", lambda rows: list(features))
    _, _, tail = _import(mod, tmp_path, {"Features": features}, rows=rows)
    listed = tail[len(EXCLUSIVE):].split(", ")
    assert tail.startswith(EXCLUSIVE) and " more" not in tail
    assert listed == sorted(features, key=str.lower) and len(listed) == 8
    # Ignoring case, Spellcheck-E sorts before SpellCheck-S; ordinally C < c.
    assert listed.index("SpellcheckEnabled") < listed.index("SpellCheckServiceEnabled")


def test_origin_built_ins_are_counted_by_distinct_key_whatever_their_value(mod, tmp_path):
    rows = mod.build_rows(_origin_installs(mod))
    _, policy, tail = _import(mod, tmp_path, {"Features": [
        "BraveRewardsDisabled", "BraveRewardsDisabled", "TorDisabled", "BraveP3AEnabled"]}, rows=rows)
    assert tail == "; 2 keys built into Brave Origin left unmanaged"
    rows = mod.build_rows(_origin_installs(mod))
    _, policy, tail = _import(mod, tmp_path, {"Features": {
        "BraveRewardsDisabled": "yes", "BraveP3AEnabled": False}}, rows=rows)
    assert policy == {"BraveP3AEnabled": False}
    assert tail == "; 1 key built into Brave Origin left unmanaged"


def test_the_clauses_come_in_their_fixed_order(mod, tmp_path):
    rows = mod.build_rows(_origin_installs(mod))
    _, policy, tail = _import(mod, tmp_path, {
        "Comment": "x",
        "Features": {
            "BraveShieldsDisabledForUrls": SHIELDS_WILDCARDS,
            "NotAPolicy": 1,
            "BraveRewardsDisabled": True,
            "ShoppingListEnabled": False,
            "IncognitoModeAvailability": 0,
            "ChromeVariations": "2",
            "metricsreportingenabled": False,
            "BraveShieldsEnabledForUrls": SHIELDS_WILDCARDS,
        }}, rows=rows)
    assert policy == {"BraveShieldsEnabledForUrls": SHIELDS_WILDCARDS}
    assert tail == (
        CASE + "metricsreportingenabled (use MetricsReportingEnabled)"
        + TYPE + 'ChromeVariations="2"'
        + VALUE + "IncognitoModeAvailability=0"
        + RETIRED + "ShoppingListEnabled"
        + UNKNOWN + "NotAPolicy"
        + FIELD + "Comment"
        + "; 1 key built into Brave Origin left unmanaged"
        + EXCLUSIVE + "BraveShieldsDisabledForUrls")


@pytest.mark.parametrize("layout", ["features-first", "features-between", "features-last"])
def test_features_items_come_before_top_level_ones_wherever_features_sits(mod, tmp_path, layout):
    """The order SlimBrave.ps1 builds its lists in: the Features entries in
    file order, then the DnsMode, then the other top-level names in file
    order, wherever in the file Features is."""
    features = {"ChromeVariations": "2", "metricsreportingenabled": False}
    before = {"dnstemplates": "https://dns.example/dns-query", "Comment": "x"}
    after = {"DnsMode": "bogus", "Version": 2}
    config = {
        "features-first": {"Features": features, **before, **after},
        "features-between": {**before, "Features": features, **after},
        "features-last": {**before, **after, "Features": features},
    }[layout]
    _, _, tail = _import(mod, tmp_path, config)
    assert tail == (CASE + "metricsreportingenabled (use MetricsReportingEnabled), "
                    "dnstemplates (use DnsTemplates)"
                    + TYPE + 'ChromeVariations="2", DnsMode="bogus"'
                    + FIELD + "Comment, Version")


def test_a_clause_keeps_file_order_and_stops_at_five(mod, tmp_path):
    names = ["Zeta", "Alpha", "Mid", "Beta", "Omega", "Gamma", "Delta"]
    _, policy, tail = _import(mod, tmp_path, {"Features": {n: 1 for n in names}})
    assert policy == {}
    assert tail == UNKNOWN + "Zeta, Alpha, Mid, Beta, Omega and 2 more"


def test_what_the_message_copies_from_the_file_is_printable_ascii(mod, tmp_path):
    """A NUL in the TUI's status line made curses raise, and --import prints
    the message as root: no control character may reach either."""
    _, _, tail = _import(mod, tmp_path, {
        "Features": {"\x00x": 1, "a\x1b[2Jb": 1, "WebRtcIPHandling": "‮default",
                     "\U0001F600": 1, "x" * 500: 1},
        "\x07": 1, "DnsMode": "\x00"})
    assert all(" " <= c <= "~" for c in tail), repr(tail)
    assert tail == (
        TYPE + 'DnsMode="\\u0000"'
        + VALUE + 'WebRtcIPHandling="\\u202Edefault"'
        + UNKNOWN + '"\\u0000x", "a\\u001B[2Jb", "\\uD83D\\uDE00", "' + "x" * 61 + '..."'
        + FIELD + '"\\u0007"')


def test_a_huge_file_of_unknown_keys_stays_one_short_message(mod, tmp_path):
    features = {f"Unknown{i:06d}": 1 for i in range(40000)}
    _, policy, tail = _import(mod, tmp_path, {"Features": features})
    assert policy == {}
    assert tail == UNKNOWN + ", ".join(list(features)[:5]) + " and 39995 more"


# ---------------------------------------------------------------------------
# What stays silent: the platform-limited keys, and the shipped presets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key,value", [("BackgroundModeEnabled", False), ("DynamicCodeSettings", 1)])
def test_a_platform_limited_key_is_skipped_silently_where_no_row_writes_it(mod, tmp_path, key, value):
    _, policy, tail = _import(mod, tmp_path, {"Features": {key: value}})
    assert tail == ""
    if key in _row_keys(mod):
        assert policy == {key: value}
    else:
        assert policy == {}


def test_darwin_skips_background_mode_and_linux_takes_it(tmp_path):
    _, policy, tail = _import(MAC_DARWIN, tmp_path, {"Features": {"BackgroundModeEnabled": False}})
    assert (policy, tail) == ({}, "")
    _, policy, tail = _import(LINUX_MOD, tmp_path, {"Features": {"BackgroundModeEnabled": False}})
    assert (policy, tail) == ({"BackgroundModeEnabled": False}, "")


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_the_presets_import_without_a_note(mod, preset):
    ok, msg = mod.import_settings(mod.build_rows(), str(preset))
    assert ok and msg == f"Imported from {preset.name}"


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_the_presets_carry_only_the_origin_count_on_origin(mod, preset):
    rows = mod.build_rows(_origin_installs(mod))
    inert = {r["key"] for r in rows if r["type"] == mod.ROW_FEATURE and r.get("inert")}
    n = len(set(json.loads(preset.read_text(encoding="utf-8"))["Features"]) & inert)
    ok, msg = mod.import_settings(rows, str(preset))
    assert ok
    count = f"; {n} key{'s' if n != 1 else ''} built into Brave Origin left unmanaged" if n else ""
    assert msg == f"Imported from {preset.name}" + count


# ---------------------------------------------------------------------------
# Refusals: keys that differ only in letter case, a mis-cased Features
# ---------------------------------------------------------------------------


def _preticked(mod):
    rows = mod.build_rows()
    row = next(r for r in rows if r["type"] == mod.ROW_FEATURE and r["key"] == "MetricsReportingEnabled")
    mod.toggle_feature_row(rows, row)
    return rows


def _untouched(mod, rows):
    policy, err = mod._build_policy(rows)
    return err == "" and policy == {"MetricsReportingEnabled": False}


CASE_TWINS = [
    ('{"Features": {}, "features": {}}', "Features, features"),
    ('{"features": {}, "Features": {}}', "features, Features"),
    ('{"Features": {"QuicAllowed": false, "quicallowed": false}}', "QuicAllowed, quicallowed"),
    ('{"DnsMode": "off", "DNSMODE": "off", "Features": {}}', "DnsMode, DNSMODE"),
    ('{"Features": {"ExtensionInstallBlocklist": [{"Id": 1, "id": 2}]}}', "Id, id"),
    ('{"Features": {}, "x": {"y": {"z": {"Deep": 1, "dEEP": 2}}}}', "Deep, dEEP"),
    ('{"Features": {"a b": 1, "A B": 2}}', '"a b", "A B"'),
    ('{"Features": {"Caf\\u00e9X": 1, "Caf\\u00e9x": 2}}', '"Caf\\u00E9X", "Caf\\u00E9x"'),
    # .NET's OrdinalIgnoreCase folds more than ASCII, so these fail on
    # Windows too: an accented letter, a dotless i, a long s.
    ('{"Features": {"\\u00c9t\\u00e9": 1, "\\u00e9t\\u00e9": 2}}',
     '"\\u00C9t\\u00E9", "\\u00E9t\\u00E9"'),
    ('{"Features": {"I": 1, "\\u0131": 2}}', 'I, "\\u0131"'),
    ('{"Features": {"\\u017fx": 1, "sx": 2}}', '"\\u017Fx", sx'),
]


@pytest.mark.parametrize("text,names", CASE_TWINS, ids=[
    "top-level", "top-level-reversed", "features", "dns-field", "inside-a-list",
    "deep", "quoted-names", "ascii-case-in-a-non-ascii-name", "non-ascii-letters",
    "dotless-i", "long-s"])
def test_keys_that_differ_only_in_letter_case_refuse_the_file(mod, tmp_path, text, names):
    """Windows PowerShell 5.1's ConvertFrom-Json cannot read such a file at
    any depth, so no script imports it."""
    rows = _preticked(mod)
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, text)))
    assert ok is False
    assert msg == "Invalid config: keys differ only in letter case: " + names
    assert _untouched(mod, rows)


def test_read_json_file_raises_a_value_error_for_case_twins_and_empty_keys(mod, tmp_path):
    with pytest.raises(ValueError):
        mod.read_json_file(str(_write(tmp_path, '{"a": 1, "A": 2}')))
    with pytest.raises(ValueError):
        mod.read_json_file(str(_write(tmp_path, '{"a": {"": 1}}')))


def test_an_accented_pair_differing_only_in_case_is_refused(mod, tmp_path):
    # U+00C9 and U+00E9 are one name to Windows PowerShell 5.1, which cannot
    # read the file, so no script imports it.
    rows = _preticked(mod)
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, '{"Features": {"\\u00c9": 1, "\\u00e9": 2}}')))
    assert ok is False and msg.startswith("Invalid config: keys differ only in letter case")
    assert _untouched(mod, rows)


def test_a_key_written_twice_in_the_same_case_is_left_to_json(mod, tmp_path):
    _, policy, tail = _import(mod, tmp_path, '{"Features": {"ChromeVariations": 1, "ChromeVariations": 2}}')
    assert policy == {"ChromeVariations": 2} and tail == ""


@pytest.mark.parametrize("text,names", [
    ('{"Features": {"Stra\\u00dfe": 1, "STRASSE": 2}}', '"Stra\\u00DFe", STRASSE'),
    ('{"Features": {"\\ufb00": 1, "FF": 2}}', '"\\uFB00", FF'),
    ('{"Features": {"\\u212a": 1, "k": 2}}', '"\\u212A", k'),
    # Beyond U+FFFF: .NET Framework folds one UTF-16 unit at a time, so a
    # surrogate pair never folds and Windows imports the pair as two names.
    ('{"Features": {"\\ud801\\udc00": 1, "\\ud801\\udc28": 2}}', '"\\uD801\\uDC00", "\\uD801\\uDC28"'),
], ids=["sharp-s", "ligature", "kelvin-sign", "beyond-bmp"])
def test_letters_one_by_one_are_folded_when_looking_for_twins(mod, tmp_path, text, names):
    """Each character folds to its own upper case, as in .NET, and only when
    that is one character: the sharp s and the ff ligature stay as they are
    (str.upper() would make them SS and FF), and the Kelvin sign is upper
    case already. Such a pair is two names in every script."""
    _, _, tail = _import(mod, tmp_path, text)
    assert tail == UNKNOWN + names


EMPTY_KEYS = [
    '{"Features": {"": true}}',
    '{"Features": {}, "": 1}',
    '{"Features": {"ExtensionInstallBlocklist": [{"": 1}]}}',
    '{"Features": {}, "x": {"y": {"z": {"": 2}}}}',
    '{"Features": {"BraveRewardsDisabled": true, "": false}}',
]


@pytest.mark.parametrize("text", EMPTY_KEYS, ids=[
    "features", "top-level", "inside-a-list", "deep", "beside-a-row-key"])
def test_an_empty_key_refuses_the_file(mod, tmp_path, text):
    """Windows PowerShell 5.1's ConvertFrom-Json cannot read a property
    with an empty name, at any depth, so no script imports such a file."""
    rows = _preticked(mod)
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, text)))
    assert (ok, msg) == (False, "Invalid config: a key is empty")
    assert _untouched(mod, rows)


def test_an_empty_legacy_entry_is_a_name_not_a_key(mod, tmp_path):
    _, policy, tail = _import(mod, tmp_path, {"Features": ["", "BraveRewardsDisabled"]})
    assert policy == {"BraveRewardsDisabled": True}
    assert tail == UNKNOWN + '""'


@pytest.mark.parametrize("config,hint", [
    ({"features": {"MetricsReportingEnabled": False}}, " (found features; names are case-sensitive)"),
    ({"FEATURES": ["BraveRewardsDisabled"]}, " (found FEATURES; names are case-sensitive)"),
    ({"fEaTuReS": 5}, " (found fEaTuReS; names are case-sensitive)"),
    ({"Features ": {}}, ""),
    ({"Features": None}, ""),
    ({"DnsMode": "off"}, ""),
], ids=["lower", "upper-legacy", "mixed-not-a-block", "trailing-blank", "null", "dns-only"])
def test_a_refusal_for_no_features_block_points_at_a_miscased_one(mod, tmp_path, config, hint):
    rows = _preticked(mod)
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, config)))
    assert ok is False
    assert msg == "Invalid config: no Features block (not a SlimBrave Neo config)" + hint
    assert _untouched(mod, rows)


# ---------------------------------------------------------------------------
# --import: exit 1, and nothing written, when nothing in the file was taken
# ---------------------------------------------------------------------------


@pytest.fixture
def applied(mod, monkeypatch):
    """The policies cli_import hands to Apply (which never runs for real)."""
    calls = []

    def fake_apply(rows, *args, **kwargs):
        policy, err = mod._build_policy(rows)
        assert err == ""
        calls.append(policy)
        return True, "Applied."

    monkeypatch.setattr(mod, "apply_policy", fake_apply)
    monkeypatch.setattr(mod, "_is_profile_installed", lambda: False, raising=False)
    return calls


NOTHING_TAKEN = [
    {"Features": {"HomepageLocation": "https://example.com"}},
    {"Features": ["NotAPolicy", 5]},
    {"Features": {"ShoppingListEnabled": False}},
    {"Features": {"metricsreportingenabled": False}},
    {"Features": {"DefaultNotificationsSetting": 3}},
    {"Features": {"DynamicCodeSettings": 1}},
    {"Features": {"HomepageLocation": "x"}, "DnsMode": "bogus"},
    {"Features": {"HomepageLocation": "x"}, "DnsMode": "unmanaged"},
    {"Features": {"HomepageLocation": "x"}, "DnsMode": False,
     "DnsTemplates": "https://dns.example/dns-query"},
]


@pytest.mark.parametrize("config", NOTHING_TAKEN, ids=[
    "unknown", "legacy-unknown", "retired", "miscased", "unoffered-value",
    "platform-limited", "unknown-dns-mode", "unmanaged-dns", "false-dns-mode"])
def test_cli_import_writes_nothing_when_no_entry_was_taken(mod, tmp_path, applied, capsys, config):
    """Applying would write an empty policy and remove SlimBrave's own. The
    words hold after a --reset in the same command, which runs first."""
    path = _write(tmp_path, config)
    assert mod.cli_import(str(path), None) == 1
    assert applied == []
    out, err = capsys.readouterr()
    rows = mod.build_rows()
    assert out == mod.import_settings(rows, str(path))[1] + "\n"
    assert err == f"Error: nothing in {path} can be applied; --import wrote nothing.\n"


def test_cli_import_names_the_path_escaped_when_it_writes_nothing(mod, tmp_path, applied, capsys):
    path = _write_named(tmp_path, {"Features": {"HomepageLocation": "x"}}, ODD_NAME)
    assert mod.cli_import(str(path), None) == 1
    out, err = capsys.readouterr()
    assert out.startswith(f"Imported from {_esc_name(ODD_NAME)}; ")
    assert err == f"Error: nothing in {_esc_name(str(path))} can be applied; --import wrote nothing.\n"
    # The --doh-templates conflict names the file the same way.
    path = _write_named(tmp_path, {"Features": {}, "DnsMode": "off"}, "off " + ODD_NAME)
    assert mod.cli_import(str(path), None, doh_templates="https://dns.example/dns-query") == 1
    err = capsys.readouterr().err
    assert err == ("Error: --doh-templates conflicts with DnsMode 'off' in "
                   f"{_esc_name(str(path))}. Remove one of them.\n")
    assert applied == []


# The child loads a script, stubs Apply (it never writes anything) and runs
# cli_import, printing to an ASCII stdout with strict errors.
ASCII_CHILD = r"""
import importlib.util
import sys

assert (sys.stdout.encoding, sys.stdout.errors) == ("ascii", "strict"), sys.stdout
script, platform, target = sys.argv[1:4]
real = sys.platform
if platform:
    sys.platform = platform
try:
    spec = importlib.util.spec_from_file_location("slimbrave_ascii_child", script)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
finally:
    sys.platform = real
mod.apply_policy = lambda rows, *args, **kwargs: (True, "Applied.")
mod._is_profile_installed = lambda: False
sys.exit(mod.cli_import(target, None))
"""


def _cli_on_an_ascii_stdout(script, platform, target, cwd):
    """(exit code, stdout, stderr) of the child; output that is not ASCII
    fails to decode."""
    env = dict(os.environ, LC_ALL="C", PYTHONIOENCODING="ascii:strict", PYTHONUTF8="1")
    proc = subprocess.run([sys.executable, "-c", ASCII_CHILD, str(ROOT / script), platform, target],
                          cwd=cwd, env=env, capture_output=True, encoding="ascii", timeout=120)
    return proc.returncode, proc.stdout, proc.stderr


@pytest.mark.parametrize("script,platform", [
    ("slimbrave-linux.py", ""), ("slimbrave-mac.py", ""), ("slimbrave-mac.py", "darwin"),
], ids=MODULE_IDS)
def test_cli_import_on_an_ascii_stdout_prints_the_file_name_escaped(tmp_path, script, platform):
    """With LC_ALL=C and PYTHONIOENCODING=ascii, print() raised
    UnicodeEncodeError on 'Imported from caf\u00e9.json' before anything was
    applied, and a newline or an ESC in a name went to the terminal. The
    child runs without root; Apply is a stub there."""
    good = _write_named(tmp_path, {"Features": {"BraveRewardsDisabled": True, "NotAPolicy": 1}}, ODD_NAME)
    rc, out, err = _cli_on_an_ascii_stdout(script, platform, str(good), str(tmp_path))
    assert (rc, out, err) == (0, f"Imported from {_esc(ODD_NAME)}{UNKNOWN}NotAPolicy\nApplied.\n", "")
    bad = _write_named(tmp_path, {"Features": {"NotAPolicy": 1}}, "x" + ODD_NAME)
    rc, out, err = _cli_on_an_ascii_stdout(script, platform, str(bad), str(tmp_path))
    assert (rc, out) == (1, f"Imported from {_esc(bad.name)}{UNKNOWN}NotAPolicy\n")
    assert err == f"Error: nothing in {_esc(str(bad))} can be applied; --import wrote nothing.\n"


@pytest.mark.parametrize("config,policy", [
    ({"Features": {}}, {}),
    ({"Features": []}, {}),
    ({"Features": {"HomepageLocation": "x", "BraveRewardsDisabled": True}}, {"BraveRewardsDisabled": True}),
    ({"Features": ["NotAPolicy", "BraveRewardsDisabled"]}, {"BraveRewardsDisabled": True}),
    ({"Features": {"HomepageLocation": "x"}, "DnsMode": "off"}, {"DnsOverHttpsMode": "off"}),
    ({"Features": {"HomepageLocation": "x"}, "DnsTemplates": "https://dns.example/dns-query"},
     {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": "https://dns.example/dns-query"}),
    ({"Features": {"BraveShieldsDisabledForUrls": SHIELDS_WILDCARDS,
                   "BraveShieldsEnabledForUrls": SHIELDS_WILDCARDS}},
     {"BraveShieldsEnabledForUrls": SHIELDS_WILDCARDS}),
], ids=["empty-object", "empty-array", "one-taken", "legacy-one-taken", "dns-mode",
        "bare-template", "group"])
def test_cli_import_applies_whatever_was_taken(mod, tmp_path, applied, capsys, config, policy):
    """An empty Features block still applies an empty policy, as it always
    has; anything taken, a DNS mode included, is applied."""
    path = _write(tmp_path, config)
    assert mod.cli_import(str(path), None) == 0
    assert applied == [policy]
    out, err = capsys.readouterr()
    assert out.startswith(f"Imported from {path.name}")
    assert "Error" not in err


def test_cli_import_names_what_it_left_out_and_applies_the_rest(mod, tmp_path, applied, capsys):
    path = _write(tmp_path, {"Features": {"NotAPolicy": 1, "BraveRewardsDisabled": True}})
    assert mod.cli_import(str(path), None) == 0
    assert applied == [{"BraveRewardsDisabled": True}]
    out = capsys.readouterr().out
    assert out.startswith(f"Imported from {path.name}{UNKNOWN}NotAPolicy\n")


def test_cli_import_of_background_mode_alone_depends_on_the_row(mod, tmp_path, applied):
    path = _write(tmp_path, {"Features": {"BackgroundModeEnabled": False}})
    has_row = "BackgroundModeEnabled" in _row_keys(mod)
    assert mod.cli_import(str(path), None) == (0 if has_row else 1)
    assert applied == ([{"BackgroundModeEnabled": False}] if has_row else [])


def test_doh_templates_do_not_make_an_untaken_file_apply(mod, tmp_path, applied):
    """The decision is about the file: the flag only fills in its DNS."""
    path = _write(tmp_path, {"Features": {"HomepageLocation": "x"}})
    assert mod.cli_import(str(path), None, doh_templates="https://dns.example/dns-query") == 1
    assert applied == []


def test_cli_import_on_origin_applies_a_preset_and_refuses_built_ins_alone(mod, tmp_path, applied):
    installs = _origin_installs(mod)
    preset = ROOT / "Presets" / "Brave Origin Preset.json"
    assert mod.cli_import(str(preset), installs) == 0
    assert len(applied) == 1 and set(applied[0]) == {"BraveP3AEnabled", "BraveStatsPingEnabled"}
    path = _write(tmp_path, {"Features": {"BraveRewardsDisabled": True}})
    assert mod.cli_import(str(path), installs) == 1
    assert len(applied) == 1


# ---------------------------------------------------------------------------
# The TUI: a status of up to four lines
# ---------------------------------------------------------------------------


TUI_MODULES = [LINUX_MOD, MAC_MOD]


@pytest.fixture(params=TUI_MODULES, ids=["linux", "mac"])
def tui(request):
    return request.param


def test_status_lines_wraps_to_four_lines_and_marks_a_cut(tui):
    assert tui.status_lines("", 80) == []
    assert tui.status_lines("short", 80) == ["short"]
    assert tui.status_lines("a" * 76, 80) == ["a" * 76]
    assert len(tui.status_lines("a" * 77, 80)) == 2
    words = " ".join(f"word{i:02d}" for i in range(60))   # 419 characters
    lines = tui.status_lines(words, 80)
    assert len(lines) == 4
    assert all(len(line) <= 76 for line in lines)
    assert lines[-1].endswith("...") and not lines[-1].endswith(" ...")
    assert " ".join(lines[:3]) == words[:len(" ".join(lines[:3]))]
    fits = " ".join(f"word{i:02d}" for i in range(30))    # 209: three lines whole
    assert " ".join(tui.status_lines(fits, 80)) == fits
    # A resolver URL is not split at its hyphen.
    url = "see https://dns.example/dns-query now"
    assert "https://dns.example/dns-query" in tui.status_lines(url, 34)
    # Fewer lines when asked, the cut marked on the last.
    one = tui.status_lines(words, 80, 1)
    assert len(one) == 1 and one[0].endswith("...")


def test_layout_takes_status_lines_from_the_list(tui):
    one = tui.layout(24, 80, True)
    assert tui.layout(24, 80, True, 1) == one
    assert one["status_lines"] == 1 and one["status_y"] == 23
    four = tui.layout(24, 80, True, 4)
    assert (four["status_y"], four["status_lines"]) == (20, 4)
    assert four["list_rows"] == one["list_rows"] - 3
    assert four["pane_lines"] == one["pane_lines"] == 4
    assert tui.layout(24, 80, True, 9) == four        # at most four
    assert tui.layout(24, 80, False, 4)["list_rows"] == tui.layout(24, 80, False)["list_rows"] - 3
    for max_y in range(9, 60):
        for show in (False, True):
            for want in range(0, 6):
                lay = tui.layout(max_y, 80, show, want)
                n = lay["status_lines"]
                assert n == max(1, min(want, 4, max_y - 8))
                assert lay["status_y"] + n == max_y
                assert lay["btn_top"] + 2 == lay["status_y"] - 1
                assert lay["list_rows"] >= 1 and lay["list_bottom"] < lay["btn_top"]
    # The unframed stack keeps one status line.
    for max_y in range(5, 9):
        lay = tui.layout(max_y, 80, True, 4)
        assert not lay["framed"]
        assert (lay["status_y"], lay["status_lines"]) == (max_y - 1, 1)


class _FakeScreen:
    def __init__(self, lines=24, cols=80):
        self._size = (lines, cols)

    def getmaxyx(self):
        return self._size


def test_viewport_rows_counts_the_status_lines(tui):
    screen = _FakeScreen(24, 80)
    assert tui.viewport_rows(screen, show_desc=True) == 10
    assert tui.viewport_rows(screen, True, "a short note") == 10
    assert tui.viewport_rows(screen, True, "x" * 300) == 7    # four lines of 76
    assert tui.viewport_rows(screen, False, "x" * 300) == 13


class _FakeCurses:
    """The curses surface the scripts touch, minus the terminal."""

    error = curses.error

    def __init__(self):
        for name in dir(curses):
            if name.startswith(("KEY_", "A_", "COLOR_")):
                setattr(self, name, getattr(curses, name))

    def curs_set(self, v):
        pass

    def start_color(self):
        pass

    def use_default_colors(self):
        pass

    def init_pair(self, *args):
        pass

    def color_pair(self, n):
        return n << 8

    def update_lines_cols(self):
        pass


class _GridScreen:
    """A curses window that keeps its cells and, like ncurses, refuses a NUL."""

    def __init__(self, lines, cols, keys=()):
        self.lines, self.cols, self.keys = lines, cols, list(keys)
        self.frames = []
        self.refused = 0
        self.erase()

    def erase(self):
        self.cells = [[" "] * self.cols for _ in range(self.lines)]

    def getmaxyx(self):
        return (self.lines, self.cols)

    def addnstr(self, y, x, s, n, attr=0):
        if "\x00" in str(s):
            self.refused += 1
            raise ValueError("embedded null character")
        if not (0 <= y < self.lines and 0 <= x < self.cols):
            raise curses.error("outside the window")
        s = str(s)[:max(0, n)][:self.cols - x]
        for i, ch in enumerate(s):
            self.cells[y][x + i] = ch

    def refresh(self):
        self.frames.append(["".join(row) for row in self.cells])

    def getch(self):
        return self.keys.pop(0) if self.keys else 27   # Esc: quit

    def keypad(self, v):
        pass

    def timeout(self, v):
        pass


def _install(tui, tmp_path):
    chan = {"id": "stable", "label": "Brave", "process_name": "brave",
            "user_data_dir": "BraveSoftware/Brave-Browser"}
    return tui._make_installation(chan, plist_path=str(tmp_path / "slimbrave.json"),
                                  prefs_path=str(tmp_path / "Preferences"))


def _run_tui(tui, monkeypatch, tmp_path, keys, lines=24, cols=80):
    monkeypatch.setattr(tui, "curses", _FakeCurses())
    monkeypatch.setattr(tui, "_box_glyphs", tui.BOX_ASCII)
    monkeypatch.setattr(tui, "_disclosure_glyphs", tui.DISCLOSURE_ASCII)
    inst = _install(tui, tmp_path)
    monkeypatch.setattr(tui, "detect_brave",
                        lambda: {"method": "", "warnings": [], "installations": [inst]})
    screen = _GridScreen(lines, cols, keys)
    tui.main(screen, override_installations=[inst])
    return screen


def _import_keys(path):
    """Tab to the Import button, Enter, clear the prompt, type, Enter."""
    text = str(path)
    if not all(32 <= ord(c) <= 126 for c in text):
        pytest.skip("the prompt takes printable ASCII only")
    return ([ord("\t"), 10] + [127] * len("./Presets/")
            + [ord(c) for c in text] + [10])


LONG_RESULT = {
    "Comment": "x", "dnsmode": "off",
    "Features": {"NotAPolicyNumberOne": 1, "NotAPolicyNumberTwo": 1,
                 "NotAPolicyNumberThree": 1, "metricsreportingenabled": False,
                 "IncognitoModeAvailability": 0, "ShoppingListEnabled": False,
                 "ChromeVariations": "2"},
}


@pytest.mark.parametrize("config", [
    {"Features": {"metricsreportingenabled": False, "NotAPolicy": 1}},
    LONG_RESULT,
], ids=["three-lines", "cut-at-four"])
def test_the_tui_shows_an_import_result_on_up_to_four_lines(tui, monkeypatch, tmp_path, config):
    path = _write(tmp_path, config)
    _, msg = tui.import_settings(tui.build_rows([_install(tui, tmp_path)]), str(path))
    want = tui.status_lines(msg, 80)
    assert 1 < len(want) <= 4
    frame = _run_tui(tui, monkeypatch, tmp_path, _import_keys(path)).frames[-1]
    lay = tui.layout(24, 80, True, len(want))
    assert lay["status_lines"] == len(want)
    shown = [frame[lay["status_y"] + i] for i in range(len(want))]
    assert [row[2:].rstrip() for row in shown] == want
    assert all(row[:2] == "  " and row[79] == " " for row in shown)
    if config is LONG_RESULT:
        assert len(tui.status_lines(msg, 80, 99)) > 4 and want[-1].endswith("...")
    else:
        assert " ".join(want) == msg
    # The buttons sit right above the status, and the list paid for it.
    assert frame[lay["btn_top"] + 2].startswith("+-")
    assert frame[lay["list_bottom"]].startswith("+")
    assert lay["list_rows"] == tui.layout(24, 80, True)["list_rows"] - (len(want) - 1)


def test_the_list_gets_its_rows_back_when_the_status_clears(tui, monkeypatch, tmp_path):
    path = _write(tmp_path, LONG_RESULT)
    # Up from the buttons goes back to the list and clears the status.
    frame = _run_tui(tui, monkeypatch, tmp_path, _import_keys(path) + [curses.KEY_UP]).frames[-1]
    lay = tui.layout(24, 80, True)
    assert frame[lay["status_y"]].strip() == ""
    assert frame[lay["list_bottom"]].startswith("+") and lay["list_rows"] == 10
    assert frame[lay["btn_top"] + 2].startswith("+-")


def test_an_imported_nul_no_longer_ends_the_tui(tui, monkeypatch, tmp_path):
    """{"Features":{},"DnsMode":"\\u0000"} used to raise ValueError out of
    curses; the message now carries the escape, never the NUL."""
    path = _write(tmp_path, '{"Features": {}, "DnsMode": "\\u0000"}')
    screen = _run_tui(tui, monkeypatch, tmp_path, _import_keys(path))
    assert screen.refused == 0
    text = "\n".join(screen.frames[-1])
    assert 'DnsMode="\\u0000"' in text


def test_put_survives_a_nul_in_any_text(tui, monkeypatch):
    """Defence in depth: whatever else reaches the screen, a NUL costs that
    text, not the TUI."""
    monkeypatch.setattr(tui, "curses", _FakeCurses())
    monkeypatch.setattr(tui, "_box_glyphs", tui.BOX_ASCII)
    monkeypatch.setattr(tui, "_disclosure_glyphs", tui.DISCLOSURE_ASCII)
    screen = _GridScreen(24, 80)
    rows = tui.build_rows()
    tui.draw(screen, rows, 1, 0, tui.FOCUS_BUTTONS, 0, "a\x00b", False, show_desc=True)
    assert screen.refused == 1
    assert len(screen.frames) == 1


def test_the_tui_refuses_an_import_that_raises_recursion_error(tui, monkeypatch, tmp_path):
    """The RecursionError used to escape curses.wrapper and end the TUI."""
    path = _write(tmp_path, {"Features": {"BraveRewardsDisabled": True}})
    monkeypatch.setattr(tui, "_enforce_groups", _recursion_error)
    screen = _run_tui(tui, monkeypatch, tmp_path, _import_keys(path))
    assert "Invalid config: nesting too deep" in "\n".join(screen.frames[-1])


# A template the policy file holds reaches the field unchecked (Import
# refuses a control character, policy-sync does not): line feed, carriage
# return, tab, ESC, NEL, the two separators, then four bidi controls.
HIDDEN = "\n\r\t\x1b\x85\u2028\u2029\u202a\u202e\u2066\u2069"


def test_the_template_field_draws_control_and_bidi_characters_as_question_marks(tui, monkeypatch, tmp_path):
    """A line feed moved the cursor and painted the rest of the template
    over the list, a bidi control reordered the row. Printable non-ASCII,
    an IDN host's, is drawn as it is; the cursor's character is masked too."""
    monkeypatch.setattr(tui, "curses", _FakeCurses())
    monkeypatch.setattr(tui, "_box_glyphs", tui.BOX_ASCII)
    monkeypatch.setattr(tui, "_disclosure_glyphs", tui.DISCLOSURE_ASCII)
    rows = tui.build_rows([_install(tui, tmp_path)])
    tmpl = "https://a" + HIDDEN + "b.r\u00e9solveur.example/q"
    tui.sync_rows_with_policy(rows, {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": tmpl})
    assert tui.get_dns_mode(rows) == "custom" and tui.get_dns_template(rows) == tmpl
    idx = next(i for i, r in enumerate(rows) if r["type"] == tui.ROW_DNS_TEMPLATE)
    rows[idx]["cursor"] = tmpl.index("\n")      # the cursor on the line feed
    vis = tui.visible_indices(rows)
    screen = _GridScreen(24, 80)
    tui.draw(screen, rows, idx, max(0, vis.index(idx) - 1), tui.FOCUS_LIST, 0, "", True,
             show_desc=True)
    frame = screen.frames[-1]
    line = next(row for row in frame if "Template: [" in row)
    shown = "https://a" + "?" * len(HIDDEN) + "b.r\u00e9solveur.example/q"
    assert "Template: [" + shown + " " in line, repr(line)
    assert not any(c in HIDDEN for row in frame for c in row)
    start = line.index("Template: [") + len("Template: [")
    assert line[start + tmpl.index("\n")] == "?"


# ---------------------------------------------------------------------------
# Final review fixes: number range, Greek case pairs, bidi controls in a
# template, and what the template field draws
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    '{"Features": {"MetricsReportingEnabled": 1e400}}',
    '{"Features": {"MetricsReportingEnabled": -1e400}}',
    '{"Features": {"ChromeVariations": 1' + "0" * 400 + '}}',
    '{"Features": {}, "DnsMode": 1' + "0" * 400 + '}',
    '{"Features": ["BraveRewardsDisabled", 1' + "0" * 400 + ']}',
], ids=["float-overflow", "negative-overflow", "long-integer", "dns-mode", "legacy-entry"])
def test_a_number_past_the_double_range_refuses_the_file(mod, tmp_path, text):
    """Windows PowerShell 5.1's reader cannot read such a number, so no
    script imports the file; reading it as a float also keeps a huge digit
    string linear on a Python without the 4300-digit limit."""
    rows = _preticked(mod)
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, text)))
    assert (ok, msg) == (False, "Invalid JSON: a number is out of range")
    assert _untouched(mod, rows)


def test_an_integer_past_64_bits_but_within_a_double_is_not_an_integer(mod, tmp_path):
    _, policy, tail = _import(mod, tmp_path, '{"Features": {"ChromeVariations": 18446744073709551616}}')
    assert policy == {}
    assert tail == "; left unmanaged because the value is not one this policy accepts: ChromeVariations"


@pytest.mark.parametrize("pair", [("\\u1f80", "\\u1f88"), ("\\u1fb3", "\\u1fbc"), ("\\u1ff3", "\\u1ffc")],
                         ids=["1F80", "1FB3", "1FF3"])
def test_a_greek_letter_with_ypogegrammeni_folds_as_on_windows(mod, tmp_path, pair):
    """.NET folds U+1F80 to U+1F88 (one character, its simple upper case),
    where str.upper() gives two, so such a pair is one name on Windows and
    is refused here too."""
    rows = _preticked(mod)
    text = '{"Features": {"%s": 1, "%s": 2}}' % pair
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, text)))
    assert ok is False and msg.startswith("Invalid config: keys differ only in letter case")
    assert _untouched(mod, rows)


@pytest.mark.parametrize("ch", ["؜", "‎", "‏", "‮", "⁦", "⁩"],
                         ids=["ALM", "LRM", "RLM", "RLO", "LRI", "PDI"])
def test_a_bidi_control_in_a_template_refuses_the_file(mod, tmp_path, ch):
    rows = _preticked(mod)
    text = json.dumps({"Features": {}, "DnsMode": "custom", "DnsTemplates": "https://dns.example/" + ch + "dns-query"})
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, text)))
    assert (ok, msg) == (False, "Invalid config: DnsTemplates contains a control character")
    assert _untouched(mod, rows)


@pytest.mark.parametrize("text,shown", [
    ("https://dns.exämple/dns-query", "https://dns.exämple/dns-query"),  # narrow, kept
    ("https://ｄｎｓ/x", "https://???/x"),                              # fullwidth: two cells each
    ("https://例え/x", "https://??/x"),                                     # CJK: wide
    ("https://áb/x", "https://a?b/x"),                                        # combining mark: no cell
    ("https://a​b/x", "https://a?b/x"),                                        # zero-width space: format
    ("https://a‎b/x", "https://a?b/x"),                                        # bidi control
])
def test_the_template_field_draws_one_cell_per_character(mod, text, shown):
    assert mod._field_text(text) == shown
