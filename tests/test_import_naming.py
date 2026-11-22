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
import pathlib
import re
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
    "_ASCII_LOWER", "_KeysDifferInCase", "_refuse_case_twins", "read_json_file",
    "CONFIG_FIELDS", "PLATFORM_LIMITED_KEYS", "FEATURES_NAME_HINTS",
    "IMPORT_NOTES", "EXCLUSIVE_REASON", "SHOWN_MAX", "MAX_SHOWN_ITEMS",
    "_PLAIN_NAME_CHARS", "_quoted", "_shown_name", "_shown_value", "_shown_item",
    "_note_clause", "import_settings", "_import_config", "STATUS_MAX_LINES",
    "status_lines", "layout", "viewport_rows", "draw",
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
    (10 ** 70, str(10 ** 70)[:61] + "..."),
    ("x", '"x"'), ("", '""'), ("DISABLE_NON_PROXIED_UDP", '"DISABLE_NON_PROXIED_UDP"'),
    ("\x00", '"\\u0000"'),
    (2.0, None), (2.5, None), (float("inf"), None), ([], None), ([1], None), ({}, None),
], ids=["true", "false", "null", "int", "negative", "zero", "big-int", "huge-int",
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
    # file order, not table order
    assert tail == EXCLUSIVE + "SpellCheckServiceEnabled, BraveShieldsDisabledForUrls"


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


@pytest.mark.parametrize("first", ["DnsMode", "Features"])
def test_items_keep_file_order_across_the_top_level_and_features(mod, tmp_path, first):
    features = {"ChromeVariations": "2", "metricsreportingenabled": False}
    top = {"DnsMode": "bogus", "dnstemplates": "https://dns.example/dns-query"}
    config = {"Features": features, **top} if first == "Features" else {**top, "Features": features}
    _, _, tail = _import(mod, tmp_path, config)
    if first == "Features":
        assert tail == (CASE + "metricsreportingenabled (use MetricsReportingEnabled), "
                        "dnstemplates (use DnsTemplates)"
                        + TYPE + 'ChromeVariations="2", DnsMode="bogus"')
    else:
        assert tail == (CASE + "dnstemplates (use DnsTemplates), "
                        "metricsreportingenabled (use MetricsReportingEnabled)"
                        + TYPE + 'DnsMode="bogus", ChromeVariations="2"')


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
                     "\U0001F600": 1, "": 2, "x" * 500: 1},
        "\x07": 1, "DnsMode": "\x00"})
    assert all(" " <= c <= "~" for c in tail), repr(tail)
    assert tail == (
        TYPE + 'DnsMode="\\u0000"'
        + VALUE + 'WebRtcIPHandling="\\u202Edefault"'
        + UNKNOWN + '"\\u0000x", "a\\u001B[2Jb", "\\uD83D\\uDE00", "", "' + "x" * 61 + '..."'
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
]


@pytest.mark.parametrize("text,names", CASE_TWINS, ids=[
    "top-level", "top-level-reversed", "features", "dns-field", "inside-a-list",
    "deep", "quoted-names", "ascii-case-in-a-non-ascii-name"])
def test_keys_that_differ_only_in_letter_case_refuse_the_file(mod, tmp_path, text, names):
    """Windows PowerShell 5.1's ConvertFrom-Json cannot read such a file at
    any depth, so no script imports it."""
    rows = _preticked(mod)
    ok, msg = mod.import_settings(rows, str(_write(tmp_path, text)))
    assert ok is False
    assert msg == "Invalid config: keys differ only in letter case: " + names
    assert _untouched(mod, rows)


def test_read_json_file_raises_a_value_error_for_case_twins(mod, tmp_path):
    with pytest.raises(ValueError):
        mod.read_json_file(str(_write(tmp_path, '{"a": 1, "A": 2}')))


def test_a_key_written_twice_in_the_same_case_is_left_to_json(mod, tmp_path):
    _, policy, tail = _import(mod, tmp_path, '{"Features": {"ChromeVariations": 1, "ChromeVariations": 2}}')
    assert policy == {"ChromeVariations": 2} and tail == ""


def test_only_ascii_letters_are_folded_when_looking_for_twins(mod, tmp_path):
    """The rule Import's names follow; ConvertFrom-Json folds more, so this
    pair is refused on Windows alone."""
    _, _, tail = _import(mod, tmp_path, '{"Features": {"\\u00c9": 1, "\\u00e9": 2}}')
    assert tail == UNKNOWN + '"\\u00C9", "\\u00E9"'


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
]


@pytest.mark.parametrize("config", NOTHING_TAKEN, ids=[
    "unknown", "legacy-unknown", "retired", "miscased", "unoffered-value",
    "platform-limited", "unknown-dns-mode", "unmanaged-dns"])
def test_cli_import_writes_nothing_when_no_entry_was_taken(mod, tmp_path, applied, capsys, config):
    """Applying would write an empty policy and remove SlimBrave's own."""
    path = _write(tmp_path, config)
    assert mod.cli_import(str(path), None) == 1
    assert applied == []
    out, err = capsys.readouterr()
    rows = mod.build_rows()
    assert out == mod.import_settings(rows, str(path))[1] + "\n"
    assert err == f"Error: nothing in {path} can be applied; the policy was left as it was.\n"


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
