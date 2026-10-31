"""Unit tests for the pure logic shared by slimbrave-linux.py and slimbrave-mac.py.

Both scripts are loaded as modules (their entry points are guarded by
__main__) and every test runs against each, so a fix applied to one file
that is missed in the other fails loudly here. slimbrave-mac.py is loaded a
second time with sys.platform faked as Darwin, which is the only way to
reach its Configuration Profile helpers off a Mac. Nothing in this file
touches /etc, the registry, or a real Brave profile — filesystem work stays
in pytest's tmp_path.
"""

import ast
import curses
import importlib.util
import json
import os
import pathlib
import plistlib
import random
import re
import socket
import stat
import sys
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(alias, filename):
    spec = importlib.util.spec_from_file_location(alias, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


def _load_as(platform, alias, filename):
    """Load a module with sys.platform faked for the length of the import."""
    real_platform = sys.platform
    sys.platform = platform
    try:
        return _load(alias, filename)
    finally:
        sys.platform = real_platform


def _load_as_darwin(alias, filename):
    """Load a module with sys.platform faked as macOS.

    slimbrave-mac.py keeps `plistlib`, `uuid` and every persistence
    constant inside an `if IS_MAC:` block, so the Configuration Profile
    helpers are unreachable when the file is imported anywhere else.
    Faking the platform for the length of the import is what makes them
    testable off a Mac; the module body only defines things.
    """
    return _load_as("darwin", alias, filename)


LINUX_MOD = _load("slimbrave_linux", "slimbrave-linux.py")
MAC_MOD = _load("slimbrave_mac", "slimbrave-mac.py")
MODULES = [LINUX_MOD, MAC_MOD]

# The macOS-flavoured copy of the same file, used only by the persistence
# tests. Everything else runs against MAC_MOD, which sees whatever the
# runner's real platform produces.
MAC_DARWIN = _load_as_darwin("slimbrave_mac_darwin", "slimbrave-mac.py")

PRESETS = sorted((ROOT / "Presets").glob("*.json"))

# Keys presets may contain that are deliberately absent on some platforms;
# the import silently skips them there. BackgroundModeEnabled and
# NetworkServiceSandboxEnabled are chrome.win / chrome.linux only in
# Chromium (see AUDIT.md), so the mac script exposes them only when it runs
# on Linux. DynamicCodeSettings is chrome.win only, so SlimBrave.ps1 alone
# offers it and neither Python script has the row.
PLATFORM_OMITTED_KEYS = {"BackgroundModeEnabled", "NetworkServiceSandboxEnabled",
                         "DynamicCodeSettings"}


@pytest.fixture(params=MODULES, ids=["linux", "mac"])
def mod(request):
    return request.param


def _get_feature(mod, rows, name):
    for row in rows:
        if row["type"] == mod.ROW_FEATURE and row["text"] == name:
            return row
    raise AssertionError(f"feature not found: {name}")


def _check_feature(mod, rows, name):
    """Check the feature row with the given display name (via toggle logic)."""
    row = _get_feature(mod, rows, name)
    if not row["checked"]:
        mod.toggle_feature_row(rows, row)
    return row


def _set_dns(mod, rows, mode, template=""):
    for row in rows:
        if row["type"] == mod.ROW_DNS:
            row["selected"] = row["options"].index(mode)
        elif row["type"] == mod.ROW_DNS_TEMPLATE:
            row["value"] = template
            row["cursor"] = len(template)


def _checked_policy_pairs(mod, rows):
    return {
        row["key"]: row["value"]
        for row in rows
        if row["type"] == mod.ROW_FEATURE and row["checked"]
    }


def _write_config(tmp_path, name, features):
    path = tmp_path / name
    path.write_text(json.dumps({"Features": features}))
    return path


# ---------------------------------------------------------------------------
# _build_policy
# ---------------------------------------------------------------------------


def test_build_policy_collects_checked_features(mod):
    rows = mod.build_rows()
    _check_feature(mod, rows, "Disable Brave Rewards")
    _check_feature(mod, rows, "Disable WebRTC IP Leak")
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy["BraveRewardsDisabled"] is True
    assert policy["WebRtcIPHandling"] == "disable_non_proxied_udp"
    assert "DnsOverHttpsMode" not in policy  # DNS defaults to unmanaged


def test_build_policy_custom_dns_requires_template(mod):
    rows = mod.build_rows()
    _set_dns(mod, rows, "custom", "")
    policy, err = mod._build_policy(rows)
    assert policy is None
    assert "template" in err.lower()


def test_build_policy_custom_maps_to_secure_with_template(mod):
    rows = mod.build_rows()
    _set_dns(mod, rows, "custom", "https://dns.example/dns-query")
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy["DnsOverHttpsMode"] == "secure"
    assert policy["DnsOverHttpsTemplates"] == "https://dns.example/dns-query"


def test_build_policy_secure_dns_requires_template(mod):
    # secure + no template is a config that resolves nothing: Chromium
    # applies the mode, blanks the templates pref and gates off the system
    # resolver, and the user can't undo it because the policy is managed.
    rows = mod.build_rows()
    _set_dns(mod, rows, "secure", "")
    policy, err = mod._build_policy(rows)
    assert policy is None
    assert "template" in err.lower()


def test_build_policy_secure_writes_mode_and_template(mod):
    rows = mod.build_rows()
    _set_dns(mod, rows, "secure", "https://dns.example/dns-query")
    policy, _ = mod._build_policy(rows)
    assert policy["DnsOverHttpsMode"] == "secure"
    assert policy["DnsOverHttpsTemplates"] == "https://dns.example/dns-query"


def test_build_policy_automatic_allows_empty_template(mod):
    # The guard must not widen to "automatic" — an empty template there is
    # valid and documented (the plaintext fallback stays).
    rows = mod.build_rows()
    _set_dns(mod, rows, "automatic", "")
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy["DnsOverHttpsMode"] == "automatic"
    assert "DnsOverHttpsTemplates" not in policy


def test_build_policy_off_mode_writes_no_template(mod):
    rows = mod.build_rows()
    _set_dns(mod, rows, "off", "https://ignored.example/dns-query")
    policy, _ = mod._build_policy(rows)
    assert policy["DnsOverHttpsMode"] == "off"
    assert "DnsOverHttpsTemplates" not in policy


# ---------------------------------------------------------------------------
# Group exclusivity
# ---------------------------------------------------------------------------


def _rows_by_group(mod, rows):
    groups = {}
    for row in rows:
        if row["type"] == mod.ROW_FEATURE and row.get("group"):
            groups.setdefault(row["group"], []).append(row)
    return groups


def test_toggle_feature_row_group_exclusivity(mod):
    """Every group, discovered from the table — not just the two obvious ones.

    Hand-written cases only ever covered incognito and shields, so the
    referrers group (both rows on one key) had no coverage at all and a
    new group would arrive untested.
    """
    rows = mod.build_rows()
    groups = _rows_by_group(mod, rows)
    assert groups, "no grouped rows found — the group mechanism went missing"
    for group, members in groups.items():
        assert len(members) >= 2, f"group {group} has a single member"
        for member in members:
            mod.toggle_feature_row(rows, member)
            assert member["checked"] is True
        checked = [m["text"] for m in members if m["checked"]]
        assert checked == [members[-1]["text"]], (
            f"group {group}: {checked} left checked, expected only "
            f"{members[-1]['text']}"
        )


# ---------------------------------------------------------------------------
# Export / import round trip
# ---------------------------------------------------------------------------


def test_export_import_round_trip(mod, tmp_path):
    rows = mod.build_rows()
    _check_feature(mod, rows, "Force Incognito Mode")       # multi-value key, value 2
    _check_feature(mod, rows, "Force Shields On (All Sites)")  # list value
    _check_feature(mod, rows, "Block Local Network Access")    # list value outside Shields
    _check_feature(mod, rows, "Disable Brave Rewards")
    _set_dns(mod, rows, "custom", "https://dns.example/dns-query")
    expected = _checked_policy_pairs(mod, rows)

    out = tmp_path / "export.json"
    ok, _ = mod.export_settings(rows, str(out))
    assert ok

    fresh = mod.build_rows()
    ok, _ = mod.import_settings(fresh, str(out))
    assert ok
    assert _checked_policy_pairs(mod, fresh) == expected
    assert mod.get_dns_mode(fresh) == "custom"
    assert mod.get_dns_template(fresh) == "https://dns.example/dns-query"
    # The multi-value key restored the *right* row
    assert _get_feature(mod, fresh, "Force Incognito Mode")["checked"] is True
    assert _get_feature(mod, fresh, "Disable Incognito Mode")["checked"] is False


def test_export_omits_dns_when_unmanaged(mod, tmp_path):
    rows = mod.build_rows()
    _check_feature(mod, rows, "Disable Brave Rewards")
    out = tmp_path / "export.json"
    ok, _ = mod.export_settings(rows, str(out))
    assert ok
    data = json.loads(out.read_text())
    assert "DnsMode" not in data
    assert "DnsTemplates" not in data


def test_import_legacy_array_first_match_wins(mod, tmp_path):
    cfg = _write_config(tmp_path, "legacy.json",
                        ["IncognitoModeAvailability", "BraveRewardsDisabled"])
    rows = mod.build_rows()
    ok, _ = mod.import_settings(rows, str(cfg))
    assert ok
    # First row for the key wins (Disable, value 1); Force stays unchecked.
    assert _get_feature(mod, rows, "Disable Incognito Mode")["checked"] is True
    assert _get_feature(mod, rows, "Force Incognito Mode")["checked"] is False
    assert _get_feature(mod, rows, "Disable Brave Rewards")["checked"] is True


def test_import_legacy_array_safe_browsing_key_keeps_its_old_row(mod, tmp_path):
    # A pre-2026 array named SafeBrowsingProtectionLevel when its only row
    # was Disable Safe Browsing; the first row for the key still takes it,
    # so an old export never turns into the Strict Parental lock.
    cfg = _write_config(tmp_path, "legacy-sb.json", ["SafeBrowsingProtectionLevel"])
    rows = mod.build_rows()
    ok, _ = mod.import_settings(rows, str(cfg))
    assert ok
    assert _get_feature(mod, rows, "Disable Safe Browsing (security downgrade)")["checked"] is True
    assert _get_feature(mod, rows, "Lock Safe Browsing On (Standard)")["checked"] is False


# The two groups whose members sit on different keys, so a config or a
# policy file can name both: the Shields pair asks for force-off and
# force-on over the same wildcards, and the spellcheck pair names
# SpellCheckServiceEnabled, which does nothing once SpellcheckEnabled is off.
SHIELDS_OFF = ("Disable Brave Shields", "BraveShieldsDisabledForUrls")
SHIELDS_ON = ("Force Shields On (All Sites)", "BraveShieldsEnabledForUrls")
SHIELDS_WILDCARDS = ["https://*", "http://*"]
SPELL_SERVICE = ("Disable Enhanced Spell Check", "SpellCheckServiceEnabled")
SPELL_ALL = ("Disable Spellcheck", "SpellcheckEnabled")
CONFLICT_MSG = "mutually exclusive with another imported row"


@pytest.mark.parametrize("order", [
    (SHIELDS_OFF, SHIELDS_ON),
    (SHIELDS_ON, SHIELDS_OFF),
], ids=["off-then-on", "on-then-off"])
def test_import_collapses_conflicting_shields_rows(mod, tmp_path, order):
    """The later row in table order wins whatever the key order, which is
    what Brave enforces when both lists are set."""
    cfg = _write_config(tmp_path, "both.json",
                        {key: SHIELDS_WILDCARDS for _, key in order})
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok
    # Nothing outside the group is touched either, so compare the whole set
    checked = [row["text"] for row in rows
               if row["type"] == mod.ROW_FEATURE and row["checked"]]
    assert checked == [SHIELDS_ON[0]]
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy == {SHIELDS_ON[1]: SHIELDS_WILDCARDS}
    assert CONFLICT_MSG in msg and SHIELDS_OFF[1] in msg, msg


@pytest.mark.parametrize("order", [
    (SPELL_SERVICE, SPELL_ALL),
    (SPELL_ALL, SPELL_SERVICE),
], ids=["service-then-all", "all-then-service"])
def test_import_collapses_conflicting_spellcheck_rows(mod, tmp_path, order):
    cfg = _write_config(tmp_path, "spell.json", {key: False for _, key in order})
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy == {"SpellcheckEnabled": False}
    assert CONFLICT_MSG in msg and SPELL_SERVICE[1] in msg, msg


@pytest.mark.parametrize("names", [
    [SHIELDS_OFF[1], SHIELDS_ON[1]],
    [SHIELDS_ON[1], SHIELDS_OFF[1]],
], ids=["off-then-on", "on-then-off"])
def test_import_legacy_array_collapses_shields_group(mod, tmp_path, names):
    cfg = _write_config(tmp_path, "legacy-both.json", names)
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok
    assert _get_feature(mod, rows, SHIELDS_ON[0])["checked"] is True
    assert _get_feature(mod, rows, SHIELDS_OFF[0])["checked"] is False
    assert CONFLICT_MSG in msg and SHIELDS_OFF[1] in msg, msg


def test_parse_imported_features_formats(mod):
    assert mod._parse_imported_features({"A": 1}) == ({"A": 1}, False)
    assert mod._parse_imported_features(["A", "B"]) == ({"A": None, "B": None}, True)
    assert mod._parse_imported_features("garbage") == ({}, False)
    assert mod._parse_imported_features(None) == ({}, False)


# ---------------------------------------------------------------------------
# Import checks, in the order import_settings runs them: the JSON itself, a
# Features block, the DNS fields, each value's JSON type. Every refusal
# returns before any row changes.
# ---------------------------------------------------------------------------


def _preticked_rows(mod):
    """Rows with Disable Metrics Reporting ticked and DNS set to off."""
    rows = mod.build_rows()
    _check_feature(mod, rows, "Disable Metrics Reporting")
    _set_dns(mod, rows, "off")
    return rows


def _assert_untouched(mod, rows):
    assert _checked_policy_pairs(mod, rows) == {"MetricsReportingEnabled": False}
    assert mod.get_dns_mode(rows) == "off"


def _write_json(tmp_path, data, name="cfg.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


NOT_A_CONFIG = [
    ({}, "empty"),
    ({"DnsMode": "off"}, "dns-only"),
    ({"Features": None}, "null"),
    ({"Features": "x"}, "string"),
    ({"Features": 5}, "number"),
    ({"Features": False}, "false"),
    ({"features": {"MetricsReportingEnabled": False}}, "lowercase-key"),
    ({"roots": {}, "version": 1}, "bookmarks"),
]


@pytest.mark.parametrize("config", [c for c, _ in NOT_A_CONFIG],
                         ids=[i for _, i in NOT_A_CONFIG])
def test_import_without_a_features_block_is_refused(mod, tmp_path, config):
    """These used to import as a success after clearing every row, and
    --import then wrote an empty policy. Now nothing changes."""
    rows = _preticked_rows(mod)
    ok, msg = mod.import_settings(rows, str(_write_json(tmp_path, config)))
    assert ok is False
    assert "no Features block" in msg
    _assert_untouched(mod, rows)


@pytest.mark.parametrize("features", [{}, []], ids=["object", "array"])
def test_import_with_an_empty_features_block_still_imports(mod, tmp_path, features):
    rows = _preticked_rows(mod)
    ok, msg = mod.import_settings(rows, str(_write_config(tmp_path, "empty.json", features)))
    assert ok, msg
    assert _checked_policy_pairs(mod, rows) == {}
    assert mod.get_dns_mode(rows) == "unmanaged"


def test_cli_import_of_a_file_without_features_writes_nothing(mod, tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(mod, "apply_policy",
                        lambda *a, **k: calls.append(a) or (True, "applied"))
    path = _write_json(tmp_path, {"MetricsReportingEnabled": False}, "policy.json")
    assert mod.cli_import(str(path), None) == 1
    assert calls == []
    assert "no Features block" in capsys.readouterr().err


@pytest.mark.parametrize("tmpl", [5, True, {"a": 1}, ["https://a/dns-query", 7]],
                         ids=["number", "true", "object", "mixed-list"])
def test_import_refuses_a_template_that_is_not_a_string(mod, tmp_path, tmpl):
    rows = _preticked_rows(mod)
    path = _write_json(tmp_path, {"Features": {}, "DnsMode": "custom", "DnsTemplates": tmpl})
    ok, msg = mod.import_settings(rows, str(path))
    assert ok is False
    assert "DnsTemplates" in msg
    _assert_untouched(mod, rows)


def test_import_joins_a_template_list_with_spaces(mod, tmp_path):
    """As SlimBrave.ps1's [string] cast joins an array."""
    rows = mod.build_rows()
    path = _write_json(tmp_path, {"Features": {}, "DnsMode": "custom", "DnsTemplates":
                                  ["https://a/dns-query", "https://b/dns-query"]})
    ok, msg = mod.import_settings(rows, str(path))
    assert ok, msg
    assert mod.get_dns_template(rows) == "https://a/dns-query https://b/dns-query"


@pytest.mark.parametrize("tmpl", [False, 0, []], ids=["false", "zero", "empty-list"])
def test_import_takes_a_falsy_template_as_none(mod, tmp_path, tmpl):
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(_write_json(tmp_path, {"Features": {}, "DnsTemplates": tmpl})))
    assert ok, msg
    assert mod.get_dns_template(rows) == ""
    assert mod.get_dns_mode(rows) == "unmanaged"


@pytest.mark.parametrize("text", [
    "[" * 100000 + "]" * 100000,
    '{"Features": {"ChromeVariations": ' + "1" * 5000 + "}}",
], ids=["deep-nesting", "5000-digit-integer"])
def test_import_reports_json_it_cannot_read_instead_of_raising(mod, tmp_path, text):
    path = tmp_path / "bad.json"
    path.write_text(text)
    rows = _preticked_rows(mod)
    ok, msg = mod.import_settings(rows, str(path))
    assert ok is False
    assert "Invalid JSON" in msg
    _assert_untouched(mod, rows)


def _dns_policy_after_import(mod, tmp_path, mode):
    """Rows synced to DNS off, then a file naming `mode`; the policy built."""
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {"DnsOverHttpsMode": "off"})
    ok, msg = mod.import_settings(rows, str(_write_json(tmp_path, {"Features": {}, "DnsMode": mode})))
    assert ok, msg
    policy, err = mod._build_policy(rows)
    assert err == ""
    return policy, msg


def test_import_takes_the_dns_mode_in_any_letter_case(mod, tmp_path):
    policy, _ = _dns_policy_after_import(mod, tmp_path, "Automatic")
    assert policy.get("DnsOverHttpsMode") == "automatic"


@pytest.mark.parametrize("mode", ["bogus", 5], ids=["word", "number"])
def test_import_names_an_unknown_dns_mode_and_leaves_dns_unmanaged(mod, tmp_path, mode):
    """The mode the TUI had before the import (off) does not survive."""
    policy, msg = _dns_policy_after_import(mod, tmp_path, mode)
    assert "DnsOverHttpsMode" not in policy
    assert f"DnsMode={mode}" in msg


def test_sync_ignores_a_template_that_is_not_a_string(mod):
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": 5})
    assert mod.get_dns_template(rows) == ""


# A value only in its policy's JSON type: an integer policy only a JSON
# integer, a boolean true/false or an integer, a list an array.
WRONG_TYPE_CASES = [
    ("ChromeVariations", True),
    ("DefaultBraveReferrersSetting", True),
    ("IncognitoModeAvailability", True),
    ("SafeBrowsingProtectionLevel", False),
    ("BrowserSignin", False),
    ("ChromeVariations", "2"),
    ("ChromeVariations", 2.0),
    ("MetricsReportingEnabled", "0"),
    ("MetricsReportingEnabled", None),
    ("ExtensionInstallBlocklist", "*"),
]


@pytest.mark.parametrize("key,bad", WRONG_TYPE_CASES,
                         ids=[f"{k}-{v!r}" for k, v in WRONG_TYPE_CASES])
def test_import_takes_a_value_only_in_its_policys_json_type(mod, tmp_path, key, bad):
    """`True == 1` in Python, so a JSON true used to tick ChromeVariations 1
    or Allow Permissive Referrers; now it is refused and named, once even
    where two rows share the key."""
    path = _write_config(tmp_path, "bad.json", {key: bad})
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(path))
    assert ok, msg
    assert not any(r["checked"] for r in rows
                   if r["type"] == mod.ROW_FEATURE and r["key"] == key)
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert key not in policy
    tail = msg[len(f"Imported from {path}"):]
    assert tail.count(key) == 1, f"{key}={bad!r} is not named once in: {msg!r}"


@pytest.mark.parametrize("key,value,name", [
    ("MetricsReportingEnabled", 0, "Disable Metrics Reporting"),
    ("MetricsReportingEnabled", False, "Disable Metrics Reporting"),
    ("BraveRewardsDisabled", 1, "Disable Brave Rewards"),
    ("BraveShieldsEnabledForUrls", ["http://*", "https://*"], SHIELDS_ON[0]),
], ids=["metrics-0", "metrics-false", "rewards-1", "shields-reordered"])
def test_import_still_takes_windows_numbers_and_reordered_lists(mod, tmp_path, key, value, name):
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(_write_config(tmp_path, "ok.json", {key: value})))
    assert ok, msg
    assert _get_feature(mod, rows, name)["checked"] is True
    assert "left unmanaged" not in msg


def test_sync_does_not_tick_an_integer_row_from_a_bool(mod):
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {"ChromeVariations": True})
    assert _checked_policy_pairs(mod, rows) == {}


# ---------------------------------------------------------------------------
# BOM-aware JSON reader (PowerShell export compatibility)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("encoding,bom", [
    ("utf-8", b""),
    ("utf-8", b"\xef\xbb\xbf"),
    ("utf-16-le", b"\xff\xfe"),
    ("utf-16-be", b"\xfe\xff"),
])
def test_read_json_file_handles_boms(mod, tmp_path, encoding, bom):
    payload = {"Features": {"BraveRewardsDisabled": True}}
    path = tmp_path / f"{encoding}.json"
    path.write_bytes(bom + json.dumps(payload).encode(encoding))
    assert mod.read_json_file(str(path)) == payload


# ---------------------------------------------------------------------------
# --policy-file path validation
# ---------------------------------------------------------------------------


def _good_policy_name(mod):
    # MAC_MOD is darwin on the macOS runner, where the name is a bundle id's.
    return "com.brave.Browser.plist" if getattr(mod, "IS_MAC", False) else "slimbrave.json"


def test_allowed_policy_file_accepts_inside_path(mod, tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setattr(mod, "ALLOWED_POLICY_DIRS", (str(allowed),))
    assert mod._is_allowed_policy_file(str(allowed / _good_policy_name(mod)))
    if not getattr(mod, "IS_MAC", False):
        # CI's Linux smoke leg uses this name
        assert mod._is_allowed_policy_file(str(allowed / "slimbrave-smoke.json"))


def test_allowed_policy_file_rejects_outside_path(mod, tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setattr(mod, "ALLOWED_POLICY_DIRS", (str(allowed),))
    good = _good_policy_name(mod)
    for path in (
        allowed / "corp.json",           # another tool's file in the same dir
        allowed / "policy.json",
        allowed / "sub" / good,          # Chromium never descends into it
        allowed / ".." / good,
        tmp_path / "shadow",
        allowed,                         # the dir itself is not a target
    ):
        assert not mod._is_allowed_policy_file(str(path)), path


@pytest.mark.skipif(
    os.name == "nt",
    reason="symlink creation requires elevation or Developer Mode")
def test_allowed_policy_file_rejects_symlink_escape(mod, tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    good = _good_policy_name(mod)
    (outside / good).write_text("{}")
    (allowed / "link").symlink_to(outside)
    monkeypatch.setattr(mod, "ALLOWED_POLICY_DIRS", (str(allowed),))
    assert not mod._is_allowed_policy_file(str(allowed / "link" / good))
    # The right name, but a symlink to a file outside the dir
    (allowed / good).symlink_to(outside / good)
    assert not mod._is_allowed_policy_file(str(allowed / good))


def test_mac_policy_file_names(tmp_path, monkeypatch):
    """On macOS the name must be a channel's bundle-id plist, the only plists
    Brave reads there; a Linux-style SlimBrave name does not count."""
    dirs = (tmp_path / "Managed Preferences", tmp_path / "Preferences")
    for d in dirs:
        d.mkdir()
    monkeypatch.setattr(MAC_DARWIN, "ALLOWED_POLICY_DIRS", tuple(str(d) for d in dirs))
    for d in dirs:
        for name in ("com.brave.Browser.plist", "com.brave.Browser.beta.plist",
                     "com.brave.Browser.nightly.plist"):
            assert MAC_DARWIN._is_allowed_policy_file(str(d / name)), name
        for rel in ("com.apple.loginwindow.plist",
                    os.path.join("SystemConfiguration", "preferences.plist"),
                    "slimbrave-smoke.plist"):
            assert not MAC_DARWIN._is_allowed_policy_file(str(d / rel)), rel


# ---------------------------------------------------------------------------
# Target dedupe + policy sync
# ---------------------------------------------------------------------------


def test_dedupe_plist_targets(mod):
    shared = [
        {"plist_path": "/etc/x.json", "label": "Stable"},
        {"plist_path": "/etc/x.json", "label": "Beta"},
    ]
    assert mod._dedupe_plist_targets(shared) == [("/etc/x.json", "Stable, Beta")]
    split = [
        {"plist_path": "/etc/a.plist", "label": "Stable"},
        {"plist_path": "/etc/b.plist", "label": "Beta"},
    ]
    assert mod._dedupe_plist_targets(split) == [
        ("/etc/a.plist", "Stable"), ("/etc/b.plist", "Beta"),
    ]


def test_sync_rows_with_policy_checks_matching_rows(mod):
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {
        "BraveRewardsDisabled": True,
        "IncognitoModeAvailability": 2,
    })
    assert _get_feature(mod, rows, "Disable Brave Rewards")["checked"] is True
    assert _get_feature(mod, rows, "Force Incognito Mode")["checked"] is True
    assert _get_feature(mod, rows, "Disable Incognito Mode")["checked"] is False


def test_sync_rows_with_policy_respects_referrers_group(mod):
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {"DefaultBraveReferrersSetting": 1})
    assert _get_feature(
        mod, rows, "Allow Permissive Referrers (unsafe-url)")["checked"] is True
    assert _get_feature(
        mod, rows, "Cap Referrers (Strict Origin)")["checked"] is False


@pytest.mark.parametrize("first,second,winner,loser", [
    (SHIELDS_OFF, SHIELDS_ON, SHIELDS_ON, SHIELDS_OFF),
    (SHIELDS_ON, SHIELDS_OFF, SHIELDS_ON, SHIELDS_OFF),
    (SPELL_SERVICE, SPELL_ALL, SPELL_ALL, SPELL_SERVICE),
    (SPELL_ALL, SPELL_SERVICE, SPELL_ALL, SPELL_SERVICE),
], ids=["shields-off-first", "shields-on-first", "spell-service-first", "spell-all-first"])
def test_sync_rows_with_policy_collapses_conflicting_shields(mod, first, second, winner, loser):
    # A policy file holding both keys is exactly what the buggy import used
    # to write; reading it back must not tick both rows again, and the row
    # kept is the later one in table order, whatever order the file has.
    def value(key):
        return SHIELDS_WILDCARDS if key in (SHIELDS_OFF[1], SHIELDS_ON[1]) else False
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {first[1]: value(first[1]),
                                     second[1]: value(second[1])})
    assert _get_feature(mod, rows, winner[0])["checked"] is True
    assert _get_feature(mod, rows, loser[0])["checked"] is False


def test_sync_rows_shows_secure_plus_template_as_custom(mod):
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {
        "DnsOverHttpsMode": "secure",
        "DnsOverHttpsTemplates": "https://dns.example/dns-query",
    })
    assert mod.get_dns_mode(rows) == "custom"
    assert mod.get_dns_template(rows) == "https://dns.example/dns-query"


# ---------------------------------------------------------------------------
# Prefs-leak repair
# ---------------------------------------------------------------------------


def test_repair_one_prefs_scrubs_only_slimbrave_patterns(mod, tmp_path, monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    prefs = {
        "bookmarks": {"kept": True},
        "profile": {"content_settings": {"exceptions": {"braveShields": {
            "http://*,*": {"setting": 2},
            "https://*,*": {"setting": 2},
            "https://example.com,*": {"setting": 2},  # user's own override
        }}}},
    }
    path = tmp_path / "Preferences"
    path.write_text(json.dumps(prefs))

    assert mod._repair_one_prefs(str(path)) == 2

    after = json.loads(path.read_text())
    shields = after["profile"]["content_settings"]["exceptions"]["braveShields"]
    assert list(shields) == ["https://example.com,*"]
    assert after["bookmarks"] == {"kept": True}
    # Idempotent: nothing left to remove on a second pass
    assert mod._repair_one_prefs(str(path)) == 0


def test_repair_one_prefs_ignores_missing_or_invalid(mod, tmp_path):
    assert mod._repair_one_prefs(str(tmp_path / "nope")) == 0
    bad = tmp_path / "Preferences"
    bad.write_text("{not json")
    assert mod._repair_one_prefs(str(bad)) == 0


# ---------------------------------------------------------------------------
# Root and elevated file handling: the invoking user, the privilege-dropped
# child, Export, and the import cap
#
# The fork tests fork for real. os.geteuid is faked to 0 so the drop path
# runs, and initgroups/setgid/setuid are faked so the child never changes
# identity; each fake records its name in a file, because the child's memory
# is gone by the time the parent looks. Windows has no fork, so they skip
# there and the scripts run inline.
# ---------------------------------------------------------------------------

needs_fork = pytest.mark.skipif(not hasattr(os, "fork"), reason="no os.fork on Windows")
posix_only = pytest.mark.skipif(os.name == "nt", reason="pwd, fork and POSIX modes")

LEAKED_PREFS = {"profile": {"content_settings": {"exceptions": {"braveShields": {
    "http://*,*": {"setting": 2}, "https://*,*": {"setting": 2}}}}}}


def _fake_root_dropping_to_self(mod, monkeypatch, log, fail_setuid=False):
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod, "_sudo_user_identity", lambda: (me, os.getuid(), os.getgid()))

    def recorder(name, fail=False):
        def fake(*args):
            with open(log, "a", encoding="utf-8") as f:
                f.write(name + "\n")
            if fail:
                raise PermissionError(f"{name} refused")
        return fake

    monkeypatch.setattr(os, "initgroups", recorder("initgroups"), raising=False)
    monkeypatch.setattr(os, "setgid", recorder("setgid"))
    monkeypatch.setattr(os, "setuid", recorder("setuid", fail=fail_setuid))


def _fake_passwd(monkeypatch, accounts):
    """Answer pwd.getpwnam from {name: uid}; everyone else is unknown."""
    import pwd

    def getpwnam(name):
        if name not in accounts:
            raise KeyError(name)
        uid = accounts[name]
        return pwd.struct_passwd((name, "x", uid, uid, "", f"/home/{name}", "/bin/sh"))

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)


@posix_only
def test_invoking_user_is_sudo_user_then_user_never_root(mod, monkeypatch):
    _fake_passwd(monkeypatch, {"alice": 1000, "bob": 1001, "toor": 0})
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setenv("USER", "bob")
    assert mod._invoking_user() == ("alice", 1000, 1000, "/home/alice")
    assert mod._sudo_user_identity() == ("alice", 1000, 1000)
    assert mod._user_home_for_brave() == "/home/alice"
    # a plain `su` to root keeps USER and sets no SUDO_USER
    monkeypatch.delenv("SUDO_USER")
    assert mod._invoking_user() == ("bob", 1001, 1001, "/home/bob")
    for name in ("root", "toor", "nobody-known"):
        monkeypatch.setenv("USER", name)
        assert mod._invoking_user() is None, name
        assert mod._user_home_for_brave() is None, name
    monkeypatch.delenv("USER")
    assert mod._invoking_user() is None


@needs_fork
def test_run_as_invoking_user_drops_in_a_child(mod, monkeypatch, tmp_path):
    log = tmp_path / "drop.log"
    _fake_root_dropping_to_self(mod, monkeypatch, log)
    child = mod._run_as_invoking_user(os.getpid, default=None)
    assert isinstance(child, int) and child != os.getpid()
    assert log.read_text(encoding="utf-8").split() == ["initgroups", "setgid", "setuid"]


@needs_fork
def test_run_as_invoking_user_returns_a_large_reply(mod, monkeypatch, tmp_path):
    # Several times the pipe buffer: the parent must read while the child writes.
    _fake_root_dropping_to_self(mod, monkeypatch, tmp_path / "drop.log")
    assert mod._run_as_invoking_user(lambda: "x" * 300_000, default=None) == "x" * 300_000


@needs_fork
def test_run_as_invoking_user_returns_default_if_drop_fails(mod, monkeypatch, tmp_path):
    _fake_root_dropping_to_self(mod, monkeypatch, tmp_path / "drop.log", fail_setuid=True)
    marker = tmp_path / "ran-without-the-drop"
    assert mod._run_as_invoking_user(marker.touch, default="default") == "default"
    assert not marker.exists()


def _logging_fake(log, name, fail=False):
    def fake(*args):
        with open(log, "a", encoding="utf-8") as f:
            f.write(name + "\n")
        if fail:
            raise PermissionError(f"{name} refused")
    return fake


@needs_fork
@pytest.mark.parametrize("setgroups_fails", [False, True])
def test_run_as_invoking_user_never_keeps_root_groups(mod, monkeypatch, tmp_path, setgroups_fails):
    # A failed initgroups leaves the child with only the user's primary
    # group; if even that fails, the drop fails and fn never runs.
    log = tmp_path / "drop.log"
    _fake_root_dropping_to_self(mod, monkeypatch, log)
    monkeypatch.setattr(os, "initgroups", _logging_fake(log, "initgroups", fail=True), raising=False)
    monkeypatch.setattr(os, "setgroups", _logging_fake(log, "setgroups", fail=setgroups_fails))
    marker = tmp_path / "ran"
    result = mod._run_as_invoking_user(lambda: marker.touch() or "ran", default="default")
    steps = log.read_text(encoding="utf-8").split()
    if setgroups_fails:
        assert result == "default" and not marker.exists()
        assert steps == ["initgroups", "setgroups"]
    else:
        assert result == "ran" and marker.exists()
        assert steps == ["initgroups", "setgroups", "setgid", "setuid"]


@needs_fork
def test_export_writes_as_invoking_user(mod, monkeypatch, tmp_path):
    log = tmp_path / "drop.log"
    _fake_root_dropping_to_self(mod, monkeypatch, log)

    def no_chown(*args, **kwargs):
        raise OSError("Export must not change owner after the fact")

    monkeypatch.setattr(os, "chown", no_chown)
    rows = mod.build_rows()
    _check_feature(mod, rows, "Disable Brave Rewards")
    out = tmp_path / "a" / "b" / "x.json"
    ok, msg = mod.export_settings(rows, str(out))
    assert ok, msg
    assert json.loads(out.read_text(encoding="utf-8"))["Features"] == {"BraveRewardsDisabled": True}
    assert log.read_text(encoding="utf-8").split() == ["initgroups", "setgid", "setuid"]


@posix_only
def test_export_permission_error_suggests_home(mod, monkeypatch, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can write the locked folder")
    import pwd
    me = pwd.getpwuid(os.getuid())
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("USER", me.pw_name)
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        ok, msg = mod.export_settings(mod.build_rows(), str(locked / "x.json"))
    finally:
        locked.chmod(0o700)
    assert not ok
    assert f"{me.pw_name} cannot write" in msg
    assert os.path.join(me.pw_dir, "SlimBraveNeoSettings.json") in msg


def test_import_caps_at_one_mib(mod, tmp_path):
    assert mod.MAX_IMPORT_BYTES == 1024 * 1024
    body = json.dumps({"Features": {"BraveRewardsDisabled": True}}).encode("utf-8")
    path = tmp_path / "padded.json"
    path.write_bytes(body + b" " * (mod.MAX_IMPORT_BYTES - len(body)))
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(path))
    assert ok, msg
    assert _get_feature(mod, rows, "Disable Brave Rewards")["checked"] is True
    path.write_bytes(body + b" " * (mod.MAX_IMPORT_BYTES - len(body) + 1))
    ok, msg = mod.import_settings(mod.build_rows(), str(path))
    assert not ok
    assert "larger than 1 MiB" in msg


@posix_only
def test_import_reads_a_pipe(mod):
    """`--import /dev/stdin` keeps working: nothing asks for a regular file."""
    config = {"Features": {"BraveRewardsDisabled": True}}
    r, w = os.pipe()
    try:
        os.write(w, json.dumps(config).encode("utf-8"))
        os.close(w)
        w = None
        assert mod.read_json_file(f"/dev/fd/{r}") == config
    finally:
        os.close(r)
        if w is not None:
            os.close(w)


def test_no_path_chown():
    """Export and the profile scrub write as the user and the macOS stage dir
    stays root's, so nothing changes owner by path any more."""
    for name in ("slimbrave-linux.py", "slimbrave-mac.py"):
        src = (ROOT / name).read_text(encoding="utf-8")
        assert "os.chown(" not in src, name
        assert "_chown_to_sudo_user" not in src, name


@posix_only
def test_repair_drops_to_user_under_su(mod, monkeypatch, tmp_path):
    """A plain `su` leaves USER and no SUDO_USER: the scrub still forks to
    drop to that user rather than rewriting their home as root."""
    _fake_passwd(monkeypatch, {"alice": 1000})
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("USER", "alice")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    forks, scrubbed = [], []

    def refused_fork():
        forks.append(1)
        raise OSError("no fork in this test")

    monkeypatch.setattr(os, "fork", refused_fork)
    monkeypatch.setattr(mod, "_scrub_one_prefs", lambda p: scrubbed.append(p) or 2)
    prefs = tmp_path / "Preferences"
    prefs.write_text(json.dumps(LEAKED_PREFS))
    assert mod._repair_one_prefs(str(prefs)) == 0
    assert forks == [1]
    assert scrubbed == []


@posix_only
@pytest.mark.parametrize("user", [None, "root"])
def test_repair_as_root_without_an_invoking_user_scrubs_nothing(mod, monkeypatch, tmp_path, user):
    """A root login or `su -`: nobody to drop to, so nothing is scrubbed
    rather than scrubbed as root."""
    monkeypatch.delenv("SUDO_USER", raising=False)
    if user is None:
        monkeypatch.delenv("USER", raising=False)
    else:
        monkeypatch.setenv("USER", user)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    forks, scrubbed = [], []

    def refused_fork():
        forks.append(1)
        raise OSError("no fork in this test")

    monkeypatch.setattr(os, "fork", refused_fork)
    monkeypatch.setattr(mod, "_scrub_one_prefs", lambda p: scrubbed.append(p) or 2)
    prefs = tmp_path / "Default" / "Preferences"
    prefs.parent.mkdir()
    prefs.write_text(json.dumps(LEAKED_PREFS))
    assert mod._repair_one_prefs(str(prefs)) == 0
    assert mod._repair_user_data_dir(str(prefs)) == [0, 0]
    assert forks == [] and scrubbed == []


@needs_fork
def test_repair_lists_profiles_in_the_child_and_forks_once(mod, monkeypatch, tmp_path):
    """One drop per user-data dir, with the profile listing inside it, so
    the parent never reads a directory in the user's home as root."""
    user_data = tmp_path / "Brave-Browser"
    for profile in ("Default", "Profile 1"):
        (user_data / profile).mkdir(parents=True)
        (user_data / profile / "Preferences").write_text(json.dumps(LEAKED_PREFS))
    _fake_root_dropping_to_self(mod, monkeypatch, tmp_path / "drop.log")
    monkeypatch.setattr(mod, "_is_brave_running", lambda *a: False)
    real_fork, real_listdir = os.fork, os.listdir
    forks, listed = [], []

    def counting_fork():
        forks.append(1)
        return real_fork()

    def watching_listdir(path="."):
        listed.append(os.fspath(path))
        return real_listdir(path)

    monkeypatch.setattr(os, "fork", counting_fork)
    monkeypatch.setattr(os, "listdir", watching_listdir)
    inst = {"prefs_path": str(user_data / "Default" / "Preferences")}
    # two records on one user-data dir still mean one drop
    assert mod.repair_brave_prefs([inst, dict(inst)]) == (4, {}, False)
    assert forks == [1]
    assert str(user_data) not in listed
    for profile in ("Default", "Profile 1"):
        after = json.loads((user_data / profile / "Preferences").read_text())
        assert after["profile"]["content_settings"]["exceptions"]["braveShields"] == {}


@pytest.mark.parametrize("content", [
    '{"profile": null}', "[]", '{"profile": {"content_settings": []}}', b"\xff",
], ids=["null-profile", "top-level-list", "list-content-settings", "not-utf-8"])
def test_scrub_survives_malformed_prefs(mod, monkeypatch, tmp_path, content):
    """Valid JSON in the wrong shape, or bytes that are not UTF-8, is not a
    file holding our entries: nothing to clean, no failure, no traceback
    after the policy is already written."""
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr(mod, "_is_brave_running", lambda *a: False)
    prefs = tmp_path / "Brave-Browser" / "Default" / "Preferences"
    prefs.parent.mkdir(parents=True)
    if isinstance(content, bytes):
        prefs.write_bytes(content)
    else:
        prefs.write_text(content, encoding="utf-8")
    assert mod.repair_brave_prefs([{"prefs_path": str(prefs)}]) == (0, {}, False)


def _two_profiles_one_locked(tmp_path):
    """Default can be cleaned; Profile 1 holds the entries in a folder its
    owner cannot write, so its rewrite fails."""
    user_data = tmp_path / "Brave-Browser"
    for profile in ("Default", "Profile 1"):
        (user_data / profile).mkdir(parents=True)
        (user_data / profile / "Preferences").write_text(json.dumps(LEAKED_PREFS))
    (user_data / "Profile 1").chmod(0o500)
    return user_data


@posix_only
def test_scrub_names_the_profiles_it_could_not_clean(mod, monkeypatch, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root writes the locked folder anyway")
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr(mod, "_is_brave_running", lambda *a: False)
    user_data = _two_profiles_one_locked(tmp_path)
    unreadable = tmp_path / "Brave-Browser-Beta" / "Default" / "Preferences"
    unreadable.parent.mkdir(parents=True)
    unreadable.write_text(json.dumps(LEAKED_PREFS))
    unreadable.chmod(0o000)
    try:
        result = mod.repair_brave_prefs([
            {"prefs_path": str(user_data / "Default" / "Preferences")},
            {"prefs_path": str(unreadable)},
        ])
    finally:
        (user_data / "Profile 1").chmod(0o700)
        unreadable.chmod(0o600)
    beta = str(unreadable.parent.parent)
    assert result == (2, {str(user_data): 1, beta: 1}, False)
    note = f"Failed to clean 2 profiles; check ownership of {user_data}, {beta}."
    assert mod._scrub_failure_note(result[1]) == note
    assert note in mod._post_apply_message(*result, labels=["Stable"])
    assert mod._scrub_failure_note({str(user_data): 1}) == (
        f"Failed to clean 1 profile; check ownership of {user_data}.")
    assert mod._scrub_failure_note({}) == ""


@needs_fork
def test_scrub_failures_come_back_from_the_dropped_child(mod, monkeypatch, tmp_path):
    """The child replies [removed, failed], so a failure it meets as the
    user reaches the parent's message."""
    if os.geteuid() == 0:
        pytest.skip("root writes the locked folder anyway")
    _fake_root_dropping_to_self(mod, monkeypatch, tmp_path / "drop.log")
    monkeypatch.setattr(mod, "_is_brave_running", lambda *a: False)
    user_data = _two_profiles_one_locked(tmp_path)
    try:
        result = mod.repair_brave_prefs(
            [{"prefs_path": str(user_data / "Default" / "Preferences")}])
    finally:
        (user_data / "Profile 1").chmod(0o700)
    assert result == (2, {str(user_data): 1}, False)


def test_reset_names_the_profiles_it_could_not_clean(mod, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(mod, "IS_MAC", False, raising=False)
    monkeypatch.setattr(mod, "repair_brave_prefs",
                        lambda *a, **k: (0, {"/home/u/.config/BraveSoftware/Brave-Browser": 2}, False))
    plist = tmp_path / "slimbrave.json"
    plist.write_text("{}", encoding="utf-8")
    inst = [{"channel": "stable", "label": "Stable", "plist_path": str(plist)}]
    note = ("Failed to clean 2 profiles; check ownership of "
            "/home/u/.config/BraveSoftware/Brave-Browser.")
    ok, msg = mod.reset_policy(mod.build_rows(), inst)
    assert ok and msg.endswith(note)
    plist.write_text("{}", encoding="utf-8")
    assert mod.cli_reset(inst) == 0
    assert f"Warning: {note}" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Atomic policy writes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows has no POSIX mode bits — chmod only moves the read-only flag")
def test_atomic_write_sets_mode(mod, tmp_path):
    target = tmp_path / "policy.json"
    mod._atomic_write(str(target), '{"a": 1}')
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    # Overwriting an existing file re-applies the mode rather than
    # inheriting whatever the old file had.
    target.chmod(0o600)
    mod._atomic_write(str(target), '{"a": 2}')
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    mod._atomic_write(str(target), '{"a": 3}', mode=0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_write_round_trip_leaves_no_temp_file(mod, tmp_path):
    target = tmp_path / "policy.json"
    mod._atomic_write(str(target), '{"a": 1}')
    mod._atomic_write(str(target), '{"a": 2}')
    assert target.read_text(encoding="utf-8") == '{"a": 2}'
    # Text is pinned to utf-8, not the locale's codec — readers decode
    # with utf-8 explicitly.
    mod._atomic_write(str(target), '{"a": "café"}')
    assert target.read_bytes() == '{"a": "café"}'.encode("utf-8")
    mod._atomic_write(str(target), b"\x00\xffbin", binary=True)
    assert target.read_bytes() == b"\x00\xffbin"
    assert list(tmp_path.glob(".slimbrave.*")) == []


def test_atomic_write_failure_keeps_original(mod, tmp_path, monkeypatch):
    target = tmp_path / "policy.json"
    target.write_text("original", encoding="utf-8")

    def boom(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(mod.os, "replace", boom)
    with pytest.raises(OSError):
        mod._atomic_write(str(target), "replacement")
    assert target.read_text(encoding="utf-8") == "original"
    assert list(tmp_path.glob(".slimbrave.*")) == []


def test_atomic_write_fsyncs_before_replace(mod, tmp_path, monkeypatch):
    """The data reaches the disk before the rename makes it the file, so a
    crash leaves the old file or the new one, never an empty one."""
    events = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    def replace(src, dst):
        events.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    mod._atomic_write(str(tmp_path / "policy.json"), "{}")
    assert "replace" in events and events.index("fsync") < events.index("replace")
    if os.name == "posix":
        # and the directory once the rename is done
        assert events == ["fsync", "replace", "fsync"]


def test_atomic_write_interrupt_leaves_no_temp(mod, tmp_path, monkeypatch):
    def interrupted(src, dst):
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        mod._atomic_write(str(tmp_path / "policy.json"), "{}")
    assert list(tmp_path.glob(".slimbrave.*")) == []


def test_atomic_write_survives_a_directory_it_cannot_fsync(mod, tmp_path, monkeypatch):
    real_open = os.open
    dirs = []

    def no_directories(path, flags, *args, **kwargs):
        if os.path.isdir(path):
            dirs.append(os.fspath(path))
            raise PermissionError("no directory fsync here")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_directories)
    target = tmp_path / "policy.json"
    mod._atomic_write(str(target), '{"a": 1}')
    assert target.read_text(encoding="utf-8") == '{"a": 1}'
    assert dirs == ([str(tmp_path)] if os.name == "posix" else [])


@posix_only
def test_policy_dirs_created_0755_under_strict_umask(mod, tmp_path):
    """sudo keeps a strict caller umask (027, or 077 here); the directories
    Brave has to enter as the user are still created 0755."""
    target = tmp_path / "a" / "b" / "c" / "slimbrave.json"
    old = os.umask(0o077)
    try:
        ok, err = mod._write_one_policy(str(target), {})
        after = os.umask(0o077)
    finally:
        os.umask(old)
    assert ok, err
    assert after == 0o077  # put back
    for d in (tmp_path / "a", tmp_path / "a" / "b", tmp_path / "a" / "b" / "c"):
        assert stat.S_IMODE(d.stat().st_mode) == 0o755, d


@posix_only
def test_unreadable_policy_dir_is_found(mod, tmp_path):
    top, leaf = tmp_path / "brave", tmp_path / "brave" / "managed"
    leaf.mkdir(parents=True)
    leaf.chmod(0o755)
    top.chmod(0o750)
    try:
        assert mod._unreadable_policy_dir(str(leaf), stop=str(tmp_path)) == (str(top), 0o750)
        top.chmod(0o755)
        assert mod._unreadable_policy_dir(str(leaf), stop=str(tmp_path)) is None
        leaf.chmod(0o711)  # enterable, but Brave could not list it
        assert mod._unreadable_policy_dir(str(leaf), stop=str(tmp_path)) == (str(leaf), 0o711)
        # only directories below `stop` are judged
        assert mod._unreadable_policy_dir(str(leaf), stop=str(tmp_path / "other")) is None
    finally:
        top.chmod(0o755)
        leaf.chmod(0o755)


def test_linux_apply_leads_with_an_unreadable_policy_dir(mod, tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "IS_MAC", False, raising=False)
    monkeypatch.setattr(mod, "repair_brave_prefs", lambda *a, **k: (0, {}, False))
    monkeypatch.setattr(mod, "_unreadable_policy_dir",
                        lambda directory, stop="/etc": ("/etc/brave", 0o750))
    inst = [{"channel": "stable", "label": "Stable",
             "plist_path": str(tmp_path / "slimbrave.json")}]
    ok, msg = mod.apply_policy(mod.build_rows(), inst)
    assert ok
    # The command is quoted so the joining ". " is not copied with it.
    assert msg.startswith("Brave cannot read /etc/brave (mode 750); run 'sudo chmod 755 "
                          "/etc/brave'. Settings applied to Stable.")


# ---------------------------------------------------------------------------
# --channels filtering
# ---------------------------------------------------------------------------


def _fake_installations(channel_ids):
    return [{"channel": cid, "label": cid.title(), "plist_path": f"/x/{cid}.plist"}
            for cid in channel_ids]


@pytest.fixture
def channels(mod, monkeypatch):
    """Pin CHANNEL_IDS: the mac module resolves it from LINUX_CHANNELS
    anywhere but Darwin, so the valid set otherwise depends on the runner."""
    monkeypatch.setattr(mod, "CHANNEL_IDS", ["stable", "beta", "nightly"])
    return _fake_installations(["stable", "beta", "nightly"])


def test_filter_installations_keeps_all_when_unset(mod, channels):
    assert mod._filter_installations_by_channels(channels, "") == (channels, "")
    assert mod._filter_installations_by_channels(channels, "auto") == (channels, "")


def test_filter_installations_normalizes_spec(mod, channels):
    filtered, err = mod._filter_installations_by_channels(channels, " BETA , stable ")
    assert err == ""
    # Detection order is kept, not the order the flag listed them in
    assert [i["channel"] for i in filtered] == ["stable", "beta"]


def test_filter_installations_rejects_unknown_channel(mod, channels):
    filtered, err = mod._filter_installations_by_channels(channels, "stable,canary")
    assert filtered is None  # the caller turns this into exit 2
    assert "Unknown channel(s): canary" in err
    assert "stable, beta, nightly" in err


def test_filter_installations_reports_empty_match(mod, channels):
    installed = _fake_installations(["stable"])
    filtered, err = mod._filter_installations_by_channels(installed, "nightly")
    assert filtered is None
    assert "No installed Brave channel matches --channels nightly" in err
    assert "Detected: stable" in err


# ---------------------------------------------------------------------------
# Command line: flags that cannot go together are refused before anything
# runs, and before the root check, with exit status 2
# ---------------------------------------------------------------------------

ALLOWED_POLICY = "/etc/brave/policies/managed/slimbrave.json"


@pytest.mark.parametrize("argv,error", [
    (["--export", "b.json", "--reset"],
     "Error: --export cannot be combined with --reset. Run --export first, then --reset."),
    (["--import", ""], "Error: --import needs a path."),
    (["--export", ""], "Error: --export needs a path."),
    (["--policy-file", "", "--reset"], "Error: --policy-file needs a path."),
    (["--channels", "beta"],
     "Error: --channels applies only to --import, --export or --reset, and not with --policy-file."),
    (["--channels", "beta", "--policy-file", ALLOWED_POLICY, "--import", "x.json"],
     "Error: --channels applies only to --import, --export or --reset, and not with --policy-file."),
    (["--doh-templates", "https://dns.example/dns-query", "--reset"],
     "Error: --doh-templates requires --import"),
])
def test_check_args_refuses(mod, argv, error):
    assert mod._check_args(mod.parse_args(argv)) == error


@pytest.mark.parametrize("argv", [
    [],
    ["--policy-file", ALLOWED_POLICY],
    ["--channels", "beta", "--import", "x.json"],
    ["--channels", "stable", "--reset"],
    ["--reset", "--import", "x.json"],
    ["--import", "x.json", "--export", "y.json"],
    ["--policy-file", ALLOWED_POLICY, "--import", "x.json"],
])
def test_check_args_accepts(mod, argv):
    assert mod._check_args(mod.parse_args(argv)) is None


def test_check_args_refuses_persist_on_with_a_policy_file():
    plist = "/Library/Managed Preferences/com.brave.Browser.plist"
    args = MAC_DARWIN.parse_args(["--policy-file", plist, "--persist", "on", "--import", "x.json"])
    assert MAC_DARWIN._check_args(args) == (
        "Error: --persist on cannot be combined with --policy-file: a Configuration "
        "Profile targets each channel's bundle, not a file.")
    args = MAC_DARWIN.parse_args(["--policy-file", plist, "--persist", "off", "--import", "x.json"])
    assert MAC_DARWIN._check_args(args) is None


@pytest.mark.parametrize("script", ["slimbrave-linux.py", "slimbrave-mac.py"])
def test_bad_flags_exit_2_without_root(script, tmp_path):
    """The check runs before the root check, so it needs no sudo."""
    import subprocess
    result = subprocess.run(
        [sys.executable, str(ROOT / script), "--export", "b.json", "--reset"],
        cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert "--export cannot be combined with --reset" in result.stderr
    assert "must be run as root" not in result.stdout
    assert not (tmp_path / "b.json").exists()


@posix_only
def test_prompt_path_tilde_is_the_invoking_users_home(mod, monkeypatch):
    _fake_passwd(monkeypatch, {"alice": 1000})
    monkeypatch.setenv("SUDO_USER", "alice")
    assert mod._expand_prompt_path("~/x.json") == "/home/alice/x.json"
    assert mod._expand_prompt_path("~") == "/home/alice"
    assert mod._expand_prompt_path("./x.json") == "./x.json"
    assert mod._expand_prompt_path("/srv/x.json") == "/srv/x.json"
    real_expanduser = os.path.expanduser
    monkeypatch.setattr(os.path, "expanduser",
                        lambda p: "/home/bob" + p[4:] if p.startswith("~bob") else real_expanduser(p))
    assert mod._expand_prompt_path("~bob/x.json") == "/home/bob/x.json"


@pytest.mark.parametrize("script", ["slimbrave-linux.py", "slimbrave-mac.py"])
def test_tui_import_and_export_expand_the_prompt_path(script):
    src = (ROOT / script).read_text(encoding="utf-8")
    for action in ("import_settings", "export_settings"):
        assert re.search(action + r"\(\s*rows, _expand_prompt_path\(path\)\)", src), (script, action)


def test_selected_channel_targets_is_mac_only():
    # slimbrave-linux.py dropped this helper (every channel shares one
    # policy file there); the mac script still scopes writes per channel.
    assert not hasattr(LINUX_MOD, "_selected_channel_targets")
    installs = _fake_installations(["stable", "beta"])
    assert MAC_MOD._selected_channel_targets(installs) == installs
    assert [i["channel"]
            for i in MAC_MOD._selected_channel_targets(installs, {"beta"})] == ["beta"]
    assert MAC_MOD._selected_channel_targets(installs, set()) == []


def test_bundle_id_for_plist_is_mac_only():
    assert not hasattr(LINUX_MOD, "_bundle_id_for_plist")
    assert MAC_MOD._bundle_id_for_plist(
        "/Library/Managed Preferences/com.brave.Browser.plist") == "com.brave.Browser"
    assert MAC_MOD._bundle_id_for_plist(
        "com.brave.Browser.beta.plist") == "com.brave.Browser.beta"


# ---------------------------------------------------------------------------
# macOS persistence (Configuration Profile)
#
# These run against MAC_DARWIN, the copy imported with sys.platform faked,
# so the mobileconfig helpers are reachable off a Mac. They are pure dict
# and uuid5 work — nothing here shells out to `profiles`.
# ---------------------------------------------------------------------------


def test_stable_uuid_is_deterministic():
    first = MAC_DARWIN._stable_uuid("io.example.thing")
    assert first == MAC_DARWIN._stable_uuid("io.example.thing")
    assert first != MAC_DARWIN._stable_uuid("io.example.other")
    assert first == first.upper() and len(first) == 36


def test_build_mobileconfig_wraps_policy_per_bundle():
    policy = {"BraveRewardsDisabled": True, "IncognitoModeAvailability": 2}
    profile = MAC_DARWIN._build_mobileconfig({"com.brave.Browser": policy})

    assert profile["PayloadScope"] == "System"
    assert profile["PayloadIdentifier"] == MAC_DARWIN.PERSIST_PROFILE_IDENTIFIER
    inner, = profile["PayloadContent"]
    assert inner["PayloadType"] == "com.apple.ManagedClient.preferences"
    forced = inner["PayloadContent"]["com.brave.Browser"]["Forced"]
    assert forced[0]["mcx_preference_settings"] == policy


def test_build_mobileconfig_one_payload_per_channel():
    profile = MAC_DARWIN._build_mobileconfig({
        "com.brave.Browser": {"TorDisabled": True},
        "com.brave.Browser.beta": {"TorDisabled": True},
    })
    payloads = profile["PayloadContent"]
    assert [list(p["PayloadContent"])[0] for p in payloads] == [
        "com.brave.Browser", "com.brave.Browser.beta",
    ]
    # Distinct UUIDs, or macOS treats the second payload as a redefinition
    assert len({p["PayloadUUID"] for p in payloads}) == 2


def test_mobileconfig_serializes_every_feature_value():
    """Every value in the table has to survive plistlib, nesting included."""
    bundle = MAC_DARWIN.MAC_CHANNELS[0]["bundle_id"]
    for cat in MAC_DARWIN.CATEGORIES:
        for feat in cat["features"]:
            policy = {feat["key"]: feat["value"]}
            profile = MAC_DARWIN._build_mobileconfig({bundle: policy})
            restored = plistlib.loads(plistlib.dumps(profile))
            forced = restored["PayloadContent"][0]["PayloadContent"][bundle]["Forced"]
            assert forced[0]["mcx_preference_settings"] == policy, feat["name"]


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="on a real Mac this shells out to `profiles` and can be either")
def test_detect_persist_mode_is_off_without_macos():
    assert MAC_MOD.detect_persist_mode() == "off"


@pytest.mark.skipif(os.name == "nt", reason="pwd and POSIX modes")
def test_profile_stage_dir_stays_root_owned(monkeypatch, tmp_path):
    """The staged profile changes owner never: its dir is 0755 and the file
    0644, readable by the user's `open` and System Settings, writable by
    root alone. `open` runs as the invoking user, by absolute path."""
    if os.geteuid() == 0:
        pytest.skip("as root SUDO_USER cannot name a non-root user here")
    import pwd
    import tempfile
    me = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    calls = []

    def recorder(cmd, **kw):
        calls.append(list(cmd))
        return type("R", (), {"returncode": 0, "stdout": b""})()

    def no_chown(*args, **kwargs):
        raise AssertionError("the stage dir must not change owner")

    monkeypatch.setattr(MAC_DARWIN.subprocess, "run", recorder)
    monkeypatch.setattr(os, "chown", no_chown)
    monkeypatch.setenv("SUDO_USER", me)
    ok, staged = MAC_DARWIN._install_profile_from_policy({"com.brave.Browser": {}})
    stage, = tmp_path.glob("slimbrave-neo-*")
    assert stat.S_IMODE(stage.stat().st_mode) == 0o755
    profile = stage / "slimbrave-neo-policy.mobileconfig"
    assert stat.S_IMODE(profile.stat().st_mode) == 0o644
    # the hand-off succeeded, so it reports where the profile is staged
    assert ok and staged == str(profile)
    assert calls[0][:4] == ["/usr/bin/sudo", "-u", me, "/usr/bin/open"]


@posix_only
def test_mac_app_search_follows_the_invoking_user_under_su(monkeypatch):
    """A plain `su` keeps USER and sets no SUDO_USER: the per-user
    Applications folder searched is still the caller's, not root's."""
    _fake_passwd(monkeypatch, {"alice": 1000})
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("USER", "alice")
    assert MAC_DARWIN._mac_app_search_paths("Brave Browser.app") == [
        "/Applications/Brave Browser.app", "/home/alice/Applications/Brave Browser.app"]


# ---------------------------------------------------------------------------
# macOS Apply and Reset against a faked Mac
#
# Every program slimbrave-mac.py runs goes through subprocess.run, so one
# fake answers for the Mac: `profiles list` reports the SlimBrave profile
# while `installed` is set, `profiles remove` takes it away (unless it
# fails), and `open`, `killall` and `pgrep` answer as configured. Each argv
# is recorded. The managed-preferences folder and the temp dir are moved
# under tmp_path.
# ---------------------------------------------------------------------------


class _FakeMac:
    def __init__(self):
        self.calls = []
        self.installed = False
        self.list_rc = 0
        self.remove_rc = 0
        self.open_rc = 0
        self.open_error = None

    def run(self, cmd, **kwargs):
        cmd = list(cmd)
        self.calls.append(cmd)
        rc, out = 0, b""
        if cmd[:2] == ["/usr/bin/profiles", "list"]:
            listed = ([{"ProfileIdentifier": MAC_DARWIN.PERSIST_PROFILE_IDENTIFIER}]
                      if self.installed else [])
            rc, out = self.list_rc, plistlib.dumps({"_computerlevel": listed})
        elif cmd[:2] == ["/usr/bin/profiles", "remove"]:
            rc = self.remove_rc
            if rc == 0:
                self.installed = False
        elif "/usr/bin/open" in cmd and cmd[-1].endswith(".mobileconfig"):
            if self.open_error is not None:
                raise self.open_error
            rc = self.open_rc
        elif cmd[0] in MAC_DARWIN.PGREP_PATHS:
            rc = 1
        return type("R", (), {"returncode": rc, "stdout": out})()

    def ran(self, *prefix):
        return [c for c in self.calls if c[:len(prefix)] == list(prefix)]

    def plist(self, channel):
        return self.dir / (_mac_channel(channel)["bundle_id"] + ".plist")

    def staged(self):
        return sorted(self.temp.glob("slimbrave-neo-*/slimbrave-neo-policy.mobileconfig"))


def _mac_channel(channel_id):
    return next(c for c in MAC_DARWIN.MAC_CHANNELS if c["id"] == channel_id)


@pytest.fixture
def mac(monkeypatch, tmp_path):
    import tempfile
    box = _FakeMac()
    box.dir = tmp_path / "Managed Preferences"
    box.temp = tmp_path / "tmp"
    box.dir.mkdir()
    box.temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(box.temp))
    monkeypatch.setattr(MAC_DARWIN.subprocess, "run", box.run)
    monkeypatch.setattr(MAC_DARWIN, "POLICY_DIR", str(box.dir))
    monkeypatch.setattr(MAC_DARWIN, "POLICY_FILE", str(box.dir / "com.brave.Browser.plist"))
    return box


def _mac_installs(box, *ids):
    return [MAC_DARWIN._make_installation(_mac_channel(cid), app_path="",
                                          plist_path=str(box.plist(cid)), prefs_path=None)
            for cid in ids]


def _mac_override(box):
    return [MAC_DARWIN._make_installation(
        {**MAC_DARWIN.MAC_CHANNELS[0], "id": "override", "label": "Override", "bundle_id": ""},
        plist_path=str(box.plist("stable")), prefs_path=None)]


def _put_plist(path, data):
    path.write_bytes(plistlib.dumps(data))


def _get_plist(path):
    return plistlib.loads(path.read_bytes())


def _mac_rows(*ticked):
    rows = MAC_DARWIN.build_rows()
    for name in ticked:
        _check_feature(MAC_DARWIN, rows, name)
    return rows


# C08: the plist is shared, so Apply and Reset touch only SlimBrave's keys.

def test_mac_apply_and_reset_keep_keys_they_do_not_manage(mac, capsys):
    stable, = _mac_installs(mac, "stable")
    _put_plist(mac.plist("stable"), {
        "URLBlocklist": ["x"], "BraveRewardsDisabled": True,
        "SafeSitesFilterBehavior": 1, "PromotionsEnabled": False, "EnableDoNotTrack": 1,
    })
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), [stable], persist_mode="off")
    assert ok, msg
    # Rewards unticked and two leftovers holding what an old version wrote
    # go; the foreign list stays, and so does an int 1 where SlimBrave
    # wrote the bool true.
    assert _get_plist(mac.plist("stable")) == {
        "URLBlocklist": ["x"], "EnableDoNotTrack": 1, "TorDisabled": True}
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable])
    assert ok, msg
    assert _get_plist(mac.plist("stable")) == {"URLBlocklist": ["x"], "EnableDoNotTrack": 1}
    # a plist holding only SlimBrave keys goes altogether
    _put_plist(mac.plist("stable"), {"TorDisabled": True, "EnableDoNotTrack": True})
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable])
    assert ok and not mac.plist("stable").exists()
    # --reset says which it did
    _put_plist(mac.plist("stable"), {"TorDisabled": True, "URLBlocklist": ["x"], "Foo": 1})
    assert MAC_DARWIN.cli_reset([stable]) == 0
    out = capsys.readouterr().out
    assert f"Removed SlimBrave keys from {mac.plist('stable')} (Stable); kept 2 other keys" in out
    _put_plist(mac.plist("stable"), {"TorDisabled": True})
    assert MAC_DARWIN.cli_reset([stable]) == 0
    assert f"Removed {mac.plist('stable')} (Stable)" in capsys.readouterr().out


def test_mac_a_value_slimbrave_never_wrote_survives(mac):
    stable, = _mac_installs(mac, "stable")
    _put_plist(mac.plist("stable"), {"SafeSitesFilterBehavior": 0})
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows(), [stable], persist_mode="off")
    assert ok, msg
    assert _get_plist(mac.plist("stable")) == {"SafeSitesFilterBehavior": 0}
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable])
    assert ok, msg
    assert _get_plist(mac.plist("stable")) == {"SafeSitesFilterBehavior": 0}


def test_mac_background_mode_is_retired_on_macos_only():
    assert MAC_DARWIN._is_retired("BackgroundModeEnabled", False)
    assert not MAC_DARWIN._is_retired("BackgroundModeEnabled", True)
    assert not MAC_DARWIN._is_retired("EnableDoNotTrack", 1)
    assert MAC_DARWIN._is_retired("EnableDoNotTrack", True)
    rows = {r.get("key") for r in MAC_DARWIN.build_rows()}
    assert not set(MAC_DARWIN.MAC_ONLY_RETIRED_POLICIES) & rows
    if sys.platform.startswith("linux"):
        # where a row still writes it, it is a managed key, not a leftover
        assert "BackgroundModeEnabled" in MAC_MOD._managed_keys()


def test_retired_lists_agree():
    """slimbrave-mac.py and SlimBrave.ps1 delete the same leftovers, each
    only while it holds the value an old version wrote."""
    ps1 = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    block = re.search(r"\$script:retiredPolicies = \[ordered\]@\{(.*?)\n\}", ps1, re.S)
    table = {k: int(v) for k, v in re.findall(r'"(\w+)"\s*=\s*(\d+)', block.group(1))}
    assert table == {k: int(v) for k, v in MAC_DARWIN.RETIRED_POLICIES.items()}
    assert MAC_DARWIN.RETIRED_POLICIES == MAC_MOD.RETIRED_POLICIES


def test_mac_foreign_keys_are_not_a_slimbrave_policy(mac, capsys):
    stable, beta = _mac_installs(mac, "stable", "beta")
    _put_plist(mac.plist("stable"), {"URLBlocklist": ["x"]})
    _put_plist(mac.plist("beta"), {"URLBlocklist": ["x"], "TorDisabled": True})
    assert MAC_DARWIN.detect_managed_channel_ids([stable, beta]) == {"beta"}
    assert MAC_DARWIN.load_existing_policy([stable]) == {}
    assert MAC_DARWIN.load_existing_policy([stable, beta])["TorDisabled"] is True
    assert MAC_DARWIN.cli_export(str(mac.temp / "out.json"), [stable]) == 1
    assert "No existing policy found." in capsys.readouterr().err


def test_linux_policy_file_is_still_rewritten_whole(mod, tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "IS_MAC", False, raising=False)
    monkeypatch.setattr(mod, "repair_brave_prefs", lambda *a, **k: (0, {}, False))
    path = tmp_path / "slimbrave.json"
    path.write_text(json.dumps({"URLBlocklist": ["x"], "EnableDoNotTrack": True}))
    inst = [{"channel": "stable", "label": "Stable", "plist_path": str(path)}]
    ok, msg = mod.apply_policy(mod.build_rows(), inst)
    assert ok, msg
    assert json.loads(path.read_text(encoding="utf-8")) == {}


# C06: with the profile installed, a scope that leaves out a channel holding
# a SlimBrave policy is refused before the profile is removed.

@pytest.mark.parametrize("persist", ["on", "off"])
def test_partial_apply_with_profile_installed_is_refused(mac, persist):
    mac.installed = True
    stable, beta = _mac_installs(mac, "stable", "beta")
    _put_plist(mac.plist("stable"), {"BraveRewardsDisabled": True})
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows(), [stable, beta], persist_mode=persist,
                                      selected_channel_ids={"beta"})
    assert not ok
    assert msg == "Stable also has a SlimBrave policy; select it too, or Reset first."
    assert mac.ran("/usr/bin/profiles", "remove") == []
    assert mac.staged() == [] and not mac.plist("beta").exists()


def test_partial_apply_names_every_channel_it_would_strip(mac):
    mac.installed = True
    installs = _mac_installs(mac, "stable", "beta", "nightly")
    for channel in ("stable", "nightly"):
        _put_plist(mac.plist(channel), {"TorDisabled": True})
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows(), installs, persist_mode="off",
                                      selected_channel_ids={"beta"})
    assert not ok
    assert msg == "Stable, Nightly also have a SlimBrave policy; select them too, or Reset first."


def test_partial_apply_ignores_a_channel_without_policy(mac):
    mac.installed = True
    stable, beta = _mac_installs(mac, "stable", "beta")
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), [stable, beta],
                                      persist_mode="off", selected_channel_ids={"stable"})
    assert ok, msg
    assert _get_plist(mac.plist("stable")) == {"TorDisabled": True}


def test_partial_reset_with_profile_installed_is_refused(mac):
    mac.installed = True
    stable, beta = _mac_installs(mac, "stable", "beta")
    _put_plist(mac.plist("stable"), {"BraveRewardsDisabled": True})
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable, beta], selected_channel_ids={"beta"})
    assert not ok and msg.startswith("Stable also has a SlimBrave policy")
    assert _get_plist(mac.plist("stable")) == {"BraveRewardsDisabled": True}
    assert mac.ran("/usr/bin/profiles", "remove") == []


def test_full_scope_apply_with_profile_installed_behaves_as_before(mac):
    mac.installed = True
    stable, beta = _mac_installs(mac, "stable", "beta")
    _put_plist(mac.plist("stable"), {"BraveRewardsDisabled": True})
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), [stable, beta], persist_mode="on",
                                      selected_channel_ids={"stable", "beta"})
    assert ok, msg
    assert mac.ran("/usr/bin/profiles", "remove")
    staged, = mac.staged()
    payloads = _get_plist(staged)["PayloadContent"]
    assert [list(p["PayloadContent"])[0] for p in payloads] == [
        "com.brave.Browser", "com.brave.Browser.beta"]
    # the profile carries the policy now; the old plist's SlimBrave keys went
    assert not mac.plist("stable").exists()


def test_scope_guard_fails_open_when_profiles_list_fails(mac):
    mac.installed, mac.list_rc = True, 1
    stable, beta = _mac_installs(mac, "stable", "beta")
    _put_plist(mac.plist("stable"), {"BraveRewardsDisabled": True})
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows(), [stable, beta], persist_mode="off",
                                      selected_channel_ids={"beta"})
    assert ok, msg


def test_cli_scope_check_refuses_before_any_action(mac):
    mac.installed = True
    stable, beta = _mac_installs(mac, "stable", "beta")
    _put_plist(mac.plist("stable"), {"BraveRewardsDisabled": True})

    def error(*argv, selected=(beta,)):
        return MAC_DARWIN._cli_scope_error(MAC_DARWIN.parse_args(list(argv)),
                                           [stable, beta], list(selected))

    expected = (
        "Error: Stable also holds a SlimBrave policy, and with the Configuration "
        "Profile installed every Apply or Reset removes the whole profile. Add it to "
        "--channels, or run --reset first and then apply to Beta.")
    assert error("--import", "x.json", "--channels", "beta") == expected
    assert error("--reset", "--channels", "beta") == expected
    assert error("--export", "x.json", "--channels", "beta") is None
    assert error("--import", "x.json", selected=(stable, beta)) is None
    mac.list_rc = 1
    assert error("--import", "x.json", "--channels", "beta") is None
    src = (ROOT / "slimbrave-mac.py").read_text(encoding="utf-8")
    main = src[src.index('if __name__ == "__main__":'):]
    assert main.index("_cli_scope_error(") < main.index("cli_reset(")


# C07: a failed hand-off is reported with the staged path.

@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_failed_profile_hand_off_is_reported_with_the_staged_path(mac, failure):
    import subprocess
    if failure == "exit":
        mac.open_rc = 1
    else:
        mac.open_error = subprocess.TimeoutExpired("open", 15)
    stable, = _mac_installs(mac, "stable")
    _put_plist(mac.plist("stable"), {"TorDisabled": True})
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), [stable], persist_mode="on")
    staged, = mac.staged()
    assert not ok
    assert msg.startswith("Could not hand the profile to System Settings (")
    assert f"It is staged at {staged}; double-click it" in msg
    assert ("timed out" if failure == "timeout" else "exit status 1") in msg
    assert staged.exists()
    # staging failed, so the plist stays in force
    assert _get_plist(mac.plist("stable")) == {"TorDisabled": True}


def test_profile_hand_off_says_the_channels_wait_for_approval(mac, capsys):
    stable, = _mac_installs(mac, "stable")
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), [stable], persist_mode="on")
    assert ok
    assert msg.startswith("Profile staged to Stable. Those channels have no SlimBrave policy "
                          "until you install it in System Settings > General > Device Management.")
    config = mac.temp / "config.json"
    config.write_text(json.dumps({"Features": {"TorDisabled": True}}))
    assert MAC_DARWIN.cli_import(str(config), [stable], persist_mode="on") == 0
    staged = MAC_DARWIN._last_staged_profile
    assert staged and pathlib.Path(staged) in mac.staged()
    out = capsys.readouterr().out
    assert f"Profile file: {staged}\n" in out
    assert out.index("Profile file: ") < out.index("Finish in System Settings")


# C09: --policy-file never touches the profile; a Reset that leaves it
# installed says so; a full Reset also clears uninstalled channels.

@pytest.mark.parametrize("installed", [False, True])
def test_policy_file_override_never_touches_the_profile(mac, installed):
    mac.installed = installed
    override = _mac_override(mac)
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), override, persist_mode="off")
    assert ok, msg
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), override, all_channels=True)
    assert ok, msg
    assert mac.ran("/usr/bin/profiles") == []
    assert mac.ran("/usr/bin/killall", "cfprefsd")  # still flushed
    ok, msg = MAC_DARWIN.apply_policy(_mac_rows("Disable Tor"), override, persist_mode="on")
    assert not ok
    assert mac.staged() == []


def test_reset_that_leaves_the_profile_installed_says_so(mac, capsys):
    mac.installed, mac.remove_rc = True, 1
    stable, = _mac_installs(mac, "stable")
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable])
    assert not ok and msg == MAC_DARWIN.PROFILE_STILL_INSTALLED
    assert "still installed" in msg
    assert MAC_DARWIN.cli_reset([stable]) == 1
    captured = capsys.readouterr()
    assert "Removed Configuration Profile" not in captured.out
    assert "still installed" in captured.err
    mac.remove_rc = 0
    assert MAC_DARWIN.cli_reset([stable]) == 0
    assert "Removed Configuration Profile" in capsys.readouterr().out
    assert MAC_DARWIN._remove_profile() is True


def test_full_reset_clears_channels_that_are_no_longer_installed(mac, capsys):
    stable, = _mac_installs(mac, "stable")
    _put_plist(mac.plist("beta"), {"TorDisabled": True})
    _put_plist(mac.plist("nightly"), {"TorDisabled": True, "URLBlocklist": ["x"]})
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable])
    assert ok and mac.plist("beta").exists()  # not a full reset
    ok, msg = MAC_DARWIN.reset_policy(_mac_rows(), [stable], all_channels=True)
    assert ok, msg
    assert "Beta (not installed)" in msg and "Nightly (not installed)" in msg
    assert not mac.plist("beta").exists()
    assert _get_plist(mac.plist("nightly")) == {"URLBlocklist": ["x"]}
    _put_plist(mac.plist("beta"), {"TorDisabled": True})
    assert MAC_DARWIN.cli_reset([stable], all_channels=True) == 0
    assert (f"Removed SlimBrave keys from {mac.plist('beta')} (Beta, not installed)"
            in capsys.readouterr().out)


# ---------------------------------------------------------------------------
# Linux detection — Brave Origin
#
# Origin is a separate build that installs beside regular Brave. The paths
# come from brave-core v1.94.121 (chrome_paths_linux.cc for the profile,
# installer/linux/common/brave-origin/chromium-browser.info for the deb/rpm
# layout) and from the AUR package on the maintainer's machine; the policy
# directory was proven end to end there. AUDIT.md, Brave Origin, has the
# receipts.
# ---------------------------------------------------------------------------

_PROBED_ROOTS = ("/opt/", "/snap/", "/var/lib/flatpak/", "/home/u/")
ORIGIN_PROFILE = "/home/u/.config/BraveSoftware/Brave-Origin"


def _slash(path):
    """os.path.join spells these with backslashes on the Windows runner; the
    probes and assertions here are written with forward slashes."""
    return str(path).replace("\\", "/")


def _fake_linux_box(mod, monkeypatch, files=(), dirs=(), on_path=()):
    """Answer the detector's probes from a fixed picture of one machine.

    Only the roots detect_brave() looks under are faked; every other path
    still reaches the real filesystem, so pytest's own lookups keep working.
    """
    files, dirs, on_path = set(files), set(dirs), set(on_path)
    real_isfile, real_isdir = os.path.isfile, os.path.isdir
    monkeypatch.setattr(
        mod.os.path, "isfile",
        lambda p: _slash(p) in files if _slash(p).startswith(_PROBED_ROOTS) else real_isfile(p))
    monkeypatch.setattr(
        mod.os.path, "isdir",
        lambda p: _slash(p) in dirs if _slash(p).startswith(_PROBED_ROOTS) else real_isdir(p))
    monkeypatch.setattr(mod.shutil, "which",
                        lambda n: f"/usr/bin/{n}" if n in on_path else None)
    monkeypatch.setattr(mod, "_user_home_for_brave", lambda: "/home/u")
    # slimbrave-mac.py takes its macOS branch on a Mac runner; force Linux.
    monkeypatch.setattr(mod, "IS_MAC", False, raising=False)


def test_linux_channels_carry_brave_origin(mod):
    origin = {c["id"]: c for c in mod.LINUX_CHANNELS if c["id"].startswith("origin")}
    # chrome_paths_linux.cc names the profile, brave_channel_info_posix.cc
    # the suffix; the process name is the launcher's comm on every packaging.
    assert {k: (c["user_data_dir"], c["process_name"]) for k, c in origin.items()} == {
        "origin": ("Brave-Origin", "brave-origin"),
        "origin-beta": ("Brave-Origin-Beta", "brave-origin-beta"),
        "origin-nightly": ("Brave-Origin-Nightly", "brave-origin-nightly"),
    }
    assert [c for c in LINUX_MOD.CHANNEL_IDS if c.startswith("origin")] == [
        "origin", "origin-beta", "origin-nightly"]


def test_detect_origin_beta_and_nightly_by_profile_or_launcher(mod, monkeypatch):
    # No native path is probed for these, exactly as for Brave's own beta
    # and nightly: the profile directory or the launcher on PATH is the tell.
    _fake_linux_box(mod, monkeypatch,
                    dirs={"/home/u/.config/BraveSoftware/Brave-Origin-Beta"},
                    on_path={"brave-origin-nightly"})
    info = mod.detect_brave()
    assert info["found"] is True                        # the nightly launcher counts
    assert info["method"] == "unknown (Brave Origin): Origin Beta, Origin Nightly"
    assert [i["channel"] for i in info["installations"]] == ["origin-beta", "origin-nightly"]
    by_channel = {i["channel"]: i for i in info["installations"]}
    assert _slash(by_channel["origin-beta"]["prefs_path"]) == (
        "/home/u/.config/BraveSoftware/Brave-Origin-Beta/Default/Preferences")
    assert by_channel["origin-nightly"]["process_name"] == "brave-origin-nightly"
    assert by_channel["origin-nightly"]["app_path"] == ""
    assert info["notes"]


def test_detect_arch_origin_alone(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave-origin-bin/brave"}, on_path={"brave-origin"})
    info = mod.detect_brave()
    assert info["found"] is True
    assert info["method"] == "arch (Brave Origin)"
    assert info["path"] == "/opt/brave-origin-bin/brave"
    assert [i["channel"] for i in info["installations"]] == ["origin"]
    inst = info["installations"][0]
    assert inst["app_path"] == "/opt/brave-origin-bin/brave"
    assert inst["plist_path"] == mod.POLICY_FILE       # the one shared policy file
    assert _slash(inst["prefs_path"]) == f"{ORIGIN_PROFILE}/Default/Preferences"
    assert inst["process_name"] == "brave-origin"
    assert info["warnings"] == []
    assert len(info["notes"]) == 1
    assert info["notes"][0].startswith("Brave Origin found")


def test_detect_deb_rpm_origin_alone(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave.com/brave-origin/brave-origin",
                           "/opt/brave.com/brave-origin/brave"},
                    on_path={"brave-origin", "brave-origin-stable"})
    info = mod.detect_brave()
    assert info["method"] == "deb/rpm (Brave Origin)"
    assert info["path"] == "/opt/brave.com/brave-origin/brave-origin"
    assert [i["channel"] for i in info["installations"]] == ["origin"]
    assert info["installations"][0]["app_path"] == "/opt/brave.com/brave-origin/brave-origin"


def test_detect_origin_beside_regular_brave(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave-bin/brave", "/opt/brave-origin-bin/brave"},
                    dirs={"/home/u/.config/BraveSoftware/Brave-Browser", ORIGIN_PROFILE},
                    on_path={"brave", "brave-origin"})
    info = mod.detect_brave()
    assert info["method"] == "arch: Stable, Origin"
    assert info["path"] == "/opt/brave-bin/brave"      # regular Brave stays primary
    by_channel = {i["channel"]: i for i in info["installations"]}
    assert set(by_channel) == {"stable", "origin"}
    assert by_channel["stable"]["app_path"] == "/opt/brave-bin/brave"
    assert by_channel["origin"]["app_path"] == "/opt/brave-origin-bin/brave"
    assert _slash(by_channel["origin"]["prefs_path"]) == f"{ORIGIN_PROFILE}/Default/Preferences"
    assert info["warnings"] == []
    assert info["notes"]


def test_detect_origin_launcher_on_path_only(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch, on_path={"brave-origin"})
    info = mod.detect_brave()
    assert info["found"] is True
    assert info["method"] == "unknown (Brave Origin)"
    assert info["path"] == "/usr/bin/brave-origin"
    assert [i["channel"] for i in info["installations"]] == ["origin"]
    assert info["installations"][0]["app_path"] == "/usr/bin/brave-origin"


def test_detect_origin_profile_without_a_binary(mod, monkeypatch):
    # The package is gone but the profile remains: not found, yet the
    # profile still gets prefs repair, and the note still explains itself.
    _fake_linux_box(mod, monkeypatch, dirs={ORIGIN_PROFILE})
    info = mod.detect_brave()
    assert info["found"] is False
    assert info["method"] == "not found"
    assert info["warnings"][0].startswith("Brave browser not found")
    assert [i["channel"] for i in info["installations"]] == ["origin"]
    assert info["installations"][0]["app_path"] == ""
    assert info["notes"]


def test_detect_without_origin_is_unchanged(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch, files={"/opt/brave-bin/brave"}, on_path={"brave"})
    info = mod.detect_brave()
    assert info["method"] == "arch"
    assert info["path"] == "/opt/brave-bin/brave"
    assert [i["channel"] for i in info["installations"]] == ["stable"]
    assert info["installations"][0]["app_path"] == "/opt/brave-bin/brave"
    assert info["notes"] == []


def test_detect_nothing_still_falls_back_to_stable(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch)
    info = mod.detect_brave()
    assert info["found"] is False and info["method"] == "not found"
    assert [i["channel"] for i in info["installations"]] == ["stable"]
    assert info["notes"] == []


def test_channels_flag_accepts_origin():
    installed = _fake_installations(["stable", "origin"])
    filtered, err = LINUX_MOD._filter_installations_by_channels(installed, "origin")
    assert err == ""
    assert [i["channel"] for i in filtered] == ["origin"]


def test_running_check_names_the_origin_launcher(mod, monkeypatch):
    # comm of the bash launcher that stays alive around the browser is
    # brave-origin (12 chars, inside pgrep's 15-char cap); the browser
    # itself is brave, which the stable row already covers.
    asked, exes = [], []

    def fake_run(cmd, **kw):
        exes.append(cmd[0])
        asked.append(cmd[-1])
        return type("R", (), {"returncode": 1})()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    origin = next(c for c in mod.LINUX_CHANNELS if c["id"] == "origin")
    inst = mod._make_installation(origin, plist_path="/x", prefs_path=None)
    assert mod._is_brave_running([inst]) is False
    assert asked == ["brave-origin"]
    assert exes == ["/usr/bin/pgrep"]


def test_running_check_without_pgrep(mod, monkeypatch):
    """No pgrep at either fixed path (the Windows test leg, a minimal
    container): not running, after trying both, and no PATH lookup."""
    tried = []

    def fake_run(cmd, **kw):
        tried.append(cmd[0])
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    stable = mod._make_installation(mod.LINUX_CHANNELS[0], plist_path="/x", prefs_path=None)
    assert mod._is_brave_running([stable]) is False
    assert tried == list(mod.PGREP_PATHS)


def test_detect_beta_only_deb_layout(mod, monkeypatch):
    """A Beta-only deb or rpm registers /usr/bin/brave-browser as an
    alternative for its own launcher (Chromium's postinst, which brave-core
    keeps), so the stable probe finds a Brave and nothing is wrong: found,
    no warning, and only the Beta record."""
    _fake_linux_box(mod, monkeypatch, on_path={"brave-browser", "brave-browser-beta"},
                    dirs={"/home/u/.config/BraveSoftware/Brave-Browser-Beta"})
    info = mod.detect_brave()
    assert info["found"] is True and info["warnings"] == []
    assert [i["channel"] for i in info["installations"]] == ["beta"]


def _locked_profile(tmp_path, target):
    """A profile whose SingletonLock points at `target`, as Chromium leaves it."""
    user_data = tmp_path / "Brave-Browser"
    (user_data / "Default").mkdir(parents=True)
    os.symlink(target, user_data / "SingletonLock")
    return {"prefs_path": str(user_data / "Default" / "Preferences"), "process_name": "brave"}


@posix_only
@pytest.mark.parametrize("exe,running", [
    ("/usr/bin/bash", False),
    ("/opt/brave.com/brave/brave (deleted)", True),
])
def test_a_lock_on_this_host_counts_only_for_a_brave_binary(mod, monkeypatch, tmp_path, exe, running):
    """A crash leaves the lock behind and the pid can be reused: on Linux
    the holder must still be a brave binary, as Chromium checks it."""
    inst = _locked_profile(tmp_path, f"{socket.gethostname()}-4242")
    real_readlink, real_isdir = os.readlink, os.path.isdir
    monkeypatch.setattr(os, "readlink", lambda p, *a, **k: (
        exe if os.fspath(p) == "/proc/4242/exe" else real_readlink(p, *a, **k)))
    monkeypatch.setattr(os.path, "isdir", lambda p: p == "/proc/self" or real_isdir(p))
    monkeypatch.setattr(mod, "_pid_is_alive", lambda pid: pid == 4242)
    monkeypatch.setattr(mod, "_pgrep", lambda name, uid=None: 1)
    assert mod._singleton_lock_pid(inst["prefs_path"]) == (socket.gethostname(), 4242)
    assert mod._is_brave_running([inst]) is running


@posix_only
def test_a_lock_from_another_host_counts_as_running(mod, monkeypatch, tmp_path):
    """The profile is in use on that host (a shared home); Chromium treats
    it the same way."""
    inst = _locked_profile(tmp_path, "otherhost-1")
    monkeypatch.setattr(socket, "gethostname", lambda: "thishost")
    monkeypatch.setattr(mod, "_pgrep", lambda *a, **k: pytest.fail("the lock decides"))
    assert mod._is_brave_running([inst]) is True


@posix_only
def test_pgrep_looks_only_at_the_invoking_users_processes(mod, monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(list(cmd))
        return type("R", (), {"returncode": 1})()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    stable = mod._make_installation(mod.LINUX_CHANNELS[0], plist_path="/x", prefs_path=None)
    _fake_passwd(monkeypatch, {"alice": 1000})
    monkeypatch.setenv("SUDO_USER", "alice")
    assert mod._is_brave_running([stable]) is False
    assert seen == [["/usr/bin/pgrep", "-u", "1000", "-x", "brave"]]
    seen.clear()
    monkeypatch.delenv("SUDO_USER")
    monkeypatch.delenv("USER", raising=False)
    assert mod._is_brave_running([stable]) is False
    assert seen == [["/usr/bin/pgrep", "-x", "brave"]]


def test_subprocess_argv0_is_absolute():
    """sudo can pass the caller's PATH through, so every helper program the
    scripts run as root is named by absolute path."""
    seen = {}
    for script in ("slimbrave-linux.py", "slimbrave-mac.py"):
        tree = ast.parse((ROOT / script).read_text(encoding="utf-8"))
        runs = open_cmds = 0
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run" and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess" and node.args
                    and isinstance(node.args[0], ast.List) and node.args[0].elts
                    and isinstance(node.args[0].elts[0], ast.Constant)
                    and isinstance(node.args[0].elts[0].value, str)):
                runs += 1
                assert node.args[0].elts[0].value.startswith("/"), (script, node.lineno)
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "open_cmd" for t in node.targets):
                open_cmds += 1
                first = node.value.elts[0]
                assert isinstance(first, ast.Constant) and first.value.startswith("/"), (
                    script, node.lineno)
        seen[script] = (runs, open_cmds)
    # the walk reaches what it checks: profiles x2, killall, and open_cmd
    runs, open_cmds = seen["slimbrave-mac.py"]
    assert runs >= 3 and open_cmds >= 1
    for m in MODULES:
        assert m.PGREP_PATHS and all(p.startswith("/") for p in m.PGREP_PATHS)


# ---------------------------------------------------------------------------
# Brave Origin — inert rows
#
# On a machine whose only Brave is Origin, the rows for the features Origin
# compiles out are shown but inert. Off Origin nothing here may change a
# thing, which the "stable" and mixed cases below pin down.
# ---------------------------------------------------------------------------


def _installs(mod, *ids, plist_path="/x/slimbrave.json"):
    out = []
    for cid in ids:
        ch = next(c for c in mod.LINUX_CHANNELS if c["id"] == cid)
        out.append(mod._make_installation(ch, plist_path=plist_path, prefs_path=None))
    return out


def _row_by_key(mod, rows, key):
    return next(r for r in rows if r["type"] == mod.ROW_FEATURE and r["key"] == key)


def _inert_keys(mod, rows):
    return {r["key"] for r in rows if r["type"] == mod.ROW_FEATURE and r.get("inert")}


def _header_index(mod, rows, text):
    return next(i for i, r in enumerate(rows)
                if r["type"] == mod.ROW_HEADER and r["text"] == text)


def test_is_origin_only(mod):
    assert mod.is_origin_only(_installs(mod, "origin")) is True
    assert mod.is_origin_only(_installs(mod, "origin", "origin-beta")) is True
    assert mod.is_origin_only([]) is False
    assert mod.is_origin_only(None) is False
    assert mod.is_origin_only(_installs(mod, "stable")) is False
    assert mod.is_origin_only(_installs(mod, "origin", "stable")) is False
    assert mod.is_origin_only([{"channel": "override", "label": "Override"}]) is False


def test_origin_builtin_keys_name_real_rows(mod):
    rows = mod.build_rows()
    keys = {r["key"] for r in rows if r["type"] == mod.ROW_FEATURE}
    assert mod.ORIGIN_BUILTIN_KEYS <= keys
    assert len(mod.ORIGIN_BUILTIN_KEYS) == 13
    # None sits in a mutually exclusive group, so inert never strands a partner.
    assert not any(r.get("group") for r in rows
                   if r["type"] == mod.ROW_FEATURE and r["key"] in mod.ORIGIN_BUILTIN_KEYS)
    # Unguarded in brave_simple_policy_map.h: Origin only defaults these off.
    assert "BraveP3AEnabled" not in mod.ORIGIN_BUILTIN_KEYS
    assert "BraveStatsPingEnabled" not in mod.ORIGIN_BUILTIN_KEYS


def test_rows_go_inert_only_when_origin_is_the_only_brave(mod):
    expected = set(mod.ORIGIN_BUILTIN_KEYS)
    assert _inert_keys(mod, mod.build_rows(_installs(mod, "origin"))) == expected
    assert _inert_keys(mod, mod.build_rows(_installs(mod, "origin-nightly"))) == expected
    for installs in (None, [], _installs(mod, "stable"), _installs(mod, "origin", "stable"),
                     [{"channel": "override", "label": "Override"}]):
        rows = mod.build_rows(installs)
        assert _inert_keys(mod, rows) == set(), installs
        # off Origin the rows do not even carry the flag
        assert not any("inert" in r for r in rows), installs


def test_inert_rows_cannot_be_toggled(mod):
    rows = mod.build_rows(_installs(mod, "origin"))
    dead = _row_by_key(mod, rows, "BraveRewardsDisabled")
    live = _row_by_key(mod, rows, "BraveP3AEnabled")
    mod.toggle_feature_row(rows, dead)
    assert dead["checked"] is False
    assert mod.activate_row(rows, dead) is False
    assert dead["checked"] is False
    assert mod.activate_row(rows, live) is True
    assert live["checked"] is True


def test_inert_rows_never_reach_the_policy_or_the_export(mod, tmp_path):
    rows = mod.build_rows(_installs(mod, "origin"))
    _row_by_key(mod, rows, "TorDisabled")["checked"] = True   # a state no path produces
    mod.toggle_feature_row(rows, _row_by_key(mod, rows, "BraveP3AEnabled"))
    policy, err = mod._build_policy(rows)
    assert err == "" and policy == {"BraveP3AEnabled": False}
    out = tmp_path / "export.json"
    ok, _ = mod.export_settings(rows, str(out))
    assert ok
    assert json.loads(out.read_text(encoding="utf-8"))["Features"] == {"BraveP3AEnabled": False}


def test_sync_leaves_inert_rows_unticked(mod):
    on_disk = {"BraveRewardsDisabled": True, "BraveP3AEnabled": False}
    rows = mod.build_rows(_installs(mod, "origin"))
    mod.sync_rows_with_policy(rows, on_disk)
    assert _row_by_key(mod, rows, "BraveRewardsDisabled")["checked"] is False
    assert _row_by_key(mod, rows, "BraveP3AEnabled")["checked"] is True
    # the same file on a regular Brave ticks both
    rows = mod.build_rows(_installs(mod, "stable"))
    mod.sync_rows_with_policy(rows, on_disk)
    assert _row_by_key(mod, rows, "BraveRewardsDisabled")["checked"] is True
    assert _row_by_key(mod, rows, "BraveP3AEnabled")["checked"] is True


def test_import_skips_inert_keys_and_says_so(mod):
    preset = str(ROOT / "Presets" / "Brave Origin Preset.json")
    rows = mod.build_rows(_installs(mod, "origin"))
    ok, msg = mod.import_settings(rows, preset)
    assert ok
    assert "13 keys built into Brave Origin left unmanaged" in msg
    checked = {r["key"] for r in rows if r["type"] == mod.ROW_FEATURE and r["checked"]}
    assert checked == {"BraveP3AEnabled", "BraveStatsPingEnabled"}
    rows = mod.build_rows(_installs(mod, "stable"))
    ok, msg = mod.import_settings(rows, preset)
    assert ok and "built into" not in msg
    assert sum(1 for r in rows if r["type"] == mod.ROW_FEATURE and r["checked"]) == 15


def test_header_counts_leave_inert_rows_out(mod):
    rows = mod.build_rows(_installs(mod, "origin"))
    h = _header_index(mod, rows, "Brave Features")
    assert mod.header_counts(rows, h) == (0, 3)
    assert mod.header_inert_count(rows, h) == 12
    assert mod.header_inert_count(rows, _header_index(mod, rows, "Performance & Bloat")) == 1
    assert "3 settings, 0 on, 12 built into Origin." in mod.describe_row(rows, h, mod.FOCUS_LIST, 0)
    dead = rows.index(_row_by_key(mod, rows, "BraveRewardsDisabled"))
    assert mod.describe_row(rows, dead, mod.FOCUS_LIST, 0).startswith("Built into Brave Origin")
    rows = mod.build_rows(_installs(mod, "stable"))
    h = _header_index(mod, rows, "Brave Features")
    assert mod.header_counts(rows, h) == (0, 15)
    assert mod.header_inert_count(rows, h) == 0
    assert "built into" not in mod.describe_row(rows, h, mod.FOCUS_LIST, 0)


def test_an_all_inert_section_folds_at_startup(mod):
    rows = mod.build_rows(_installs(mod, "origin"))
    h = _header_index(mod, rows, "Telemetry & Reporting")
    start, end = mod.header_span(rows, h)
    for r in rows[start:end]:
        r["inert"] = True
    # A managed DNS mode keeps the DNS header open; a section with no
    # countable rows must not borrow that rule.
    dns = next(r for r in rows if r["type"] == mod.ROW_DNS)
    dns["selected"] = 1
    assert mod.get_dns_mode(rows) != "unmanaged"
    mod.apply_startup_collapse(rows)
    assert mod.header_counts(rows, h) == (0, 0)
    assert rows[h]["collapsed"] is True


def test_tui_draws_inert_rows_on_origin(mod, monkeypatch, tmp_path):
    installs = _installs(mod, "origin", plist_path=str(tmp_path / "slimbrave.json"))
    frame = _render(mod, monkeypatch, tmp_path, 120, 100, keys=[ord("c")],
                    installations=installs)[-1]
    assert any("[-] Disable Brave Rewards (built into Origin)" in row for row in frame)
    assert any("[-] Disable Wayback Machine (built into Origin)" in row for row in frame)
    header = next(row for row in frame if "Brave Features" in row)
    assert "0/3 on" in header
    assert not any("[ ] Disable Brave Rewards" in row for row in frame)


def test_tui_off_origin_draws_the_rows_as_before(mod, monkeypatch, tmp_path):
    frame = _render(mod, monkeypatch, tmp_path, 120, 100, keys=[ord("c")])[-1]
    assert any("[ ] Disable Brave Rewards" in row for row in frame)
    assert not any("built into Origin" in row for row in frame)
    header = next(row for row in frame if "Brave Features" in row)
    assert "0/15 on" in header


def test_regular_brave_never_started_beside_origin_keeps_the_machine_mixed(mod, monkeypatch):
    # deb brave-browser and deb brave-origin, regular Brave never launched:
    # no Brave-Browser profile and no `brave` on PATH, yet the package is
    # there and reads the same file, so nothing may go inert.
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave.com/brave/brave-browser", "/opt/brave-origin-bin/brave"},
                    on_path={"brave-browser", "brave-origin"})
    info = mod.detect_brave()
    assert [i["channel"] for i in info["installations"]] == ["stable", "origin"]
    assert info["method"] == "deb/rpm: Stable, Origin"
    assert info["installations"][0]["app_path"] == "/opt/brave.com/brave/brave-browser"
    assert mod.is_origin_only(info["installations"]) is False
    assert info["notes"] == [mod.ORIGIN_NOTE_BESIDE]
    assert _inert_keys(mod, mod.build_rows(info["installations"])) == set()


def test_flatpak_never_started_beside_origin_keeps_the_machine_mixed(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave-origin-bin/brave"},
                    dirs={"/var/lib/flatpak/app/com.brave.Browser"},
                    on_path={"brave-origin"})
    info = mod.detect_brave()
    assert [i["channel"] for i in info["installations"]] == ["stable", "origin"]
    assert info["method"].endswith(": Stable, Origin")
    assert mod.is_origin_only(info["installations"]) is False
    assert _inert_keys(mod, mod.build_rows(info["installations"])) == set()


def test_regular_brave_alone_is_detected_exactly_as_before(mod, monkeypatch):
    # The never-started deb used to reach the stable fallback; it now gets
    # the same record from the loop. Either way: one stable record, its
    # binary as app_path, the plain method string, no note.
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave.com/brave/brave-browser"}, on_path={"brave-browser"})
    info = mod.detect_brave()
    assert info["method"] == "deb/rpm"
    assert [(i["channel"], i["label"], i["app_path"]) for i in info["installations"]] == [
        ("stable", "Stable", "/opt/brave.com/brave/brave-browser")]
    assert info["notes"] == []
    # A launched Flatpak alone still yields its one synthetic record only.
    _fake_linux_box(mod, monkeypatch,
                    dirs={"/var/lib/flatpak/app/com.brave.Browser",
                          "/home/u/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"})
    info = mod.detect_brave()
    assert info["method"] == "flatpak"
    assert [i["label"] for i in info["installations"]] == ["Stable (Flatpak)"]
    assert info["notes"] == []


def test_channels_origin_cannot_narrow_a_mixed_machine_into_origin_only(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch,
                    files={"/opt/brave-bin/brave", "/opt/brave-origin-bin/brave"},
                    dirs={"/home/u/.config/BraveSoftware/Brave-Browser", ORIGIN_PROFILE},
                    on_path={"brave", "brave-origin"})
    info = mod.detect_brave()
    filtered = [i for i in info["installations"] if i["channel"] == "origin"]
    assert filtered and all(i["origin_only"] is False for i in info["installations"])
    assert mod.is_origin_only(filtered) is False
    assert _inert_keys(mod, mod.build_rows(filtered)) == set()
    # and on a real Origin-only machine the stamp says so
    _fake_linux_box(mod, monkeypatch, files={"/opt/brave-origin-bin/brave"}, on_path={"brave-origin"})
    info = mod.detect_brave()
    assert all(i["origin_only"] is True for i in info["installations"])


def test_origin_beta_launcher_alone_counts_as_found(mod, monkeypatch):
    _fake_linux_box(mod, monkeypatch, on_path={"brave-origin-beta"})
    info = mod.detect_brave()
    assert info["found"] is True
    assert info["method"] == "unknown (Brave Origin)"
    assert [i["channel"] for i in info["installations"]] == ["origin-beta"]
    assert info["warnings"] == []
    assert info["notes"] == [mod.ORIGIN_NOTE_ONLY]


def test_cli_export_says_which_dead_keys_it_left_out(tmp_path, capsys):
    mod = LINUX_MOD
    plist = tmp_path / "slimbrave.json"
    plist.write_text(json.dumps({"BraveRewardsDisabled": True, "BraveP3AEnabled": False}),
                     encoding="utf-8")
    installs = _installs(mod, "origin", plist_path=str(plist))
    out = tmp_path / "backup.json"
    assert mod.cli_export(str(out), installs) == 0
    assert "1 key built into Brave Origin left out of the export" in capsys.readouterr().err
    assert json.loads(out.read_text(encoding="utf-8"))["Features"] == {"BraveP3AEnabled": False}


def test_a_long_inert_row_keeps_its_suffix_at_80_columns(mod, monkeypatch, tmp_path):
    installs = _installs(mod, "origin", plist_path=str(tmp_path / "slimbrave.json"))
    frame = _render(mod, monkeypatch, tmp_path, 120, 80, keys=[ord("c")],
                    installations=installs)[-1]
    row = next(r for r in frame if "Disable Local AI" in r)
    assert row.rstrip().endswith("... (built into Origin) |")
    assert row[78] == "|"


# ---------------------------------------------------------------------------
# SlimBrave.ps1 <-> Python feature-table parity
# ---------------------------------------------------------------------------

# One PS1 feature row: Name/Key/Value/Type, with an optional Group and an
# optional Choices block. A choice row writes Type without a trailing `;`
# and puts `Choices = @(...)` on the following line, so the two optional
# tails never compete: no row in the table carries both.
_PS1_FEATURE_RE = re.compile(
    r'@\{\s*Name\s*=\s*"([^"]*)";'
    r'\s*Key\s*=\s*"([^"]*)";'
    r'\s*Value\s*=\s*(.+?);'
    r'\s*Type\s*=\s*"[^"]*"'
    r'(?:;\s*Group\s*=\s*"([^"]*)")?'
    r'(?:\s*Choices\s*=\s*@\(([^)]*)\))?'
)

# One entry inside a PS1 `Choices = @(...)` block.
_PS1_CHOICE_RE = re.compile(
    r'@\{\s*Label\s*=\s*"([^"]*)";\s*Value\s*=\s*([^\s},]+)\s*\}'
)


def _parse_ps1_value(raw):
    """Turn a PS1 literal into the Python value it is meant to mirror."""
    raw = raw.strip()
    if raw == "$null":                  # "not managed" in a Choices block
        return None
    if raw.startswith("@("):            # @("*") / @("https://*", "http://*")
        return re.findall(r'"([^"]*)"', raw)
    if raw.startswith('"'):
        return raw[1:-1]
    return int(raw)                     # DWord


def _parse_ps1_choices(raw):
    """Turn a PS1 `Choices = @(...)` body into [(label, value), ...].

    Returns None for a row that has no Choices block, which is what the
    Python side's `feat.get("choices")` yields for a plain checkbox — so
    the two compare directly and a Choices block added on one side only
    shows up as None vs a list.
    """
    if raw is None:
        return None
    choices = [(m.group(1), _parse_ps1_value(m.group(2)))
               for m in _PS1_CHOICE_RE.finditer(raw)]
    # `Label = "` is unique to a choice entry, so it counts them honestly
    # even if one were written with its fields reordered.
    assert len(choices) == raw.count('Label = "'), (
        f"the PS1 choice regex missed an entry in: {raw!r}"
    )
    return choices


def _ps1_feature_rows():
    """Return {(name, key): (value, group, choices)} for every PS1 feature row."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    rows = {}
    for m in _PS1_FEATURE_RE.finditer(text):
        rows[(m.group(1), m.group(2))] = (
            _parse_ps1_value(m.group(3)),
            m.group(4),
            _parse_ps1_choices(m.group(5)),
        )
    # A row written with its fields in a different order would slip past the
    # regex and shrink the comparison silently. `Key = "` appears once per
    # feature row and nowhere else in the file, so it is the honest count.
    assert len(rows) == text.count('Key = "'), (
        "the PS1 feature regex missed a row — check the hashtable field order"
    )
    # Same guard for the Choices tail: it is optional in the regex, so a
    # block the regex failed to reach would silently read as "no choices"
    # and the parity check below would compare None against None. The
    # lookbehind keeps `$ignoredChoices = @()` in the import handler from
    # being counted as a table entry.
    parsed_choice_rows = sum(1 for v in rows.values() if v[2] is not None)
    declared_choice_blocks = len(re.findall(r'(?<![$\w])Choices\s*=\s*@\(', text))
    assert parsed_choice_rows == declared_choice_blocks, (
        "the PS1 choices regex missed a block — check the hashtable field order"
    )
    return rows


# BraveVPNDisabled is labelled "(no effect on Linux builds)" by both Python
# scripts when they run on Linux: enable_brave_vpn omits is_linux, so
# brave-core compiles the handler out there while Windows and macOS honour
# it. Compare that row on its key alone.
PS1_NAME_EXEMPT_KEYS = {"BraveVPNDisabled"}


def test_ps1_feature_table_matches_python(mod):
    ps1_rows = _ps1_feature_rows()
    py_rows = {(feat["name"], feat["key"]): (feat["value"],
                                             feat.get("group"),
                                             feat.get("choices"))
               for cat in mod.CATEGORIES for feat in cat["features"]}

    # Only drop a platform-gated key when this module really lacks it, so
    # the comparison still covers it on the platform that ships it.
    py_keys = {key for _, key in py_rows}
    skip = {k for k in PLATFORM_OMITTED_KEYS if k not in py_keys}

    def identify(rows):
        return {(key if key in PS1_NAME_EXEMPT_KEYS else name, key): rows[(name, key)]
                for name, key in rows if key not in skip}

    ps1_ident, py_ident = identify(ps1_rows), identify(py_rows)
    assert set(ps1_ident) ^ set(py_ident) == set(), (
        f"feature tables diverge — ps1-only: {sorted(set(ps1_ident) - set(py_ident))}, "
        f"python-only: {sorted(set(py_ident) - set(ps1_ident))}"
    )

    for ident, (py_value, py_group, py_choices) in py_ident.items():
        ps1_value, ps1_group, ps1_choices = ps1_ident[ident]
        # PowerShell has no bool: every bool policy is a DWord 0/1.
        if isinstance(py_value, bool) and ps1_value in (0, 1):
            ps1_value = bool(ps1_value)
        assert ps1_value == py_value, f"{ident}: PS1 {ps1_value!r} vs {py_value!r}"
        assert ps1_group == py_group, f"{ident}: PS1 group {ps1_group!r} vs {py_group!r}"
        # The ordered choices list has to agree exactly: same labels, same
        # values, same order. Order is what the dropdown and the TUI's
        # left/right cycling both walk, and a value present on one side
        # only is a policy the other platform silently cannot write (or,
        # worse, one Chromium rejects). None on both sides means the row
        # is a plain checkbox in all three scripts.
        py_choices = [tuple(c) for c in py_choices] if py_choices else py_choices
        assert ps1_choices == py_choices, (
            f"{ident}: choices diverge — PS1 {ps1_choices!r} vs Python {py_choices!r}"
        )


# ---------------------------------------------------------------------------
# Tri-state content settings (choice rows)
#
# These eight keys used to be plain checkboxes that wrote a hardcoded 2
# (block) when ticked and nothing when unticked, which threw away the
# "Ask" state Chromium supports. They are now choice rows.
# DefaultClipboardSetting joined later, as a choice row from the start.
#
# The table below is written out per key on purpose rather than sharing two
# aliases the way the scripts do: the enum is NOT uniform, and a test that
# reuses the scripts' own grouping cannot notice a key being moved into the
# wrong group. Allow (1) is a legal member of the notifications,
# geolocation and sensors enums only. For the three guard settings and for
# local fonts / window management / clipboard, Allow is not a schema
# member: a 1 is dropped for the three guard settings and applied as a
# managed Allow for local fonts, window management and clipboard. Offering
# it there is the trap this feature exists to avoid, so it gets its own
# assertion below.
# ---------------------------------------------------------------------------

EXPECTED_CHOICES = {
    # No Ask: under a managed 3 a site can prompt but never show a
    # notification (AUDIT.md, DefaultNotificationsSetting row).
    "DefaultNotificationsSetting": [
        ("Not managed", None), ("Allow", 1), ("Block", 2)],
    "DefaultGeolocationSetting": [
        ("Not managed", None), ("Allow", 1), ("Ask", 3), ("Block", 2)],
    "DefaultSensorsSetting": [
        ("Not managed", None), ("Allow", 1), ("Ask", 3), ("Block", 2)],
    "DefaultWebUsbGuardSetting": [
        ("Not managed", None), ("Ask", 3), ("Block", 2)],
    "DefaultSerialGuardSetting": [
        ("Not managed", None), ("Ask", 3), ("Block", 2)],
    "DefaultWebHidGuardSetting": [
        ("Not managed", None), ("Ask", 3), ("Block", 2)],
    "DefaultLocalFontsSetting": [
        ("Not managed", None), ("Ask", 3), ("Block", 2)],
    "DefaultWindowManagementSetting": [
        ("Not managed", None), ("Ask", 3), ("Block", 2)],
    "DefaultClipboardSetting": [
        ("Not managed", None), ("Ask", 3), ("Block", 2)],
}

# The six keys whose enum has no Allow member. Derived from the table
# above so the two can never disagree, then pinned by count.
ASK_BLOCK_ONLY_KEYS = sorted(
    key for key, choices in EXPECTED_CHOICES.items()
    if 1 not in [value for _, value in choices]
)
assert len(ASK_BLOCK_ONLY_KEYS) == 6, ASK_BLOCK_ONLY_KEYS


def _choice_rows(mod, rows):
    """Return {key: row} for every choice row."""
    return {row["key"]: row for row in rows if row["type"] == mod.ROW_CHOICE}


def _selected_label(row):
    return row["choices"][row["selected"]][0]


def test_choice_rows_are_exactly_the_documented_keys(mod):
    """A tenth choice row, or one of the nine demoted back to a checkbox,
    fails here rather than silently changing what the GUI offers."""
    rows = mod.build_rows()
    assert set(_choice_rows(mod, rows)) == set(EXPECTED_CHOICES)
    # The feature table and the row builder have to agree about which rows
    # carry choices — build_rows() branching on a key the table no longer
    # sets would leave a stale checkbox behind.
    table_keys = {feat["key"] for cat in mod.CATEGORIES
                  for feat in cat["features"] if "choices" in feat}
    assert table_keys == set(EXPECTED_CHOICES)


def test_choice_rows_offer_exactly_the_legal_values(mod):
    """Asserted against the literal table above, not against the scripts'
    own constants, so adding an illegal member fails loudly."""
    rows = _choice_rows(mod, mod.build_rows())
    for key, expected in EXPECTED_CHOICES.items():
        actual = [tuple(choice) for choice in rows[key]["choices"]]
        assert actual == expected, f"{key}: offers {actual!r}, expected {expected!r}"


def test_ask_block_only_keys_never_offer_allow(mod):
    """Spelled out separately from the table comparison because this is the
    one mistake that would look plausible: on these six keys a 1 is dropped
    for the three guard settings and applied as a managed Allow for local
    fonts, window management and clipboard, so a row offering it writes a
    policy Brave either ignores or turns into a grant for every site."""
    rows = _choice_rows(mod, mod.build_rows())
    for key in ASK_BLOCK_ONLY_KEYS:
        values = [value for _, value in rows[key]["choices"]]
        assert 1 not in values, f"{key} offers Allow (1), which is not a legal member"
        assert values == [None, 3, 2], f"{key}: {values!r}"


def test_choice_rows_default_to_not_managed(mod):
    """Out of the box a choice row behaves exactly like the unticked
    checkbox it replaced: nothing is written for its key."""
    rows = mod.build_rows()
    for key, row in _choice_rows(mod, rows).items():
        assert row["selected"] == 0, key
        assert _selected_label(row) == "Not managed", key
        assert row["choices"][0][1] is None, key
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert set(policy) & set(EXPECTED_CHOICES) == set(), (
        "an untouched choice row wrote a policy key"
    )


def test_choice_rows_export_nothing_when_unmanaged(mod, tmp_path):
    rows = mod.build_rows()
    out = tmp_path / "export.json"
    ok, _ = mod.export_settings(rows, str(out))
    assert ok
    features = json.loads(out.read_text())["Features"]
    assert set(features) & set(EXPECTED_CHOICES) == set()


# Every legal (key, label, value) triple, so a value dropped from one row
# loses its round-trip case instead of going untested.
CHOICE_VALUE_CASES = [
    (key, label, value)
    for key, choices in EXPECTED_CHOICES.items()
    for label, value in choices
    if value is not None
]


@pytest.mark.parametrize(
    "key,label,value", CHOICE_VALUE_CASES,
    ids=[f"{key}-{label}" for key, label, _ in CHOICE_VALUE_CASES])
def test_choice_value_round_trips(mod, tmp_path, key, label, value):
    """import -> selection -> _build_policy -> export -> import again.

    The exported JSON has to keep the same {key: value} shape it had when
    these rows were checkboxes, or a v1.9.5 config stops being readable.
    """
    cfg = _write_config(tmp_path, "in.json", {key: value})
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok, msg
    assert _selected_label(_choice_rows(mod, rows)[key]) == label

    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy == {key: value}

    out = tmp_path / "out.json"
    ok, _ = mod.export_settings(rows, str(out))
    assert ok
    assert json.loads(out.read_text())["Features"] == {key: value}

    # And the exported file reads back to the same selection.
    again = mod.build_rows()
    ok, msg = mod.import_settings(again, str(out))
    assert ok, msg
    assert _selected_label(_choice_rows(mod, again)[key]) == label


@pytest.mark.parametrize("key", sorted(EXPECTED_CHOICES))
def test_choice_key_absent_from_config_is_not_managed(mod, tmp_path, key):
    """Import is authoritative: a config that does not name the key leaves
    the row unmanaged even if it had been set beforehand."""
    rows = mod.build_rows()
    row = _choice_rows(mod, rows)[key]
    row["selected"] = len(row["choices"]) - 1          # Block
    cfg = _write_config(tmp_path, "other.json", {"BraveRewardsDisabled": True})
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok, msg
    assert _choice_rows(mod, rows)[key]["selected"] == 0
    policy, _ = mod._build_policy(rows)
    assert key not in policy


# Values no choice row may accept. 1 is listed for the six Ask/Block-only
# keys specifically: it is a legal member of the *other* three enums, so a
# row that quietly shares the wrong choices list would accept it here.
# True is included because `True == 1` in Python — a JSON `true` must not
# select "Allow" on the three keys that have one. 3 is listed for
# notifications, the one key that is legal at 3 but offers no Ask.
ILLEGAL_CHOICE_CASES = (
    [(key, 1) for key in ASK_BLOCK_ONLY_KEYS]
    + [("DefaultNotificationsSetting", 3)]
    + [(key, bad) for key in sorted(EXPECTED_CHOICES)
       for bad in (0, 4, "2", True)]
)


@pytest.mark.parametrize(
    "key,bad", ILLEGAL_CHOICE_CASES,
    ids=[f"{key}-{bad!r}" for key, bad in ILLEGAL_CHOICE_CASES])
def test_illegal_choice_value_is_rejected_and_named(mod, tmp_path, key, bad):
    """An illegal value leaves the row unmanaged and says so.

    Writing it through would hand Brave a policy it ignores or misapplies
    (a 1 on local fonts, window management or clipboard becomes a managed
    Allow), and doing that silently would look identical to "not managed"
    in the UI.
    """
    cfg = _write_config(tmp_path, "bad.json", {key: bad})
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok, msg
    row = _choice_rows(mod, rows)[key]
    assert row["selected"] == 0, (
        f"{key}={bad!r} selected {_selected_label(row)!r} instead of Not managed")
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert key not in policy
    assert key in msg, f"{key} was rejected but not named in: {msg!r}"


def test_illegal_choice_value_in_existing_policy_is_ignored(mod):
    """Same rule on the read-back path: a hand-edited policy file holding
    an illegal value shows the row as unmanaged rather than inventing a
    selection for it."""
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {
        "DefaultWebUsbGuardSetting": 1,     # no Allow member on this key
        "DefaultGeolocationSetting": 3,     # legal: Ask
        "DefaultNotificationsSetting": 3,   # legal in Chromium, not offered
    })
    choices = _choice_rows(mod, rows)
    assert choices["DefaultWebUsbGuardSetting"]["selected"] == 0
    assert _selected_label(choices["DefaultGeolocationSetting"]) == "Ask"
    assert _selected_label(choices["DefaultNotificationsSetting"]) == "Not managed"


def test_legacy_array_config_selects_block(mod, tmp_path):
    """A v1.9.5 array-format export carries keys without values; naming one
    used to tick a checkbox that wrote 2, so it has to land on Block."""
    cfg = _write_config(tmp_path, "legacy.json", sorted(EXPECTED_CHOICES))
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok, msg
    for key, row in _choice_rows(mod, rows).items():
        assert _selected_label(row) == "Block", key
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy == {key: 2 for key in EXPECTED_CHOICES}


def test_choice_rows_carry_no_checkbox_state(mod):
    """The two row kinds stay disjoint: a choice row with a stray `checked`
    would be counted twice by _build_policy and by every group helper."""
    rows = mod.build_rows()
    for key, row in _choice_rows(mod, rows).items():
        assert "checked" not in row, key
        assert not row.get("group"), key
    feature_keys = {row["key"] for row in rows if row["type"] == mod.ROW_FEATURE}
    assert feature_keys & set(EXPECTED_CHOICES) == set()


# ---------------------------------------------------------------------------
# Presets stay in sync with the feature definitions
# ---------------------------------------------------------------------------


def _feature_pairs(mod):
    pairs = {}
    for cat in mod.CATEGORIES:
        for feat in cat["features"]:
            pairs.setdefault(feat["key"], []).append(feat["value"])
    return pairs


# Rows no preset may ship. Matched on display name, not key+value: the same
# key legitimately carries value 2 (Cap Referrers) in most presets, and
# Strict Parental Controls writes SafeBrowsingProtectionLevel 1 (Lock Safe
# Browsing On), where a slip to 0 would silently turn Safe Browsing off.
FORBIDDEN_IN_PRESETS = {"Allow Permissive Referrers (unsafe-url)",
                        "Disable Safe Browsing (security downgrade)"}

_MISSING = object()


def test_presets_directory_is_not_empty():
    assert PRESETS, "no preset files found — the parametrized tests below are vacuous"


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_presets_match_feature_definitions(mod, preset):
    config = json.loads(preset.read_text())
    known = _feature_pairs(mod)
    for key, value in config["Features"].items():
        if key in PLATFORM_OMITTED_KEYS and key not in known:
            continue
        assert key in known, f"{preset.name}: unknown policy key {key}"
        # Type-strict: `False in [0]` and `0 in [False]` are both True in
        # Python, so plain membership waves through a bool where the row
        # wants an int. PS1's Test-FeatureValueMatches compares the String
        # forms, where '0' and 'False' are not the same value at all.
        assert any(type(v) is type(value) and v == value for v in known[key]), (
            f"{preset.name}: {key}={value!r} matches no feature row "
            f"(expected one of {known[key]!r}) — the import would silently skip it"
        )
    dns_mode = config.get("DnsMode")
    if dns_mode is not None:
        assert dns_mode in mod.DNS_MODES
    if "DnsTemplates" in config:
        assert dns_mode in ("custom", "secure")


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_presets_exclude_forbidden_rows(mod, preset):
    features = json.loads(preset.read_text())["Features"]
    for cat in mod.CATEGORIES:
        for feat in cat["features"]:
            if feat["name"] not in FORBIDDEN_IN_PRESETS:
                continue
            assert features.get(feat["key"], _MISSING) != feat["value"], (
                f"{preset.name}: {feat['name']} ({feat['key']}={feat['value']!r}) "
                f"weakens privacy and is excluded from every preset"
            )


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_presets_hold_no_mutually_exclusive_pair(mod, preset):
    """Checking one group member unchecks the others, so a preset naming two
    of them silently loses one. The shields group spans two different keys,
    which is why a per-key check cannot see it."""
    features = json.loads(preset.read_text())["Features"]
    claimed = {}
    for cat in mod.CATEGORIES:
        for feat in cat["features"]:
            group = feat.get("group")
            if not group or features.get(feat["key"], _MISSING) != feat["value"]:
                continue
            assert group not in claimed, (
                f"{preset.name}: {claimed.get(group)} and {feat['name']} are both "
                f"in the '{group}' group — importing keeps only the last one"
            )
            claimed[group] = feat["name"]


def _expected_policy(mod, config):
    """The policy dict a preset promises, minus anything this platform omits."""
    known = {feat["key"] for cat in mod.CATEGORIES for feat in cat["features"]}
    expected = {k: v for k, v in config["Features"].items() if k in known}
    dns_mode = config.get("DnsMode")
    dns_template = config.get("DnsTemplates", "")
    if dns_mode == "custom":
        expected["DnsOverHttpsMode"] = "secure"
        expected["DnsOverHttpsTemplates"] = dns_template
    elif dns_mode and dns_mode != "unmanaged":
        expected["DnsOverHttpsMode"] = dns_mode
        if dns_template:
            expected["DnsOverHttpsTemplates"] = dns_template
    return expected


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_preset_import_produces_promised_policy(mod, preset):
    config = json.loads(preset.read_text())
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(preset))
    assert ok, msg
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy == _expected_policy(mod, config)
    # The only keys allowed to go missing are the platform-gated ones
    assert set(config["Features"]) - set(policy) <= PLATFORM_OMITTED_KEYS


def test_maximum_privacy_preset_never_forces_incognito(mod):
    # Deliberately dropped: Force Incognito loses logins and extensions,
    # which is not what the preset's audience is asking for (README).
    preset = ROOT / "Presets" / "Maximum Privacy Preset.json"
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(preset))
    assert ok, msg
    policy, _ = mod._build_policy(rows)
    assert "IncognitoModeAvailability" not in policy


def test_history_deletion_lock_is_parental_only():
    # Prevent Deleting History keeps history from the person browsing; it
    # belongs to the parental lockdown, never to a privacy preset (AUDIT.md).
    for preset in PRESETS:
        features = json.loads(preset.read_text())["Features"]
        if preset.stem == "Strict Parental Controls Preset":
            assert features.get("AllowDeletingBrowserHistory") is False
        else:
            assert "AllowDeletingBrowserHistory" not in features, preset.name


def test_maximum_privacy_preset_keeps_the_pdf_viewer(mod):
    # Deliberately dropped: with the viewer off, navigator.plugins goes empty
    # and pdfViewerEnabled false outside Brave's farbling, which undoes the
    # preset's own fingerprinting pin for no privacy gain (AUDIT.md).
    preset = ROOT / "Presets" / "Maximum Privacy Preset.json"
    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(preset))
    assert ok, msg
    policy, _ = mod._build_policy(rows)
    assert "AlwaysOpenPdfExternally" not in policy


# Rows offered only for the user to tick: each breaks something every preset
# audience relies on (web calls, one-click app links), so no preset carries
# one (AUDIT.md rows). The PS1 copies follow through
# test_ps1_embedded_presets_match_preset_files.
OPT_IN_ONLY_KEYS = {"AudioCaptureAllowed", "VideoCaptureAllowed",
                    "ExternalProtocolDialogShowAlwaysOpenCheckbox"}


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_opt_in_only_rows_stay_out_of_presets(preset):
    features = json.loads(preset.read_text())["Features"]
    assert not OPT_IN_ONLY_KEYS & set(features), sorted(OPT_IN_ONLY_KEYS & set(features))


def test_capture_blocks_are_site_permission_checkboxes(mod):
    # Their policies are booleans whose true equals unset, so false is the
    # only managed state: a checkbox at the end of Site Permissions, not a
    # choice row and not grouped.
    found = {}
    for cat in mod.CATEGORIES:
        for feat in cat["features"]:
            if feat["key"] in ("AudioCaptureAllowed", "VideoCaptureAllowed"):
                found[feat["key"]] = (cat["name"], feat)
    assert set(found) == {"AudioCaptureAllowed", "VideoCaptureAllowed"}
    for key, (category, feat) in found.items():
        assert category == "Site Permissions", key
        assert feat["value"] is False, key
        assert "choices" not in feat and "group" not in feat, key


def test_command_line_extension_row_writes_only_the_legal_value(mod):
    assert [f["value"] for c in mod.CATEGORIES for f in c["features"]
            if f["key"] == "ExtensionInstallTypeBlocklist"] == [["command_line"]]


# ---------------------------------------------------------------------------
# SlimBrave.ps1 embedded presets <-> Presets/*.json
#
# The Windows quick start downloads SlimBrave.ps1 on its own, so the PS1
# carries its own copy of all five presets instead of reading Presets/. That
# copy is the whole risk of embedding: edit a preset file six months from
# now and Windows keeps shipping the old values, silently, for as long as
# nobody thinks to check. These two tests are what makes the embedding safe.
# ---------------------------------------------------------------------------

# The embedded block starts here. Everything below the marker is scanned for
# entries, which keeps the two `Add-Type ... -MemberDefinition @'` blocks
# higher up the file out of both the match and the count below.
_PS1_PRESETS_MARKER = "$script:embeddedPresets = [ordered]@{"

# One embedded entry: `"Preset Name" = @'`, the JSON body, then the closing
# '@ flush left because that is the only column PowerShell accepts it in.
_PS1_PRESET_RE = re.compile(
    r'^\s*"([^"]*)"\s*=\s*@\'\r?\n(.*?)\r?\n\'@\s*$',
    re.MULTILINE | re.DOTALL,
)


def _ps1_embedded_presets():
    """Return {preset name: parsed config} for every preset embedded in the PS1.

    The bodies are verbatim JSON rather than PowerShell literals — the PS1
    hands each one to the same ConvertFrom-Json the Import button uses — so
    unlike the feature table there is no DWord 0/1 to read back as a bool
    and no $null to fold into "absent". json.loads is the entire parse, and
    a body that stopped being valid JSON fails here instead of under a
    user's click.
    """
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    start = text.find(_PS1_PRESETS_MARKER)
    assert start != -1, "the embedded presets hashtable is gone from SlimBrave.ps1"
    block = text[start:]
    presets = {name: json.loads(body)
               for name, body in _PS1_PRESET_RE.findall(block)}
    # An entry whose opener was reformatted, or two entries sharing a name,
    # would shrink the comparison silently — which is the drift this section
    # exists to catch. The closing '@ is counted rather than the opener,
    # because PowerShell forces it to column 0 and nothing about it is a
    # matter of style: one per entry, and none above the marker.
    assert len(presets) == len(re.findall(r"^'@\s*$", block, re.MULTILINE)), (
        "the PS1 embedded-preset regex missed an entry — check the here-string form"
    )
    return presets


def _preset_items(config):
    """Flatten one preset config into comparable (path, value) pairs.

    Features are prefixed so a policy key cannot collide with DnsMode or
    DnsTemplates, and values are re-serialised so a list policy
    (ExtensionInstallBlocklist) is hashable and a set difference can name it.
    """
    items = set()
    for section, value in config.items():
        if section == "Features":
            for key, feature_value in value.items():
                items.add((f"Features.{key}", json.dumps(feature_value)))
        else:
            items.add((section, json.dumps(value)))
    return items


def test_ps1_embedded_presets_match_preset_files():
    embedded = _ps1_embedded_presets()
    on_disk = {preset.stem: json.loads(preset.read_text()) for preset in PRESETS}

    assert set(embedded) ^ set(on_disk) == set(), (
        f"preset sets diverge — ps1-only: {sorted(set(embedded) - set(on_disk))}, "
        f"disk-only: {sorted(set(on_disk) - set(embedded))}"
    )

    for name in sorted(embedded):
        ps1_items = _preset_items(embedded[name])
        disk_items = _preset_items(on_disk[name])
        # One symmetric difference covers all three ways a preset drifts: a
        # key on one side only, a value that changed, and the DNS entries,
        # which sit beside Features rather than inside it.
        assert ps1_items ^ disk_items == set(), (
            f"{name} drifted — ps1-only: {sorted(ps1_items - disk_items)}, "
            f"disk-only: {sorted(disk_items - ps1_items)}"
        )


def test_ps1_embedded_preset_names_match_files():
    """A renamed preset file has to be renamed in the PS1 too.

    The Quick Presets buttons are labelled straight from these keys, so a
    name with no file behind it is a button offering a preset the
    repository no longer has. Compared against the glob's stems rather than
    a path existence check, which Windows would answer case-insensitively.
    """
    stems = {preset.stem for preset in PRESETS}
    for name in sorted(_ps1_embedded_presets()):
        assert name in stems, f"embedded preset {name!r} has no Presets/{name}.json"


# ---------------------------------------------------------------------------
# v1.9.5 preset regression
#
# The tri-state rewrite changed how the eight content-setting keys are
# stored and drawn, and three of them (notifications, geolocation, sensors)
# ship inside Maximum Privacy Preset. A shipped preset importing to a
# different policy than it did before is a silent behaviour change on
# somebody's managed machine, so the policy every preset produces is pinned
# here rather than derived from the preset file.
#
# Revised deliberately in the v2.1.0 preset curation: the post-v1.9.5
# toggles were folded into the presets whose promises they fit, and each
# pin below was updated in the same commit. Revised again in v2.4.0:
# ShoppingListEnabled, AlternateErrorPagesEnabled and
# DNSInterceptionChecksEnabled left every preset when the scripts dropped
# them as inert (AUDIT.md, Considered and rejected), the lock-only
# HardwareAccelerationModeEnabled left Performance Focused, and
# AlwaysOpenPdfExternally left Maximum Privacy (its empty plugin list
# undoes the preset's fingerprinting pin), ChromeVariations left
# Balanced Privacy and Developer (AUDIT ChromeVariations row), and Maximum
# Privacy gained the new engine and process-isolation hardening
# (XSLTEnabled, DefaultJavaScriptOptimizerSetting, SitePerProcess,
# OriginKeyedProcessesEnabled, NetworkServiceSandboxEnabled). Balanced
# Privacy and Maximum Privacy then gained ExtensionInstallTypeBlocklist,
# those two and Developer gained AccessibilityImageLabelsEnabled, and Strict
# Parental Controls gained its history and safety locks
# (AllowDeletingBrowserHistory, ForceYouTubeRestrict,
# SafeBrowsingProtectionLevel 1, DisableSafeBrowsingProceedAnyway,
# SSLErrorOverrideAllowed); those pins changed in the same commit. A pin
# change outside such a deliberate curation is the drift this table exists
# to catch.
#
# Captured by loading the v1.9.5 scripts (git tag v1.9.5) and running
# import_settings + _build_policy over the presets as they ship. The values
# below are the Linux module's output; the mac module omits exactly the
# PLATFORM_OMITTED_KEYS it does not define, which the test filters for.
# ---------------------------------------------------------------------------

V195_PRESET_POLICIES = {
    "Balanced Privacy Preset": {
        "AccessibilityImageLabelsEnabled": False,
        "AutofillCreditCardEnabled": False,
        "BackgroundModeEnabled": False,
        "BasicAuthOverHttpEnabled": False,
        "BlockExternalExtensions": True,
        "BlockThirdPartyCookies": True,
        "BraveAIChatEnabled": False,
        "BraveDeAmpEnabled": True,
        "BraveDebouncingEnabled": True,
        "BraveGlobalPrivacyControlEnabled": True,
        "BraveLocalAIEnabled": False,
        "BraveNewsDisabled": True,
        "BraveP3AEnabled": False,
        "BraveReduceLanguageEnabled": True,
        "BraveRewardsDisabled": True,
        "BraveStatsPingEnabled": False,
        "BraveTalkDisabled": True,
        "BraveTrackingQueryParametersFilteringEnabled": True,
        "BraveVPNDisabled": True,
        "BraveWalletDisabled": True,
        "BraveWebDiscoveryEnabled": False,
        "BrowserSignin": 0,
        "DefaultBrowserSettingEnabled": False,
        "DnsOverHttpsMode": "automatic",
        "ExtensionInstallTypeBlocklist": ['command_line'],
        "MetricsReportingEnabled": False,
        "NetworkPredictionOptions": 2,
        "PaymentMethodQueryEnabled": False,
        "QuicAllowed": False,
        "RemoteDebuggingAllowed": False,
        "SpellCheckServiceEnabled": False,
        "SyncDisabled": True,
        "TorDisabled": True,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
        "WebRtcIPHandling": "disable_non_proxied_udp",
    },
    "Developer Preset": {
        "AccessibilityImageLabelsEnabled": False,
        "BackgroundModeEnabled": False,
        "BraveAIChatEnabled": False,
        "BraveLocalAIEnabled": False,
        "BraveNewsDisabled": True,
        "BraveP3AEnabled": False,
        "BraveRewardsDisabled": True,
        "BraveStatsPingEnabled": False,
        "BraveTalkDisabled": True,
        "BraveVPNDisabled": True,
        "BraveWalletDisabled": True,
        "DefaultBrowserSettingEnabled": False,
        "DnsOverHttpsMode": "automatic",
        "MetricsReportingEnabled": False,
        "SpellCheckServiceEnabled": False,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
    },
    "Maximum Privacy Preset": {
        "AccessibilityImageLabelsEnabled": False,
        "AutofillAddressEnabled": False,
        "AutofillCreditCardEnabled": False,
        "BackgroundModeEnabled": False,
        "BasicAuthOverHttpEnabled": False,
        "BlockExternalExtensions": True,
        "BlockThirdPartyCookies": True,
        "BraveAIChatEnabled": False,
        "BraveDeAmpEnabled": True,
        "BraveDebouncingEnabled": True,
        "BraveGlobalPrivacyControlEnabled": True,
        "BraveLocalAIEnabled": False,
        "BraveNewsDisabled": True,
        "BraveP3AEnabled": False,
        "BravePlaylistEnabled": False,
        "BraveReduceLanguageEnabled": True,
        "BraveRewardsDisabled": True,
        "BraveSpeedreaderEnabled": False,
        "BraveStatsPingEnabled": False,
        "BraveTalkDisabled": True,
        "BraveTrackingQueryParametersFilteringEnabled": True,
        "BraveVPNDisabled": True,
        "BraveWalletDisabled": True,
        "BraveWaybackMachineEnabled": False,
        "BraveWebDiscoveryEnabled": False,
        "BrowserSignin": 0,
        "ChromeVariations": 1,
        "DefaultBraveAdblockSetting": 2,
        "DefaultBraveFingerprintingV2Setting": 3,
        "DefaultBraveHttpsUpgradeSetting": 2,
        "DefaultBraveReferrersSetting": 2,
        "DefaultBraveRemember1PStorageSetting": 2,
        "DefaultBrowserSettingEnabled": False,
        "DefaultGeolocationSetting": 2,
        "DefaultJavaScriptOptimizerSetting": 2,
        "DefaultNotificationsSetting": 2,
        "DefaultSensorsSetting": 2,
        "DeveloperToolsAvailability": 2,
        "EmailAliasesEnabled": False,
        "EnableMediaRouter": False,
        "ExtensionInstallTypeBlocklist": ['command_line'],
        "MetricsReportingEnabled": False,
        "NetworkPredictionOptions": 2,
        "NetworkServiceSandboxEnabled": True,
        "OriginKeyedProcessesEnabled": True,
        "PasswordLeakDetectionEnabled": False,
        "PasswordManagerEnabled": False,
        "PaymentMethodQueryEnabled": False,
        "PrintingEnabled": False,
        "QuicAllowed": False,
        "RemoteDebuggingAllowed": False,
        "SearchSuggestEnabled": False,
        "SitePerProcess": True,
        "SpellcheckEnabled": False,
        "SyncDisabled": True,
        "TorDisabled": True,
        "TranslateEnabled": False,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "XSLTEnabled": False,
    },
    "Performance Focused Preset": {
        "BackgroundModeEnabled": False,
        "BraveAIChatEnabled": False,
        "BraveDeAmpEnabled": True,
        "BraveDebouncingEnabled": True,
        "BraveLocalAIEnabled": False,
        "BraveNewsDisabled": True,
        "BraveP3AEnabled": False,
        "BravePlaylistEnabled": False,
        "BraveRewardsDisabled": True,
        "BraveSpeedreaderEnabled": False,
        "BraveStatsPingEnabled": False,
        "BraveTalkDisabled": True,
        "BraveTrackingQueryParametersFilteringEnabled": True,
        "BraveVPNDisabled": True,
        "BraveWalletDisabled": True,
        "BraveWaybackMachineEnabled": False,
        "BraveWebDiscoveryEnabled": False,
        "DefaultBrowserSettingEnabled": False,
        "DnsOverHttpsMode": "automatic",
        "EnableMediaRouter": False,
        "HighEfficiencyModeEnabled": True,
        "MetricsReportingEnabled": False,
    },
    "Strict Parental Controls Preset": {
        "AllowDeletingBrowserHistory": False,
        "BraveAIChatEnabled": False,
        "BraveDeAmpEnabled": True,
        "BraveDebouncingEnabled": True,
        "BraveNewsDisabled": True,
        "BraveP3AEnabled": False,
        "BraveReduceLanguageEnabled": True,
        "BraveRewardsDisabled": True,
        "BraveStatsPingEnabled": False,
        "BraveTalkDisabled": True,
        "BraveTrackingQueryParametersFilteringEnabled": True,
        "BraveVPNDisabled": True,
        "BraveWalletDisabled": True,
        "BraveWebDiscoveryEnabled": False,
        "BrowserGuestModeEnabled": False,
        "BrowserSignin": 0,
        "DeveloperToolsAvailability": 2,
        "DisableSafeBrowsingProceedAnyway": True,
        "DnsOverHttpsMode": "secure",
        "DnsOverHttpsTemplates": "https://family.cloudflare-dns.com/dns-query",
        "ExtensionInstallBlocklist": ['*'],
        "ForceGoogleSafeSearch": True,
        "ForceYouTubeRestrict": 2,
        "IncognitoModeAvailability": 1,
        "RemoteDebuggingAllowed": False,
        "SSLErrorOverrideAllowed": False,
        "SafeBrowsingProtectionLevel": 1,
        "SyncDisabled": True,
        "TorDisabled": True,
    },
    # Pinned at introduction (v2.1.0), not captured from v1.9.5 - the preset
    # did not exist then. Same contract as the five above: the policy a
    # shipped preset produces must never drift silently. The 15 keys are the
    # policy-mapped half of Brave Origin's enforced set, source-verified
    # against brave_origin_service_factory.cc; PsstEnabled is the 16th and
    # is deliberately not exposed (see AUDIT.md).
    "Brave Origin Preset": {
        "BraveAIChatEnabled": False,
        "BraveLocalAIEnabled": False,
        "BraveNewsDisabled": True,
        "BraveP3AEnabled": False,
        "BravePlaylistEnabled": False,
        "BraveRewardsDisabled": True,
        "BraveSpeedreaderEnabled": False,
        "BraveStatsPingEnabled": False,
        "BraveTalkDisabled": True,
        "BraveVPNDisabled": True,
        "BraveWalletDisabled": True,
        "BraveWaybackMachineEnabled": False,
        "BraveWebDiscoveryEnabled": False,
        "EmailAliasesEnabled": False,
        "TorDisabled": True,
    },
}


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.stem)
def test_presets_produce_their_v195_policy(mod, preset):
    expected = V195_PRESET_POLICIES[preset.stem]
    known = {feat["key"] for cat in mod.CATEGORIES for feat in cat["features"]}
    # Only the platform-gated keys may be dropped, and only by a module
    # that genuinely lacks them — anything else has to match exactly.
    dropped = {k for k in expected if k not in known and k != "DnsOverHttpsMode"
               and k != "DnsOverHttpsTemplates"}
    assert dropped <= PLATFORM_OMITTED_KEYS, (
        f"{preset.name}: {sorted(dropped)} vanished from the feature table")
    expected = {k: v for k, v in expected.items() if k not in dropped}

    rows = mod.build_rows()
    ok, msg = mod.import_settings(rows, str(preset))
    assert ok, msg
    policy, err = mod._build_policy(rows)
    assert err == ""
    added = {k: policy[k] for k in set(policy) - set(expected)}
    removed = {k: expected[k] for k in set(expected) - set(policy)}
    changed = {k: (expected[k], policy[k]) for k in set(policy) & set(expected)
               if policy[k] != expected[k]}
    assert policy == expected, (
        f"{preset.name} no longer produces its v1.9.5 policy — "
        f"added: {added}, removed: {removed}, changed (was, now): {changed}"
    )


def test_v195_snapshot_covers_every_preset():
    """A preset added without a snapshot entry would KeyError above, but a
    stale entry for a deleted preset would just sit there unused."""
    assert set(V195_PRESET_POLICIES) == {p.stem for p in PRESETS}


def test_v195_snapshot_pins_the_tri_state_keys():
    """Guards the snapshot itself: if the three content-setting keys ever
    fell out of Maximum Privacy, this file would still 'pass' while
    silently no longer testing the thing the rewrite touched."""
    maximum = V195_PRESET_POLICIES["Maximum Privacy Preset"]
    assert maximum["DefaultNotificationsSetting"] == 2
    assert maximum["DefaultGeolocationSetting"] == 2
    assert maximum["DefaultSensorsSetting"] == 2


def test_variations_rows_name_their_griffin_costs(mod):
    """Either ChromeVariations row also refuses what Brave ships only through
    Griffin (AUDIT ChromeVariations row); both descriptions must say so, and
    neither may claim that no critical study applies."""
    rows = {f["value"]: f for c in mod.CATEGORIES for f in c["features"]
            if f["key"] == "ChromeVariations"}
    assert set(rows) == {1, 2}
    for row in rows.values():
        assert "WebGL/WebGPU fingerprint masking" in row["desc"], row["name"]
        assert "Google sign-in fix" in row["desc"], row["name"]
        assert "None applies" not in row["desc"], row["name"]
    assert "brave://flags" in rows[1]["desc"]


def test_strict_https_preset_keeps_its_variations_partner():
    """DefaultBraveHttpsUpgradeSetting = 2 stays enforced on Brave's
    HTTPS-First rollout only while ChromeVariations filters
    TransitionToUpstreamHttpsUpgrade (AUDIT DefaultBraveHttpsUpgradeSetting
    row), so a preset that promises strict HTTPS must carry one of its rows."""
    for preset in PRESETS:
        features = json.loads(preset.read_text(encoding="utf-8"))["Features"]
        if features.get("DefaultBraveHttpsUpgradeSetting") == 2:
            assert features.get("ChromeVariations") in (1, 2), preset.name


# ---------------------------------------------------------------------------
# Collapsible sections, live filter and paging
#
# The list view is the only part of the TUI carrying state of its own, and
# none of it needs a terminal: visible_indices, selectable_indices,
# resolve_cursor, header_counts and clamp_scroll are pure over rows[] plus
# a filter string, exactly like every other function tested above.
#
# What main() adds on top is three small pieces of arithmetic — the `c`
# fold-all branch, the PageUp/PageDown branch, and the `/` prompt's
# snapshot/restore — which the helpers below mirror rather than reach
# through curses. That mirror is the seam these tests pin: change the
# arithmetic in one of the scripts and the copies here stop agreeing with
# it, which is the failure worth having.
# ---------------------------------------------------------------------------


class _FakeScreen:
    """The one thing viewport_rows() asks a curses window for."""

    def __init__(self, lines=24, cols=80):
        self._size = (lines, cols)

    def getmaxyx(self):
        return self._size


def _header_indices(mod, rows):
    return [i for i, row in enumerate(rows) if row["type"] == mod.ROW_HEADER]


def _header_index(mod, rows, name):
    for i, row in enumerate(rows):
        if row["type"] == mod.ROW_HEADER and row["text"] == name:
            return i
    raise AssertionError(f"header not found: {name}")


def _texts(rows, indices):
    return [rows[i]["text"] for i in indices]


def _fold_all(mod, rows):
    """Mirror main()'s `c` branch: fold everything unless it already is."""
    headers = [rows[i] for i in _header_indices(mod, rows)]
    fold = any(not h.get("collapsed", False) for h in headers)
    for header in headers:
        header["collapsed"] = fold
    return fold


def _page(mod, rows, cursor_idx, step, filter_text=""):
    """Mirror main()'s PageUp/PageDown branch; return the new cursor row.

    main() re-resolves the cursor against the visible list at the top of
    every pass and only then adds or subtracts a viewport, so the clamp is
    against len(sel) and never against len(rows).
    """
    sel = mod.selectable_indices(rows, filter_text)
    if not sel:
        return cursor_idx
    cursor_pos, cursor_idx = mod.resolve_cursor(sel, cursor_idx)
    cursor_pos = max(0, min(len(sel) - 1, cursor_pos + step))
    return sel[cursor_pos]


def _set_choice(mod, rows, name, label):
    """Select a choice row by display name and choice label."""
    for row in rows:
        if row["type"] == mod.ROW_CHOICE and row["text"] == name:
            labels = [choice[0] for choice in row["choices"]]
            row["selected"] = labels.index(label)
            return row
    raise AssertionError(f"choice row not found: {name}")


def _expected_counts(mod, rows, header_idx):
    """(on, total) computed straight off the rows a header owns."""
    start, end = mod.header_span(rows, header_idx)
    on = sum(
        1 for row in rows[start:end]
        if (row["type"] == mod.ROW_FEATURE and row["checked"])
        or (row["type"] == mod.ROW_CHOICE and row["selected"] > 0)
    )
    total = sum(1 for row in rows[start:end]
                if row["type"] in (mod.ROW_FEATURE, mod.ROW_CHOICE))
    return on, total


# ---------------------------------------------------------------------------
# Collapse
# ---------------------------------------------------------------------------


def test_collapse_hides_exactly_that_categorys_rows(mod):
    """Folding one section removes its rows and nothing else: the header
    stays, and every surviving row keeps its position."""
    rows = mod.build_rows()
    before = mod.visible_indices(rows)
    header_idx = _header_index(mod, rows, "Brave Features")
    start, end = mod.header_span(rows, header_idx)
    assert end > start  # a category with no rows would make this vacuous

    rows[header_idx]["collapsed"] = True
    after = mod.visible_indices(rows)
    assert set(before) - set(after) == set(range(start, end))
    assert set(after) - set(before) == set()
    assert after == [i for i in before if not start <= i < end]
    assert header_idx in after


def test_collapse_excludes_its_rows_from_selectable(mod):
    """The cursor cannot land on a row the list is not painting."""
    rows = mod.build_rows()
    before_sel = mod.selectable_indices(rows)
    header_idx = _header_index(mod, rows, "Site Permissions")
    start, end = mod.header_span(rows, header_idx)
    owned = set(range(start, end))
    assert owned <= set(before_sel)

    rows[header_idx]["collapsed"] = True
    sel = mod.selectable_indices(rows)
    assert not owned & set(sel)
    assert header_idx in sel  # the header stays selectable so it can unfold
    # Nothing outside the folded section moved.
    assert sel == [i for i in before_sel if i not in owned]


def test_collapsing_every_section_leaves_only_headers(mod):
    rows = mod.build_rows()
    assert _fold_all(mod, rows) is True
    headers = _header_indices(mod, rows)
    assert mod.visible_indices(rows) == headers
    assert mod.selectable_indices(rows) == headers


def test_header_counts_track_checkboxes_and_choice_rows(mod):
    """The on-count is checked checkboxes plus choice rows sitting off
    "Not managed" — an unmanaged choice row must not read as on."""
    rows = mod.build_rows()
    for header_idx in _header_indices(mod, rows):
        assert mod.header_counts(rows, header_idx) == \
            _expected_counts(mod, rows, header_idx)
        assert mod.header_counts(rows, header_idx)[0] == 0

    controls = _header_index(mod, rows, "Access Controls")
    _, ctl_total = mod.header_counts(rows, controls)
    _check_feature(mod, rows, "Block All Extensions")
    assert mod.header_counts(rows, controls) == (1, ctl_total)
    # Selecting a choice counts, exactly like ticking a checkbox - under its
    # own Site Permissions header, not the Access Controls one next door.
    site = _header_index(mod, rows, "Site Permissions")
    _, site_total = mod.header_counts(rows, site)
    notifications = _set_choice(mod, rows, "Web Notifications", "Allow")
    assert mod.header_counts(rows, site) == (1, site_total)
    assert mod.header_counts(rows, controls) == (1, ctl_total)
    # Cycling back to "Not managed" takes the count away again.
    notifications["selected"] = 0
    assert mod.header_counts(rows, site) == (0, site_total)

    for header_idx in _header_indices(mod, rows):
        assert mod.header_counts(rows, header_idx) == \
            _expected_counts(mod, rows, header_idx)


def test_dns_header_counts_nothing(mod):
    """The DNS section holds no checkbox and no choice row, so it reports
    (0, 0) and draw() omits the counter rather than painting "0/0 on"."""
    rows = mod.build_rows()
    dns_header = _header_index(mod, rows, "DNS Over HTTPS")
    _set_dns(mod, rows, "custom", "https://dns.example/dns-query")
    assert mod.header_counts(rows, dns_header) == (0, 0)


def test_collapse_all_then_expand_all_round_trips(mod):
    """Two presses of `c` from an all-expanded list put every row back."""
    rows = mod.build_rows()
    before_vis = mod.visible_indices(rows)
    before_sel = mod.selectable_indices(rows)
    before_state = mod.collapse_state(rows)

    assert _fold_all(mod, rows) is True
    assert mod.visible_indices(rows) == _header_indices(mod, rows)
    assert _fold_all(mod, rows) is False

    assert mod.collapse_state(rows) == before_state
    assert mod.visible_indices(rows) == before_vis
    assert mod.selectable_indices(rows) == before_sel


def test_collapse_all_from_a_mixed_state_folds_before_unfolding(mod):
    """From a half-folded list the first press folds the rest rather than
    unfolding the sections already down."""
    rows = mod.build_rows()
    headers = _header_indices(mod, rows)
    rows[headers[0]]["collapsed"] = True
    rows[headers[2]]["collapsed"] = True

    assert _fold_all(mod, rows) is True
    assert mod.collapse_state(rows) == [True] * len(headers)
    assert _fold_all(mod, rows) is False
    assert mod.collapse_state(rows) == [False] * len(headers)


# ---------------------------------------------------------------------------
# Collapse state survives the operations that rewrite rows in place
#
# import, reset and policy-sync all walk rows[] setting `checked`,
# `selected` and the DNS fields. None of them may touch `collapsed`: a fold
# is a view preference, and an import that silently unfolded the list would
# move the user's cursor somewhere else mid-session.
# ---------------------------------------------------------------------------


def _mixed_collapse(mod, rows):
    """Fold alternate sections and return the resulting snapshot."""
    for n, header_idx in enumerate(_header_indices(mod, rows)):
        rows[header_idx]["collapsed"] = bool(n % 2)
    return mod.collapse_state(rows)


def test_collapse_state_survives_import_settings(mod, tmp_path):
    rows = mod.build_rows()
    expected = _mixed_collapse(mod, rows)
    before_vis = mod.visible_indices(rows)

    cfg = _write_config(tmp_path, "in.json", {
        "BraveRewardsDisabled": True,
        "DefaultNotificationsSetting": 2,
    })
    ok, msg = mod.import_settings(rows, str(cfg))
    assert ok, msg
    assert _get_feature(mod, rows, "Disable Brave Rewards")["checked"] is True
    assert mod.collapse_state(rows) == expected
    assert mod.visible_indices(rows) == before_vis


def test_collapse_state_survives_sync_rows_with_policy(mod):
    rows = mod.build_rows()
    expected = _mixed_collapse(mod, rows)
    before_vis = mod.visible_indices(rows)

    mod.sync_rows_with_policy(rows, {
        "BraveRewardsDisabled": True,
        "IncognitoModeAvailability": 2,
        "DefaultGeolocationSetting": 3,
    })
    assert _get_feature(mod, rows, "Disable Brave Rewards")["checked"] is True
    assert mod.collapse_state(rows) == expected
    assert mod.visible_indices(rows) == before_vis


def test_collapse_state_survives_reset_policy(mod, tmp_path, monkeypatch):
    """reset_policy unchecks every row and deletes the policy file; the
    prefs repair is stubbed so nothing here goes near a real profile."""
    monkeypatch.setattr(mod, "repair_brave_prefs", lambda *a, **k: (0, {}, False))
    plist = tmp_path / "policy.json"
    plist.write_text(json.dumps({"BraveRewardsDisabled": True}))
    installations = [{"channel": "stable", "label": "Stable",
                      "plist_path": str(plist)}]

    rows = mod.build_rows()
    _check_feature(mod, rows, "Disable Brave Rewards")
    _set_choice(mod, rows, "Web Notifications", "Block")
    expected = _mixed_collapse(mod, rows)
    before_vis = mod.visible_indices(rows)

    ok, msg = mod.reset_policy(rows, installations)
    assert ok, msg
    assert not plist.exists()
    assert _get_feature(mod, rows, "Disable Brave Rewards")["checked"] is False
    assert _choice_rows(mod, rows)["DefaultNotificationsSetting"]["selected"] == 0
    assert mod.collapse_state(rows) == expected
    assert mod.visible_indices(rows) == before_vis


# ---------------------------------------------------------------------------
# Filter
#
# "block" is the needle these tests lean on: twelve rows spread over four of
# the seven categories, so the match set proves the filter keeps row order,
# carries the owning header down with each group, and drops the categories
# matching nothing. The expected rows are written out rather than derived
# from row["text"], which would only re-run the implementation.
# ---------------------------------------------------------------------------

FILTER_NEEDLE = "block"
FILTER_EXPECTED = [
    "Privacy & Security",
    "Block Third Party Cookies",
    "Block Payment Method Probing",
    "Block Remote Debugging",
    "Block Local Network Access",
    "Site Permissions",
    "Block Microphone Access",
    "Block Camera Access",
    "Access Controls",
    "Block Bypassing Safe Browsing Warnings",
    "Block Bypassing Certificate Warnings",
    "Block All Extensions",
    "Block Sideloaded (External) Extensions",
    "Block Command-Line Extensions (--load-extension)",
    "Shields & Content Protection",
    "Enforce Ad Blocking",
]


def test_filter_shows_matching_rows_under_their_headers(mod):
    rows = mod.build_rows()
    vis = mod.visible_indices(rows, FILTER_NEEDLE)
    assert _texts(rows, vis) == FILTER_EXPECTED
    # Nothing painted in a filtered list is unreachable: every row can be
    # walked onto, headers included.
    assert mod.selectable_indices(rows, FILTER_NEEDLE) == vis


@pytest.mark.parametrize("query", ["block", "BLOCK", "  Block  ", "bLoCk"],
                         ids=["lower", "upper", "padded", "mixed"])
def test_filter_is_case_and_whitespace_insensitive(mod, query):
    rows = mod.build_rows()
    assert _texts(rows, mod.visible_indices(rows, query)) == FILTER_EXPECTED


def test_filter_matching_nothing_hides_everything(mod):
    """Headers included — a filter with no matches paints an empty list,
    which is the case that leaves the cursor on no row at all."""
    rows = mod.build_rows()
    assert mod.visible_indices(rows, "no such setting") == []
    assert mod.selectable_indices(rows, "no such setting") == []
    assert mod.resolve_cursor([], 12) == (0, -1)


def test_empty_filter_is_the_unfiltered_list(mod):
    rows = mod.build_rows()
    unfiltered = mod.visible_indices(rows)
    assert mod.visible_indices(rows, "") == unfiltered
    assert mod.visible_indices(rows, "   ") == unfiltered


def test_filter_reveals_a_match_inside_a_collapsed_section(mod):
    """A search that quietly skipped folded sections would be worse than no
    search at all, so the fold is ignored while a filter is live — and the
    section is still folded underneath it."""
    rows = mod.build_rows()
    _fold_all(mod, rows)
    assert mod.visible_indices(rows) == _header_indices(mod, rows)

    header_idx = _header_index(mod, rows, "Brave Features")
    rewards_idx = rows.index(_get_feature(mod, rows, "Disable Brave Rewards"))
    vis = mod.visible_indices(rows, "rewards")
    assert _texts(rows, vis) == ["Brave Features", "Disable Brave Rewards"]
    assert rewards_idx in mod.selectable_indices(rows, "rewards")
    assert rows[header_idx]["collapsed"] is True


def test_clearing_the_filter_restores_the_exact_collapse_state(mod):
    """Mirror the `/` prompt: snapshot on the way in, and Esc puts the folds
    back even after the user re-folded sections while filtering."""
    rows = mod.build_rows()
    before = _mixed_collapse(mod, rows)
    before_vis = mod.visible_indices(rows)

    saved_collapse = mod.collapse_state(rows)
    filter_text = FILTER_NEEDLE
    assert mod.visible_indices(rows, filter_text) == \
        mod.visible_indices(mod.build_rows(), filter_text)
    # Folding stays live under a filter, so the user can leave the sections
    # in a completely different shape than they found them.
    for header_idx in _header_indices(mod, rows):
        rows[header_idx]["collapsed"] = not rows[header_idx]["collapsed"]
    assert mod.collapse_state(rows) != before

    filter_text = ""
    mod.restore_collapse_state(rows, saved_collapse)
    assert mod.collapse_state(rows) == before
    assert mod.visible_indices(rows, filter_text) == before_vis


def test_restore_collapse_state_ignores_none(mod):
    """main() hands the snapshot straight through, and it is None until the
    filter prompt has been opened at least once."""
    rows = mod.build_rows()
    expected = _mixed_collapse(mod, rows)
    mod.restore_collapse_state(rows, None)
    assert mod.collapse_state(rows) == expected


def test_toggling_a_row_while_filtered_keeps_the_filter(mod):
    """Ticking a match must not drop the user back into the full list."""
    rows = mod.build_rows()
    filter_text = "rewards"
    vis = mod.visible_indices(rows, filter_text)
    sel = mod.selectable_indices(rows, filter_text)
    cursor_pos, cursor_idx = next(
        (pos, idx) for pos, idx in enumerate(sel)
        if rows[idx]["type"] == mod.ROW_FEATURE
    )

    mod.toggle_feature_row(rows, rows[cursor_idx])
    assert rows[cursor_idx]["checked"] is True
    assert mod.visible_indices(rows, filter_text) == vis
    assert mod.selectable_indices(rows, filter_text) == sel
    # And the cursor is still on the row that was just ticked.
    assert mod.resolve_cursor(mod.selectable_indices(rows, filter_text),
                              cursor_idx) == (cursor_pos, cursor_idx)
    header_idx = _header_index(mod, rows, "Brave Features")
    assert mod.header_counts(rows, header_idx)[0] == 1


def test_cycling_a_choice_row_while_filtered_keeps_the_filter(mod):
    rows = mod.build_rows()
    filter_text = "notification"
    vis = mod.visible_indices(rows, filter_text)
    assert _texts(rows, vis) == ["Site Permissions", "Web Notifications"]

    row = _choice_rows(mod, rows)["DefaultNotificationsSetting"]
    mod.cycle_choice_row(row, 1)
    assert row["selected"] == 1
    assert mod.visible_indices(rows, filter_text) == vis
    assert mod.selectable_indices(rows, filter_text) == vis


# ---------------------------------------------------------------------------
# Paging
#
# PageUp/PageDown were unbound through v1.9.5, which left an 87-row list
# reachable one Down at a time. The step is a whole viewport, which on the
# 80x24 terminal these tests assume is 16 rows with the description pane
# hidden and 10 with it shown.
# ---------------------------------------------------------------------------


# The PageUp/PageDown branch is inline in main(), which nothing here can
# reach without a terminal, so _page() above is a hand copy of it. This is
# what keeps the copy honest: the branch is pulled out of both scripts by
# source and compared against the arithmetic the helper actually runs. Edit
# the clamp in the scripts and this fails, naming the mirror to update —
# without it, a broken clamp would sail past every paging test below.
PAGING_BRANCH = '''\
if focus == FOCUS_LIST and sel:
    step = visible_count
    if key == curses.KEY_PPAGE:
        step = -visible_count
    cursor_pos = max(0, min(len(sel) - 1, cursor_pos + step))
    cursor_idx = sel[cursor_pos]
    status_msg = ""'''

_PAGING_BRANCH_RE = re.compile(
    r"^ {8}elif key in \(curses\.KEY_PPAGE, curses\.KEY_NPAGE\):\n"
    r"((?:^ {12}.*\n|^\n)+)",
    re.MULTILINE,
)


@pytest.mark.parametrize("script", ["slimbrave-linux.py", "slimbrave-mac.py"])
def test_paging_branch_matches_the_helper_that_mirrors_it(script):
    source = (ROOT / script).read_text(encoding="utf-8")
    match = _PAGING_BRANCH_RE.search(source)
    assert match, f"{script}: PageUp/PageDown is not bound in main()"
    body = textwrap.dedent(match.group(1)).strip()
    assert body == PAGING_BRANCH, (
        f"{script}: the PageUp/PageDown branch changed. Update _page() in "
        f"this file to match, or the paging tests stop testing the TUI:\n"
        f"{body}"
    )


def test_viewport_rows_leaves_room_for_the_chrome(mod):
    # Title, hints, the list box's two edges, the three-row button box and
    # the status line: eight rows. The description pane, when shown, takes
    # its text lines (four at 80 columns, three at 120) plus two edges on top.
    assert mod.viewport_rows(_FakeScreen(24, 80)) == 16
    assert mod.viewport_rows(_FakeScreen(24, 80), show_desc=True) == 10
    assert mod.viewport_rows(_FakeScreen(50, 120)) == 42
    assert mod.viewport_rows(_FakeScreen(50, 120), show_desc=True) == 37
    # Never zero or negative, however small the terminal gets.
    assert mod.viewport_rows(_FakeScreen(6, 20)) == 1
    assert mod.viewport_rows(_FakeScreen(1, 20)) == 1


def test_page_down_clamps_at_the_last_selectable_row(mod):
    rows = mod.build_rows()
    page = mod.viewport_rows(_FakeScreen(24, 80))
    sel = mod.selectable_indices(rows)
    assert len(sel) > 2 * page  # or the steps below would not be measurable

    cursor_idx = sel[0]
    seen = []
    for _ in range(len(sel) // page + 3):
        cursor_idx = _page(mod, rows, cursor_idx, page)
        seen.append(cursor_idx)
    assert seen[:2] == [sel[page], sel[2 * page]]
    assert cursor_idx == sel[-1]
    # Once pinned to the end it stays there rather than running off it.
    assert _page(mod, rows, cursor_idx, page) == sel[-1]


def test_page_up_clamps_at_the_first_selectable_row(mod):
    rows = mod.build_rows()
    page = mod.viewport_rows(_FakeScreen(24, 80))
    sel = mod.selectable_indices(rows)

    cursor_idx = sel[-1]
    seen = []
    for _ in range(len(sel) // page + 3):
        cursor_idx = _page(mod, rows, cursor_idx, -page)
        seen.append(cursor_idx)
    assert seen[:2] == [sel[-1 - page], sel[-1 - 2 * page]]
    assert cursor_idx == sel[0]
    assert _page(mod, rows, cursor_idx, -page) == sel[0]


def test_paging_never_lands_on_a_folded_row(mod):
    """The step is measured in selectable positions, not rows, so a folded
    list pages over the hidden rows instead of into them."""
    rows = mod.build_rows()
    page = mod.viewport_rows(_FakeScreen(24, 80))
    for header_idx in _header_indices(mod, rows)[::2]:
        rows[header_idx]["collapsed"] = True
    vis = mod.visible_indices(rows)
    sel = mod.selectable_indices(rows)

    cursor_idx = sel[0]
    for _ in range(len(sel) + 4):
        cursor_idx = _page(mod, rows, cursor_idx, page)
        assert cursor_idx in sel and cursor_idx in vis
    assert cursor_idx == sel[-1]
    for _ in range(len(sel) + 4):
        cursor_idx = _page(mod, rows, cursor_idx, -page)
        assert cursor_idx in sel and cursor_idx in vis
    assert cursor_idx == sel[0]


def test_paging_stays_inside_the_match_set_while_filtered(mod):
    rows = mod.build_rows()
    page = mod.viewport_rows(_FakeScreen(24, 80))
    sel = mod.selectable_indices(rows, FILTER_NEEDLE)
    assert len(sel) <= page  # the whole match set fits on one screen

    cursor_idx = _page(mod, rows, sel[0], page, FILTER_NEEDLE)
    assert cursor_idx == sel[-1]
    assert _page(mod, rows, cursor_idx, -page, FILTER_NEEDLE) == sel[0]


def test_paging_an_empty_match_set_is_a_no_op(mod):
    """A filter matching nothing leaves the cursor on no row; main() guards
    the branch with `and sel`, so paging there must not raise."""
    rows = mod.build_rows()
    assert _page(mod, rows, -1, 18, "no such setting") == -1
    assert _page(mod, rows, -1, -18, "no such setting") == -1


def test_paging_from_a_row_the_fold_just_hid(mod):
    """Fold the section under the cursor, then page: main() re-resolves
    against the new selectable list before stepping, so the stale row index
    must not survive into the result."""
    rows = mod.build_rows()
    page = mod.viewport_rows(_FakeScreen(24, 80))
    header_idx = _header_index(mod, rows, "Privacy & Security")
    start, end = mod.header_span(rows, header_idx)
    stale = start + 3

    rows[header_idx]["collapsed"] = True
    sel = mod.selectable_indices(rows)
    for step in (page, -page):
        landed = _page(mod, rows, stale, step)
        assert landed in sel
        assert not start <= landed < end


# ---------------------------------------------------------------------------
# The cursor invariant
#
# Every fold and every filter keystroke can delete the row the cursor was
# sitting on. Rather than one test per way of doing that, walk a long
# pseudo-random sequence of the operations main() binds and assert after
# each one that the cursor still points at a row the list actually paints.
# ---------------------------------------------------------------------------

NEEDLES = ["", "block", "brave", "notification", "disable", "no such setting"]


def _owning_header(mod, rows, idx):
    """Return the index of the header the row at `idx` belongs to."""
    return max(i for i in _header_indices(mod, rows) if i <= idx)


def _assert_cursor_is_landed(mod, rows, cursor_idx, filter_text, trail):
    """Resolve the cursor the way main() does, then check where it landed."""
    vis = mod.visible_indices(rows, filter_text)
    sel = mod.selectable_indices(rows, filter_text)
    cursor_pos, cursor_idx = mod.resolve_cursor(sel, cursor_idx)
    if not sel:
        assert cursor_idx == -1, trail
        assert vis == [], trail
        return cursor_idx

    assert cursor_idx in sel, trail
    assert cursor_idx in vis, trail
    assert sel[cursor_pos] == cursor_idx, trail
    assert rows[cursor_idx]["type"] in mod.SELECTABLE_TYPES, trail
    if not filter_text.strip():
        # Unfiltered, a fold is the only thing that can hide a row, and no
        # header is ever hidden by its own fold.
        header_idx = _owning_header(mod, rows, cursor_idx)
        assert (header_idx == cursor_idx
                or not rows[header_idx]["collapsed"]), trail

    # The viewport offset has to stay inside the visible list too, or draw()
    # paints past the end of it. Both a wildly high and a negative offset
    # come back in range.
    visible_count = mod.viewport_rows(_FakeScreen(24, 80))
    cursor_vpos = vis.index(cursor_idx)
    ceiling = max(0, len(vis) - visible_count)
    for offset in (len(rows) * 2, -5):
        clamped = mod.clamp_scroll(rows, vis, offset, cursor_vpos,
                                   visible_count)
        assert 0 <= clamped <= ceiling, trail
    return cursor_idx


# Whatever the seed goes on to do, the walk opens with these, so the
# states worth reaching are reached on every run: everything folded, a
# search that matches nothing, and a search that has to reach inside the
# folds. Written in the same "op" vocabulary the random half draws from.
SCRIPTED_OPS = [
    "fold_all",
    "filter:no such setting",
    "end",
    "page_down",
    "filter:block",
    "end",
    "toggle_row",
    "clear_filter",
    "home",
]


@pytest.mark.parametrize("seed", range(6))
def test_cursor_always_lands_on_a_visible_selectable_row(mod, seed):
    """Property-style: a scripted prefix then 120 random fold/filter/move
    operations, with the invariant checked after each one. `trail` names
    the sequence that broke it, so a failure reproduces without the seed."""
    rng = random.Random(seed)
    rows = mod.build_rows()
    filter_text = ""
    cursor_idx = mod.selectable_indices(rows)[0]
    page = mod.viewport_rows(_FakeScreen(24, 80))
    trail = []

    random_ops = []
    for _ in range(120):
        op = rng.choice([
            "fold_all", "toggle_header", "filter", "clear_filter",
            "up", "down", "page_up", "page_down", "home", "end", "toggle_row",
        ])
        if op == "toggle_header":
            op = f"toggle_header:{rng.randrange(len(_header_indices(mod, rows)))}"
        elif op == "filter":
            op = f"filter:{rng.choice(NEEDLES)}"
        random_ops.append(op)

    for op in SCRIPTED_OPS + random_ops:
        sel = mod.selectable_indices(rows, filter_text)
        cursor_pos, cursor_idx = mod.resolve_cursor(sel, cursor_idx)

        if op == "fold_all":
            _fold_all(mod, rows)
        elif op.startswith("toggle_header:"):
            header_idx = _header_indices(mod, rows)[int(op.split(":", 1)[1])]
            rows[header_idx]["collapsed"] = \
                not rows[header_idx].get("collapsed", False)
        elif op.startswith("filter:"):
            filter_text = op.split(":", 1)[1]
        elif op == "clear_filter":
            filter_text = ""
        elif op == "up" and sel:
            cursor_idx = sel[max(0, cursor_pos - 1)]
        elif op == "down" and sel:
            cursor_idx = sel[min(len(sel) - 1, cursor_pos + 1)]
        elif op == "page_up":
            cursor_idx = _page(mod, rows, cursor_idx, -page, filter_text)
        elif op == "page_down":
            cursor_idx = _page(mod, rows, cursor_idx, page, filter_text)
        elif op == "home" and sel:
            cursor_idx = sel[0]
        elif op == "end" and sel:
            cursor_idx = sel[-1]
        elif op == "toggle_row" and cursor_idx >= 0:
            row = rows[cursor_idx]
            if row["type"] == mod.ROW_HEADER:
                row["collapsed"] = not row.get("collapsed", False)
            elif row["type"] == mod.ROW_FEATURE:
                mod.toggle_feature_row(rows, row)
            elif row["type"] == mod.ROW_CHOICE:
                mod.cycle_choice_row(row, 1)

        trail.append(op)
        cursor_idx = _assert_cursor_is_landed(
            mod, rows, cursor_idx, filter_text, " -> ".join(trail))

    # The walk has to have actually reached the interesting states, or the
    # invariant above was checked against a list that never moved.
    assert "fold_all" in trail, trail
    assert "filter:no such setting" in trail, trail
    assert "filter:block" in trail, trail
    assert len(trail) == len(SCRIPTED_OPS) + 120


@pytest.mark.parametrize("seed", range(6))
def test_header_counts_survive_the_same_walk(mod, seed):
    """The same shape of walk, asserting the counters rather than the
    cursor: folding a section must not change what it reports as on."""
    rng = random.Random(seed)
    rows = mod.build_rows()
    togglable = [row for row in rows
                 if row["type"] in (mod.ROW_FEATURE, mod.ROW_CHOICE)]
    for _ in range(60):
        row = rng.choice(togglable)
        if row["type"] == mod.ROW_FEATURE:
            mod.toggle_feature_row(rows, row)
        else:
            mod.cycle_choice_row(row, rng.choice([-1, 1]))
        for header_idx in _header_indices(mod, rows):
            rows[header_idx]["collapsed"] = bool(rng.getrandbits(1))
        for header_idx in _header_indices(mod, rows):
            assert mod.header_counts(rows, header_idx) == \
                _expected_counts(mod, rows, header_idx)


# ---------------------------------------------------------------------------
# Startup fold state is derived from what is already applied
# ---------------------------------------------------------------------------


def _open_sections(mod, rows):
    return [row["text"] for row in rows
            if row["type"] == mod.ROW_HEADER and not row["collapsed"]]


def test_startup_collapse_folds_everything_on_a_clean_machine(mod):
    """Nothing managed -> a short overview rather than an 87-row list."""
    rows = mod.build_rows()
    mod.apply_startup_collapse(rows)
    assert _open_sections(mod, rows) == []


def test_startup_collapse_opens_only_sections_in_use(mod):
    """A configured machine opens on exactly what it has applied."""
    rows = mod.build_rows()
    target = next(row for row in rows
                  if row["type"] == mod.ROW_FEATURE
                  and row["key"] == "BraveRewardsDisabled")
    target["checked"] = True
    mod.apply_startup_collapse(rows)
    assert _open_sections(mod, rows) == ["Brave Features"]


def test_startup_collapse_counts_managed_choice_rows(mod):
    """A tri-state row off "Not managed" keeps its section open."""
    rows = mod.build_rows()
    choice = next(row for row in rows if row["type"] == mod.ROW_CHOICE)
    choice["selected"] = 2
    mod.apply_startup_collapse(rows)
    assert _open_sections(mod, rows) == ["Site Permissions"]


def test_startup_collapse_judges_dns_by_mode(mod):
    """The DNS header owns no countable rows, so it keys off the mode."""
    rows = mod.build_rows()
    dns = next(row for row in rows if row["type"] == mod.ROW_DNS)
    dns["selected"] = dns["options"].index("automatic")
    mod.apply_startup_collapse(rows)
    assert _open_sections(mod, rows) == ["DNS Over HTTPS"]


def test_startup_collapse_leaves_every_selectable_row_visible(mod):
    """The cursor must never start on a row the fold just hid."""
    rows = mod.build_rows()
    mod.apply_startup_collapse(rows)
    visible = mod.visible_indices(rows)
    selectable = mod.selectable_indices(rows)
    assert selectable
    assert all(idx in visible for idx in selectable)


# ---------------------------------------------------------------------------
# Windows GUI: panel content must fit beside the vertical scrollbar
# ---------------------------------------------------------------------------


def test_ps1_row_control_columns_do_not_collide():
    """The interface's row geometry must stay internally consistent.

    Every control in a settings row is placed from a script-scope constant.
    They are independent numbers, so nothing but this stops an edit to one
    from overlapping another - which is how the expander chevron ended up
    under the "Not managed" hint during development. Bounds are checked
    against the row width rather than eyeballed, because a collision is
    invisible in a diff and obvious only on screen.
    """
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")

    # Constants are 96-DPI design pixels, written either bare or as `S n`
    # (the display-scale helper, which is the identity at 100%). The
    # relations below hold in design units whichever way they are spelt.
    def const(name):
        m = re.search(r"^\$script:" + name + r"\s*=\s*(?:S\s+)?(\d+)", text, re.MULTILINE)
        assert m, f"layout constant {name} is missing from SlimBrave.ps1"
        return int(m.group(1))

    m = re.search(
        r"\$p\.Size=New-Object System\.Drawing\.Size (?:\(S (\d+)\)|(\d+)),\$script:COLLAPSED", text
    )
    assert m, "the settings-row width is no longer declared where this test looks"
    row_w = int(m.group(1) or m.group(2))

    exp_x, exp_choice = const("EXP_X"), const("EXP_X_CHOICE")
    dd_x, dd_w = const("DD_X"), const("DD_W")
    tg_x, tg_w = const("TG_X"), const("TG_W")
    chevron_w = 26

    assert dd_x + dd_w <= row_w, "the dropdown runs past the row"
    assert tg_x + tg_w <= row_w, "the toggle runs past the row"
    # a chevron must clear the control to its right on its own row type
    assert exp_choice + chevron_w <= dd_x, "the expander overlaps the dropdown"
    assert exp_x + chevron_w <= tg_x, "the expander overlaps the toggle"


# ---------------------------------------------------------------------------
# Windows GUI: the action bar must survive display scaling
# ---------------------------------------------------------------------------


def test_ps1_action_bar_row_is_right_anchored_and_status_is_bounded():
    """Issue #20. The bar is a fixed 930 px wide, but every button takes its
    width from its rendered label and the fonts are in points, so the row
    grows with display scaling. Packed left-to-right from a hardcoded x it
    ran off the form above 100%, and the status text - drawn with no width
    bound - ran under the buttons and showed through the gaps between them.

    The row overrun never shows at 100% and neither defect shows in a diff,
    so pin the RELATIONS that fix them rather than the spelling of any one
    line: the running x starts at the bar's right edge, a button is placed
    only after its width is subtracted, the specs are walked last-first so
    Apply Settings lands rightmost, and the status paint takes its budget
    from wherever the leftmost button actually landed and trims on a word
    boundary with the full text in a tooltip. The as-written predecessor of
    this test passed three one-line breakages that reintroduced the defects.
    """
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")

    def const(name):  # same shape as the row-geometry test above
        m = re.search(r"^\$script:" + name + r"\s*=\s*(?:S\s+)?(\d+)", text, re.MULTILINE)
        assert m, f"layout constant {name} is missing from SlimBrave.ps1"
        return int(m.group(1))

    assert const("BAR_PAD") > 0 and const("BAR_GAP") > 0

    m = re.search(r"^# -+ action bar\n(.*?)^# -+ rows", text, re.MULTILINE | re.DOTALL)
    assert m, "the action-bar section is no longer delimited where this test looks"
    bar = m.group(1)

    # Pin the RELATIONS, not the spelling of the locals: renaming $bx or
    # $specs is behaviour-preserving and used to fail this test with a message
    # ("no longer starts from the bar's right edge") that was simply untrue.
    m = re.search(r"^(\$\w+)\s*=\s*\$bar\.Width\s*-\s*\$script:BAR_PAD", bar, re.M)
    assert m, "the button row no longer starts from the bar's right edge"
    bx = re.escape(m.group(1))
    assert not re.search(r"^\$\w+\s*=\s*\d+\s*$", bar, re.M), (
        "the button row is packed from a fixed x again"
    )
    assert re.search(r"for\s*\(\s*\$\w+\s*=\s*\$\w+\.Count\s*-\s*1\s*;.*--\s*\)", bar), (
        "the specs are not walked last-first, so Apply Settings would not land rightmost"
    )
    # a newline may separate the two statements as well as a semicolon
    assert re.search(rf"{bx}\s*-=\s*\$\w+\.Width\s*;?\s*\$\w+\.Left\s*=\s*{bx}", bar), (
        "a button is placed before its width is subtracted, so the row overruns the bar"
    )
    assert re.search(rf"^\$script:barButtonsLeft\s*=\s*{bx}\s*\+\s*\$script:BAR_GAP", bar, re.M), (
        "the leftmost button's x is not recorded where the row is built"
    )

    m = re.search(r"\$bar\.Add_Paint\((.*?)^function Set-Status", bar, re.M | re.S)
    assert m, "the bar's Paint handler is no longer where this test looks"
    paint = m.group(1)
    assert re.search(
        r"\$room\s*=\s*\$script:barButtonsLeft\s*-\s*\(\s*2\s*\*\s*\$script:BAR_PAD\s*\)", paint
    ), "the status budget is not the room before the leftmost button, minus padding both sides"
    assert "EllipsisWord" in paint, "the status text is not trimmed on a word boundary"
    assert re.search(r"\$script:barTip\.SetToolTip\(", paint), (
        "a truncated status has no tooltip carrying the full text"
    )
    assert re.search(r"if\s*\(\s*\$room\s*-gt\s*0\s*\)\s*\{[^}]*DrawString", paint), (
        "the status is drawn even when there is no room for it"
    )


# ---------------------------------------------------------------------------
# Hazards the Fluent review uncovered
# ---------------------------------------------------------------------------


def test_ps1_no_function_is_defined_twice():
    """PowerShell silently binds the LATER of two same-named function
    definitions. The prototype engine survived graduation as a full second
    copy of four functions, dead at runtime - while every grep-based test in
    this file still matched it. A guard removed from the live copy would have
    passed as long as the dead copy kept it."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    names = re.findall(r"^function\s+([A-Za-z][\w-]*)", text, re.MULTILINE)
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"defined more than once (later definition wins silently): {dupes}"


def test_ps1_user_scope_registry_path_is_sid_aware():
    """Under over-the-shoulder UAC the elevated process's HKCU is the approving
    admin's hive. The invoking user's hive is addressed by SID under
    HKEY_USERS instead. 94a736a restored the $OriginalSid parameter but the
    live $script:userReg still hard-coded HKCU - only the dead engine used the
    SID-aware path. Pin both halves."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    assert re.search(r"^\s*\[string\]\s*\$OriginalSid", text, re.MULTILINE), (
        "$OriginalSid is not a parameter"
    )
    assert re.search(r"HKEY_USERS\\\$OriginalSid\\", text), "no SID-addressed user hive path"
    assert re.search(r"^\$script:userReg\s*=\s*\$userRegistryPath", text, re.MULTILINE), (
        "$script:userReg is not derived from the SID-aware $userRegistryPath"
    )
    assert not re.search(r"^\$script:userReg\s*=\s*\"HKCU:", text, re.MULTILINE), (
        "$script:userReg hard-codes HKCU again"
    )


def _ps1_function(text, name):
    """One PS1 function's text, from its definition to the next one."""
    m = re.search(rf"^function {re.escape(name)}\b", text, re.MULTILINE)
    assert m, f"function {name} is missing from SlimBrave.ps1"
    nxt = re.search(r"^function ", text[m.end():], re.MULTILINE)
    return text[m.start():m.end() + nxt.start()] if nxt else text[m.start():]


def test_ps1_prefs_repair_stays_in_the_invoking_account_and_skips_links():
    """The elevated scrub used to walk every account in ProfileList and
    follow any junction through a fixed temp name, so a standard user on a
    shared PC could aim the admin's write anywhere. It now covers the
    invoking account only, checks every path component for a reparse point
    before the read and again before the rename, and writes through a fresh
    random CreateNew file."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    assert "ProfileList" not in _ps1_function(text, "Get-UserAppDataRoots")
    assert "ReparsePoint" in _ps1_function(text, "Test-NoReparsePoint")
    one = re.sub(r"(?m)^\s*#.*$", "", _ps1_function(text, "Repair-OneBravePrefs"))
    assert "CreateNew" in one
    assert one.count("Test-NoReparsePoint") == 2
    assert "$pref.slimbrave-tmp" not in one
    user_root = _ps1_function(text, "Repair-OneUserRoot")
    assert re.search(r"Repair-OneBravePrefs\s+\(Join-Path[^)]*\)\s+\$localAppData", user_root), (
        "Repair-OneUserRoot does not pass its root to Repair-OneBravePrefs")
    assert "user profiles on this PC" not in text


def test_ps1_row_mousedown_uses_zone_of_for_the_expander():
    """The expander click used a bare rectangle that ignored whether the row
    has a chevron, so empty row space toggled rows with no expander. Click,
    hover and highlight must share the one resolver, Zone-Of."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    start = text.index("function New-FluentRow")
    body = text[start:text.index("\n}\n", start)]
    md = body[body.index("Add_MouseDown"):]
    assert re.search(r"\$zone\s*=\s*Zone-Of \$s \$ev\.X \$ev\.Y", md), (
        "MouseDown does not resolve the zone through Zone-Of"
    )
    assert not re.search(r"\$ev\.Y\s*-le\s*\(?S?\s*50", md), (
        "the expander is hit-tested with a bare rectangle again"
    )
    z = md.find("Zone-Of $s $ev.X $ev.Y")
    e = md.find('"exp"')
    assert 0 <= z < e, "MouseDown does not resolve the zone before testing for the expander"


# ---------------------------------------------------------------------------
# Windows GUI: every layout number is a 96-DPI design pixel and goes through S()
# ---------------------------------------------------------------------------
#
# The process is per-monitor DPI aware, so Windows lays the window out at the
# literal pixel sizes while the point-size fonts grow with the display. The
# grid therefore scales itself: S() maps a design pixel to a device pixel and
# every layout literal in the GUI is wrapped in it. S() is the identity at
# 100%, which is exactly the hazard - a literal that escapes the wrap is
# invisible on the developer's screen and shows up only as a collision at
# 125% and above. These two tests are the mechanical half of the discipline.


def _gui_text():
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    return text[text.index("$form = New-Object System.Windows.Forms.Form") :]


def _strip_parens(s):
    """Drop every parenthesised group, innermost first, so `(S 18)` and
    arithmetic such as `($s.Width-1)` vanish and only bare tokens remain.

    Known gap: a bare literal inside arithmetic, `($script:COLLAPSED+776)`,
    vanishes with it. No constructor in the file does that today, and keeping
    the 1 px hairline insets and the placement math exempt matters more."""
    while True:
        new = re.sub(r"\([^()]*\)", "", s)
        if new == s:
            return s
        s = new


def test_ps1_gui_constructors_take_no_bare_pixel_literal():
    """Every Point / Size / RectangleF built from the form onward must be made
    of S() calls, script-scope constants (themselves S'd once at definition)
    or values derived from them. Zero is exempt; the 1 and 2 px hairline
    insets live inside parentheses and are stripped with everything else."""
    bad = []
    for m in re.finditer(r"New-Object System\.Drawing\.(?:Point|Size|RectangleF) ([^\r\n]*)", _gui_text()):
        args = _strip_parens(m.group(1).split("#")[0])
        if re.search(r"(?<![\w$.])[1-9]\d*\b", args):
            bad.append(m.group(0).strip())
    assert not bad, "bare pixel literal(s) in GUI constructors - wrap each in S():\n" + "\n".join(bad)


def test_ps1_gui_paint_calls_take_no_bare_pixel_literal():
    """The same rule for what the Paint handlers hand to GDI+: DrawString /
    DrawLine / FillEllipse / FillRectangle coordinates, Fill-Round and
    Stroke-Round radii and PointF vertices. Here the arithmetic is not
    stripped, so `($wcol-30)` fails and `($s.Width-1)` passes: exempt are
    `(S n)`, the scaled pen widths, colours, string literals, `/2` centring
    ratios and the 1 and 2 px hairline insets."""
    verbs = re.compile(
        r"\.(?:DrawString|DrawLine|DrawLines|FillEllipse|FillRectangle)\(|Fill-Round |Stroke-Round |PointF\]::new\("
    )
    bad = []
    for line in _gui_text().splitlines():
        if not verbs.search(line):
            continue
        s = line.split("#")[0]
        s = re.sub(r'"[^"]*"', '""', s)
        s = re.sub(r"\(S [\d.]+\)", "", s)
        s = re.sub(r"\[float\]\([^()]*\$script:DPI\)", "", s)
        s = re.sub(r"FromArgb\([^()]*\)", "", s)
        if re.search(r"(?<![\w$.*/])(?:[3-9]|[1-9]\d+)\b", s):
            bad.append(line.strip())
    assert not bad, "bare pixel literal(s) in GUI paint calls - wrap each in S():\n" + "\n".join(bad)


def test_ps1_dark_title_bar_is_actually_requested():
    """DwmSetWindowAttribute was declared in the DPI block and never called,
    so the dark UI opened under Windows' light title bar. Same class as the
    ownership guard that was defined and never used: pin the call."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    live = re.sub(r"(?m)^\s*#.*$", "", text)   # a commented-out call is not a call
    calls = re.findall(r"::DwmSetWindowAttribute\(", live)
    assert len(calls) >= 1, "DwmSetWindowAttribute is declared but never called"
    assert "Add_HandleCreated" in text, "the dark-mode attribute must be set once the handle exists"


def test_ps1_gui_fonts_follow_the_layout_factor():
    """Fonts are built through New-UiFont in pixel units from $script:DPI, so
    that when the factor is clamped to the screen width the glyphs shrink
    with the grid. A point-unit font in the GUI region would outgrow its row
    on exactly the screens the clamp exists for."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    body = text[text.index("function New-UiFont"):]
    body = body[:body.index("\n}\n")]
    gui = text[text.index("$form = New-Object System.Windows.Forms.Form"):]
    assert "GraphicsUnit]::Pixel" in body and "$script:DPI" in body, (
        "New-UiFont no longer builds pixel-unit fonts from the layout factor"
    )
    outside = gui.replace(body, "")   # New-UiFont itself is where a Font is built
    assert not re.search(r"New-Object System\.Drawing\.Font\b", outside), (
        "a GUI font is built directly, bypassing the factor"
    )
    assert re.search(r"if\(\$fitDpi -lt \$script:DPI\)\{\s*\$script:DPI=", text), (
        "the width-factor clamp is missing or disabled"
    )
    assert text.index("$fitDpi") < text.index("$clientH=[math]::Max"), (
        "the factor must be clamped before the first S() call"
    )


def test_ps1_status_bar_grows_to_its_message_instead_of_hiding_it():
    """After Apply, the sentence telling the user to close Brave so leaked
    prefs can be cleared used to end up as "..." with the rest behind a
    hover. Critical text must be visible without a mouse: Set-Status sizes
    the bar from the measured line count (up to a cap), re-centres the
    buttons and gives the page the remainder, and the note that needs acting
    on leads the message."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    start = text.index("function Set-Status(")
    body = text[start:text.index("\n}\n", start)]
    assert "MeasureString" in body and "[ref]$nl" in body, "Set-Status does not measure the message's lines"
    live = re.sub(r"(?m)^\s*#.*$", "", body)   # a commented-out assignment is not one
    assert re.search(r"\$bar\.Height\s*=\s*\$need", live), "Set-Status does not resize the bar"
    assert re.search(r"\$page\.Height\s*=", body), "the page does not yield the bar's extra height"
    assert re.search(r"\$c\.Top\s*=", body), "buttons are not re-centred in a taller bar"
    assert re.search(r"^\$script:BAR_MAX_LINES\s*=\s*[3-6]\s*$", text, re.MULTILINE), "no sane line cap"

    js = text[text.index("function Join-Status("):]
    js = js[:js.index("\n}\n")]
    assert re.search(r"if\s*\(\s*\$repair\.Skipped\s*\)\s*\{\s*return\s+\"\$n \$lead\"", js), (
        "the skipped-repair note does not lead the message"
    )


def test_ps1_search_word_set_is_not_a_hashtable():
    """PowerShell resolves $table.Keys to the entry named "keys" when the
    table has one - and "registry keys" is in several descriptions - so the
    word set came back as $true and Test-SearchHit threw on every keystroke.
    The set must be a HashSet, and nothing may read .Keys off it."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    start = text.index("function Get-SearchWords(")
    words = text[start:text.index("\n}\n", start)]
    assert "HashSet[string]" in words, "the search word set is not a HashSet"
    assert re.search(r"return\s+,\$out", words), "the HashSet is unrolled on return (needs the unary comma)"
    start = text.index("function Test-SearchHit(")
    hit = text[start:text.index("\n}\n", start)]
    assert ".Keys" not in hit and "ContainsKey" not in hit, "Test-SearchHit still treats the word set as a hashtable"


# ---------------------------------------------------------------------------
# Engine guards the GUI rewrite dropped once already
# ---------------------------------------------------------------------------


def test_ps1_engine_guards_are_wired_not_merely_defined():
    """94a736a restored four guards main had and the rewrite lost, and its own
    message says they were lost because no test covered these paths. That is
    still the risk: each of these is a call site, not a definition."""
    text = re.sub(r"(?m)^\s*#.*$", "", (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8"))

    apply_body = text[text.index("function Invoke-ApplyPolicy"):text.index("function Invoke-ResetPolicy")]
    reset_body = text[text.index("function Invoke-ResetPolicy"):]
    reset_body = reset_body[:reset_body.index("\n}\n")]
    for name, body in (("Apply", apply_body), ("Reset", reset_body)):
        assert "Remove-OwnedListPolicy" in body, (
            f"{name} deletes list policies without the ownership guard"
        )

    assert re.search(r"^\$script:userReg\s*=\s*\$userRegistryPath", text, re.MULTILINE), (
        "the user hive is not the SID-aware one"
    )

    imp = text[text.index("function Import-PresetIntoState"):]
    imp = imp[:imp.index("\n}\n")]
    assert "Compare-Object" in imp, "Import stages a list row without comparing its value"
    assert "Enforce-ExclusionGroups" in imp, "Import can stage two members of one exclusion group"

    sync = text[text.index("function Sync-FromRegistry"):]
    sync = sync[:sync.index("\n}\n")]
    assert "Enforce-ExclusionGroups" in sync, "Re-sync can stage two members of one exclusion group"

    relaunch = text[text.index("$relaunchArgs"):]
    relaunch = relaunch[:relaunch.index("Start-Process")]
    assert '`"$($script:selfPath)`"' in relaunch, "the relaunch path is unquoted again"

    # Apply's removal loop skips a scope that does not exist, as Reset's
    # does, so an absent user key is not reported as a list left alone.
    assert re.search(
        r"foreach \(\$scope in @\(\$script:machineReg, \$script:userReg\)\) \{\s*"
        r"if \(-not \(Test-Path \$scope\)\) \{ continue \}\s*"
        r"if \(-not \(Remove-OwnedListPolicy \$scope \$key \$declaredLists\)\)", apply_body), (
        "Apply's removal loop does not skip an absent scope")
    # A ticked list's user-scope copy goes under the ownership test too.
    assert "Remove-ListPolicy $script:userReg" not in apply_body
    assert "[void](Remove-OwnedListPolicy $script:userReg $f.Key $declaredLists)" in apply_body
    # Ownership checks the JSON-string form as well as the subkey.
    exact = _ps1_function(text, "Test-ListPolicyIsExactly")
    assert re.search(r"try \{ \$parsed = ConvertFrom-Json -InputObject \$raw -ErrorAction Stop \}"
                     r" catch \{ return \$false \}", exact), "the JSON-string form is not parsed inside a try"
    assert "@(ConvertFrom-Json" not in exact and "| ConvertFrom-Json)" not in exact
    assert exact.index("ConvertFrom-Json") < exact.index("Join-Path $RegistryPath $Name")
    # Provider errors do not throw by themselves: each write says Stop.
    set_list = _ps1_function(text, "Set-ListPolicy")
    for verb in ("Remove-Item -Path $listKey", "New-Item -Path $listKey", "Set-ItemProperty -Path $listKey"):
        line = next(ln for ln in set_list.splitlines() if verb in ln)
        assert "-ErrorAction Stop" in line, f"Set-ListPolicy: {verb} does not stop on failure"
    assert re.search(r"Set-ItemProperty -Path \$script:machineReg -Name \$f\.Key `\s*\n\s*-Value [^\n]*"
                     r"-ErrorAction Stop", apply_body), "Apply's scalar write does not stop on failure"
    assert re.search(r'Set-ItemProperty -Path \$script:machineReg -Name "DnsOverHttpsMode" '
                     r'[^\n]*-ErrorAction Stop', apply_body), "the DNS mode write does not stop on failure"
    assert re.search(r'Set-ItemProperty -Path \$script:machineReg -Name "DnsOverHttpsTemplates" `\s*\n'
                     r'\s*-Value [^\n]*-ErrorAction Stop', apply_body), "the template write does not stop on failure"
    prefs = _ps1_function(text, "Repair-OneBravePrefs")
    assert re.search(r"Move-Item [^\n]*-ErrorAction Stop", prefs)
    assert "catch { }" not in apply_body, "Apply swallows a failed write"
    assert "$failed += $key" in apply_body and "$failed += 'DnsOverHttpsMode'" in apply_body
    failed_at = apply_body.index("if ($failed.Count -gt 0)")
    assert "Failed to write: " in apply_body[failed_at:]
    assert "return $false" in apply_body[failed_at:apply_body.index("$lead = ", failed_at)], (
        "Apply marks a failed write as applied")
    assert not re.search(r"\$ErrorActionPreference\s*=", text), (
        "$ErrorActionPreference is set; Repair-BravePrefs would inherit it")


def test_ps1_legacy_array_import_takes_the_first_row_per_key():
    """Several policy keys carry two rows with opposite values (Force vs
    Disable Incognito, the two Variations rows, the two Referrers rows). The
    legacy-array branch guarded against staging both by testing the row's own
    state - which the function had just cleared, so it never fired."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    imp = text[text.index("function Import-PresetIntoState"):]
    imp = imp[:imp.index("\n}\n")]
    branch = imp[imp.index("$feat -is [array]"):]
    assert "$handled" in branch, "the legacy-array branch has no handled-keys set"
    assert re.search(r"\$handled\.ContainsKey\(\$row\.key\)", branch), (
        "the first-row-per-key guard does not key on $row.key"
    )


def _ps1_live():
    """SlimBrave.ps1 with whole-line comments removed."""
    return re.sub(r"(?m)^\s*#.*$", "", (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8"))


def test_ps1_import_applies_the_python_rules():
    """The import rules the Python tests above pin, in SlimBrave.ps1, which
    nothing here can run: the later row of a group wins and is named,
    Features must be an object or an array, a value is taken only in its
    policy's JSON type with nothing cast, the file is read as UTF-8, and a
    failed import puts the staged state back."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    live = _ps1_live()

    groups = _ps1_function(live, "Enforce-ExclusionGroups")
    assert "[array]::Reverse($rows)" in groups and "foreach ($row in $rows)" in groups
    assert "First row of a group wins" not in text
    assert "$script:importConflicts += $row.key" in groups
    # An array before anything appends: += onto $null joins strings.
    init = re.search(r"^\$script:importConflicts = @\(\)$", live, re.MULTILINE)
    assert init and init.start() < live.index("Sync-FromRegistry }"), (
        "$script:importConflicts is not an array before the first Re-sync")

    imp = _ps1_function(live, "Import-PresetIntoState")
    assert "$script:importConflicts = @()" in imp
    assert "[int]$want" not in imp, "the choice import casts, and a [long] past Int32 throws"
    assert "$ok = ($want -is [int] -or $want -is [long])" in imp
    assert "[double]" not in imp and "[byte]" not in imp
    # An unmatched choice (an off-enum value such as Notifications' 3) is named.
    assert 'if (-not $matched) { $script:importNotes += "$($row.key)=$want" }' in imp
    assert "$fits = ($want -is [array])" in imp
    assert "if ($fits -and $wantList.Count -eq $mine.Count -and" in imp
    assert "$fits = ($want -is [string])" in imp
    assert "$script:intEnumKeys -contains $row.key" in imp
    assert "$fits = (($want -is [bool]) -or ($want -is [int]) -or ($want -is [long]))" in imp
    assert 'if (-not $fits) {\n                $script:importNotes += "$($row.key)=$want"' in imp

    handler = live[live.index('"Import" {'):]
    handler = handler[:handler.index('Set-Status "Import failed')]
    assert "[System.IO.File]::ReadAllText($dlg.FileName)" in handler
    assert "Get-Content" not in handler
    guard = handler[handler.index("if(-not ($cfg -is"):handler.index('throw "no Features block"')]
    assert "$cfg.Features -is [array]" in guard
    assert "$cfg.Features -is [System.Management.Automation.PSCustomObject]" in guard
    assert "[pscustomobject]" not in guard.lower() and "[psobject]" not in guard.lower()
    try_at = handler.index("try{")
    assert handler.index("$snap[$id]=@{On=$script:state[$id].On; Sel=$script:state[$id].Sel}") < try_at
    assert handler.index("$dnsSnap=@{Mode=$script:dnsState.Mode; Tmpl=$script:dnsState.Tmpl}") < try_at
    catch = re.search(r"\} catch \{((?:[^{}]|\{[^{}]*\})*)\}", handler[handler.index("$ok=$true"):])
    assert catch, "the Import handler has no catch after the import"
    body = catch.group(1)
    for restore in ("$script:state[$id].On=$snap[$id].On", "$script:state[$id].Sel=$snap[$id].Sel",
                    "$script:dnsState.Mode=$dnsSnap.Mode", "$script:dnsState.Tmpl=$dnsSnap.Tmpl"):
        assert restore in body, f"a failed import does not restore {restore}"
    assert body.rstrip().endswith("$ok=$false")
    assert "($script:importNotes | Sort-Object -Unique)" in handler
    assert "($script:importConflicts | Sort-Object -Unique)" in handler
    assert "mutually exclusive with another imported row" in handler


# DynamicCodeSettings is an integer enum (chrome.win only), offered by the
# PS1 alone, so no Python row can vouch for its type.
PS1_ONLY_INT_KEYS = {"DynamicCodeSettings"}


def test_ps1_int_enum_keys_are_the_python_integer_rows(mod):
    """The PS1 tables write booleans and enums alike as DWord, so its import
    learns which checkbox rows take only a JSON integer from
    $script:intEnumKeys. It must name exactly the rows whose Python value is
    an int and not a bool, or one script refuses a value another takes."""
    live = _ps1_live()
    m = re.search(r"^\$script:intEnumKeys = @\(([^)]*)\)", live, re.MULTILINE)
    assert m, "$script:intEnumKeys is missing"
    ps1 = re.findall(r"'([^']*)'", m.group(1))
    assert len(ps1) == len(set(ps1))
    py = {feat["key"] for cat in mod.CATEGORIES for feat in cat["features"]
          if "choices" not in feat and type(feat["value"]) is int}
    assert PS1_ONLY_INT_KEYS <= PLATFORM_OMITTED_KEYS
    assert set(ps1) == py | PS1_ONLY_INT_KEYS
    ps1_rows = _ps1_feature_rows()
    for key in PS1_ONLY_INT_KEYS:
        assert [v for (_, k), (v, _, _) in ps1_rows.items() if k == key] == [1], key


def _ps1_rows_in_table_order():
    """[(name, key, group)] for every PS1 feature row, in Get-AllRows order."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    # Get-AllRows walks $categories; file order is the same order only
    # while $categories lists the tables in the order they are defined.
    defined = re.findall(r"^\$(\w+Features) = @\($", text, re.MULTILINE)
    cats = text[text.index("$categories = @("):]
    listed = re.findall(r"Features = \$(\w+)", cats[:cats.index("\n)\n")])
    assert listed == defined, "$categories no longer lists the tables in file order"
    return [(m.group(1), m.group(2), m.group(4)) for m in _PS1_FEATURE_RE.finditer(text)]


def _group_members(triples):
    groups = {}
    for name, key, group in triples:
        if group:
            groups.setdefault(group, []).append((name, key))
    return groups


def test_exclusion_groups_list_their_members_in_the_same_order_everywhere(mod):
    """An import or a policy that ticks two members of a group keeps the
    later one in table order, in all three scripts. Category order differs
    between the PS1 and Python, so this is what keeps that rule in lockstep:
    every group, with its members in the same order."""
    ps1 = _group_members(_ps1_rows_in_table_order())
    py = _group_members([(f["name"], f["key"], f.get("group"))
                         for cat in mod.CATEGORIES for f in cat["features"]])
    assert ps1 == py
    # The two groups that span two keys, where the order decides what Brave
    # is left with: Force Shields On, and spell checking off altogether.
    for group, first, later in (("shields", "BraveShieldsDisabledForUrls", "BraveShieldsEnabledForUrls"),
                                ("spellcheck", "SpellCheckServiceEnabled", "SpellcheckEnabled")):
        keys = [key for _, key in ps1[group]]
        assert keys.index(first) < keys.index(later), group


def _ps1_doh_brace_pattern():
    doh = _ps1_function(_ps1_live(), "Test-DohTemplate")
    m = re.search(r"\$piece -notmatch '([^']*)'", doh)
    assert m, "Test-DohTemplate no longer checks each template's braces"
    return m.group(1)


def test_ps1_windows_fixes_are_wired():
    live = _ps1_live()
    user_root = _ps1_function(live, "Repair-OneUserRoot")
    channels = re.search(r"foreach \(\$channelDir in @\(([^)]*)\)\)", user_root)
    assert channels, "Repair-OneUserRoot has no channel list"
    for name in ("Brave-Origin", "Brave-Origin-Beta", "Brave-Origin-Nightly", "Brave-Origin-Dev"):
        assert f"'{name}'" in channels.group(1), name
    # The relaunched copy that is still not elevated stops instead of looping.
    branch = live[live.index("if (-not $isAdmin) {"):]
    assert branch.index("IsNullOrWhiteSpace($OriginalSid)") < branch.index("Start-Process")
    reader = _ps1_function(live, "Read-LivePolicy")
    assert '-notlike "PS*"' not in reader
    assert "'PSProvider')" in reader and "-cnotcontains $pr.Name" in reader
    doh = _ps1_function(live, "Test-DohTemplate")
    assert "foreach ($piece in @($v -split '\\s+' | Where-Object { $_ }))" in doh
    assert "$uri.Host -like '*slimbraveprobe*'" in doh
    assert _ps1_doh_brace_pattern() == r"^[^{}]*(\{[^{}]*\}[^{}]*)*$"


@pytest.mark.parametrize("template,ok", [
    ("https://dns.google/dns-query{?dns}", True),
    ("https://a.example/dns-query", True),
    ("https://a.example/q{?dns}", True),
    ("https://dns.google/dns-query{?dns", False),
    ("https://a.example/q}", False),
    ("https://a.example/{{dns}}", False),
])
def test_ps1_doh_brace_rule_refuses_what_chromium_refuses(template, ok):
    """Chromium rejects an unbalanced or nested brace and still sets the
    pref, which leaves secure mode with no resolver. The pattern has no
    lookaround or backreference, so Python's re reads it as .NET does."""
    assert bool(re.search(_ps1_doh_brace_pattern(), template)) is ok


def test_ps1_names_profiles_it_could_not_clean_in_the_python_words(mod):
    """All three scripts report a failed prefs scrub the same way:
    Repair-OneBravePrefs returns -1 where _scrub_one_prefs does (a file it
    cannot read, or cannot rewrite), and Get-RepairNote says what
    _scrub_failure_note says."""
    live = _ps1_live()
    one = _ps1_function(live, "Repair-OneBravePrefs")
    assert "catch { return -1 }" in one, "an unreadable Preferences is not a failure"
    assert one.count("return -1") == 3, "a failed rewrite or move is not reported"
    root = _ps1_function(live, "Repair-OneUserRoot")
    assert "catch { $n = -1 }" in root and "return @{ Removed = $removed; Failed = $failed }" in root
    prefs = _ps1_function(live, "Repair-BravePrefs")
    assert prefs.count("Failed = ") == 2
    note = _ps1_function(live, "Get-RepairNote")
    assert ('" Failed to clean $n profile$plural; check ownership of " + '
            '(@($repair.Failed.Keys) -join ", ") + "."') in note
    assert mod._scrub_failure_note({"D1": 1}) == "Failed to clean 1 profile; check ownership of D1."
    assert (mod._scrub_failure_note({"D1": 1, "D2": 2})
            == "Failed to clean 3 profiles; check ownership of D1, D2.")


def test_ps1_paint_handlers_agree_on_text_rendering():
    """Three handlers forced ClearTypeGridFit and six inherited SystemDefault,
    so the same font rendered differently in the rail than in a row. Either
    all nine choose, or none does - a split is the bug."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    blocks = re.split(r"\.Add_Paint\(\{", text)[1:]
    with_hint = sum(1 for b in blocks if "TextRenderingHint" in b[:4000])
    assert with_hint in (0, len(blocks)), (
        f"{with_hint} of {len(blocks)} Paint handlers set TextRenderingHint - "
        "text renders inconsistently between them"
    )


def test_ps1_transient_gui_objects_are_disposed():
    """Two leaks the review found: pages were detached with Controls.Clear()
    instead of disposed (~85 handles per All Options visit), and a fresh
    ContextMenuStrip was built on every dropdown click and never released."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    assert "$page.Controls.Clear()" not in text, (
        "a view builder detaches its children instead of disposing them"
    )
    assert re.search(r"while\(\$page\.Controls\.Count -gt 0\)\{ \$page\.Controls\[0\]\.Dispose\(\) \}", text), (
        "no disposing sweep in the view builders"
    )
    menus = len(re.findall(r"New-Object System\.Windows\.Forms\.ContextMenuStrip", text))
    disposes = len(re.findall(r"\$script:ddMenu\.Dispose\(\)", text))
    assert disposes == menus, f"{menus} ContextMenuStrip sites but {disposes} dispose the previous one"


def test_ps1_owner_drawn_controls_take_keyboard_focus():
    """Every interactive control is an owner-drawn Panel, which cannot take
    focus by default - so before this, nothing but the two TextBoxes was
    reachable without a mouse, a regression from the pre-Fluent GUI. Each
    factory must make its control selectable, handle KeyDown, and draw a
    focus ring; activation must go through the mouse's own handler."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    live = re.sub(r"(?m)^\s*#.*$", "", text)
    for fn in ("New-NavItem", "New-BarButton", "New-FluentRow", "New-PresetCard"):
        start = live.index(f"function {fn}(")
        body = live[start:live.index("\n}\n", start)]
        assert "Enable-Focusable" in body, f"{fn} does not make its control focusable"
        assert "Add-KeyActivation" in body, f"{fn} does not arm on KeyDown and fire on KeyUp"
        assert "Draw-FocusRing" in body, f"{fn} draws no focus indicator"
        assert re.search(r"Invoke-(MouseAt|ClickOn)", body), (
            f"{fn} activates from the keyboard through a separate path, not the mouse's"
        )
    assert "ControlStyles]::Selectable" in live, "Selectable is never set"
    # MethodInfo.Invoke on a void method returns $null and PowerShell EMITS it,
    # so an uncast Invoke inside a factory makes that factory return
    # @($null, $panel) - the bar's packing loop then dies on $btn.Left. Every
    # reflective Invoke must be [void]-cast.
    assert not re.search(r"^\s*\$script:mi\w+\.Invoke\(", live, re.M), (
        "a reflective .Invoke( is not [void]-cast and will leak $null into a factory's output"
    )
    assert re.search(r"^\$form\.KeyPreview\s*=\s*\$true", live, re.M), "the form does not see Escape"
    for i, name in enumerate(("rail", "searchHost", "page", "bar")):
        assert re.search(rf"\${name}\.TabIndex\s*=\s*{i}\b", live), f"{name} is not region {i} in Tab order"
    # Activation is armed on KeyDown and fired on KeyUp through one latch:
    # KeyDown auto-repeats while a key is held, KeyUp never does, so a held
    # Space flips a toggle once and a held Enter on Reset cannot answer its
    # own confirm box. The DNS card is the fifth control that uses it.
    act = live[live.index("function Add-KeyActivation"):]
    assert "Add_KeyDown" in act and "Add_KeyUp" in act and "Tag.Armed" in act
    assert live.count("Add-KeyActivation $") >= 5, "a control activates on KeyDown alone"
    # An exception that escapes a handler must be reported, not turned into
    # .NET's crash dialog, which ends the process with the staged changes in
    # it. A handler that runs while a PowerShell try block is active up the
    # chain is exactly what produces that dialog, so no page rebuild may sit
    # inside one: Import rebuilds after its try, not in it.
    assert "add_ThreadException" in live, "no thread-exception guard"
    imp = live[live.index('"Import" {'):]
    # The catch restores the staged state (one level of braces for its loop)
    # and ends on $ok=$false; the rebuild comes only after it.
    catch = re.search(r"\} catch \{(?:[^{}]|\{[^{}]*\})*\$ok=\$false\s*\}", imp)
    assert catch and "Refresh-View" not in imp[:catch.end()] and re.search(
        r"if\(\$ok\)\{[\s\S]*?Refresh-View", imp[catch.end():]), (
        "Import rebuilds the page inside its try block"
    )
    assert "$form.Dispose()" in live, "the form is never disposed while the script scope is alive"
    # Escape in a text box belongs to the box; closing with staged changes asks.
    assert "Add_FormClosing" in live and "Get-StateSnapshot" in live


# ---------------------------------------------------------------------------
# TUI frames and the description pane
# ---------------------------------------------------------------------------
#
# draw() sets the list, the description pane and the buttons in boxes, and
# `d` shows or hides the pane. The row arithmetic lives in layout(), which
# viewport_rows() shares with draw(); wrap_description() and describe_row()
# are pure over rows[]. The descriptions themselves are the PS1 Tips,
# copied into the Python tables so the three scripts explain a policy in
# the same words - the parity test below is what keeps them the same.

_PS1_TIP_RE = re.compile(r'Tip\s*=\s*"((?:[^"]|"")*)"')


def _ps1_tips():
    """Return {(key, value): tip} for every PS1 feature row."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    rows = list(_PS1_FEATURE_RE.finditer(text))
    tips = {}
    for i, m in enumerate(rows):
        end = rows[i + 1].start() if i + 1 < len(rows) else len(text)
        tip = _PS1_TIP_RE.search(text, m.start(), end)
        assert tip, f"PS1 row without a Tip: {m.group(1)}"
        value = _parse_ps1_value(m.group(3))
        if isinstance(value, list):
            value = tuple(value)
        tips[(m.group(2), value)] = tip.group(1).replace('""', '"')
    assert len(tips) == text.count('Key = "'), (
        "a PS1 row lost its Tip, or two rows share a key and value"
    )
    return tips


def _py_identity(feat):
    """(key, value) the way the PS1 table spells it: no bools, no lists."""
    value = feat["value"]
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, list):
        value = tuple(value)
    return (feat["key"], value)


# One script may append a platform note to a Tip - the PS1 text first, word
# for word, then its own sentence. The VPN row on Linux is the only case:
# the key is honoured on Windows and macOS and compiled out of Linux builds,
# so slimbrave-linux.py always carries the note and slimbrave-mac.py carries
# it when it runs on Linux.
PS1_DESC_SUFFIX_ALLOWED = {"slimbrave_linux": {("BraveVPNDisabled", 1)}}
if sys.platform.startswith("linux"):
    PS1_DESC_SUFFIX_ALLOWED["slimbrave_mac"] = {("BraveVPNDisabled", 1)}


def test_every_python_row_carries_the_ps1_description(mod):
    tips = _ps1_tips()
    allowed = PS1_DESC_SUFFIX_ALLOWED.get(mod.__name__, set())
    for cat in mod.CATEGORIES:
        for feat in cat["features"]:
            ident = _py_identity(feat)
            assert feat.get("desc"), f"{feat['name']} has no description"
            assert ident in tips, f"{feat['name']} {ident} has no PS1 row to take a Tip from"
            if ident in allowed:
                assert feat["desc"].startswith(tips[ident] + " ") and feat["desc"] != tips[ident], (
                    f"{feat['name']}: the platform note must follow the PS1 Tip, not replace it"
                )
            else:
                assert feat["desc"] == tips[ident], (
                    f"{feat['name']}: the description differs from the PS1 Tip"
                )


def _features(module):
    return [f for cat in module.CATEGORIES for f in cat["features"]]


@pytest.mark.parametrize("key,value", [("BackgroundModeEnabled", 0),
                                       ("NetworkServiceSandboxEnabled", 1)])
def test_the_mac_scripts_linux_only_rows_carry_their_descriptions(key, value):
    """slimbrave-mac.py adds the chrome.win / chrome.linux rows at import
    time when it runs on Linux, outside the table literal - so the parity
    test above only meets them on a Linux runner. Import the file as Linux
    on every platform, and check that the macOS copy leaves them out."""
    on_linux = _load_as("linux", "slimbrave_mac_linux", "slimbrave-mac.py")
    row = next((f for f in _features(on_linux) if f["key"] == key), None)
    assert row, f"slimbrave-mac.py on Linux has no {key} row"
    ps1_name = next(name for name, k in _ps1_feature_rows() if k == key)
    assert row["name"] == ps1_name
    assert row["desc"] == _ps1_tips()[(key, value)]
    assert not any(f["key"] == key for f in _features(MAC_DARWIN))
    # Inserted where slimbrave-linux.py lists it, so the two TUIs match.
    def keys(module):
        return [[f["key"] for f in cat["features"]] for cat in module.CATEGORIES]
    assert keys(on_linux) == keys(LINUX_MOD)


def test_dynamic_code_settings_is_offered_by_the_ps1_alone():
    """DynamicCodeSettings is chrome.win only (AUDIT.md), so SlimBrave.ps1 is
    the one script that offers it; neither Python script may grow the row,
    on any platform."""
    rows = _ps1_feature_rows()
    assert rows[("Block Dynamic Code in the Browser Process", "DynamicCodeSettings")][0] == 1
    on_linux = _load_as("linux", "slimbrave_mac_linux", "slimbrave-mac.py")
    for module in (LINUX_MOD, MAC_MOD, MAC_DARWIN, on_linux):
        assert not any(f["key"] == "DynamicCodeSettings" for f in _features(module)), (
            module.__name__)


def test_the_mac_scripts_vpn_row_says_it_does_nothing_on_linux():
    """slimbrave-mac.py relabels BraveVPNDisabled at import time when it runs
    on Linux, where the key is compiled out, and leaves it plain on macOS,
    where it works. Import the file as both, so every runner checks both."""
    def vpn(module):
        return next(f for cat in module.CATEGORIES for f in cat["features"]
                    if f["key"] == "BraveVPNDisabled")

    on_linux = vpn(_load_as("linux", "slimbrave_mac_linux", "slimbrave-mac.py"))
    linux_row = vpn(LINUX_MOD)
    assert on_linux["name"] == linux_row["name"] == "Disable Brave VPN (no effect on Linux builds)"
    assert on_linux["desc"] == linux_row["desc"]

    on_mac = vpn(MAC_DARWIN)
    ps1_name = next(name for name, key in _ps1_feature_rows() if key == "BraveVPNDisabled")
    assert on_mac["name"] == ps1_name
    assert on_mac["desc"] == _ps1_tips()[("BraveVPNDisabled", 1)]


def test_build_rows_carries_the_description_onto_every_setting_row(mod):
    for row in mod.build_rows():
        if row["type"] in (mod.ROW_FEATURE, mod.ROW_CHOICE):
            assert row["desc"], f"{row['text']} reached the TUI without its description"


def test_pane_lines_follow_the_longest_description_at_that_width(mod):
    # At 80 columns the two longest descriptions want five lines; the pane
    # stops at four and they end in an ellipsis. At 100 they still want
    # four. From about 120 columns nothing needs more than three, and the
    # list gets a row back.
    assert mod.desc_pane_lines(80) == 4
    assert mod.desc_pane_lines(100) == 4
    assert mod.desc_pane_lines(120) == 3
    assert mod.desc_pane_lines(140) == 3
    assert mod.desc_pane_lines(20) == mod.DESC_PANE_MAX_LINES


def test_layout_budgets_the_rows_and_drops_the_pane_when_cramped(mod):
    lay = mod.layout(24, 80, True)
    assert lay["framed"]
    assert (lay["list_top"], lay["list_rows"], lay["list_bottom"]) == (3, 10, 13)
    assert (lay["pane_top"], lay["pane_lines"]) == (14, 4)
    assert (lay["btn_top"], lay["btn_y"], lay["status_y"]) == (20, 21, 23)
    assert mod.layout(24, 80, False)["list_rows"] == 16
    # 17 rows leave the list 3 with the four-line pane, under the minimum
    # of 4: the pane gives way and the list keeps 9. One more row and it fits.
    assert mod.layout(17, 80, True)["pane_lines"] == 0
    assert mod.layout(17, 80, True)["list_rows"] == 9
    assert mod.layout(18, 80, True)["pane_lines"] == 4
    # Every framed screen ends on its last row: the button box's bottom
    # edge sits right above the status line.
    for max_y in range(9, 60):
        for show in (False, True):
            lay = mod.layout(max_y, 80, show)
            assert lay["framed"]
            assert lay["btn_top"] + 2 == lay["status_y"] - 1, (
                f"{max_y} rows, pane={show}: the boxes do not fill the screen"
            )
            assert lay["list_bottom"] < lay["btn_top"]
    # Under nine rows the frames go and the old stack comes back: list from
    # row 2, buttons on the second-last row, status on the last, no pane.
    for max_y in range(5, 9):
        for show in (False, True):
            lay = mod.layout(max_y, 80, show)
            assert not lay["framed"] and lay["pane_lines"] == 0
            assert lay["list_top"] == 2 and lay["list_rows"] == max(1, max_y - 5)
            assert (lay["btn_y"], lay["status_y"]) == (max_y - 2, max_y - 1)


def test_wrap_description_marks_a_cut(mod):
    text = "one two three four five six seven eight nine ten"
    assert mod.wrap_description(text, 20, 5) == [
        "one two three four", "five six seven eight", "nine ten",
    ]
    cut = mod.wrap_description(text, 20, 2, "...")
    assert len(cut) == 2 and cut[-1].endswith("...") and len(cut[-1]) <= 20
    # A resolver URL stays whole: no break at its hyphen.
    lines = mod.wrap_description("see https://dns.example/dns-query now", 30, 3)
    assert "https://dns.example/dns-query" in lines
    assert mod.wrap_description("", 20, 3) == []
    assert mod.wrap_description(text, 0, 3) == []
    assert mod.wrap_description(text, 20, 0) == []


def test_describe_row_covers_every_kind_of_row_and_the_buttons(mod):
    rows = mod.build_rows()
    for i, row in enumerate(rows):
        text = mod.describe_row(rows, i, mod.FOCUS_LIST, 0)
        assert text, f"row {row['text']!r} has nothing to say"
        if row["type"] in (mod.ROW_FEATURE, mod.ROW_CHOICE):
            assert text == row["desc"]
    for i, label in enumerate(mod.BUTTONS):
        assert mod.describe_row(rows, 0, mod.FOCUS_BUTTONS, i) == mod.BUTTON_DESC[label]
    # A filter matching nothing leaves the cursor on no row at all.
    assert mod.describe_row(rows, -1, mod.FOCUS_LIST, 0) == ""
    assert mod.describe_row(rows, len(rows), mod.FOCUS_LIST, 0) == ""
    # A header states its live count.
    hdr = _header_index(mod, rows, "Telemetry & Reporting")
    text = mod.describe_row(rows, hdr, mod.FOCUS_LIST, 0)
    on, total = mod.header_counts(rows, hdr)
    assert text.startswith(f"Telemetry & Reporting: {total} settings, {on} on")


def test_box_glyphs_fall_back_to_ascii_when_the_codec_cannot_encode_them(mod, monkeypatch):
    monkeypatch.setattr(mod, "_box_glyphs", None)
    monkeypatch.setattr(mod.locale, "getpreferredencoding", lambda do_setlocale=False: "ascii")
    assert mod.box_glyphs() == mod.BOX_ASCII
    monkeypatch.setattr(mod, "_box_glyphs", None)
    monkeypatch.setattr(mod.locale, "getpreferredencoding", lambda do_setlocale=False: "utf-8")
    assert mod.box_glyphs() == mod.BOX_UNICODE


def _call_spans(text, name):
    """Yield the source of every call to `name(...)`.

    The def line is excluded, and so is a bare `name()` - that is how a
    docstring mentions a function, never how the scripts call these.
    """
    for m in re.finditer(rf"(?<!def )\b{re.escape(name)}\(", text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        span = text[m.start():i + 1]
        if span != f"{name}()":
            yield span


def test_the_pane_flag_reaches_every_frame_and_d_toggles_it(mod):
    """A draw() or viewport_rows() call that forgets show_desc paints the
    old layout for one frame - the list jumps - so every call site passes
    it, and `d` is the key that flips it."""
    text = open(mod.__file__, encoding="utf-8").read()
    live = re.sub(r"(?m)^\s*#.*$", "", text)
    draws = list(_call_spans(live, "draw"))
    assert len(draws) >= 3, "draw() call sites went missing"
    for call in draws:
        assert "show_desc=show_desc" in call, f"a frame is drawn without the pane flag:\n{call}"
    for call in _call_spans(live, "viewport_rows"):
        assert "show_desc" in call, f"a viewport is sized without the pane flag: {call}"
    for name in ("prompt_text_input", "prompt_channel_selection", "prompt_persist_mode"):
        for call in _call_spans(live, name):
            assert "show_desc=show_desc" in call, f"{name} is called without the pane flag:\n{call}"
    assert re.search(r'^        elif key == ord\("d"\):\n            show_desc = not show_desc', live, re.M)
    assert re.search(r'^    show_desc = layout\(max_y, max_x, True\)\["pane_lines"\] > 0', live, re.M), (
        "the pane does not start shown wherever layout() finds room for it"
    )
    assert any(line.strip().startswith("d ") for line in mod.HELP_LINES), "the help overlay does not list d"
    assert "[D] Describe" in live, "the hint line does not mention the pane"
    # The DoH field width is one figure, shared by draw() and the editing keys.
    assert "max_x - 1 - 22" not in live, "a template-field width is computed by hand"
    assert live.count("template_field_width(max_x)") >= 4


def test_mac_prompt_overlay_sits_on_the_buttons_row():
    """The Apply-time overlay covers the buttons row and the status line.
    It takes both rows from layout(), inside the button box, so a moved
    box cannot leave it painting over an edge."""
    text = (ROOT / "slimbrave-mac.py").read_text(encoding="utf-8")
    start = text.index("def _draw_prompt_overlay(")
    body = text[start:text.index("\ndef ", start + 1)]
    assert 'layout(max_y, max_x, False)' in body
    assert 'lay["btn_y"]' in body and 'lay["status_y"]' in body
    assert "max_y - 3" not in body and "max_y - 2" not in body


def test_the_two_scripts_explain_the_same_things_in_the_same_words():
    """The pane's fixed texts and the help are one copy per script; they
    must not drift. macOS's Apply is the one deliberate difference: it asks
    its two questions first, and its description says so."""
    assert LINUX_MOD.DNS_DESC == MAC_MOD.DNS_DESC
    assert LINUX_MOD.HELP_LINES == MAC_MOD.HELP_LINES
    for label in LINUX_MOD.BUTTONS:
        if label != "Apply":
            assert LINUX_MOD.BUTTON_DESC[label] == MAC_MOD.BUTTON_DESC[label], label
    assert MAC_MOD.BUTTON_DESC["Apply"].startswith("Asks whether to persist")
    assert LINUX_MOD.BUTTON_DESC["Apply"].startswith("Write the selected policies")


# ---------------------------------------------------------------------------
# Rendering draw() itself
#
# Everything above is pure over rows[]; nothing renders. These two run
# main() against a window that keeps its cells, with curses swapped for a
# shim, so the frames, the pane and the tiny-terminal stack are pinned by
# what actually lands on screen.
# ---------------------------------------------------------------------------


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
    """A curses window that keeps its cells."""

    def __init__(self, lines, cols, keys=()):
        self.lines, self.cols, self.keys = lines, cols, list(keys)
        self.frames = []
        self.erase()

    def erase(self):
        self.cells = [[" "] * self.cols for _ in range(self.lines)]

    def getmaxyx(self):
        return (self.lines, self.cols)

    def addnstr(self, y, x, s, n, attr=0):
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


def _render(mod, monkeypatch, tmp_path, lines, cols, keys=(), brave_info=None,
            installations=None, override=True):
    """Drive main() on a grid screen. `override` mirrors --policy-file, the
    hermetic default; False runs the detected-installations path, with
    detect_brave() answering `brave_info` (whose installations default to
    the same tmp_path record) so nothing under /etc is ever read."""
    monkeypatch.setattr(mod, "curses", _FakeCurses())
    # locale-independent frames
    monkeypatch.setattr(mod, "_box_glyphs", mod.BOX_ASCII)
    monkeypatch.setattr(mod, "_disclosure_glyphs", mod.DISCLOSURE_ASCII)
    chan = {"id": "stable", "label": "Brave", "process_name": "brave",
            "user_data_dir": "BraveSoftware/Brave-Browser"}
    inst = mod._make_installation(chan, plist_path=str(tmp_path / "slimbrave.json"),
                                  prefs_path=str(tmp_path / "Preferences"))
    info = dict(brave_info or {"method": "", "warnings": []})
    info.setdefault("installations", installations or [inst])
    monkeypatch.setattr(mod, "detect_brave", lambda: info)
    screen = _GridScreen(lines, cols, keys)
    mod.main(screen, override_installations=(installations or [inst]) if override else None)
    return screen.frames


def test_draw_frames_the_list_the_pane_and_the_buttons_at_80x24(mod, monkeypatch, tmp_path):
    frame = _render(mod, monkeypatch, tmp_path, 24, 80)[-1]
    lay = mod.layout(24, 80, True)
    top, bottom = lay["list_top"] - 1, lay["list_bottom"]
    assert frame[top].startswith("+- Settings ") and frame[top][78] == "+"
    assert frame[bottom][0] == "+" and frame[bottom][78] == "+"
    assert set(frame[bottom][1:78]) <= {"-"}          # nothing to scroll: no marker
    first = frame[lay["list_top"]]
    assert first[0] == "|" and first[78] == "|" and "0/8 on" in first
    assert first.index("0/8 on") + len("0/8 on") <= 77   # counter inside the edge
    assert frame[lay["pane_top"]].startswith("+- Description ")
    assert frame[lay["btn_top"]][0] == "+" and frame[lay["btn_top"] + 2][0] == "+"
    assert " Import " in frame[lay["btn_y"]] and frame[lay["btn_y"]][0] == "|"
    assert frame[lay["status_y"]].strip() == ""
    # every frame stays inside the usable width: the last column is untouched
    assert all(row[79] == " " for row in frame)


@pytest.mark.parametrize("which", ["ORIGIN_NOTE_ONLY", "ORIGIN_NOTE_BESIDE"])
def test_tui_status_line_shows_the_shipped_origin_notes(mod, monkeypatch, tmp_path, which):
    note = getattr(mod, which)
    frame = _render(mod, monkeypatch, tmp_path, 24, 80, override=False, brave_info={
        "method": "arch (Brave Origin)", "warnings": [], "notes": [note]})[-1]
    lay = mod.layout(24, 80, True)
    assert frame[lay["status_y"]].strip() == note      # fits an 80-column line whole
    assert "[arch (Brave Origin)]" in frame[0]


def test_tui_policy_file_override_hides_the_origin_note(mod, monkeypatch, tmp_path):
    # The override record keeps every row live, so the note would describe
    # a list that is not on screen.
    frame = _render(mod, monkeypatch, tmp_path, 24, 80, brave_info={
        "installations": [], "method": "", "warnings": [],
        "notes": [mod.ORIGIN_NOTE_ONLY]})[-1]
    lay = mod.layout(24, 80, True)
    assert frame[lay["status_y"]].strip() == ""


def test_tui_warning_outranks_the_origin_note(mod, monkeypatch, tmp_path):
    frame = _render(mod, monkeypatch, tmp_path, 24, 80, brave_info={
        "installations": [], "method": "",
        "warnings": ["Snap confinement may prevent policies from taking effect."],
        "notes": ["Brave Origin found: policies apply."]})[-1]
    lay = mod.layout(24, 80, True)
    assert frame[lay["status_y"]].strip().startswith("Snap confinement")


def test_draw_keeps_the_old_stack_under_nine_rows(mod, monkeypatch, tmp_path):
    frame = _render(mod, monkeypatch, tmp_path, 7, 80)[-1]
    assert not any("+-" in row or row.startswith("|") for row in frame)
    assert frame[2].lstrip().startswith((">", "v"))     # the list, from row 2
    assert " Import " in frame[5] and " Quit " in frame[5]   # buttons, second-last row
    assert frame[6].strip() == ""                        # status, last row

