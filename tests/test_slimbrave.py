"""Unit tests for the pure logic shared by slimbrave-linux.py and slimbrave-mac.py.

Both scripts are loaded as modules (their entry points are guarded by
__main__) and every test runs against each, so a fix applied to one file
that is missed in the other fails loudly here. slimbrave-mac.py is loaded a
second time with sys.platform faked as Darwin, which is the only way to
reach its Configuration Profile helpers off a Mac. Nothing in this file
touches /etc, the registry, or a real Brave profile — filesystem work stays
in pytest's tmp_path.
"""

import importlib.util
import json
import os
import pathlib
import plistlib
import random
import re
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


def _load_as_darwin(alias, filename):
    """Load a module with sys.platform faked as macOS.

    slimbrave-mac.py keeps `plistlib`, `uuid` and every persistence
    constant inside an `if IS_MAC:` block, so the Configuration Profile
    helpers are unreachable when the file is imported anywhere else.
    Faking the platform for the length of the import is what makes them
    testable off a Mac; the module body only defines things.
    """
    real_platform = sys.platform
    sys.platform = "darwin"
    try:
        return _load(alias, filename)
    finally:
        sys.platform = real_platform


LINUX_MOD = _load("slimbrave_linux", "slimbrave-linux.py")
MAC_MOD = _load("slimbrave_mac", "slimbrave-mac.py")
MODULES = [LINUX_MOD, MAC_MOD]

# The macOS-flavoured copy of the same file, used only by the persistence
# tests. Everything else runs against MAC_MOD, which sees whatever the
# runner's real platform produces.
MAC_DARWIN = _load_as_darwin("slimbrave_mac_darwin", "slimbrave-mac.py")

PRESETS = sorted((ROOT / "Presets").glob("*.json"))

# Keys presets may contain that are deliberately absent on some platforms;
# the import silently skips them there. BackgroundModeEnabled has no macOS
# support in Chromium (see AUDIT.md), so the mac script doesn't expose it.
PLATFORM_OMITTED_KEYS = {"BackgroundModeEnabled"}


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


# The only group whose members sit on two different keys, so a config can
# name both and ask for force-off and force-on over the same wildcards.
SHIELDS_OFF = ("Disable Brave Shields", "BraveShieldsDisabledForUrls")
SHIELDS_ON = ("Force Shields On (All Sites)", "BraveShieldsEnabledForUrls")
SHIELDS_WILDCARDS = ["https://*", "http://*"]


@pytest.mark.parametrize("order,winner", [
    ((SHIELDS_OFF, SHIELDS_ON), SHIELDS_ON),
    ((SHIELDS_ON, SHIELDS_OFF), SHIELDS_OFF),
], ids=["off-then-on", "on-then-off"])
def test_import_collapses_conflicting_shields_rows(mod, tmp_path, order, winner):
    """Last key listed wins, matching the PS1 CheckedChanged handler."""
    cfg = _write_config(tmp_path, "both.json",
                        {key: SHIELDS_WILDCARDS for _, key in order})
    rows = mod.build_rows()
    ok, _ = mod.import_settings(rows, str(cfg))
    assert ok
    # Nothing outside the group is touched either, so compare the whole set
    checked = [row["text"] for row in rows
               if row["type"] == mod.ROW_FEATURE and row["checked"]]
    assert checked == [winner[0]]
    policy, err = mod._build_policy(rows)
    assert err == ""
    assert policy == {winner[1]: SHIELDS_WILDCARDS}


def test_import_legacy_array_collapses_shields_group(mod, tmp_path):
    cfg = _write_config(tmp_path, "legacy-both.json",
                        [SHIELDS_OFF[1], SHIELDS_ON[1]])
    rows = mod.build_rows()
    ok, _ = mod.import_settings(rows, str(cfg))
    assert ok
    assert _get_feature(mod, rows, SHIELDS_ON[0])["checked"] is True
    assert _get_feature(mod, rows, SHIELDS_OFF[0])["checked"] is False


def test_parse_imported_features_formats(mod):
    assert mod._parse_imported_features({"A": 1}) == ({"A": 1}, False)
    assert mod._parse_imported_features(["A", "B"]) == ({"A": None, "B": None}, True)
    assert mod._parse_imported_features("garbage") == ({}, False)
    assert mod._parse_imported_features(None) == ({}, False)


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


def test_allowed_policy_dir_accepts_inside_path(mod, tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setattr(mod, "ALLOWED_POLICY_DIRS", (str(allowed),))
    assert mod._is_within_allowed_policy_dir(str(allowed / "policy.json"))


def test_allowed_policy_dir_rejects_outside_path(mod, tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setattr(mod, "ALLOWED_POLICY_DIRS", (str(allowed),))
    assert not mod._is_within_allowed_policy_dir(str(tmp_path / "shadow"))
    assert not mod._is_within_allowed_policy_dir(
        str(allowed / ".." / "shadow"))
    # The allowed dir itself is not a writable target, only paths inside it
    assert not mod._is_within_allowed_policy_dir(str(allowed))


@pytest.mark.skipif(
    os.name == "nt",
    reason="symlink creation requires elevation or Developer Mode")
def test_allowed_policy_dir_rejects_symlink_escape(mod, tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "link").symlink_to(outside)
    monkeypatch.setattr(mod, "ALLOWED_POLICY_DIRS", (str(allowed),))
    assert not mod._is_within_allowed_policy_dir(
        str(allowed / "link" / "policy.json"))


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


def test_sync_rows_with_policy_collapses_conflicting_shields(mod):
    # A policy file holding both keys is exactly what the buggy import used
    # to write; reading it back must not tick both rows again.
    rows = mod.build_rows()
    mod.sync_rows_with_policy(rows, {
        SHIELDS_OFF[1]: SHIELDS_WILDCARDS,
        SHIELDS_ON[1]: SHIELDS_WILDCARDS,
    })
    assert _get_feature(mod, rows, SHIELDS_ON[0])["checked"] is True
    assert _get_feature(mod, rows, SHIELDS_OFF[0])["checked"] is False


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


# BraveVPNDisabled is labelled "(no effect on Linux builds)" in
# slimbrave-linux.py only: enable_brave_vpn omits is_linux, so brave-core
# compiles the handler out there while Windows and macOS honour it. Compare
# that row on its key alone.
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
#
# The table below is written out per key on purpose rather than sharing two
# aliases the way the scripts do: the enum is NOT uniform, and a test that
# reuses the scripts' own grouping cannot notice a key being moved into the
# wrong group. Allow (1) is a legal member of the notifications,
# geolocation and sensors enums only. For the three guard settings and for
# local fonts / window management, Chromium has no Allow state at all and
# rejects value 1 — offering it there is the trap this feature exists to
# avoid, so it gets its own assertion below.
# ---------------------------------------------------------------------------

EXPECTED_CHOICES = {
    "DefaultNotificationsSetting": [
        ("Not managed", None), ("Allow", 1), ("Ask", 3), ("Block", 2)],
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
}

# The five keys whose enum has no Allow member. Derived from the table
# above so the two can never disagree, then pinned by count.
ASK_BLOCK_ONLY_KEYS = sorted(
    key for key, choices in EXPECTED_CHOICES.items()
    if 1 not in [value for _, value in choices]
)
assert len(ASK_BLOCK_ONLY_KEYS) == 5, ASK_BLOCK_ONLY_KEYS


def _choice_rows(mod, rows):
    """Return {key: row} for every choice row."""
    return {row["key"]: row for row in rows if row["type"] == mod.ROW_CHOICE}


def _selected_label(row):
    return row["choices"][row["selected"]][0]


def test_choice_rows_are_exactly_the_documented_keys(mod):
    """A ninth choice row, or one of the eight demoted back to a checkbox,
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
    one mistake that would look plausible: Chromium rejects value 1 on
    these five keys, so a row offering it writes a policy Brave drops."""
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


# Values no choice row may accept. 1 is listed for the five Ask/Block-only
# keys specifically: it is a legal member of the *other* three enums, so a
# row that quietly shares the wrong choices list would accept it here.
# True is included because `True == 1` in Python — a JSON `true` must not
# select "Allow" on the three keys that have one.
ILLEGAL_CHOICE_CASES = (
    [(key, 1) for key in ASK_BLOCK_ONLY_KEYS]
    + [(key, bad) for key in sorted(EXPECTED_CHOICES)
       for bad in (0, 4, "2", True)]
)


@pytest.mark.parametrize(
    "key,bad", ILLEGAL_CHOICE_CASES,
    ids=[f"{key}-{bad!r}" for key, bad in ILLEGAL_CHOICE_CASES])
def test_illegal_choice_value_is_rejected_and_named(mod, tmp_path, key, bad):
    """An illegal value leaves the row unmanaged and says so.

    Writing it through would hand Brave a policy it rejects, and doing that
    silently would look identical to "not managed" in the UI.
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
    })
    choices = _choice_rows(mod, rows)
    assert choices["DefaultWebUsbGuardSetting"]["selected"] == 0
    assert _selected_label(choices["DefaultGeolocationSetting"]) == "Ask"


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
# key legitimately carries value 2 (Cap Referrers) in most presets.
FORBIDDEN_IN_PRESETS = {"Allow Permissive Referrers (unsafe-url)"}

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
# pin below was updated in the same commit. A pin change outside such a
# deliberate curation is the drift this table exists to catch.
#
# Captured by loading the v1.9.5 scripts (git tag v1.9.5) and running
# import_settings + _build_policy over the presets as they ship. The values
# below are the Linux module's output; the mac module omits exactly the
# PLATFORM_OMITTED_KEYS it does not define, which the test filters for.
# ---------------------------------------------------------------------------

V195_PRESET_POLICIES = {
    "Balanced Privacy Preset": {
        "AlternateErrorPagesEnabled": False,
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
        "ChromeVariations": 1,
        "DNSInterceptionChecksEnabled": False,
        "DefaultBrowserSettingEnabled": False,
        "DnsOverHttpsMode": "automatic",
        "MediaRecommendationsEnabled": False,
        "MetricsReportingEnabled": False,
        "NetworkPredictionOptions": 2,
        "PaymentMethodQueryEnabled": False,
        "QuicAllowed": False,
        "RemoteDebuggingAllowed": False,
        "SafeBrowsingExtendedReportingEnabled": False,
        "ShoppingListEnabled": False,
        "SpellCheckServiceEnabled": False,
        "SyncDisabled": True,
        "TorDisabled": True,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
        "WebRtcIPHandling": "disable_non_proxied_udp",
    },
    "Developer Preset": {
        "AlternateErrorPagesEnabled": False,
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
        "ChromeVariations": 1,
        "DNSInterceptionChecksEnabled": False,
        "DefaultBrowserSettingEnabled": False,
        "DnsOverHttpsMode": "automatic",
        "MediaRecommendationsEnabled": False,
        "MetricsReportingEnabled": False,
        "SafeBrowsingExtendedReportingEnabled": False,
        "ShoppingListEnabled": False,
        "SpellCheckServiceEnabled": False,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
    },
    "Maximum Privacy Preset": {
        "AlternateErrorPagesEnabled": False,
        "AlwaysOpenPdfExternally": True,
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
        "DNSInterceptionChecksEnabled": False,
        "DefaultBraveAdblockSetting": 2,
        "DefaultBraveFingerprintingV2Setting": 3,
        "DefaultBraveHttpsUpgradeSetting": 2,
        "DefaultBraveReferrersSetting": 2,
        "DefaultBraveRemember1PStorageSetting": 2,
        "DefaultBrowserSettingEnabled": False,
        "DefaultGeolocationSetting": 2,
        "DefaultNotificationsSetting": 2,
        "DefaultSensorsSetting": 2,
        "DeveloperToolsAvailability": 2,
        "EmailAliasesEnabled": False,
        "EnableMediaRouter": False,
        "MediaRecommendationsEnabled": False,
        "MetricsReportingEnabled": False,
        "NetworkPredictionOptions": 2,
        "PasswordLeakDetectionEnabled": False,
        "PasswordManagerEnabled": False,
        "PaymentMethodQueryEnabled": False,
        "PrintingEnabled": False,
        "QuicAllowed": False,
        "RemoteDebuggingAllowed": False,
        "SafeBrowsingExtendedReportingEnabled": False,
        "SearchSuggestEnabled": False,
        "ShoppingListEnabled": False,
        "SpellcheckEnabled": False,
        "SyncDisabled": True,
        "TorDisabled": True,
        "TranslateEnabled": False,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
        "WebRtcIPHandling": "disable_non_proxied_udp",
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
        "HardwareAccelerationModeEnabled": True,
        "HighEfficiencyModeEnabled": True,
        "MediaRecommendationsEnabled": False,
        "MetricsReportingEnabled": False,
        "ShoppingListEnabled": False,
    },
    "Strict Parental Controls Preset": {
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
        "DnsOverHttpsMode": "secure",
        "DnsOverHttpsTemplates": "https://family.cloudflare-dns.com/dns-query",
        "ExtensionInstallBlocklist": ['*'],
        "ForceGoogleSafeSearch": True,
        "IncognitoModeAvailability": 1,
        "RemoteDebuggingAllowed": False,
        "SafeSitesFilterBehavior": 1,
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
    # Selecting "Ask" counts, exactly like ticking a checkbox - under its
    # own Site Permissions header, not the Access Controls one next door.
    site = _header_index(mod, rows, "Site Permissions")
    _, site_total = mod.header_counts(rows, site)
    notifications = _set_choice(mod, rows, "Web Notifications", "Ask")
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
    monkeypatch.setattr(mod, "repair_brave_prefs", lambda *a, **k: (0, False))
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
# "block" is the needle these tests lean on: six rows spread over three of
# the six categories, so the match set proves the filter keeps row order,
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
    "Access Controls",
    "Block All Extensions",
    "Block Sideloaded (External) Extensions",
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
# 80x24 terminal these tests assume is 18 rows.
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
    assert mod.viewport_rows(_FakeScreen(24, 80)) == 18
    assert mod.viewport_rows(_FakeScreen(50, 120)) == 44
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
    assert len(sel) < page  # the whole match set fits on one screen

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

    assert re.search(r"^\$bx\s*=\s*\$bar\.Width\s*-\s*\$script:BAR_PAD", bar, re.M), (
        "the button row no longer starts from the bar's right edge"
    )
    assert not re.search(r"^\$bx\s*=\s*\d+", bar, re.M), "the button row is packed from a fixed x again"
    assert re.search(r"for\s*\(\s*\$i\s*=\s*\$specs\.Count\s*-\s*1\s*;.*\$i--\s*\)", bar), (
        "the specs are not walked last-first, so Apply Settings would not land rightmost"
    )
    # a newline may separate the two statements as well as a semicolon
    assert re.search(r"\$bx\s*-=\s*\$btn\.Width\s*;?\s*\$btn\.Left\s*=\s*\$bx", bar), (
        "a button is placed before its width is subtracted, so the row overruns the bar"
    )
    assert re.search(r"^\$script:barButtonsLeft\s*=\s*\$bx\s*\+\s*\$script:BAR_GAP", bar, re.M), (
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


def test_ps1_row_mousedown_uses_zone_of_for_the_expander():
    """The expander click used a bare rectangle that ignored whether the row
    has a chevron, so empty row space toggled rows with no expander. Click,
    hover and highlight must share the one resolver, Zone-Of."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    start = text.index("function New-FluentRow")
    body = text[start:text.index("\n}\n", start)]
    md = body[body.index("Add_MouseDown"):]
    assert "$ev.Y -le 50" not in md, "the expander is hit-tested with a bare rectangle again"
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
    arithmetic such as `($s.Width-1)` vanish and only bare tokens remain."""
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

