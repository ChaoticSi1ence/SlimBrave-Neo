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
import re
import stat
import sys

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


def _check_feature(mod, rows, name):
    """Check the feature row with the given display name (via toggle logic)."""
    for row in rows:
        if row["type"] == mod.ROW_FEATURE and row["text"] == name:
            if not row["checked"]:
                mod.toggle_feature_row(rows, row)
            return row
    raise AssertionError(f"feature not found: {name}")


def _get_feature(mod, rows, name):
    for row in rows:
        if row["type"] == mod.ROW_FEATURE and row["text"] == name:
            return row
    raise AssertionError(f"feature not found: {name}")


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
    cfg = tmp_path / "legacy.json"
    cfg.write_text(json.dumps(
        {"Features": ["IncognitoModeAvailability", "BraveRewardsDisabled"]}
    ))
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
    cfg = tmp_path / "both.json"
    cfg.write_text(json.dumps(
        {"Features": {key: SHIELDS_WILDCARDS for _, key in order}}
    ))
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
    cfg = tmp_path / "legacy-both.json"
    cfg.write_text(json.dumps(
        {"Features": [SHIELDS_OFF[1], SHIELDS_ON[1]]}
    ))
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

# One PS1 feature row: Name/Key/Value/Type, with an optional Group.
_PS1_FEATURE_RE = re.compile(
    r'@\{\s*Name\s*=\s*"([^"]*)";'
    r'\s*Key\s*=\s*"([^"]*)";'
    r'\s*Value\s*=\s*(.+?);'
    r'\s*Type\s*=\s*"[^"]*"'
    r'(?:;\s*Group\s*=\s*"([^"]*)")?'
)


def _parse_ps1_value(raw):
    """Turn a PS1 literal into the Python value it is meant to mirror."""
    raw = raw.strip()
    if raw.startswith("@("):            # @("*") / @("https://*", "http://*")
        return re.findall(r'"([^"]*)"', raw)
    if raw.startswith('"'):
        return raw[1:-1]
    return int(raw)                     # DWord


def _ps1_feature_rows():
    """Return {(name, key): (value, group)} for every PS1 feature row."""
    text = (ROOT / "SlimBrave.ps1").read_text(encoding="utf-8")
    rows = {}
    for m in _PS1_FEATURE_RE.finditer(text):
        rows[(m.group(1), m.group(2))] = (_parse_ps1_value(m.group(3)), m.group(4))
    # A row written with its fields in a different order would slip past the
    # regex and shrink the comparison silently. `Key = "` appears once per
    # feature row and nowhere else in the file, so it is the honest count.
    assert len(rows) == text.count('Key = "'), (
        "the PS1 feature regex missed a row — check the hashtable field order"
    )
    return rows


# BraveVPNDisabled is labelled "(no effect on Linux builds)" in
# slimbrave-linux.py only: enable_brave_vpn omits is_linux, so brave-core
# compiles the handler out there while Windows and macOS honour it. Compare
# that row on its key alone.
PS1_NAME_EXEMPT_KEYS = {"BraveVPNDisabled"}


def test_ps1_feature_table_matches_python(mod):
    ps1_rows = _ps1_feature_rows()
    py_rows = {(feat["name"], feat["key"]): (feat["value"], feat.get("group"))
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

    for ident, (py_value, py_group) in py_ident.items():
        ps1_value, ps1_group = ps1_ident[ident]
        # PowerShell has no bool: every bool policy is a DWord 0/1.
        if isinstance(py_value, bool) and ps1_value in (0, 1):
            ps1_value = bool(ps1_value)
        assert ps1_value == py_value, f"{ident}: PS1 {ps1_value!r} vs {py_value!r}"
        assert ps1_group == py_group, f"{ident}: PS1 group {ps1_group!r} vs {py_group!r}"


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
