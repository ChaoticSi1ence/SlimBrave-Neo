"""Unit tests for the pure logic shared by slimbrave-linux.py and slimbrave-mac.py.

Both scripts are loaded as modules (their entry points are guarded by
__main__) and every test runs against each, so a fix applied to one file
that is missed in the other fails loudly here. Nothing in this file touches
/etc, the registry, or a real Brave profile — filesystem work stays in
pytest's tmp_path.
"""

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(alias, filename):
    spec = importlib.util.spec_from_file_location(alias, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


MODULES = [
    _load("slimbrave_linux", "slimbrave-linux.py"),
    _load("slimbrave_mac", "slimbrave-mac.py"),
]


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


def test_build_policy_secure_keeps_optional_template(mod):
    rows = mod.build_rows()
    _set_dns(mod, rows, "secure", "https://dns.example/dns-query")
    policy, _ = mod._build_policy(rows)
    assert policy["DnsOverHttpsMode"] == "secure"
    assert policy["DnsOverHttpsTemplates"] == "https://dns.example/dns-query"


def test_build_policy_off_mode_writes_no_template(mod):
    rows = mod.build_rows()
    _set_dns(mod, rows, "off", "https://ignored.example/dns-query")
    policy, _ = mod._build_policy(rows)
    assert policy["DnsOverHttpsMode"] == "off"
    assert "DnsOverHttpsTemplates" not in policy


# ---------------------------------------------------------------------------
# Group exclusivity
# ---------------------------------------------------------------------------


def test_toggle_feature_row_group_exclusivity(mod):
    rows = mod.build_rows()
    disable = _check_feature(mod, rows, "Disable Incognito Mode")
    force = _check_feature(mod, rows, "Force Incognito Mode")
    assert force["checked"] is True
    assert disable["checked"] is False  # unchecked by the group rule


def test_shields_group_exclusivity(mod):
    rows = mod.build_rows()
    off = _check_feature(mod, rows, "Disable Brave Shields")
    on = _check_feature(mod, rows, "Force Shields On (All Sites)")
    assert on["checked"] is True
    assert off["checked"] is False


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
# Presets stay in sync with the feature definitions
# ---------------------------------------------------------------------------


def _feature_pairs(mod, browser):
    """Key → accepted values for one browser, straight from CATEGORIES.

    Reads the definitions instead of build_rows() so validating an Edge
    preset needs no select_browser() call (Edge build_rows is refused on
    Linux, where the mac script falls back to Linux paths in CI).
    """
    pairs = {}
    for cat in mod.CATEGORIES:
        cat_browsers = cat.get("browsers", mod.CHROMIUM_BROWSERS)
        if browser not in cat_browsers:
            continue
        for feat in cat["features"]:
            if browser not in feat.get("browsers", cat_browsers):
                continue
            pairs.setdefault(feat["key"], []).append(feat["value"])
    return pairs


# Keys presets may contain that are deliberately absent on some platforms;
# the import silently skips them there (see AUDIT.md):
# - BackgroundModeEnabled: no macOS support in Chromium
# - GeminiSettings: chrome.win / chrome.mac only, absent on Linux
# - StartupBoostEnabled, SpotlightExperiencesAndRecommendationsEnabled:
#   Edge on Windows only, absent from the macOS Edge catalog
# - DisableDefaultBrowserAgent: the agent is a Windows-only scheduled
#   task, so only the PowerShell script exposes the policy
PLATFORM_OMITTED_KEYS = {
    "BackgroundModeEnabled",
    "GeminiSettings",
    "StartupBoostEnabled",
    "SpotlightExperiencesAndRecommendationsEnabled",
    "DisableDefaultBrowserAgent",
}


@pytest.mark.parametrize(
    "preset", sorted((ROOT / "Presets").glob("*/*.json")),
    ids=lambda p: f"{p.parent.name}-{p.stem}",
)
def test_presets_match_feature_definitions(mod, preset):
    config = json.loads(preset.read_text())
    browser = preset.parent.name.lower()
    assert config.get("Browser") == browser, (
        f"{preset}: Browser field must match its folder ({browser})"
    )
    if browser not in mod.BROWSERS:
        pytest.skip(f"{browser} not supported by this platform script")
    known = _feature_pairs(mod, browser)
    for key, value in config["Features"].items():
        if key in PLATFORM_OMITTED_KEYS and key not in known:
            continue
        assert key in known, f"{preset.name}: unknown policy key {key}"
        assert value in known[key], (
            f"{preset.name}: {key}={value!r} matches no feature row "
            f"(expected one of {known[key]!r}) — the import would silently skip it"
        )
    dns_mode = config.get("DnsMode")
    if dns_mode is not None:
        assert dns_mode in mod.DNS_MODES
    if "DnsTemplates" in config:
        assert dns_mode in ("custom", "secure")


# ---------------------------------------------------------------------------
# Multi-browser catalog behaviour
# ---------------------------------------------------------------------------


def test_chrome_rows_contain_no_brave_keys(mod):
    pairs = _feature_pairs(mod, "chrome")
    brave_keys = [k for k in pairs if k.startswith(("Brave", "DefaultBrave", "Tor"))]
    assert brave_keys == []
    assert "BlockThirdPartyCookies" in pairs   # common keys still present


def test_edge_catalog_excludes_renamed_chromium_keys():
    mac = MODULES[1]
    if "edge" not in mac.BROWSERS:
        pytest.skip("edge catalog lives in the mac script")
    pairs = _feature_pairs(mac, "edge")
    # Edge replaces these Chromium keys with its own equivalents
    for gone, replacement in [
        ("MetricsReportingEnabled", "DiagnosticData"),
        ("IncognitoModeAvailability", "InPrivateModeAvailability"),
        ("WebRtcIPHandling", "WebRtcLocalhostIpHandling"),
        ("PasswordLeakDetectionEnabled", "PasswordMonitorAllowed"),
        ("SafeBrowsingProtectionLevel", "SmartScreenEnabled"),
        ("HighEfficiencyModeEnabled", "EfficiencyModeEnabled"),
    ]:
        assert gone not in pairs, f"{gone} leaked into the Edge catalog"
        assert replacement in pairs, f"{replacement} missing from the Edge catalog"


def test_import_rejects_cross_browser_config(mod, tmp_path):
    cfg = tmp_path / "chrome.json"
    cfg.write_text(json.dumps(
        {"Browser": "chrome", "Features": {"BlockThirdPartyCookies": True}}
    ))
    rows = mod.build_rows()   # default browser: brave
    ok, msg = mod.import_settings(rows, str(cfg))
    assert not ok
    assert "chrome" in msg


def test_export_stamps_selected_browser(mod, tmp_path):
    rows = mod.build_rows()
    _check_feature(mod, rows, "Disable Brave Rewards")
    out = tmp_path / "export.json"
    ok, _ = mod.export_settings(rows, str(out))
    assert ok
    assert json.loads(out.read_text())["Browser"] == "brave"


def test_firefox_dns_maps_to_mozilla_dialect(mod):
    try:
        mod.select_browser("firefox")
        rows = mod.build_rows()
        _set_dns(mod, rows, "custom", "https://dns.example/dns-query")
        policy, err = mod._build_policy(rows)
        assert err == ""
        assert "DnsOverHttpsMode" not in policy
        doh = policy["DNSOverHTTPS"]
        assert doh["Enabled"] is True and doh["Fallback"] is False
        assert doh["ProviderURL"] == "https://dns.example/dns-query"
        # Reverse mapping shows back as custom
        fresh = mod.build_rows()
        mod.sync_rows_with_policy(fresh, policy)
        assert mod.get_dns_mode(fresh) == "custom"
        assert mod.get_dns_template(fresh) == "https://dns.example/dns-query"
    finally:
        mod.select_browser("brave")


def test_firefox_rows_have_no_chromium_keys(mod):
    pairs = _feature_pairs(mod, "firefox")
    assert "BlockThirdPartyCookies" not in pairs
    assert "MetricsReportingEnabled" not in pairs
    assert pairs["EnableTrackingProtection"][0]["Value"] is True
    assert pairs["ExtensionSettings"] == [{"*": {"installation_mode": "blocked"}}]


def test_firefox_export_import_round_trips_nested_values(mod, tmp_path):
    try:
        mod.select_browser("firefox")
        rows = mod.build_rows()
        _check_feature(mod, rows, "Enforce Tracking Protection (Strict)")
        _check_feature(mod, rows, "Disable Telemetry")
        expected = _checked_policy_pairs(mod, rows)
        out = tmp_path / "ff.json"
        ok, _ = mod.export_settings(rows, str(out))
        assert ok
        assert json.loads(out.read_text())["Browser"] == "firefox"
        fresh = mod.build_rows()
        ok, _ = mod.import_settings(fresh, str(out))
        assert ok
        assert _checked_policy_pairs(mod, fresh) == expected
    finally:
        mod.select_browser("brave")


def test_firefox_linux_policy_file_wraps_policies(mod, tmp_path, monkeypatch):
    if getattr(mod, "IS_MAC", False):
        pytest.skip("wrapper applies to the JSON writer only")
    try:
        mod.select_browser("firefox")
        target = tmp_path / "policies.json"
        ok, err = mod._write_one_policy(str(target), {"DisableTelemetry": True})
        assert ok, err
        on_disk = json.loads(target.read_text())
        assert on_disk == {"policies": {"DisableTelemetry": True}}
        assert mod._read_one_policy(str(target)) == {"DisableTelemetry": True}
    finally:
        mod.select_browser("brave")


def test_select_browser_switches_paths_and_rows(mod):
    try:
        mod.select_browser("chrome")
        assert "chrome" in mod.POLICY_FILE.lower() or "Chrome" in mod.POLICY_FILE
        names = [r["text"] for r in mod.build_rows() if r["type"] == mod.ROW_FEATURE]
        assert "Disable Brave Rewards" not in names
        assert "Disable Chrome Labs" in names
    finally:
        mod.select_browser("brave")
