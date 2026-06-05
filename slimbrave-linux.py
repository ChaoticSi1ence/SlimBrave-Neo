#!/usr/bin/env python3
"""SlimBrave Neo - Linux TUI for debloating and hardening Brave Browser.

Sets Chromium enterprise policies via JSON files at
/etc/brave/policies/managed/slimbrave.json. Requires root.

Multi-channel handling on Linux:
  brave-core hardcodes the managed-policy directory to /etc/brave/policies
  for every Brave channel (Stable / Beta / Nightly / Dev), so a single
  policy file applies to all of them. Channel info is still used to scrub
  leaked Shields exceptions from each channel's user-data directory and
  to detect which Brave processes are currently running.

Supports interactive curses TUI and non-interactive CLI usage:
  sudo python3 slimbrave.py                        # TUI
  sudo python3 slimbrave.py --import preset.json   # CLI import
  sudo python3 slimbrave.py --export out.json      # CLI export
  sudo python3 slimbrave.py --reset                # CLI reset
"""

import argparse
import curses
import json
import os
import shutil
import subprocess
import sys
import tempfile

POLICY_DIR = "/etc/brave/policies/managed"
POLICY_FILE = os.path.join(POLICY_DIR, "slimbrave.json")

# Directories a `--policy-file` argument is permitted to target. The flag
# runs with root, so an unvalidated path combined with `--reset` would let a
# permissive sudoers rule delete arbitrary files (e.g. `--policy-file
# /etc/shadow --reset`). Chromium only reads policies from these locations,
# so legitimate use does not need to point anywhere else.
ALLOWED_POLICY_DIRS = (
    "/etc/brave/policies/managed",
    "/etc/chromium/policies/managed",
)

# Brave channel definitions on Linux. Each channel has its own user-data
# directory under ~/.config/BraveSoftware/<dir>/ and (for some channels) a
# distinct binary name on PATH. Policy targets are shared across channels.
LINUX_CHANNELS = [
    {"id": "stable", "label": "Stable",
     "user_data_dir": "Brave-Browser", "process_name": "brave"},
    {"id": "beta", "label": "Beta",
     "user_data_dir": "Brave-Browser-Beta", "process_name": "brave-browser-beta"},
    {"id": "nightly", "label": "Nightly",
     "user_data_dir": "Brave-Browser-Nightly", "process_name": "brave-browser-nightly"},
    {"id": "dev", "label": "Dev",
     "user_data_dir": "Brave-Browser-Dev", "process_name": "brave-browser-dev"},
]

CHANNEL_IDS = [c["id"] for c in LINUX_CHANNELS]


def _user_home_for_brave():
    """Return the home directory of the real user (the one running sudo)."""
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not sudo_user or sudo_user == "root":
        return None
    try:
        return os.path.expanduser(f"~{sudo_user}")
    except KeyError:
        return None


def _channel_prefs_path(user_data_dir):
    """Return the Default profile Preferences path for a channel."""
    home = _user_home_for_brave()
    if not home:
        return None
    return os.path.join(
        home, ".config", "BraveSoftware", user_data_dir, "Default", "Preferences",
    )


def _is_within_allowed_policy_dir(path):
    """Return True if `path`'s realpath lives under an allowed policy dir."""
    real_path = os.path.realpath(path)
    for allowed in ALLOWED_POLICY_DIRS:
        real_allowed = (
            os.path.realpath(allowed) if os.path.exists(allowed) else allowed
        )
        if real_path.startswith(real_allowed + os.sep):
            return True
    return False


def _atomic_write(path, data, *, binary=False, mode=0o644):
    """Write `data` to `path` atomically via a same-directory tempfile.

    `tempfile.mkstemp` uses O_CREAT|O_EXCL so it cannot be tricked into
    writing through a symlink, and `os.replace` atomically replaces the
    target directory entry without following a symlink that happened to
    exist there. Fixes two classes of root footgun at once: symlink
    races and partial-state writes if the process is killed mid-write.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".slimbrave.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb" if binary else "w") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

# ---------------------------------------------------------------------------
# Brave browser detection
# ---------------------------------------------------------------------------


def _make_installation(channel_def, *, app_path="", plist_path="", prefs_path=None):
    """Build an installation record from a channel definition."""
    return {
        "channel": channel_def["id"],
        "label": channel_def["label"],
        "app_path": app_path,
        "bundle_id": "",
        "plist_path": plist_path,
        "prefs_path": prefs_path,
        "process_name": channel_def["process_name"],
        "user_data_dir": channel_def["user_data_dir"],
    }


def detect_brave():
    """Detect Brave browser installation(s) and packaging method.

    Returns a dict with keys:
        found, method, path, warnings, installations.
    On Linux every detected channel shares POLICY_FILE (no per-channel
    plist), so installations is informational + drives prefs repair and
    process-running checks.
    """
    method = None
    primary_path = ""
    warnings = []
    found_any = False

    # Arch (brave-bin AUR package)
    if os.path.isfile("/opt/brave-bin/brave"):
        method, primary_path, found_any = "arch", "/opt/brave-bin/brave", True
    # Deb / RPM (official brave-browser package)
    elif os.path.isfile("/opt/brave.com/brave/brave-browser"):
        method, primary_path, found_any = "deb/rpm", "/opt/brave.com/brave/brave-browser", True
    elif os.path.isfile("/opt/brave.com/brave/brave"):
        method, primary_path, found_any = "deb/rpm", "/opt/brave.com/brave/brave", True
    else:
        try:
            result = subprocess.run(
                ["flatpak", "info", "com.brave.Browser"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                method, primary_path, found_any = "flatpak", "com.brave.Browser", True
        except FileNotFoundError:
            pass  # flatpak not installed

    if not found_any:
        snap_path = "/snap/brave/current/opt/brave.com/brave/brave"
        if os.path.isfile(snap_path) or os.path.isdir("/snap/brave/current"):
            method, primary_path, found_any = "snap", snap_path, True
            warnings.append(
                "Snap confinement may prevent policies from taking effect. "
                "Native packages are recommended."
            )

    if not found_any:
        for name in ("brave-browser-stable", "brave-browser", "brave"):
            found = shutil.which(name)
            if found:
                method, primary_path, found_any = "unknown", found, True
                break

    if not found_any:
        method = "not found"
        warnings.append(
            "Brave browser not found. Policies will be written but may have no effect."
        )

    # Detect installed Linux channels by user-data dir presence (best effort).
    installations = []
    home = _user_home_for_brave()
    detected_labels = []
    for ch in LINUX_CHANNELS:
        ch_dir = (
            os.path.join(home, ".config", "BraveSoftware", ch["user_data_dir"])
            if home else None
        )
        installed = (
            (ch_dir is not None and os.path.isdir(ch_dir))
            or shutil.which(ch["process_name"]) is not None
        )
        if installed:
            installations.append(_make_installation(
                ch,
                app_path=primary_path if ch["id"] == "stable" else "",
                plist_path=POLICY_FILE,
                prefs_path=_channel_prefs_path(ch["user_data_dir"]),
            ))
            detected_labels.append(ch["label"])

    if not installations:
        stable = LINUX_CHANNELS[0]
        installations.append(_make_installation(
            stable,
            app_path=primary_path,
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(stable["user_data_dir"]),
        ))

    if found_any and len(detected_labels) > 1:
        method = f"{method}: " + ", ".join(detected_labels)

    return {
        "found": found_any,
        "method": method,
        "path": primary_path,
        "warnings": warnings,
        "installations": installations,
    }


# ---------------------------------------------------------------------------
# Feature definitions - mirrors the Windows SlimBrave Neo PS1 categories
# ---------------------------------------------------------------------------

# Features with a `group` key are mutually exclusive within that group:
# checking one silently unchecks the others. Used today for
# IncognitoModeAvailability, where Disable (=1) and Force (=2) are
# conflicting values for the same policy.
CATEGORIES = [
    {
        "name": "Telemetry & Reporting",
        "features": [
            {"name": "Disable Metrics Reporting", "key": "MetricsReportingEnabled", "value": False},
            {"name": "Disable Safe Browsing Reporting", "key": "SafeBrowsingExtendedReportingEnabled", "value": False},
            {"name": "Disable URL Data Collection", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False},
            {"name": "Disable P3A Analytics", "key": "BraveP3AEnabled", "value": False},
            {"name": "Disable Stats Ping", "key": "BraveStatsPingEnabled", "value": False},
        ],
    },
    {
        "name": "Privacy & Security",
        "features": [
            {"name": "Disable Safe Browsing", "key": "SafeBrowsingProtectionLevel", "value": 0},
            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False},
            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False},
            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False},
            {"name": "Disable Browser Sign-in", "key": "BrowserSignin", "value": 0},
            {"name": "Enable Global Privacy Control", "key": "BraveGlobalPrivacyControlEnabled", "value": True},
            {"name": "Enable De-AMP", "key": "BraveDeAmpEnabled", "value": True},
            {"name": "Enable Debouncing", "key": "BraveDebouncingEnabled", "value": True},
            {"name": "Strip Tracking URL Parameters", "key": "BraveTrackingQueryParametersFilteringEnabled", "value": True},
            {"name": "Reduce Language Fingerprinting", "key": "BraveReduceLanguageEnabled", "value": True},
            {"name": "Disable WebRTC IP Leak", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp"},
            {"name": "Disable QUIC Protocol", "key": "QuicAllowed", "value": False},
            {"name": "Block Third Party Cookies", "key": "BlockThirdPartyCookies", "value": True},
            {"name": "Force Google SafeSearch", "key": "ForceGoogleSafeSearch", "value": True},
            {"name": "Disable Incognito Mode", "key": "IncognitoModeAvailability", "value": 1, "group": "incognito"},
            {"name": "Force Incognito Mode", "key": "IncognitoModeAvailability", "value": 2, "group": "incognito"},
        ],
    },
    {
        "name": "Brave Features",
        "features": [
            {"name": "Disable Brave Rewards", "key": "BraveRewardsDisabled", "value": True},
            {"name": "Disable Brave Wallet", "key": "BraveWalletDisabled", "value": True},
            {"name": "Disable Brave VPN", "key": "BraveVPNDisabled", "value": True},
            {"name": "Disable Brave AI Chat", "key": "BraveAIChatEnabled", "value": False},
            {"name": "Disable Brave Shields", "key": "BraveShieldsDisabledForUrls", "value": ["https://*", "http://*"], "group": "shields"},
            {"name": "Force Shields On (All Sites)", "key": "BraveShieldsEnabledForUrls", "value": ["https://*", "http://*"], "group": "shields"},
            {"name": "Disable Brave News", "key": "BraveNewsDisabled", "value": True},
            {"name": "Disable Brave Talk", "key": "BraveTalkDisabled", "value": True},
            {"name": "Disable Brave Playlist", "key": "BravePlaylistEnabled", "value": False},
            {"name": "Disable Web Discovery", "key": "BraveWebDiscoveryEnabled", "value": False},
            {"name": "Disable Speedreader", "key": "BraveSpeedreaderEnabled", "value": False},
            {"name": "Disable Tor", "key": "TorDisabled", "value": True},
            {"name": "Disable Sync", "key": "SyncDisabled", "value": True},
            {"name": "Disable Email Aliases", "key": "EmailAliasesEnabled", "value": False},
        ],
    },
    {
        # Brave 1.83+ content-protection enforcers. These pin Brave's own
        # privacy defaults as managed policy so neither the user nor a
        # malicious page/extension can quietly weaken them.
        "name": "Shields & Content Protection",
        "features": [
            {"name": "Enforce Ad Blocking", "key": "DefaultBraveAdblockSetting", "value": 2},
            {"name": "Enforce Fingerprinting Protection", "key": "DefaultBraveFingerprintingV2Setting", "value": 3},
            {"name": "Force HTTPS Upgrades (Strict)", "key": "DefaultBraveHttpsUpgradeSetting", "value": 2},
            {"name": "Cap Referrers (Strict Origin)", "key": "DefaultBraveReferrersSetting", "value": 2},
            {"name": "Forget First-Party Storage on Close", "key": "DefaultBraveRemember1PStorageSetting", "value": 2},
        ],
    },
    {
        "name": "Performance & Bloat",
        "features": [
            {"name": "Disable Background Mode", "key": "BackgroundModeEnabled", "value": False},
            {"name": "Disable Shopping List", "key": "ShoppingListEnabled", "value": False},
            {"name": "Always Open PDF Externally", "key": "AlwaysOpenPdfExternally", "value": True},
            {"name": "Disable Translate", "key": "TranslateEnabled", "value": False},
            {"name": "Disable Spellcheck", "key": "SpellcheckEnabled", "value": False},
            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False},
            {"name": "Disable Printing", "key": "PrintingEnabled", "value": False},
            {"name": "Disable Default Browser Prompt", "key": "DefaultBrowserSettingEnabled", "value": False},
            {"name": "Disable Developer Tools", "key": "DeveloperToolsAvailability", "value": 2},
            {"name": "Disable Wayback Machine", "key": "BraveWaybackMachineEnabled", "value": False},
        ],
    },
]

DNS_MODES = ["automatic", "off", "secure", "custom"]

# ---------------------------------------------------------------------------
# Build a flat list of rows for the TUI (headers + toggleable items + DNS)
# ---------------------------------------------------------------------------

ROW_HEADER = 0
ROW_FEATURE = 1
ROW_DNS = 2
ROW_DNS_TEMPLATE = 3
ROW_CHANNEL = 4


def build_rows(installations=None):
    """Return a list of dicts describing each visual row.

    On Linux every channel shares POLICY_FILE so a per-channel selector
    cannot meaningfully scope the policy write. The `installations`
    argument is accepted for API parity with the macOS script but does
    not produce ROW_CHANNEL rows here.
    """
    rows = []
    for cat in CATEGORIES:
        rows.append({"type": ROW_HEADER, "text": cat["name"]})
        for feat in cat["features"]:
            rows.append({
                "type": ROW_FEATURE,
                "text": feat["name"],
                "key": feat["key"],
                "value": feat["value"],
                "group": feat.get("group"),
                "checked": False,
            })
    # DNS mode selector at the end
    rows.append({"type": ROW_HEADER, "text": "DNS Over HTTPS"})
    rows.append({
        "type": ROW_DNS,
        "text": "DNS Mode",
        "options": DNS_MODES,
        "selected": 0,  # index into DNS_MODES
    })
    rows.append({
        "type": ROW_DNS_TEMPLATE,
        "text": "DoH Template",
        "value": "",        # the URL string
        "cursor": 0,        # cursor position within the text
        "scroll": 0,        # horizontal scroll offset for long URLs
    })
    return rows


def get_dns_mode(rows):
    """Return the currently selected DNS mode string."""
    for row in rows:
        if row["type"] == ROW_DNS:
            return row["options"][row["selected"]]
    return "automatic"


def get_dns_template(rows):
    """Return the current DoH template URL string."""
    for row in rows:
        if row["type"] == ROW_DNS_TEMPLATE:
            return row["value"]
    return ""


def toggle_feature_row(rows, target):
    """Flip `target`'s checked state. If it belongs to a group, uncheck the
    other group members first so at most one is active (e.g. Disable vs
    Force Incognito, which set conflicting values for the same policy)."""
    new_state = not target["checked"]
    target["checked"] = new_state
    group = target.get("group")
    if new_state and group:
        for row in rows:
            if row is target:
                continue
            if row.get("type") == ROW_FEATURE and row.get("group") == group:
                row["checked"] = False

# ---------------------------------------------------------------------------
# BOM-aware JSON reader (handles PowerShell UTF-16 exports)
# ---------------------------------------------------------------------------


def read_json_file(path):
    """Read a JSON file, handling BOM and encoding from PS1 exports."""
    with open(path, "rb") as f:
        data = f.read()

    # Detect BOM and decode accordingly
    if data[:2] == b"\xff\xfe":
        text = data[2:].decode("utf-16-le", errors="replace")
    elif data[:2] == b"\xfe\xff":
        text = data[2:].decode("utf-16-be", errors="replace")
    elif data[:3] == b"\xef\xbb\xbf":
        text = data[3:].decode("utf-8", errors="replace")
    else:
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = data.decode("utf-16-le", errors="replace")

    # Strip null bytes (UTF-16 artifacts in malformed files)
    text = text.replace("\x00", "")
    return json.loads(text)

# ---------------------------------------------------------------------------
# Profile-prefs repair
#
# Brave/Chromium writes managed `*ForUrls` content-setting policies through
# to the user's profile Preferences file. Removing the policy from the
# managed location does NOT roll those entries back — the profile keeps
# the per-URL exceptions forever, so unchecking "Disable Brave Shields"
# leaves shields stuck off. This function scrubs the specific patterns
# SlimBrave writes (`http://*,*` and `https://*,*`) from the profile
# prefs, repairing the leak.
# ---------------------------------------------------------------------------


def _is_brave_running(installations=None):
    """True if any of the listed Brave installations have a live process."""
    if installations is None:
        names = ["brave"]
    else:
        names = [i["process_name"] for i in installations if i.get("process_name")]
        if not names:
            names = ["brave"]

    for name in names:
        try:
            result = subprocess.run(
                ["pgrep", "-x", name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            return False
    return False


def _repair_one_prefs(pref_path):
    """Scrub SlimBrave's Shields-disabled exceptions from a single prefs file."""
    if not pref_path or not os.path.isfile(pref_path):
        return 0

    try:
        with open(pref_path, "r", encoding="utf-8") as f:
            prefs = json.load(f)
    except (OSError, json.JSONDecodeError):
        return 0

    bs = (
        prefs.get("profile", {})
             .get("content_settings", {})
             .get("exceptions", {})
             .get("braveShields")
    )
    if not isinstance(bs, dict) or not bs:
        return 0

    removed = 0
    for pattern in ("http://*,*", "https://*,*"):
        if pattern in bs:
            del bs[pattern]
            removed += 1

    if removed == 0:
        return 0

    try:
        original_mode = os.stat(pref_path).st_mode & 0o777
        _atomic_write(
            pref_path,
            json.dumps(prefs, separators=(",", ":")),
            mode=original_mode,
        )
    except OSError:
        return 0

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            user_info = pwd.getpwnam(sudo_user)
            os.chown(pref_path, user_info.pw_uid, user_info.pw_gid)
        except (ImportError, KeyError, OSError):
            pass

    return removed


def repair_brave_prefs(installations=None):
    """Remove SlimBrave-leaked Shields exceptions across all given channels.

    Returns (removed_count, brave_was_running).
    """
    if installations is None:
        installations = [{"prefs_path": _channel_prefs_path(LINUX_CHANNELS[0]["user_data_dir"])}]

    running = _is_brave_running(installations)
    total = 0
    seen = set()
    for inst in installations:
        path = inst.get("prefs_path")
        if not path or path in seen:
            continue
        seen.add(path)
        total += _repair_one_prefs(path)
    return (total, running)


# ---------------------------------------------------------------------------
# Policy I/O
# ---------------------------------------------------------------------------


def _read_one_policy(plist_path):
    """Read a single JSON policy file."""
    try:
        with open(plist_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, PermissionError):
        return {}
    except Exception:
        return {}


def load_existing_policy(installations=None):
    """Read the current on-disk policy and return its dict.

    On Linux every channel shares POLICY_FILE, so de-duped reads still hit
    just one file. Falls back to POLICY_FILE when no installations are
    supplied.
    """
    if installations is None:
        return _read_one_policy(POLICY_FILE)
    seen = set()
    for inst in installations:
        p = inst.get("plist_path") or POLICY_FILE
        if p in seen:
            continue
        seen.add(p)
        data = _read_one_policy(p)
        if data:
            return data
    return {}


def _build_policy(rows):
    """Translate row state into a {key: value} policy dict.

    Returns (policy, error_msg). On validation failure policy is None.
    """
    policy = {}
    dns_mode = None
    dns_template = ""
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"]:
            policy[row["key"]] = row["value"]
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    if dns_mode == "custom" and not dns_template:
        return None, "Custom DNS requires a DoH template URL."

    if dns_mode:
        if dns_mode == "custom":
            policy["DnsOverHttpsMode"] = "secure"
            policy["DnsOverHttpsTemplates"] = dns_template
        else:
            policy["DnsOverHttpsMode"] = dns_mode
            if dns_mode == "secure" and dns_template:
                policy["DnsOverHttpsTemplates"] = dns_template
    return policy, ""


def _write_one_policy(plist_path, policy):
    """Write a single JSON policy file and return (ok, error_msg)."""
    try:
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        _atomic_write(plist_path, json.dumps(policy, indent=4))
    except PermissionError:
        return False, "Permission denied. Run as root."
    except OSError as e:
        return False, f"Failed to write policy: {e}"
    return True, ""


def _selected_channel_targets(installations, rows):
    """Linux UI does not expose channel rows, so every installation is targeted."""
    return list(installations)


def _dedupe_plist_targets(installations):
    """Return distinct (plist_path, label) pairs.

    On Linux every channel maps to the same POLICY_FILE; the labels are
    joined into a single string so status messages still surface what was
    written for whom. Insertion order is preserved by the dict
    (Python 3.7+).
    """
    grouped = {}
    for inst in installations:
        path = inst.get("plist_path") or POLICY_FILE
        grouped.setdefault(path, []).append(inst["label"])
    return [(path, ", ".join(labels)) for path, labels in grouped.items()]


def apply_policy(rows, installations=None):
    """Write the policy to every selected channel's plist file."""
    policy, err = _build_policy(rows)
    if policy is None:
        return False, err

    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(_selected_channel_targets(installations, rows))

    if not targets:
        return False, "No Brave channel selected."

    written_labels = []
    for plist_path, label in targets:
        ok, err = _write_one_policy(plist_path, policy)
        if not ok:
            scope = f" ({label})" if label else ""
            return False, f"{err}{scope}"
        if label:
            written_labels.append(label)

    repair_targets = (
        _selected_channel_targets(installations, rows)
        if installations else None
    )
    return True, _post_apply_message(
        *repair_brave_prefs(repair_targets), labels=written_labels,
    )


def _post_apply_message(repaired, brave_running, labels=None):
    """Build the status message after a successful Apply or Reset."""
    scope = f" to {', '.join(labels)}" if labels else ""
    base = f"Settings applied{scope}. Restart Brave to see changes."
    if repaired > 0:
        base = (
            f"Applied{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if brave_running:
        base += " (Brave is running — fully close it before reopening.)"
    return base


def reset_policy(rows, installations=None):
    """Delete the policy file(s) and uncheck everything."""
    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(_selected_channel_targets(installations, rows))

    if not targets:
        return False, "No Brave channel selected."

    cleared_labels = []
    try:
        for plist_path, label in targets:
            if os.path.exists(plist_path):
                os.remove(plist_path)
            if label:
                cleared_labels.append(label)
        for row in rows:
            if row["type"] == ROW_FEATURE:
                row["checked"] = False
            elif row["type"] == ROW_DNS:
                row["selected"] = 0
            elif row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = ""
                row["cursor"] = 0
                row["scroll"] = 0
    except OSError as e:
        return False, f"Failed to reset: {e}"

    repair_targets = (
        _selected_channel_targets(installations, rows)
        if installations else None
    )
    repaired, running = repair_brave_prefs(repair_targets)
    scope = f" for {', '.join(cleared_labels)}" if cleared_labels else ""
    msg = f"All settings reset{scope}. Restart Brave to see changes."
    if repaired > 0:
        msg = (
            f"Reset{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if running:
        msg += " (Brave is running — fully close it before reopening.)"
    return True, msg


def sync_rows_with_policy(rows, policy):
    """Pre-check rows that match an existing policy on disk."""
    if not policy:
        return
    for row in rows:
        if row["type"] == ROW_FEATURE:
            if row["key"] in policy and policy[row["key"]] == row["value"]:
                row["checked"] = True
        elif row["type"] == ROW_DNS:
            dns_val = policy.get("DnsOverHttpsMode")
            dns_tmpl = policy.get("DnsOverHttpsTemplates", "")
            if dns_val == "secure" and dns_tmpl:
                if "custom" in row["options"]:
                    row["selected"] = row["options"].index("custom")
            elif dns_val in row["options"]:
                row["selected"] = row["options"].index(dns_val)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl = policy.get("DnsOverHttpsTemplates", "")
            if tmpl:
                row["value"] = tmpl
                row["cursor"] = len(tmpl)

# ---------------------------------------------------------------------------
# Import / Export (PS1-compatible JSON format)
# ---------------------------------------------------------------------------


def export_settings(rows, path):
    """Export current TUI selections to a SlimBrave Neo JSON config file."""
    features = {}
    dns_mode = None
    dns_template = ""
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"]:
            features[row["key"]] = row["value"]
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    settings = {"Features": features}
    if dns_mode:
        settings["DnsMode"] = dns_mode
    if dns_template:
        settings["DnsTemplates"] = dns_template

    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        _atomic_write(path, json.dumps(settings, indent=4))
        return True, f"Exported to {path}"
    except OSError as e:
        return False, f"Export failed: {e}"


def _parse_imported_features(features_obj):
    """Normalize the Features field from a config file."""
    if isinstance(features_obj, dict):
        return dict(features_obj), False
    if isinstance(features_obj, list):
        return {k: None for k in features_obj}, True
    return {}, False


def import_settings(rows, path):
    """Import a SlimBrave Neo JSON config and update TUI row states."""
    try:
        config = read_json_file(path)
    except FileNotFoundError:
        return False, f"File not found: {path}"
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return False, f"Invalid JSON: {e}"
    except OSError as e:
        return False, f"Read error: {e}"

    features_map, is_legacy = _parse_imported_features(config.get("Features"))
    dns_mode = config.get("DnsMode", "")
    dns_template = config.get("DnsTemplates", "") or ""

    legacy_handled = set()

    for row in rows:
        if row["type"] == ROW_FEATURE:
            key = row["key"]
            if key not in features_map:
                row["checked"] = False
                continue
            expected = features_map[key]
            if is_legacy:
                if key in legacy_handled:
                    row["checked"] = False
                else:
                    row["checked"] = True
                    legacy_handled.add(key)
            else:
                row["checked"] = (expected == row["value"])
        elif row["type"] == ROW_DNS:
            if dns_mode and dns_mode in row["options"]:
                row["selected"] = row["options"].index(dns_mode)
            elif dns_mode == "secure":
                if "secure" in row["options"]:
                    row["selected"] = row["options"].index("secure")
        elif row["type"] == ROW_DNS_TEMPLATE:
            row["value"] = dns_template
            row["cursor"] = len(dns_template)
            row["scroll"] = 0

    return True, f"Imported from {path}"

# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

# Color pair IDs
CP_NORMAL = 1
CP_HEADER = 2
CP_CHECKED = 3
CP_CURSOR = 4
CP_BUTTON = 5
CP_BUTTON_ACTIVE = 6
CP_STATUS_OK = 7
CP_STATUS_ERR = 8
CP_TITLE = 9
CP_DIM = 10

BUTTONS = ["Import", "Export", "Apply", "Reset", "Quit"]

FOCUS_LIST = 0
FOCUS_BUTTONS = 1
FOCUS_PROMPT = 2


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_NORMAL, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_HEADER, curses.COLOR_RED, -1)
    curses.init_pair(CP_CHECKED, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_CURSOR, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(CP_BUTTON, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_BUTTON_ACTIVE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_STATUS_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_STATUS_ERR, curses.COLOR_RED, -1)
    curses.init_pair(CP_TITLE, curses.COLOR_CYAN, -1)
    curses.init_pair(CP_DIM, curses.COLOR_WHITE, -1)


def selectable_indices(rows):
    """Return list of row indices that can receive cursor focus."""
    return [i for i, r in enumerate(rows)
            if r["type"] in (ROW_FEATURE, ROW_DNS, ROW_DNS_TEMPLATE, ROW_CHANNEL)]


def draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
         status_msg, status_ok, install_method="",
         prompt_label="", prompt_buf="", prompt_cur=0):
    """Render the full TUI screen."""
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1

    if install_method:
        title = f" SlimBrave Neo - Brave Browser Debloater [{install_method}] "
    else:
        title = " SlimBrave Neo - Brave Browser Debloater "
    pad = max(0, (usable_w - len(title)) // 2)
    try:
        stdscr.addnstr(0, 0, " " * usable_w, usable_w,
                        curses.color_pair(CP_TITLE) | curses.A_BOLD)
        stdscr.addnstr(0, pad, title, usable_w - pad,
                        curses.color_pair(CP_TITLE) | curses.A_BOLD)
    except curses.error:
        pass

    hint = " [Q/Esc] Quit  [Space/Enter] Toggle  [Tab] Buttons "
    try:
        stdscr.addnstr(1, 0, hint.center(usable_w), usable_w,
                        curses.color_pair(CP_NORMAL) | curses.A_DIM)
    except curses.error:
        pass

    list_start_y = 2
    list_end_y = max_y - 4
    visible_count = list_end_y - list_start_y
    if visible_count < 1:
        visible_count = 1

    current_dns_mode = get_dns_mode(rows)

    for vi in range(visible_count):
        ri = vi + scroll_offset
        if ri >= len(rows):
            break
        row = rows[ri]
        y = list_start_y + vi
        if y >= max_y - 3:
            break

        is_cursor = (focus == FOCUS_LIST and ri == cursor_idx)

        line = ""
        attr = curses.color_pair(CP_NORMAL)

        if row["type"] == ROW_HEADER:
            attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
            line = f"  {row['text']}"
        elif row["type"] == ROW_FEATURE:
            mark = "x" if row["checked"] else " "
            line = f"    [{mark}] {row['text']}"
            if row["checked"]:
                attr = curses.color_pair(CP_CHECKED)
            else:
                attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_CHANNEL:
            mark = "x" if row["checked"] else " "
            line = f"    [{mark}] {row['text']}"
            attr = (
                curses.color_pair(CP_CHECKED) if row["checked"]
                else curses.color_pair(CP_NORMAL)
            )
        elif row["type"] == ROW_DNS:
            current = row["options"][row["selected"]]
            line = f"    < {current} >"
            attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl_active = current_dns_mode in ("custom", "secure")
            val = row["value"] if row["value"] else ""
            if tmpl_active:
                field_w = max(10, usable_w - 22)
                scroll = row.get("scroll", 0)
                visible_text = val[scroll:scroll + field_w]
                line = f"    Template: [{visible_text}]"
                attr = curses.color_pair(CP_NORMAL)
            else:
                line = "    Template: (select custom/secure DNS)"
                attr = curses.color_pair(CP_DIM) | curses.A_DIM

        if is_cursor:
            attr = curses.color_pair(CP_CURSOR) | curses.A_BOLD

        try:
            stdscr.addnstr(y, 0, line.ljust(usable_w), usable_w, attr)
        except curses.error:
            pass

        if (is_cursor and row["type"] == ROW_DNS_TEMPLATE
                and current_dns_mode in ("custom", "secure")):
            tmpl_val = row["value"]
            field_start = 15
            scroll = row.get("scroll", 0)
            cur_pos = row.get("cursor", 0)
            cur_screen_pos = field_start + cur_pos - scroll
            if 0 <= cur_screen_pos < usable_w:
                try:
                    ch = tmpl_val[cur_pos] if cur_pos < len(tmpl_val) else " "
                    stdscr.addnstr(y, cur_screen_pos, ch, 1,
                                   curses.color_pair(CP_BUTTON_ACTIVE))
                except curses.error:
                    pass

    if scroll_offset > 0:
        try:
            stdscr.addnstr(list_start_y - 1, usable_w - 5, " ^^^ ", 5,
                            curses.color_pair(CP_NORMAL) | curses.A_DIM)
        except curses.error:
            pass
    if scroll_offset + visible_count < len(rows):
        try:
            stdscr.addnstr(list_end_y, usable_w - 5, " vvv ", 5,
                            curses.color_pair(CP_NORMAL) | curses.A_DIM)
        except curses.error:
            pass

    btn_y = max_y - 2
    btn_x = 2
    for i, label in enumerate(BUTTONS):
        display = f" {label} "
        if focus == FOCUS_BUTTONS and i == btn_idx:
            attr = curses.color_pair(CP_BUTTON_ACTIVE) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_BUTTON)
        try:
            stdscr.addnstr(btn_y, btn_x, display, usable_w - btn_x, attr)
        except curses.error:
            pass
        btn_x += len(display) + 3

    status_y = max_y - 1
    if focus == FOCUS_PROMPT:
        prompt_text = f" {prompt_label}: {prompt_buf}"
        try:
            stdscr.addnstr(status_y, 0, prompt_text.ljust(usable_w),
                            usable_w, curses.color_pair(CP_TITLE))
            cur_x = len(prompt_label) + 3 + prompt_cur
            if cur_x < usable_w:
                ch = prompt_buf[prompt_cur] if prompt_cur < len(prompt_buf) else " "
                stdscr.addnstr(status_y, cur_x, ch, 1,
                               curses.color_pair(CP_BUTTON_ACTIVE))
        except curses.error:
            pass
    elif status_msg:
        cp = CP_STATUS_OK if status_ok else CP_STATUS_ERR
        try:
            stdscr.addnstr(status_y, 2, status_msg[:usable_w - 3],
                            usable_w - 3, curses.color_pair(cp))
        except curses.error:
            pass

    stdscr.refresh()


def prompt_text_input(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                      install_method, label, default=""):
    """Show a status-line text prompt and return (ok, text) on Enter."""
    buf = list(default)
    cur = len(buf)

    while True:
        draw(stdscr, rows, cursor_idx, scroll_offset,
             FOCUS_PROMPT, btn_idx, "", True, install_method,
             prompt_label=label, prompt_buf="".join(buf), prompt_cur=cur)

        key = stdscr.getch()

        if key == 27:
            return False, ""
        elif key in (curses.KEY_ENTER, 10, 13):
            return True, "".join(buf).strip()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1
        elif key == curses.KEY_DC:
            if cur < len(buf):
                buf.pop(cur)
        elif key == curses.KEY_LEFT:
            if cur > 0:
                cur -= 1
        elif key == curses.KEY_RIGHT:
            if cur < len(buf):
                cur += 1
        elif key == curses.KEY_HOME:
            cur = 0
        elif key == curses.KEY_END:
            cur = len(buf)
        elif 32 <= key <= 126:
            buf.insert(cur, chr(key))
            cur += 1


def main(stdscr, override_installations=None):
    """Main TUI event loop."""
    curses.curs_set(0)
    init_colors()
    stdscr.keypad(True)
    stdscr.timeout(-1)

    brave_info = detect_brave()
    if override_installations is not None:
        installations = override_installations
        install_method = "policy-file override"
    else:
        installations = brave_info["installations"]
        install_method = brave_info["method"]

    rows = build_rows(installations)
    sel = selectable_indices(rows)
    if not sel:
        return

    policy = load_existing_policy(installations)
    sync_rows_with_policy(rows, policy)

    cursor_pos = 0
    cursor_idx = sel[0]
    scroll_offset = 0
    focus = FOCUS_LIST
    btn_idx = 0

    if brave_info["warnings"]:
        status_msg = brave_info["warnings"][0]
        status_ok = not brave_info["found"]
    else:
        status_msg = ""
        status_ok = True

    while True:
        max_y, _ = stdscr.getmaxyx()
        list_start_y = 2
        list_end_y = max_y - 4
        visible_count = max(1, list_end_y - list_start_y)

        if cursor_idx < scroll_offset:
            scroll_offset = cursor_idx
        if cursor_idx >= scroll_offset + visible_count:
            scroll_offset = cursor_idx - visible_count + 1
        if cursor_idx > 0 and rows[cursor_idx - 1]["type"] == ROW_HEADER:
            if cursor_idx - 1 < scroll_offset:
                scroll_offset = cursor_idx - 1

        draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
             status_msg, status_ok, install_method)

        key = stdscr.getch()
        row = rows[cursor_idx]

        if (focus == FOCUS_LIST
                and row["type"] == ROW_DNS_TEMPLATE
                and get_dns_mode(rows) in ("custom", "secure")):
            if 32 <= key <= 126:
                val = row["value"]
                cur = row["cursor"]
                row["value"] = val[:cur] + chr(key) + val[cur:]
                row["cursor"] = cur + 1
                _, max_x = stdscr.getmaxyx()
                field_w = max(10, max_x - 1 - 22)
                if row["cursor"] - row["scroll"] >= field_w:
                    row["scroll"] = row["cursor"] - field_w + 1
                status_msg = ""
                continue
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if row["cursor"] > 0:
                    val = row["value"]
                    cur = row["cursor"]
                    row["value"] = val[:cur - 1] + val[cur:]
                    row["cursor"] = cur - 1
                    if row["scroll"] > 0:
                        row["scroll"] -= 1
                    status_msg = ""
                continue
            elif key == curses.KEY_DC:
                val = row["value"]
                cur = row["cursor"]
                if cur < len(val):
                    row["value"] = val[:cur] + val[cur + 1:]
                    status_msg = ""
                continue
            elif key == curses.KEY_LEFT:
                if row["cursor"] > 0:
                    row["cursor"] -= 1
                    if row["cursor"] < row["scroll"]:
                        row["scroll"] = row["cursor"]
                continue
            elif key == curses.KEY_RIGHT:
                if row["cursor"] < len(row["value"]):
                    row["cursor"] += 1
                    _, max_x = stdscr.getmaxyx()
                    field_w = max(10, max_x - 1 - 22)
                    if row["cursor"] - row["scroll"] >= field_w:
                        row["scroll"] = row["cursor"] - field_w + 1
                continue
            elif key == curses.KEY_HOME:
                row["cursor"] = 0
                row["scroll"] = 0
                continue
            elif key == curses.KEY_END:
                row["cursor"] = len(row["value"])
                _, max_x = stdscr.getmaxyx()
                field_w = max(10, max_x - 1 - 22)
                row["scroll"] = max(0, row["cursor"] - field_w + 1)
                continue

        if key == ord("q") or key == 27:
            break

        elif key == curses.KEY_UP:
            if focus == FOCUS_LIST:
                if cursor_pos > 0:
                    cursor_pos -= 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                focus = FOCUS_LIST
                cursor_pos = len(sel) - 1
                cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == curses.KEY_DOWN:
            if focus == FOCUS_LIST:
                if cursor_pos < len(sel) - 1:
                    cursor_pos += 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
                else:
                    focus = FOCUS_BUTTONS
                    btn_idx = 0
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                pass

        elif key == ord("\t"):
            if focus == FOCUS_LIST:
                focus = FOCUS_BUTTONS
                btn_idx = 0
                status_msg = ""
            else:
                focus = FOCUS_LIST
                status_msg = ""

        elif key == curses.KEY_LEFT:
            if focus == FOCUS_BUTTONS:
                btn_idx = max(0, btn_idx - 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] - 1) % len(row["options"])
                    status_msg = ""

        elif key == curses.KEY_RIGHT:
            if focus == FOCUS_BUTTONS:
                btn_idx = min(len(BUTTONS) - 1, btn_idx + 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key == ord(" "):
            if focus == FOCUS_LIST:
                if row["type"] == ROW_FEATURE:
                    toggle_feature_row(rows, row)
                    status_msg = ""
                elif row["type"] == ROW_CHANNEL:
                    row["checked"] = not row["checked"]
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key in (curses.KEY_ENTER, 10, 13):
            if focus == FOCUS_BUTTONS:
                btn_label = BUTTONS[btn_idx]

                if btn_label == "Apply":
                    dns_mode = get_dns_mode(rows)
                    dns_tmpl = get_dns_template(rows)
                    if dns_mode == "custom" and not dns_tmpl:
                        status_msg = "Custom DNS requires a DoH template URL."
                        status_ok = False
                    else:
                        status_ok, status_msg = apply_policy(rows, installations)

                elif btn_label == "Reset":
                    status_msg = ("Reset all settings? "
                                  "Press Enter to confirm, any key to cancel.")
                    status_ok = True
                    draw(stdscr, rows, cursor_idx, scroll_offset,
                         focus, btn_idx, status_msg, status_ok,
                         install_method)
                    confirm = stdscr.getch()
                    if confirm in (curses.KEY_ENTER, 10, 13):
                        status_ok, status_msg = reset_policy(rows, installations)
                    else:
                        status_msg = "Reset cancelled."
                        status_ok = True

                elif btn_label == "Import":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "Import path (Esc=cancel)",
                        default="./Presets/")
                    if ok and path:
                        status_ok, status_msg = import_settings(rows, path)
                        sel = selectable_indices(rows)
                    else:
                        status_msg = "Import cancelled."
                        status_ok = True

                elif btn_label == "Export":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "Export path (Esc=cancel)",
                        default="./SlimBraveNeoSettings.json")
                    if ok and path:
                        status_ok, status_msg = export_settings(rows, path)
                    else:
                        status_msg = "Export cancelled."
                        status_ok = True

                elif btn_label == "Quit":
                    break

            elif focus == FOCUS_LIST:
                if row["type"] == ROW_FEATURE:
                    toggle_feature_row(rows, row)
                    status_msg = ""
                elif row["type"] == ROW_CHANNEL:
                    row["checked"] = not row["checked"]
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

# ---------------------------------------------------------------------------
# CLI (non-interactive)
# ---------------------------------------------------------------------------


def cli_import(path, installations, doh_templates=""):
    """Non-interactive: import config and apply policies."""
    rows = build_rows(installations)
    ok, msg = import_settings(rows, path)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)

    if doh_templates:
        for row in rows:
            if row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = doh_templates
                break

    ok, msg = apply_policy(rows, installations)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)
    return 0


def cli_export(path, installations):
    """Non-interactive: export current policy to a config file."""
    policy = load_existing_policy(installations)
    if not policy:
        print("No existing policy found.", file=sys.stderr)
        return 1

    rows = build_rows(installations)
    sync_rows_with_policy(rows, policy)

    ok, msg = export_settings(rows, path)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)
    return 0


def cli_reset(installations):
    """Non-interactive: delete the policy file(s) and repair leaked prefs."""
    targets = _dedupe_plist_targets(installations)
    if not targets:
        print(f"No policy file found at {POLICY_FILE}")
        return 0
    try:
        for plist_path, label in targets:
            if os.path.exists(plist_path):
                os.remove(plist_path)
                print(
                    f"Removed {plist_path}"
                    + (f" ({label})" if label else "")
                )
            else:
                print(
                    f"No policy file found at {plist_path}"
                    + (f" ({label})" if label else "")
                )
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    repaired, running = repair_brave_prefs(installations)
    if repaired > 0:
        print(
            f"Cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''} from Brave's user profile."
        )
    if running:
        print("Note: Brave is running — fully close it before reopening.")
    return 0


def _filter_installations_by_channels(installations, channel_spec):
    """Apply --channels flag semantics to detected installations.

    On Linux every channel writes to the same POLICY_FILE, so filtering
    only narrows which channels' user-data dirs get prefs repair and
    which process names are checked when reporting "Brave is running".
    """
    if not channel_spec or channel_spec == "auto":
        return installations, ""
    requested = [c.strip().lower() for c in channel_spec.split(",") if c.strip()]
    unknown = [c for c in requested if c not in CHANNEL_IDS]
    if unknown:
        return None, (
            f"Unknown channel(s): {', '.join(unknown)}. "
            f"Valid: {', '.join(CHANNEL_IDS)}"
        )
    filtered = [i for i in installations if i["channel"] in requested]
    if not filtered:
        return None, (
            f"No installed Brave channel matches --channels {channel_spec}. "
            f"Detected: {', '.join(i['channel'] for i in installations) or 'none'}"
        )
    return filtered, ""


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="slimbrave",
        description="SlimBrave Neo - Brave Browser debloater",
        epilog="Run without arguments to launch the interactive TUI.",
    )
    parser.add_argument(
        "--import", dest="import_path", metavar="PATH",
        help="import a SlimBrave Neo JSON config and apply policies",
    )
    parser.add_argument(
        "--export", dest="export_path", metavar="PATH",
        help="export current policy to a SlimBrave Neo JSON config",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="remove the SlimBrave Neo managed policy file",
    )
    parser.add_argument(
        "--policy-file", metavar="PATH",
        help=f"override policy file path (default: {POLICY_FILE})",
    )
    parser.add_argument(
        "--doh-templates", metavar="URL",
        help="set DnsOverHttpsTemplates (used with custom DNS mode)",
    )
    parser.add_argument(
        "--channels", metavar="LIST", default="auto",
        help=(
            "comma-separated channels for prefs-repair / process detection "
            f"({', '.join(CHANNEL_IDS)}). Default 'auto' = all detected. "
            "Linux always writes a single shared policy file."
        ),
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    args = parse_args()

    override_installations = None
    if args.policy_file:
        if not _is_within_allowed_policy_dir(args.policy_file):
            print(
                "--policy-file must resolve to a path inside one of: "
                + ", ".join(ALLOWED_POLICY_DIRS)
            )
            sys.exit(2)
        POLICY_FILE = os.path.realpath(args.policy_file)
        POLICY_DIR = os.path.dirname(POLICY_FILE)
        # Reuse the stable channel's user-data dir / process name for prefs
        # repair and "is Brave running" detection on the override target.
        default_channel = LINUX_CHANNELS[0]
        override_installations = [_make_installation(
            {**default_channel, "id": "override", "label": "Override"},
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(default_channel["user_data_dir"]),
        )]

    is_cli = args.import_path or args.export_path or args.reset

    if os.geteuid() != 0:
        print("SlimBrave Neo must be run as root.")
        if is_cli:
            print("Usage: sudo python3 slimbrave.py --import preset.json")
        else:
            print("Usage: sudo python3 slimbrave.py")
        sys.exit(1)

    if is_cli:
        if override_installations is not None:
            installations = override_installations
        else:
            brave_info = detect_brave()
            installations, err = _filter_installations_by_channels(
                brave_info["installations"], args.channels,
            )
            if installations is None:
                print(f"Error: {err}", file=sys.stderr)
                sys.exit(2)
            for w in brave_info["warnings"]:
                print(f"Warning: {w}", file=sys.stderr)

        rc = 0
        if args.reset:
            rc = cli_reset(installations)
        if args.import_path:
            rc = cli_import(args.import_path, installations,
                            doh_templates=args.doh_templates or "")
        if args.export_path:
            rc = cli_export(args.export_path, installations)
        sys.exit(rc)

    try:
        curses.wrapper(lambda s: main(s, override_installations))
    except KeyboardInterrupt:
        pass
