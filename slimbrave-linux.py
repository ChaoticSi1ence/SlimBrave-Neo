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
import locale
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
    home = os.path.expanduser(f"~{sudo_user}")
    # expanduser returns the input unchanged when the user is unknown
    if home.startswith("~"):
        return None
    return home


def _chown_to_sudo_user(path):
    """Return a root-created file to the invoking user (no-op without sudo)."""
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return
    try:
        import pwd
        user_info = pwd.getpwnam(sudo_user)
        os.chown(path, user_info.pw_uid, user_info.pw_gid)
    except (ImportError, KeyError, OSError):
        pass


def _channel_prefs_path(user_data_dir):
    """Return the Default profile Preferences path for a channel."""
    home = _user_home_for_brave()
    if not home:
        return None
    return os.path.join(
        home, ".config", "BraveSoftware", user_data_dir, "Default", "Preferences",
    )


def _flatpak_prefs_path():
    """Return the Flatpak Brave's Default profile Preferences path.

    Flatpak keeps the profile under ~/.var/app/com.brave.Browser/config
    instead of ~/.config, so the native channel paths never see it. The
    Flathub manifest grants --filesystem=host-etc specifically to load
    policies from /etc/brave/policies, so the shared POLICY_FILE works;
    only prefs repair needs this extra location.
    """
    home = _user_home_for_brave()
    if not home:
        return None
    return os.path.join(
        home, ".var", "app", "com.brave.Browser", "config",
        "BraveSoftware", "Brave-Browser", "Default", "Preferences",
    )


def _profile_prefs_paths(default_prefs_path):
    """Expand a channel's Default-profile Preferences path to all profiles.

    Chromium keeps one directory per profile (Default, Profile 1, ...)
    under the same user-data dir, and the Shields-exception leak lands in
    every profile that was used while the policy was active — not just
    Default.
    """
    if not default_prefs_path:
        return []
    user_data = os.path.dirname(os.path.dirname(default_prefs_path))
    try:
        entries = sorted(os.listdir(user_data))
    except OSError:
        return [default_prefs_path]
    paths = []
    for name in entries:
        if name != "Default" and not name.startswith("Profile "):
            continue
        prefs = os.path.join(user_data, name, "Preferences")
        if os.path.isfile(prefs):
            paths.append(prefs)
    return paths or [default_prefs_path]


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
        # Pin the text encoding: readers use utf-8 explicitly, so inheriting
        # the locale's would round-trip non-ASCII through the wrong codec.
        with os.fdopen(fd, "wb" if binary else "w",
                       encoding=None if binary else "utf-8") as f:
            f.write(data)
            # fchmod on the descriptor, not chmod on the path — the temp
            # file can sit in a directory the unprivileged user owns, so a
            # second path lookup here is redirectable. (Windows only grew
            # os.fchmod in 3.13; fall back there.)
            if hasattr(os, "fchmod"):
                os.fchmod(f.fileno(), mode)
            else:
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
    home = _user_home_for_brave()

    # Arch (brave-bin AUR package)
    if os.path.isfile("/opt/brave-bin/brave"):
        method, primary_path, found_any = "arch", "/opt/brave-bin/brave", True
    # Deb / RPM (official brave-browser package)
    elif os.path.isfile("/opt/brave.com/brave/brave-browser"):
        method, primary_path, found_any = "deb/rpm", "/opt/brave.com/brave/brave-browser", True
    elif os.path.isfile("/opt/brave.com/brave/brave"):
        method, primary_path, found_any = "deb/rpm", "/opt/brave.com/brave/brave", True

    # Flatpak and Snap are probed unconditionally, not as the `else` of the
    # native chain: a mixed install has both, and the Snap warning applies
    # whenever a Snap Brave exists. Flatpak is checked on the filesystem
    # rather than via `flatpak info`, which under sudo runs with HOME=/root
    # and so never sees the user's --user installation.
    if os.path.isdir("/var/lib/flatpak/app/com.brave.Browser") or (
            home and os.path.isdir(os.path.join(
                home, ".local", "share", "flatpak", "app", "com.brave.Browser"))):
        if not found_any:
            method, primary_path, found_any = "flatpak", "com.brave.Browser", True

    snap_path = "/snap/brave/current/opt/brave.com/brave/brave"
    if os.path.isfile(snap_path) or os.path.isdir("/snap/brave/current"):
        if not found_any:
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

    # Flatpak keeps its profile under ~/.var/app, so the loop above cannot
    # see it. Add a synthetic stable-channel record pointing at the Flatpak
    # prefs so leak repair covers that profile too. Channel id stays
    # "stable" so --channels filtering keeps working.
    flatpak_prefs = _flatpak_prefs_path()
    if flatpak_prefs and os.path.isdir(
            os.path.dirname(os.path.dirname(flatpak_prefs))):
        installations.append(_make_installation(
            {"id": "stable", "label": "Stable (Flatpak)",
             "user_data_dir": "Brave-Browser", "process_name": "brave"},
            app_path="com.brave.Browser" if method == "flatpak" else "",
            plist_path=POLICY_FILE,
            prefs_path=flatpak_prefs,
        ))
        detected_labels.append("Flatpak")

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
# checking one silently unchecks the others. Used for policies where two
# rows set conflicting values for the same key (IncognitoModeAvailability,
# DefaultBraveReferrersSetting, ChromeVariations), for the Shields URL
# lists, and for the two spellcheck rows — upstream states the enhanced
# spell check policy has no effect once SpellcheckEnabled is false.

# Content settings Chromium models as an enum rather than a boolean carry a
# `choices` list: an ordered list of (label, value) pairs where value None
# means "not managed" (write nothing). The first entry is always
# ("Not managed", None) and is the default selection, so an untouched row
# behaves exactly like the unticked checkbox it replaced. A feature without
# `choices` stays a plain checkbox.
#
# The enum is NOT uniform. Allow=1 is a legal member of the notifications,
# geolocation and sensors settings only; for the guard settings (WebUSB,
# Serial, WebHID) and for local fonts / window management, value 1 is not a
# member at all and Chromium rejects it, so those rows never offer "Allow".
# Each row keeps the `value` it wrote as a checkbox: that is what a legacy
# array-format config resolves to on import, and what the SlimBrave.ps1
# feature table is compared against.
CHOICES_ALLOW_ASK_BLOCK = [("Not managed", None), ("Allow", 1), ("Ask", 3), ("Block", 2)]
CHOICES_ASK_BLOCK = [("Not managed", None), ("Ask", 3), ("Block", 2)]

CATEGORIES = [
    {
        "name": "Telemetry & Reporting",
        "features": [
            {"name": "Disable Metrics Reporting", "key": "MetricsReportingEnabled", "value": False},
            {"name": "Disable Safe Browsing Reporting", "key": "SafeBrowsingExtendedReportingEnabled", "value": False},
            {"name": "Disable URL Data Collection", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False},
            {"name": "Disable P3A Analytics", "key": "BraveP3AEnabled", "value": False},
            {"name": "Disable Stats Ping", "key": "BraveStatsPingEnabled", "value": False},
            {"name": "Limit Variations to Critical Fixes", "key": "ChromeVariations", "value": 1, "group": "variations"},
            {"name": "Disable Variations / Griffin Experiments", "key": "ChromeVariations", "value": 2, "group": "variations"},
            {"name": "Disable Enhanced Spell Check (Google Web Service)", "key": "SpellCheckServiceEnabled", "value": False, "group": "spellcheck"},
        ],
    },
    {
        "name": "Privacy & Security",
        "features": [
            {"name": "Disable Safe Browsing (security downgrade)", "key": "SafeBrowsingProtectionLevel", "value": 0},
            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False},
            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False},
            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False},
            {"name": "Disable Password Leak Detection", "key": "PasswordLeakDetectionEnabled", "value": False},
            {"name": "Disable Browser Sign-in", "key": "BrowserSignin", "value": 0},
            {"name": "Enable Global Privacy Control", "key": "BraveGlobalPrivacyControlEnabled", "value": True},
            {"name": "Enable De-AMP", "key": "BraveDeAmpEnabled", "value": True},
            {"name": "Enable Debouncing", "key": "BraveDebouncingEnabled", "value": True},
            {"name": "Strip Tracking URL Parameters", "key": "BraveTrackingQueryParametersFilteringEnabled", "value": True},
            {"name": "Reduce Language Fingerprinting", "key": "BraveReduceLanguageEnabled", "value": True},
            {"name": "Disable WebRTC IP Leak", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp"},
            {"name": "Disable QUIC Protocol", "key": "QuicAllowed", "value": False},
            {"name": "Disable Network Prediction (Prefetch)", "key": "NetworkPredictionOptions", "value": 2},
            {"name": "Block Third Party Cookies", "key": "BlockThirdPartyCookies", "value": True},
            {"name": "Block Payment Method Probing", "key": "PaymentMethodQueryEnabled", "value": False},
            {"name": "Disable Alternate Error Pages", "key": "AlternateErrorPagesEnabled", "value": False},
            {"name": "Block Remote Debugging", "key": "RemoteDebuggingAllowed", "value": False},
            {"name": "Disable DNS Interception Probes", "key": "DNSInterceptionChecksEnabled", "value": False},
            {"name": "Require HTTPS for Basic Auth", "key": "BasicAuthOverHttpEnabled", "value": False},
        ],
    },
    {
        # Content-setting defaults sites are granted: every row here is a
        # selector (Not managed / Ask / Block, plus Allow where Chromium
        # has one), never a checkbox.
        "name": "Site Permissions",
        "features": [
            {"name": "Web Notifications", "key": "DefaultNotificationsSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK},
            {"name": "Location Access", "key": "DefaultGeolocationSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK},
            {"name": "Motion Sensors", "key": "DefaultSensorsSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK},
            {"name": "WebUSB Access", "key": "DefaultWebUsbGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK},
            {"name": "Web Serial Access", "key": "DefaultSerialGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK},
            {"name": "WebHID Access", "key": "DefaultWebHidGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK},
            {"name": "Local Font Enumeration", "key": "DefaultLocalFontsSetting", "value": 2, "choices": CHOICES_ASK_BLOCK},
            {"name": "Multi-Screen Access", "key": "DefaultWindowManagementSetting", "value": 2, "choices": CHOICES_ASK_BLOCK},
        ],
    },
    {
        # Lockdowns and the escape hatches (guest, incognito, extensions)
        # that would otherwise bypass the rest of the policy set.
        "name": "Access Controls",
        "features": [
            {"name": "Force Google SafeSearch", "key": "ForceGoogleSafeSearch", "value": True},
            {"name": "Filter Adult Content (SafeSites)", "key": "SafeSitesFilterBehavior", "value": 1},
            {"name": "Disable Guest Mode", "key": "BrowserGuestModeEnabled", "value": False},
            {"name": "Block All Extensions", "key": "ExtensionInstallBlocklist", "value": ["*"]},
            {"name": "Block Sideloaded (External) Extensions", "key": "BlockExternalExtensions", "value": True},
            {"name": "Disable Incognito Mode", "key": "IncognitoModeAvailability", "value": 1, "group": "incognito"},
            {"name": "Force Incognito Mode", "key": "IncognitoModeAvailability", "value": 2, "group": "incognito"},
        ],
    },
    {
        "name": "Brave Features",
        "features": [
            {"name": "Disable Brave Rewards", "key": "BraveRewardsDisabled", "value": True},
            {"name": "Disable Brave Wallet", "key": "BraveWalletDisabled", "value": True},
            {"name": "Disable Brave VPN (no effect on Linux builds)", "key": "BraveVPNDisabled", "value": True},
            {"name": "Disable Brave AI Chat", "key": "BraveAIChatEnabled", "value": False},
            {"name": "Disable Local AI (On-Device Models, Brave 1.94+)", "key": "BraveLocalAIEnabled", "value": False},
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
        # Brave 1.84+ content-protection enforcers (fingerprinting
        # protection also works on 1.83). These pin Brave's own privacy
        # defaults as managed policy so neither the user nor a malicious
        # page/extension can quietly weaken them.
        "name": "Shields & Content Protection",
        "features": [
            {"name": "Enforce Ad Blocking", "key": "DefaultBraveAdblockSetting", "value": 2},
            {"name": "Enforce Fingerprinting Protection", "key": "DefaultBraveFingerprintingV2Setting", "value": 3},
            {"name": "Force HTTPS Upgrades (Strict)", "key": "DefaultBraveHttpsUpgradeSetting", "value": 2},
            {"name": "Cap Referrers (Strict Origin)", "key": "DefaultBraveReferrersSetting", "value": 2, "group": "referrers"},
            {"name": "Allow Permissive Referrers (unsafe-url)", "key": "DefaultBraveReferrersSetting", "value": 1, "group": "referrers"},
            {"name": "Forget First-Party Storage on Close", "key": "DefaultBraveRemember1PStorageSetting", "value": 2},
        ],
    },
    {
        "name": "Performance & Bloat",
        "features": [
            {"name": "Disable Background Mode", "key": "BackgroundModeEnabled", "value": False},
            {"name": "Enable Memory Saver", "key": "HighEfficiencyModeEnabled", "value": True},
            {"name": "Force Hardware Acceleration", "key": "HardwareAccelerationModeEnabled", "value": True},
            {"name": "Disable Media Router (Cast)", "key": "EnableMediaRouter", "value": False},
            {"name": "Disable Media Recommendations", "key": "MediaRecommendationsEnabled", "value": False},
            {"name": "Disable Shopping List", "key": "ShoppingListEnabled", "value": False},
            {"name": "Always Open PDF Externally", "key": "AlwaysOpenPdfExternally", "value": True},
            {"name": "Disable Translate", "key": "TranslateEnabled", "value": False},
            {"name": "Disable Spellcheck", "key": "SpellcheckEnabled", "value": False, "group": "spellcheck"},
            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False},
            {"name": "Disable Printing", "key": "PrintingEnabled", "value": False},
            {"name": "Disable Default Browser Prompt", "key": "DefaultBrowserSettingEnabled", "value": False},
            {"name": "Disable Developer Tools", "key": "DeveloperToolsAvailability", "value": 2},
            {"name": "Disable Wayback Machine", "key": "BraveWaybackMachineEnabled", "value": False},
        ],
    },
]

# "unmanaged" (the default) writes no DNS policy at all, leaving Brave's
# DNS settings user-controlled. The other four are managed-policy values —
# including "off", which actively force-disables DoH as policy.
DNS_MODES = ["unmanaged", "automatic", "off", "secure", "custom"]

# ---------------------------------------------------------------------------
# Build a flat list of rows for the TUI (headers + toggleable items + DNS)
# ---------------------------------------------------------------------------

ROW_HEADER = 0
ROW_FEATURE = 1
ROW_DNS = 2
ROW_DNS_TEMPLATE = 3
ROW_CHOICE = 4


def build_rows(installations=None):
    """Return a list of dicts describing each visual row.

    On Linux every channel shares POLICY_FILE so a per-channel selector
    cannot meaningfully scope the policy write. The `installations`
    argument is accepted for API parity with the macOS script but does
    not affect the layout.
    """
    rows = []
    for cat in CATEGORIES:
        # `collapsed` lives only on headers, and import/reset/sync all
        # mutate rows in place without touching one, so a fold survives.
        rows.append({"type": ROW_HEADER, "text": cat["name"],
                     "collapsed": False})
        for feat in cat["features"]:
            if "choices" in feat:
                rows.append({
                    "type": ROW_CHOICE,
                    "text": feat["name"],
                    "key": feat["key"],
                    "value": feat["value"],   # what the old checkbox wrote
                    "choices": feat["choices"],
                    "selected": 0,            # index into choices; 0 = unmanaged
                })
                continue
            rows.append({
                "type": ROW_FEATURE,
                "text": feat["name"],
                "key": feat["key"],
                "value": feat["value"],
                "group": feat.get("group"),
                "checked": False,
            })
    # DNS mode selector at the end
    rows.append({"type": ROW_HEADER, "text": "DNS Over HTTPS",
                 "collapsed": False})
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
    return "unmanaged"


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


def _choice_value(row):
    """Return the policy value a choice row is set to, or None if unmanaged."""
    return row["choices"][row["selected"]][1]


def _choice_index_for_value(row, value):
    """Return the index of the choice carrying `value`, or None if illegal.

    Type-strict, because `True == 1` in Python: a JSON `true` would
    otherwise select "Allow" on the three settings that have one, and no
    bool is a legal member of any of these enums.
    """
    for idx, choice in enumerate(row["choices"]):
        choice_value = choice[1]
        if choice_value is None:
            continue
        if type(choice_value) is type(value) and choice_value == value:
            return idx
    return None


def cycle_choice_row(row, step=1):
    """Advance a choice row's selection, wrapping at both ends.

    Same idiom as the DNS selector: Left/Right/Space/Enter all walk the
    same ordered list.
    """
    row["selected"] = (row["selected"] + step) % len(row["choices"])


def activate_row(rows, row):
    """Space/Enter action for a list row: header fold, feature toggle,
    choice/DNS advance. Returns True when the row type has one, so the
    caller clears the status line; False otherwise (e.g. NO_ROW)."""
    if row["type"] == ROW_HEADER:
        row["collapsed"] = not row.get("collapsed", False)
    elif row["type"] == ROW_FEATURE:
        toggle_feature_row(rows, row)
    elif row["type"] == ROW_CHOICE:
        cycle_choice_row(row, 1)
    elif row["type"] == ROW_DNS:
        row["selected"] = (row["selected"] + 1) % len(row["options"])
    else:
        return False
    return True


def _enforce_groups(rows, features_map):
    """Collapse every group down to at most one checked row.

    Import and policy-sync set `checked` per row with no group awareness,
    so a config naming both BraveShieldsDisabledForUrls and
    BraveShieldsEnabledForUrls ticks both and _build_policy emits force-off
    and force-on for the same wildcards. `features_map` supplies the source
    order (the config's or the policy's key order) and the last key listed
    wins, matching the PS1 CheckedChanged handler's behaviour.
    """
    # Choice rows never reach the bodies below: every test here is gated on
    # ROW_FEATURE, and a choice row carries neither "checked" nor a group.
    order = list(features_map)
    groups = {r.get("group") for r in rows
              if r["type"] == ROW_FEATURE and r.get("group")}
    for group in groups:
        members = [r for r in rows
                   if r["type"] == ROW_FEATURE
                   and r.get("group") == group and r["checked"]]
        if len(members) < 2:
            continue
        keep = max(members, key=lambda r: order.index(r["key"]))
        for r in members:
            if r is not keep:
                r["checked"] = False

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


def _pid_is_alive(pid):
    """True if `pid` names a live process.

    /proc is the cheap check; signal 0 is the fallback for kernels without
    it. Never reached off POSIX — os.kill there terminates rather than
    probes.
    """
    if os.path.isdir(f"/proc/{pid}"):
        return True
    if os.name != "posix":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # it exists, we just can't signal it
    return True


def _singleton_lock_pid(prefs_path):
    """Return the pid holding a profile's Chromium SingletonLock, or None.

    Chromium symlinks <user-data-dir>/SingletonLock to "<hostname>-<pid>"
    for as long as the profile is open. This is the only running-check that
    covers every channel: `pgrep -x` matches /proc/<pid>/comm, capped at 15
    characters, so "brave-browser-beta" and friends can never match.
    """
    if not prefs_path:
        return None
    user_data = os.path.dirname(os.path.dirname(prefs_path))
    try:
        target = os.readlink(os.path.join(user_data, "SingletonLock"))
    except OSError:
        return None
    pid_part = target.rsplit("-", 1)[-1]
    return int(pid_part) if pid_part.isdigit() else None


def _is_brave_running(installations=None):
    """True if any of the listed Brave installations have a live process."""
    if installations is None:
        names = ["brave"]
    else:
        for inst in installations:
            pid = _singleton_lock_pid(inst.get("prefs_path"))
            if pid is not None and _pid_is_alive(pid):
                return True
        names = [i["process_name"] for i in installations if i.get("process_name")]
        if not names:
            names = ["brave"]

    for name in names:
        # A name longer than comm's 15-char cap can only ever be a false
        # negative, so don't spend a process asking.
        if len(name) > 15:
            continue
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


def _sudo_user_identity():
    """Return (name, uid, gid) of the invoking user, or None if there is none."""
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return None
    try:
        import pwd
        info = pwd.getpwnam(sudo_user)
    except (ImportError, KeyError):
        return None
    if info.pw_uid == 0:
        return None
    return (sudo_user, info.pw_uid, info.pw_gid)


def _repair_one_prefs(pref_path):
    """Scrub a single prefs file, dropping root first where we can.

    Every path component under the user's home is theirs to replace, so
    doing the read-modify-write as root would follow a symlinked
    `Default`/`Profile *` into a file root owns and then hand it over.
    Fork and drop to the invoking user's uid/gid instead — the child can
    only reach what that user could already reach. Returns the number of
    entries removed (0 on any failure, so a broken drop repairs nothing
    rather than repairing as root).
    """
    identity = _sudo_user_identity()
    if identity is None or not hasattr(os, "fork") or os.geteuid() != 0:
        return _scrub_one_prefs(pref_path)

    name, uid, gid = identity
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        return 0

    if pid == 0:
        removed = 0
        try:
            os.close(read_fd)
            try:
                os.initgroups(name, gid)
            except (AttributeError, OSError):
                pass  # supplementary groups are best-effort
            os.setgid(gid)
            os.setuid(uid)
            removed = _scrub_one_prefs(pref_path)
        except BaseException:
            removed = 0
        finally:
            try:
                # Decimal, not a raw byte: a single byte wraps at 256 and
                # would report a large scrub as 0. Well under PIPE_BUF, so
                # the write is atomic and one read gets all of it.
                os.write(write_fd, str(removed).encode("ascii"))
            except OSError:
                pass
            os._exit(0)

    os.close(write_fd)
    try:
        reply = os.read(read_fd, 32)
    except OSError:
        reply = b""
    os.close(read_fd)
    os.waitpid(pid, 0)
    try:
        return int(reply)
    except ValueError:
        return 0


def _scrub_one_prefs(pref_path):
    """Remove SlimBrave's Shields-disabled exceptions from one prefs file."""
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

    # Normally a no-op: _repair_one_prefs' fork already dropped to this
    # user, so the file never changed hands. Kept for the inline path.
    _chown_to_sudo_user(pref_path)

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
        for path in _profile_prefs_paths(inst.get("prefs_path")):
            if path in seen:
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
        elif row["type"] == ROW_CHOICE:
            choice_value = _choice_value(row)
            if choice_value is not None:
                policy[row["key"]] = choice_value
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    # "secure" with no template is a working configuration that resolves
    # nothing: Chromium applies the mode, blanks the templates pref, and
    # the system-resolver fallback is gated off for kSecure. The user can't
    # undo it in settings either, because the policy is machine-managed.
    # "automatic" is exempt — an empty template is valid and documented.
    if dns_mode in ("custom", "secure") and not dns_template:
        return None, "Secure/custom DNS requires a DoH template URL."

    # "unmanaged" writes no DNS keys at all; since Apply fully overwrites
    # the policy file, any previously-managed DNS policy is removed.
    if dns_mode and dns_mode != "unmanaged":
        if dns_mode == "custom":
            policy["DnsOverHttpsMode"] = "secure"
            policy["DnsOverHttpsTemplates"] = dns_template
        else:
            policy["DnsOverHttpsMode"] = dns_mode
            # Chromium honours a template in "automatic" mode too (it just
            # keeps the plaintext fallback), so don't discard one.
            if dns_mode in ("automatic", "secure") and dns_template:
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
        targets = _dedupe_plist_targets(installations)

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

    return True, _post_apply_message(
        *repair_brave_prefs(installations if installations else None),
        labels=written_labels,
    )


def _post_apply_message(repaired, brave_running, labels=None):
    """Build the status message after a successful Apply or Reset."""
    scope = f" to {', '.join(labels)}" if labels else ""
    base = f"Settings applied{scope}. Restart Brave to see changes."
    # Only claim a repair count that can survive: Chromium serves prefs
    # from an in-memory PrefService and flushes on shutdown, so a running
    # Brave writes back over whatever we just cleaned.
    if repaired > 0 and not brave_running:
        base = (
            f"Applied{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if brave_running:
        base += (
            " Brave is running: any leaked profile prefs cleaned now will be "
            "overwritten when Brave next saves. Fully close Brave and run "
            "Apply again to make it stick."
        )
    return base


def reset_policy(rows, installations=None):
    """Delete the policy file(s) and uncheck everything."""
    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(installations)

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
            elif row["type"] == ROW_CHOICE:
                row["selected"] = 0
            elif row["type"] == ROW_DNS:
                row["selected"] = 0
            elif row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = ""
                row["cursor"] = 0
                row["scroll"] = 0
    except OSError as e:
        return False, f"Failed to reset: {e}"

    repaired, running = repair_brave_prefs(installations if installations else None)
    scope = f" for {', '.join(cleared_labels)}" if cleared_labels else ""
    msg = f"All settings reset{scope}. Restart Brave to see changes."
    if repaired > 0 and not running:
        msg = (
            f"Reset{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if running:
        msg += (
            " Brave is running: any leaked profile prefs cleaned now will be "
            "overwritten when Brave next saves. Fully close Brave and run "
            "Reset again to make it stick."
        )
    return True, msg


def sync_rows_with_policy(rows, policy):
    """Pre-check rows that match an existing policy on disk."""
    if not policy:
        return
    for row in rows:
        if row["type"] == ROW_FEATURE:
            if row["key"] in policy and policy[row["key"]] == row["value"]:
                row["checked"] = True
        elif row["type"] == ROW_CHOICE:
            # A value that is not a legal member of this key's enum leaves
            # the row unmanaged, the same way a non-matching feature value
            # leaves a checkbox unticked.
            if row["key"] in policy:
                idx = _choice_index_for_value(row, policy[row["key"]])
                if idx is not None:
                    row["selected"] = idx
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
                row["scroll"] = 0
    _enforce_groups(rows, policy)

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
        elif row["type"] == ROW_CHOICE:
            # "Not managed" omits the key entirely, so the exported file has
            # the same shape it had when these rows were checkboxes.
            choice_value = _choice_value(row)
            if choice_value is not None:
                features[row["key"]] = choice_value
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    # DnsMode is omitted when DNS is unmanaged, so importing the file
    # (on any platform) lands back on "unmanaged" instead of forcing a
    # managed DNS policy. The template set mirrors _build_policy exactly —
    # "automatic" honours one too, and dropping it here would silently
    # hand DNS back to the default resolver on the next import.
    settings = {"Features": features}
    if dns_mode and dns_mode != "unmanaged":
        settings["DnsMode"] = dns_mode
        if dns_template and dns_mode in ("custom", "secure", "automatic"):
            settings["DnsTemplates"] = dns_template

    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        _atomic_write(path, json.dumps(settings, indent=4))
        # Running as root: hand the export back to the invoking user so it
        # isn't a root-owned file stranded in their home directory.
        _chown_to_sudo_user(path)
        return True, f"Exported to {path}"
    except OSError as e:
        return False, f"Export failed: {e}"


def _parse_imported_features(features_obj):
    """Normalize the Features field from a config file."""
    if isinstance(features_obj, dict):
        return dict(features_obj), False
    if isinstance(features_obj, list):
        # Drop non-string entries: a nested object would be unhashable and
        # blow up the dict comprehension.
        return {k: None for k in features_obj if isinstance(k, str)}, True
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

    # `[1,2]`, `null`, `"x"` and `3` are all valid JSON that would die at
    # the first .get() — in the TUI that traceback escapes curses.wrapper.
    if not isinstance(config, dict):
        return False, (
            f"Invalid config: expected a JSON object, got {type(config).__name__}"
        )

    features_map, is_legacy = _parse_imported_features(config.get("Features"))
    dns_mode = config.get("DnsMode", "")
    dns_template = config.get("DnsTemplates", "") or ""
    if not dns_mode:
        # No DnsMode in the file means DNS is unmanaged (a bare
        # DnsTemplates is treated as custom for legacy exports).
        dns_mode = "custom" if dns_template else "unmanaged"

    legacy_handled = set()
    # Choice keys whose value is not a legal member of that key's enum.
    # They stay unmanaged and are named in the result message rather than
    # being written out as a value Brave would reject.
    skipped_choices = []

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
        elif row["type"] == ROW_CHOICE:
            # Import is authoritative: a key the config does not name goes
            # back to "Not managed", matching the old unticked checkbox.
            row["selected"] = 0
            if row["key"] in features_map:
                if is_legacy:
                    # The array format carries no values; naming the key
                    # used to tick a checkbox that wrote row["value"].
                    idx = _choice_index_for_value(row, row["value"])
                else:
                    idx = _choice_index_for_value(row, features_map[row["key"]])
                if idx is None:
                    skipped_choices.append(row["key"])
                else:
                    row["selected"] = idx
        elif row["type"] == ROW_DNS:
            if dns_mode in row["options"]:
                row["selected"] = row["options"].index(dns_mode)
        elif row["type"] == ROW_DNS_TEMPLATE:
            row["value"] = dns_template
            row["cursor"] = len(dns_template)
            row["scroll"] = 0

    _enforce_groups(rows, features_map)
    msg = f"Imported from {path}"
    if skipped_choices:
        msg += ("; left unmanaged because the value is not one this policy "
                "accepts: " + ", ".join(skipped_choices))
    return True, msg

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

# Every row type the cursor may land on. Headers joined the list when
# Space/Enter started folding them.
SELECTABLE_TYPES = (ROW_HEADER, ROW_FEATURE, ROW_CHOICE, ROW_DNS,
                    ROW_DNS_TEMPLATE)

# Stand-in for "the cursor is on nothing", which a filter matching zero
# rows produces. Its type matches no key branch, so they all fall through.
NO_ROW = {"type": None}


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


# Disclosure markers for collapsible headers, resolved once per process.
DISCLOSURE_UNICODE = ("\u25be", "\u25b8")   # small down / right triangles
DISCLOSURE_ASCII = ("v", ">")
_disclosure_glyphs = None


def disclosure_glyphs():
    """Return the (expanded, collapsed) markers this terminal can encode.

    curses encodes everything handed to addnstr with the codeset LC_CTYPE
    gave the interpreter, and neither script sets a locale: on a plain
    VT100 that is ANSI_X3.4-1968, where the triangles raise
    UnicodeEncodeError — which the `except curses.error` guard wrapped
    around every write here does not catch. Ask the codec first.
    """
    global _disclosure_glyphs
    if _disclosure_glyphs is None:
        try:
            enc = locale.getpreferredencoding(False) or "ascii"
            for glyph in DISCLOSURE_UNICODE:
                glyph.encode(enc)
            _disclosure_glyphs = DISCLOSURE_UNICODE
        except (LookupError, UnicodeEncodeError, ValueError):
            _disclosure_glyphs = DISCLOSURE_ASCII
    return _disclosure_glyphs


def header_span(rows, header_idx):
    """Return the (start, end) row range a header owns, end-exclusive."""
    end = header_idx + 1
    while end < len(rows) and rows[end]["type"] != ROW_HEADER:
        end += 1
    return header_idx + 1, end


def header_counts(rows, header_idx):
    """Return (on, total) over the countable rows a header owns.

    A row is on when its checkbox is ticked or its choice sits off the
    "Not managed" slot. The DNS section holds neither kind, so it reports
    (0, 0) and draw() omits the counter rather than painting "0/0 on".
    """
    start, end = header_span(rows, header_idx)
    on = 0
    total = 0
    for row in rows[start:end]:
        if row["type"] == ROW_FEATURE:
            total += 1
            if row["checked"]:
                on += 1
        elif row["type"] == ROW_CHOICE:
            total += 1
            if row["selected"] > 0:
                on += 1
    return on, total


def collapse_state(rows):
    """Snapshot every header's fold state, in row order."""
    return [r.get("collapsed", False) for r in rows if r["type"] == ROW_HEADER]


def restore_collapse_state(rows, state):
    """Put a collapse_state() snapshot back; None restores nothing."""
    if state is None:
        return
    headers = [r for r in rows if r["type"] == ROW_HEADER]
    for header, collapsed in zip(headers, state):
        header["collapsed"] = collapsed


def apply_startup_collapse(rows):
    """Fold the sections that are not managing anything.

    Called once at launch, after the on-disk policy has been synced in. A
    machine with nothing applied opens on a short overview; one that is
    already configured opens with exactly those sections showing, so the
    first screen answers "what is set right now?". Nothing is persisted --
    the state is derived from what was just read off disk, and any later
    fold the user makes is theirs to keep.
    """
    dns_managed = get_dns_mode(rows) != "unmanaged"
    for idx, row in enumerate(rows):
        if row["type"] != ROW_HEADER:
            continue
        on, total = header_counts(rows, idx)
        if total:
            row["collapsed"] = on == 0
        else:
            # The DNS header owns no countable rows, so judge it by
            # whether a mode is actually being enforced.
            row["collapsed"] = not dns_managed


def row_matches_filter(row, needle):
    """True when a feature or choice row's name contains `needle`."""
    if row["type"] not in (ROW_FEATURE, ROW_CHOICE):
        return False
    return needle in row["text"].lower()


def visible_indices(rows, filter_text=""):
    """Return the row indices the list paints, top to bottom.

    Unfiltered, every header shows and the rows it owns follow unless it
    is collapsed. Filtered, only matching feature and choice rows survive
    along with the headers owning them — collapsed headers included,
    because a search that quietly skipped folded sections would be worse
    than no search at all.
    """
    needle = filter_text.strip().lower()
    out = []
    idx = 0
    while idx < len(rows):
        if rows[idx]["type"] != ROW_HEADER:
            out.append(idx)
            idx += 1
            continue
        start, end = header_span(rows, idx)
        if needle:
            matched = [i for i in range(start, end)
                       if row_matches_filter(rows[i], needle)]
            if matched:
                out.append(idx)
                out.extend(matched)
        else:
            out.append(idx)
            if not rows[idx].get("collapsed", False):
                out.extend(range(start, end))
        idx = end
    return out


def resolve_cursor(sel, cursor_idx):
    """Return the (position, row index) of the nearest selectable row.

    Folding a section or narrowing the filter can delete the row the
    cursor was sitting on; land on the closest survivor so the highlight
    never points at something the screen is not painting. With nothing
    selectable at all — a filter matching zero rows — the row index comes
    back as -1.
    """
    if not sel:
        return 0, -1
    if cursor_idx in sel:
        return sel.index(cursor_idx), cursor_idx
    pos = min(range(len(sel)), key=lambda i: (abs(sel[i] - cursor_idx), sel[i]))
    return pos, sel[pos]


def viewport_rows(stdscr):
    """Return how many list rows fit between the hints and the buttons."""
    max_y, _ = stdscr.getmaxyx()
    return max(1, (max_y - 4) - 2)


def clamp_scroll(rows, vis, scroll_offset, cursor_vpos, visible_count):
    """Clamp the viewport offset against the VISIBLE row list.

    scroll_offset counts positions in `vis`, not rows[]: collapse and
    filtering change how many rows the list paints on nearly every
    keystroke, so clamping against len(rows) would let a folded list
    scroll off the end of itself.
    """
    if cursor_vpos >= 0:
        if cursor_vpos < scroll_offset:
            scroll_offset = cursor_vpos
        if cursor_vpos >= scroll_offset + visible_count:
            scroll_offset = cursor_vpos - visible_count + 1
        # Keep the owning header on screen when the cursor sits under it.
        if (cursor_vpos > 0
                and rows[vis[cursor_vpos - 1]]["type"] == ROW_HEADER
                and cursor_vpos - 1 < scroll_offset):
            scroll_offset = cursor_vpos - 1
    return max(0, min(scroll_offset, max(0, len(vis) - visible_count)))


def selectable_indices(rows, filter_text=""):
    """Return list of row indices that can receive cursor focus.

    Headers are selectable now that Space/Enter folds them. Rows hidden
    by a collapsed header or by the filter are not, so the cursor cannot
    land on a row the list is not painting.
    """
    return [i for i in visible_indices(rows, filter_text)
            if rows[i]["type"] in SELECTABLE_TYPES]


def draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
         status_msg, status_ok, install_method="",
         prompt_label="", prompt_buf="", prompt_cur=0, filter_text=""):
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

    vis = visible_indices(rows, filter_text)
    needle = filter_text.strip()
    if needle:
        matches = sum(1 for i in vis if rows[i]["type"] != ROW_HEADER)
        plural = "" if matches == 1 else "es"
        hint = f" Filter: {needle}   {matches} match{plural}   [Esc] Clear "
    else:
        hint = " [Space/Enter] Toggle  [/] Search  [Q] Quit  [?] Help "
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
        vpos = vi + scroll_offset
        if vpos >= len(vis):
            break
        ri = vis[vpos]
        row = rows[ri]
        y = list_start_y + vi
        if y >= max_y - 3:
            break

        is_cursor = (focus == FOCUS_LIST and ri == cursor_idx)

        line = ""
        attr = curses.color_pair(CP_NORMAL)

        if row["type"] == ROW_HEADER:
            attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
            open_glyph, shut_glyph = disclosure_glyphs()
            # A filtered section is force-shown whatever its fold state,
            # so draw it open: the marker describes what is on screen.
            folded = row.get("collapsed", False) and not needle
            marker = shut_glyph if folded else open_glyph
            line = f"{marker} {row['text']}"
            on_count, total = header_counts(rows, ri)
            if total:
                counter = f"{on_count}/{total} on"
                line = line.ljust(max(len(line) + 2,
                                      usable_w - len(counter) - 2)) + counter
        elif row["type"] == ROW_FEATURE:
            mark = "x" if row["checked"] else " "
            line = f"    [{mark}] {row['text']}"
            if row["checked"]:
                attr = curses.color_pair(CP_CHECKED)
            else:
                attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_CHOICE:
            label = row["choices"][row["selected"]][0]
            line = f"    {row['text']}: < {label} >"
            if row["selected"] > 0:
                attr = curses.color_pair(CP_CHECKED)
            else:
                attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS:
            current = row["options"][row["selected"]]
            line = f"    < {current} >"
            attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl_active = current_dns_mode in ("custom", "secure")
            val = row["value"] if row["value"] else ""
            if tmpl_active:
                field_w = max(10, usable_w - 22)
                # The stored offset was computed against whatever width the
                # terminal had when the user last typed; re-derive it for
                # the current field so a resize can't strand the text.
                scroll = max(0, min(row.get("scroll", 0), len(val)))
                cur_pos = row.get("cursor", 0)
                if cur_pos - scroll >= field_w:
                    scroll = cur_pos - field_w + 1
                elif cur_pos < scroll:
                    scroll = cur_pos
                row["scroll"] = scroll
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
            field_w = max(10, usable_w - 22)
            scroll = row.get("scroll", 0)
            cur_pos = row.get("cursor", 0)
            cur_screen_pos = field_start + cur_pos - scroll
            # Stay inside the bracketed field, not just inside the line.
            if field_start <= cur_screen_pos < min(usable_w, field_start + field_w):
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
    if scroll_offset + visible_count < len(vis):
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


HELP_LINES = [
    " SlimBrave Neo - keys",
    "",
    "   Up / Down             Move the cursor",
    "   PageUp / PageDown     Move one screenful",
    "   Home / End            Jump to the first / last row",
    "   Space / Enter         Toggle a setting; fold or unfold a section",
    "   Left / Right          Cycle a selector; fold / unfold a section",
    "   c                     Fold every section, or unfold them all",
    "   /                     Filter rows by name",
    "   Esc                   Clear the filter, else quit",
    "   ?                     This help",
    "   Tab                   Jump to the button row",
    "   Q                     Quit",
    "",
    "   Press any key to close.",
]


def draw_help(stdscr):
    """Paint the key-binding overlay over the whole screen."""
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1
    for i, text in enumerate(HELP_LINES):
        if i >= max_y:
            break
        if i == 0:
            attr = curses.color_pair(CP_TITLE) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_NORMAL)
        try:
            stdscr.addnstr(i, 0, text.ljust(usable_w), usable_w, attr)
        except curses.error:
            pass
    stdscr.refresh()


def prompt_text_input(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                      install_method, label, default="", on_change=None):
    """Show a status-line text prompt and return (ok, text) on Enter.

    `on_change` is the live-filter hook: it is handed the buffer after
    every edit and returns the (cursor_idx, scroll_offset) to draw the
    list behind the prompt with, so matches narrow as the query is
    typed rather than only once it is submitted. Passing it also feeds
    the buffer to draw() as the active filter.
    """
    buf = list(default)
    cur = len(buf)
    shown = None

    while True:
        text = "".join(buf)
        if on_change is not None and text != shown:
            cursor_idx, scroll_offset = on_change(text)
            shown = text

        draw(stdscr, rows, cursor_idx, scroll_offset,
             FOCUS_PROMPT, btn_idx, "", True, install_method,
             prompt_label=label, prompt_buf=text, prompt_cur=cur,
             filter_text="" if on_change is None else text)

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

    # Fold what is not in use, then re-derive the selectable list: the
    # cursor must never start on a row the fold just hid.
    apply_startup_collapse(rows)
    sel = selectable_indices(rows)
    if not sel:
        return

    cursor_pos = 0
    # Land on the first real setting rather than the header above it, so
    # launch looks the way it did before headers became selectable.
    cursor_idx = next((i for i in sel if rows[i]["type"] != ROW_HEADER),
                      sel[0])
    scroll_offset = 0
    focus = FOCUS_LIST
    btn_idx = 0
    # The live filter, and the fold state Esc has to put back.
    filter_text = ""
    saved_collapse = None

    if brave_info["warnings"]:
        status_msg = brave_info["warnings"][0]
        # Both warnings (Snap confinement, Brave not found) are problems —
        # neither belongs in the success color.
        status_ok = False
    else:
        status_msg = ""
        status_ok = True

    while True:
        visible_count = viewport_rows(stdscr)
        # Recomputed every pass: a fold, a filter keystroke or an import can
        # change what is on screen between one getch() and the next.
        vis = visible_indices(rows, filter_text)
        sel = selectable_indices(rows, filter_text)
        cursor_pos, cursor_idx = resolve_cursor(sel, cursor_idx)
        cursor_vpos = vis.index(cursor_idx) if cursor_idx in vis else -1
        scroll_offset = clamp_scroll(rows, vis, scroll_offset,
                                     cursor_vpos, visible_count)

        draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
             status_msg, status_ok, install_method, filter_text=filter_text)

        key = stdscr.getch()
        if key == curses.KEY_RESIZE:
            curses.update_lines_cols()
            continue
        # A filter matching nothing leaves the cursor on no row at all; NO_ROW
        # matches no branch below, so every one of them falls through.
        row = rows[cursor_idx] if 0 <= cursor_idx < len(rows) else NO_ROW

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

        if key == 27:
            # Esc is the filter's cancel first and the quit key second.
            if filter_text:
                filter_text = ""
                restore_collapse_state(rows, saved_collapse)
                saved_collapse = None
                status_msg = ""
                continue
            break

        elif key == ord("q"):
            break

        elif key == curses.KEY_UP:
            if focus == FOCUS_LIST:
                if cursor_pos > 0:
                    cursor_pos -= 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                focus = FOCUS_LIST
                # sel is empty when the filter matches nothing, and
                # sel[-1] would be an IndexError rather than a no-op.
                if sel:
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

        elif key in (curses.KEY_PPAGE, curses.KEY_NPAGE):
            if focus == FOCUS_LIST and sel:
                step = visible_count
                if key == curses.KEY_PPAGE:
                    step = -visible_count
                cursor_pos = max(0, min(len(sel) - 1, cursor_pos + step))
                cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == curses.KEY_HOME:
            if focus == FOCUS_LIST and sel:
                cursor_pos = 0
                cursor_idx = sel[0]
                scroll_offset = 0
                status_msg = ""

        elif key == curses.KEY_END:
            if focus == FOCUS_LIST and sel:
                cursor_pos = len(sel) - 1
                cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == ord("c"):
            # Fold every section unless every section is already folded.
            headers = [r for r in rows if r["type"] == ROW_HEADER]
            fold = any(not h.get("collapsed", False) for h in headers)
            for header in headers:
                header["collapsed"] = fold
            status_msg = ""

        elif key == ord("?"):
            while True:
                draw_help(stdscr)
                if stdscr.getch() != curses.KEY_RESIZE:
                    break
                curses.update_lines_cols()
            status_msg = ""

        elif key == ord("/"):
            focus = FOCUS_LIST
            if not filter_text:
                # Snapshot on the way in only: reopening the prompt over a
                # live filter must not overwrite what Esc has to restore.
                saved_collapse = collapse_state(rows)

            def preview(text):
                """Re-aim the viewport at the shrinking match set."""
                new_vis = visible_indices(rows, text)
                new_sel = selectable_indices(rows, text)
                _, idx = resolve_cursor(new_sel, cursor_idx)
                vpos = new_vis.index(idx) if idx in new_vis else -1
                return idx, clamp_scroll(rows, new_vis, scroll_offset,
                                         vpos, visible_count)

            ok, text = prompt_text_input(
                stdscr, rows, cursor_idx, scroll_offset,
                btn_idx, install_method,
                "Filter (Esc=clear)",
                default=filter_text, on_change=preview)
            if ok:
                filter_text = text
            else:
                filter_text = ""
                restore_collapse_state(rows, saved_collapse)
                saved_collapse = None
            status_msg = ""

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
                if row["type"] == ROW_HEADER:
                    row["collapsed"] = True
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] - 1) % len(row["options"])
                    status_msg = ""
                elif row["type"] == ROW_CHOICE:
                    cycle_choice_row(row, -1)
                    status_msg = ""

        elif key == curses.KEY_RIGHT:
            if focus == FOCUS_BUTTONS:
                btn_idx = min(len(BUTTONS) - 1, btn_idx + 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_HEADER:
                    row["collapsed"] = False
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""
                elif row["type"] == ROW_CHOICE:
                    cycle_choice_row(row, 1)
                    status_msg = ""

        elif key == ord(" "):
            if focus == FOCUS_LIST and activate_row(rows, row):
                status_msg = ""

        elif key in (curses.KEY_ENTER, 10, 13):
            if focus == FOCUS_BUTTONS:
                btn_label = BUTTONS[btn_idx]

                if btn_label == "Apply":
                    dns_mode = get_dns_mode(rows)
                    dns_tmpl = get_dns_template(rows)
                    if dns_mode in ("custom", "secure") and not dns_tmpl:
                        status_msg = "Secure/custom DNS requires a DoH template URL."
                        status_ok = False
                    else:
                        status_ok, status_msg = apply_policy(rows, installations)

                elif btn_label == "Reset":
                    status_msg = ("Reset all settings? "
                                  "Press Enter to confirm, any key to cancel.")
                    status_ok = True
                    draw(stdscr, rows, cursor_idx, scroll_offset,
                         focus, btn_idx, status_msg, status_ok,
                         install_method, filter_text=filter_text)
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
                if activate_row(rows, row):
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

    # A template is inert unless the mode asks for one, and most presets
    # carry no DnsMode at all — promote those rather than dropping the flag
    # silently. "automatic" keeps its mode (Chromium honours a template
    # there); "off" is a contradiction only the caller can resolve.
    if doh_templates:
        dns_mode = get_dns_mode(rows)
        if dns_mode == "off":
            print(
                "Error: --doh-templates conflicts with DnsMode 'off' in "
                f"{path}. Remove one of them.",
                file=sys.stderr,
            )
            return 1
        for row in rows:
            if row["type"] == ROW_DNS and dns_mode == "unmanaged":
                row["selected"] = row["options"].index("custom")
            elif row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = doh_templates
                row["cursor"] = len(doh_templates)
                row["scroll"] = 0

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
    if repaired > 0 and not running:
        print(
            f"Cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''} from Brave's user profile."
        )
    if running:
        print(
            "Note: Brave is running — any leaked profile prefs cleaned now "
            "will be overwritten when Brave next saves. Fully close Brave "
            "and run --reset again to make it stick."
        )
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

    # --doh-templates is only ever read by cli_import; --reset, --export and
    # the TUI would drop it without a word.
    if args.doh_templates and not args.import_path:
        print("Error: --doh-templates requires --import", file=sys.stderr)
        sys.exit(2)

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

        # Accumulate so a later success cannot mask an earlier failure
        # (e.g. --reset failing followed by a clean --import).
        rc = 0
        if args.reset:
            rc = max(rc, cli_reset(installations))
        if args.import_path:
            rc = max(rc, cli_import(args.import_path, installations,
                                    doh_templates=args.doh_templates or ""))
        if args.export_path:
            rc = max(rc, cli_export(args.export_path, installations))
        sys.exit(rc)

    try:
        curses.wrapper(lambda s: main(s, override_installations))
    except KeyboardInterrupt:
        pass
