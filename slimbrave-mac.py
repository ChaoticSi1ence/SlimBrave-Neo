#!/usr/bin/env python3
"""SlimBrave Neo - Linux and macOS TUI for debloating and hardening Brave Browser.

Sets Chromium enterprise policies via JSON files on Linux or Plist on macOS. Requires root (sudo).

Multi-channel support:
  - macOS: each Brave channel (Stable / Beta / Nightly) has its own bundle
    ID and Managed Preferences plist. When more than one channel is
    detected, the TUI shows a Channels selector so policies can be applied
    per channel; CLI --channels=stable,beta selects the same.
  - Linux: all Brave channels share /etc/brave/policies/managed (hardcoded
    in brave-core), so a single policy file applies to all of them. The
    per-channel info is used to scrub leaked prefs from each channel's
    user-data directory and to detect running channels.

Supports interactive curses TUI and non-interactive CLI usage:
  sudo python3 slimbrave.py                              # TUI
  sudo python3 slimbrave.py --import preset.json         # CLI import
  sudo python3 slimbrave.py --export out.json            # CLI export
  sudo python3 slimbrave.py --reset                      # CLI reset
  sudo python3 slimbrave.py --channels stable,beta ...   # restrict (macOS)
"""

import argparse
import curses
import json
import os
import shutil
import subprocess
import sys
import tempfile

IS_MAC = sys.platform == "darwin"
if IS_MAC:
    import plistlib
    import uuid
    POLICY_DIR = "/Library/Managed Preferences"
    POLICY_FILE = os.path.join(POLICY_DIR, "com.brave.Browser.plist")
    # Directories a `--policy-file` argument is permitted to target on macOS.
    # Allowed locations mirror the documented Chromium managed-policy paths.
    ALLOWED_POLICY_DIRS = (
        "/Library/Managed Preferences",
        "/Library/Preferences",
    )

    # Persistence on modern macOS (Apple Silicon / 13+):
    # cfprefsd / mdmclient may clear directly-written /Library/Managed
    # Preferences/*.plist files at reboot when no matching configuration
    # profile is installed. With persist=on, a Configuration Profile is
    # installed instead — Apple's recommended path. See README.
    PERSIST_MODES = ("off", "on")
    PERSIST_DEFAULT = "off"

    # Configuration Profile (mode=on) — single mobileconfig wraps every
    # selected channel's policies; one PayloadContent entry per channel.
    PERSIST_PROFILE_IDENTIFIER = "io.github.slimbrave-neo.brave-policy"
    PERSIST_PROFILE_DISPLAY = "SlimBrave Neo - Brave Policy"
    PERSIST_PROFILE_FILE = "/tmp/slimbrave-neo-policy.mobileconfig"
else:
    POLICY_DIR = "/etc/brave/policies/managed"
    POLICY_FILE = os.path.join(POLICY_DIR, "slimbrave.json")
    ALLOWED_POLICY_DIRS = (
        "/etc/brave/policies/managed",
        "/etc/chromium/policies/managed",
        "/etc/opt/chrome/policies/managed",
        "/etc/firefox/policies",
    )
    PERSIST_MODES = ("off",)
    PERSIST_DEFAULT = "off"

# Brave channel definitions. On macOS every channel ships with its own bundle
# ID and Managed Preferences plist file (verified against brave-core
# BRANDING.* and CFBundleIdentifier of installed apps). On Linux all channels
# read policies from /etc/brave/policies (hardcoded in
# brave-core/app/brave_main_delegate.cc), so the channel info is only used
# for prefs repair and process detection there.
MAC_CHANNELS = [
    {
        "id": "stable",
        "label": "Stable",
        "app_name": "Brave Browser.app",
        "bundle_id": "com.brave.Browser",
        "user_data_dir": "Brave-Browser",
        "process_name": "Brave Browser",
    },
    {
        "id": "beta",
        "label": "Beta",
        "app_name": "Brave Browser Beta.app",
        "bundle_id": "com.brave.Browser.beta",
        "user_data_dir": "Brave-Browser-Beta",
        "process_name": "Brave Browser Beta",
    },
    {
        "id": "nightly",
        "label": "Nightly",
        "app_name": "Brave Browser Nightly.app",
        "bundle_id": "com.brave.Browser.nightly",
        "user_data_dir": "Brave-Browser-Nightly",
        "process_name": "Brave Browser Nightly",
    },
]

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

CHANNEL_IDS = [c["id"] for c in (MAC_CHANNELS if IS_MAC else LINUX_CHANNELS)]

# Google Chrome channels. Since Chrome 77 every macOS channel reads managed
# policy from the shared com.google.Chrome preference domain, so all
# channel entries deliberately carry the same bundle_id — the plist-target
# dedupe collapses them into one write.
CHROME_MAC_CHANNELS = [
    {"id": "stable", "label": "Stable", "app_name": "Google Chrome.app",
     "bundle_id": "com.google.Chrome", "user_data_dir": "Chrome",
     "process_name": "Google Chrome"},
    {"id": "beta", "label": "Beta", "app_name": "Google Chrome Beta.app",
     "bundle_id": "com.google.Chrome", "user_data_dir": "Chrome Beta",
     "process_name": "Google Chrome Beta"},
    {"id": "dev", "label": "Dev", "app_name": "Google Chrome Dev.app",
     "bundle_id": "com.google.Chrome", "user_data_dir": "Chrome Dev",
     "process_name": "Google Chrome Dev"},
    {"id": "canary", "label": "Canary", "app_name": "Google Chrome Canary.app",
     "bundle_id": "com.google.Chrome", "user_data_dir": "Chrome Canary",
     "process_name": "Google Chrome Canary"},
]

CHROME_LINUX_CHANNELS = [
    {"id": "stable", "label": "Stable",
     "user_data_dir": "google-chrome", "process_name": "chrome"},
    {"id": "beta", "label": "Beta",
     "user_data_dir": "google-chrome-beta", "process_name": "chrome"},
    {"id": "unstable", "label": "Unstable",
     "user_data_dir": "google-chrome-unstable", "process_name": "chrome"},
]

# Microsoft Edge channels. Per Microsoft's macOS deployment docs, every
# Edge channel reads from the shared com.microsoft.Edge preference domain
# (channel-specific domains were retired in the Edge 77 betas).
EDGE_MAC_CHANNELS = [
    {"id": "stable", "label": "Stable", "app_name": "Microsoft Edge.app",
     "bundle_id": "com.microsoft.Edge", "user_data_dir": "Microsoft Edge",
     "process_name": "Microsoft Edge"},
    {"id": "beta", "label": "Beta", "app_name": "Microsoft Edge Beta.app",
     "bundle_id": "com.microsoft.Edge", "user_data_dir": "Microsoft Edge Beta",
     "process_name": "Microsoft Edge Beta"},
    {"id": "dev", "label": "Dev", "app_name": "Microsoft Edge Dev.app",
     "bundle_id": "com.microsoft.Edge", "user_data_dir": "Microsoft Edge Dev",
     "process_name": "Microsoft Edge Dev"},
    {"id": "canary", "label": "Canary", "app_name": "Microsoft Edge Canary.app",
     "bundle_id": "com.microsoft.Edge", "user_data_dir": "Microsoft Edge Canary",
     "process_name": "Microsoft Edge Canary"},
]

# Mozilla Firefox channels. Firefox reads managed preferences from its own
# bundle's preference domain on macOS (plus EnterprisePoliciesEnabled=true
# to activate the policy engine); Developer Edition and Nightly have their
# own domains, like Brave's channels.
FIREFOX_MAC_CHANNELS = [
    {"id": "stable", "label": "Stable", "app_name": "Firefox.app",
     "bundle_id": "org.mozilla.firefox", "user_data_dir": "Firefox",
     "process_name": "firefox"},
    {"id": "developer", "label": "Developer Edition",
     "app_name": "Firefox Developer Edition.app",
     "bundle_id": "org.mozilla.firefoxdeveloperedition", "user_data_dir": "Firefox",
     "process_name": "firefox"},
    {"id": "nightly", "label": "Nightly", "app_name": "Firefox Nightly.app",
     "bundle_id": "org.mozilla.nightly", "user_data_dir": "Firefox",
     "process_name": "firefox"},
]

FIREFOX_LINUX_CHANNELS = [
    {"id": "stable", "label": "Stable",
     "user_data_dir": "firefox", "process_name": "firefox"},
    {"id": "esr", "label": "ESR",
     "user_data_dir": "firefox", "process_name": "firefox-esr"},
]

# ---------------------------------------------------------------------------
# Browser registry
#
# All three speak the Chromium managed-policy dialect; only locations,
# channel layouts, and vendor keys differ. Feature rows and categories
# carry an optional "browsers" tuple; untagged entries apply everywhere.
# Edge has no Linux entry: Microsoft's per-policy docs list Windows and
# macOS only, so a Linux Edge catalog cannot be audited.
# ---------------------------------------------------------------------------

BROWSERS = {
    "brave": {
        "label": "Brave",
        "engine": "chromium",
        "mac_channels": MAC_CHANNELS,
        "linux_channels": LINUX_CHANNELS,
        "config_root": "BraveSoftware",
        "linux_policy_dir": "/etc/brave/policies/managed",
        "prefs_repair": True,
        "profile_identifier": "io.github.slimbrave-neo.brave-policy",
        "profile_display": "SlimBrave Neo - Brave Policy",
    },
    "chrome": {
        "label": "Google Chrome",
        "engine": "chromium",
        "mac_channels": CHROME_MAC_CHANNELS,
        "linux_channels": CHROME_LINUX_CHANNELS,
        "config_root": "Google",
        "linux_policy_dir": "/etc/opt/chrome/policies/managed",
        "prefs_repair": False,
        "profile_identifier": "io.github.slimbrave-neo.chrome-policy",
        "profile_display": "SlimBrave Neo - Google Chrome Policy",
    },
    "edge": {
        "label": "Microsoft Edge",
        "engine": "chromium",
        "mac_channels": EDGE_MAC_CHANNELS,
        "linux_channels": None,   # unsupported: no auditable policy source
        "config_root": "",
        "linux_policy_dir": None,
        "prefs_repair": False,
        "profile_identifier": "io.github.slimbrave-neo.edge-policy",
        "profile_display": "SlimBrave Neo - Microsoft Edge Policy",
    },
    "firefox": {
        "label": "Mozilla Firefox",
        "engine": "firefox",
        "mac_channels": FIREFOX_MAC_CHANNELS,
        "linux_channels": FIREFOX_LINUX_CHANNELS,
        "config_root": "",
        "linux_policy_dir": "/etc/firefox/policies",
        "linux_policy_file": "policies.json",
        "prefs_repair": False,
        "profile_identifier": "io.github.slimbrave-neo.firefox-policy",
        "profile_display": "SlimBrave Neo - Mozilla Firefox Policy",
    },
}

# Untagged catalog rows apply to every Chromium-engine browser; Firefox
# speaks a different policy dialect, so its rows are always tagged.
CHROMIUM_BROWSERS = tuple(
    name for name, cfg in BROWSERS.items() if cfg["engine"] == "chromium"
)

SELECTED_BROWSER = "brave"


def browser_config():
    return BROWSERS[SELECTED_BROWSER]


def browser_label():
    return browser_config()["label"]


def browser_engine():
    return browser_config()["engine"]


def _browser_channels(cfg=None):
    cfg = cfg or browser_config()
    return cfg["mac_channels"] if IS_MAC else cfg["linux_channels"]


def select_browser(name):
    """Point module-level paths and persistence identifiers at a browser."""
    global SELECTED_BROWSER, POLICY_DIR, POLICY_FILE
    global PERSIST_PROFILE_IDENTIFIER, PERSIST_PROFILE_DISPLAY, PERSIST_PROFILE_FILE
    cfg = BROWSERS[name]
    if not IS_MAC and cfg["linux_policy_dir"] is None:
        raise SystemExit(f"{cfg['label']} is not supported on Linux.")
    SELECTED_BROWSER = name
    if IS_MAC:
        POLICY_FILE = os.path.join(
            POLICY_DIR, f"{cfg['mac_channels'][0]['bundle_id']}.plist")
        PERSIST_PROFILE_IDENTIFIER = cfg["profile_identifier"]
        PERSIST_PROFILE_DISPLAY = cfg["profile_display"]
        PERSIST_PROFILE_FILE = f"/tmp/slimbrave-neo-{name}-policy.mobileconfig"
    else:
        POLICY_DIR = cfg["linux_policy_dir"]
        POLICY_FILE = os.path.join(
            POLICY_DIR, cfg.get("linux_policy_file", "slimbrave.json"))


def _user_home_for_brave():
    """Return the home directory of the real user (the one running sudo).

    Brave's profile lives under the invoking user's home, not root's.
    Returns None when we can't determine it.
    """
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


def _mac_app_search_paths(app_name):
    """Possible locations for a Brave app bundle (system + per-user)."""
    paths = [f"/Applications/{app_name}"]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        paths.append(f"/Users/{sudo_user}/Applications/{app_name}")
    else:
        paths.append(os.path.expanduser(f"~/Applications/{app_name}"))
    return paths


def _channel_prefs_path(user_data_dir):
    """Return the Default profile Preferences path for a channel."""
    home = _user_home_for_brave()
    if not home:
        return None
    root = browser_config()["config_root"]
    if IS_MAC:
        parts = [home, "Library", "Application Support"]
    else:
        parts = [home, ".config"]
    if root:
        parts.append(root)
    return os.path.join(*parts, user_data_dir, "Default", "Preferences")


def _flatpak_prefs_path():
    """Return the Flatpak Brave's Default profile Preferences path (Linux).

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
    """Return True if `path`'s realpath lives under an allowed policy dir.

    Prevents `--policy-file /etc/shadow --reset` (run under a permissive
    sudoers rule) from deleting arbitrary files. Chromium only reads
    policies from the paths in ALLOWED_POLICY_DIRS anyway.
    """
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
    exist there. Also avoids leaving a half-written policy if the
    process is killed mid-write.
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
    """Build an installation record from a channel definition + per-OS paths."""
    return {
        "channel": channel_def["id"],
        "label": channel_def["label"],
        "app_path": app_path,
        "bundle_id": channel_def.get("bundle_id", ""),
        "plist_path": plist_path,
        "prefs_path": prefs_path,
        "process_name": channel_def["process_name"],
        "user_data_dir": channel_def["user_data_dir"],
    }


def detect_brave():
    """Detect Brave browser installation(s) and packaging method.

    Returns a dict with keys:
        found (bool)        - whether any Brave install was located
        method (str)        - packaging label, e.g. "macOS App: Stable, Beta"
        path (str)          - canonical path of the primary install (legacy)
        warnings (list)     - human-readable warnings
        installations (list)- one entry per detected channel, each with
                              channel/label/app_path/bundle_id/plist_path/
                              prefs_path/process_name/user_data_dir
    """
    if IS_MAC:
        installations = []
        for ch in _browser_channels():
            for app_path in _mac_app_search_paths(ch["app_name"]):
                if os.path.isdir(app_path):
                    installations.append(_make_installation(
                        ch,
                        app_path=app_path,
                        plist_path=os.path.join(POLICY_DIR, f"{ch['bundle_id']}.plist"),
                        prefs_path=_channel_prefs_path(ch["user_data_dir"]),
                    ))
                    break

        if not installations:
            stable = _browser_channels()[0]
            return {
                "found": False,
                "method": "not found",
                "path": "",
                "warnings": [
                    f"{browser_label()} not found. Policies will be written but may have no effect."
                ],
                "installations": [_make_installation(
                    stable,
                    app_path="",
                    plist_path=os.path.join(POLICY_DIR, f"{stable['bundle_id']}.plist"),
                    prefs_path=_channel_prefs_path(stable["user_data_dir"]),
                )],
            }

        if len(installations) == 1:
            method = "macOS App"
        else:
            method = "macOS App: " + ", ".join(i["label"] for i in installations)
        return {
            "found": True,
            "method": method,
            "path": installations[0]["app_path"],
            "warnings": [],
            "installations": installations,
        }

    # ---- Linux ----
    method = None
    primary_path = ""
    warnings = []
    found_any = False

    if SELECTED_BROWSER == "chrome":
        native_paths = ("/opt/google/chrome/google-chrome", "/opt/google/chrome/chrome")
        flatpak_id = "com.google.Chrome"
        path_names = ("google-chrome-stable", "google-chrome", "chrome")
        snap_root = None
    elif SELECTED_BROWSER == "firefox":
        native_paths = ("/usr/lib/firefox/firefox", "/opt/firefox/firefox",
                        "/usr/lib64/firefox/firefox")
        flatpak_id = "org.mozilla.firefox"
        path_names = ("firefox", "firefox-esr")
        snap_root = "/snap/firefox/current"
    else:
        native_paths = (
            "/opt/brave-bin/brave",                  # Arch (brave-bin AUR)
            "/opt/brave.com/brave/brave-browser",    # official deb/rpm
            "/opt/brave.com/brave/brave",
        )
        flatpak_id = "com.brave.Browser"
        path_names = ("brave-browser-stable", "brave-browser", "brave")
        snap_root = "/snap/brave/current"

    for np in native_paths:
        if os.path.isfile(np):
            label = "arch" if np == "/opt/brave-bin/brave" else "deb/rpm"
            method, primary_path, found_any = label, np, True
            break
    if not found_any:
        try:
            result = subprocess.run(
                ["flatpak", "info", flatpak_id],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                method, primary_path, found_any = "flatpak", flatpak_id, True
        except FileNotFoundError:
            pass  # flatpak not installed

    if not found_any and snap_root:
        snap_path = snap_root + "/opt/brave.com/brave/brave"
        if os.path.isfile(snap_path) or os.path.isdir(snap_root):
            method, primary_path, found_any = "snap", snap_path, True
            warnings.append(
                "Snap confinement may prevent policies from taking effect. "
                "Native packages are recommended."
            )

    if not found_any:
        for name in path_names:
            found = shutil.which(name)
            if found:
                method, primary_path, found_any = "unknown", found, True
                break

    if not found_any:
        method = "not found"
        warnings.append(
            f"{browser_label()} not found. Policies will be written but may have no effect."
        )

    # Detect installed Linux channels by user-data dir presence (best effort).
    # On Linux all channels share POLICY_FILE, so installations is used only
    # for prefs repair and "is Brave running" checks.
    installations = []
    home = _user_home_for_brave()
    detected_labels = []
    for ch in _browser_channels():
        ch_dir = (
            os.path.join(
                home, ".config",
                *( [browser_config()["config_root"]]
                   if browser_config()["config_root"] else [] ),
                ch["user_data_dir"])
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
    flatpak_prefs = _flatpak_prefs_path() if SELECTED_BROWSER == "brave" else None
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
        # Nothing detected per-channel — fall back to a single stable record so
        # apply/reset still has a target plist.
        stable = _browser_channels()[0]
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
# DefaultBraveReferrersSetting) and for the Shields URL lists.
CATEGORIES = [
    {
        "name": "Telemetry & Reporting",
        "features": [
            {"name": "Disable Metrics Reporting", "key": "MetricsReportingEnabled", "value": False, "browsers": ("brave", "chrome")},
            {"name": "Disable Safe Browsing Reporting", "key": "SafeBrowsingExtendedReportingEnabled", "value": False, "browsers": ("brave", "chrome")},
            {"name": "Disable URL Data Collection", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False, "browsers": ("brave", "chrome")},
            {"name": "Disable P3A Analytics", "key": "BraveP3AEnabled", "value": False, "browsers": ("brave",)},
            {"name": "Disable Stats Ping", "key": "BraveStatsPingEnabled", "value": False, "browsers": ("brave",)},
        ],
    },
    {
        "name": "Privacy & Security",
        "features": [
            {"name": "Disable Safe Browsing", "key": "SafeBrowsingProtectionLevel", "value": 0, "browsers": ("brave", "chrome")},
            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False},
            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False},
            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False},
            {"name": "Disable Password Leak Detection", "key": "PasswordLeakDetectionEnabled", "value": False, "browsers": ("brave", "chrome")},
            {"name": "Disable Browser Sign-in", "key": "BrowserSignin", "value": 0},
            {"name": "Disable Sync", "key": "SyncDisabled", "value": True},
            {"name": "Enable Global Privacy Control", "key": "BraveGlobalPrivacyControlEnabled", "value": True, "browsers": ("brave",)},
            {"name": "Enable De-AMP", "key": "BraveDeAmpEnabled", "value": True, "browsers": ("brave",)},
            {"name": "Enable Debouncing", "key": "BraveDebouncingEnabled", "value": True, "browsers": ("brave",)},
            {"name": "Strip Tracking URL Parameters", "key": "BraveTrackingQueryParametersFilteringEnabled", "value": True, "browsers": ("brave",)},
            {"name": "Reduce Language Fingerprinting", "key": "BraveReduceLanguageEnabled", "value": True, "browsers": ("brave",)},
            {"name": "Disable WebRTC IP Leak", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp", "browsers": ("brave", "chrome")},
            {"name": "Disable QUIC Protocol", "key": "QuicAllowed", "value": False},
            {"name": "Disable Network Prediction (Prefetch)", "key": "NetworkPredictionOptions", "value": 2},
            {"name": "Block Third Party Cookies", "key": "BlockThirdPartyCookies", "value": True},
            {"name": "Block Payment Method Probing", "key": "PaymentMethodQueryEnabled", "value": False},
            {"name": "Disable Alternate Error Pages", "key": "AlternateErrorPagesEnabled", "value": False},
        ],
    },
    {
        # Site permissions and access lockdowns: content-setting defaults
        # plus the escape hatches (guest, incognito, extensions) that would
        # otherwise bypass the rest of the policy set.
        "name": "Permissions & Access",
        "features": [
            {"name": "Block Web Notifications", "key": "DefaultNotificationsSetting", "value": 2},
            {"name": "Block Location Access", "key": "DefaultGeolocationSetting", "value": 2},
            {"name": "Block Motion Sensors", "key": "DefaultSensorsSetting", "value": 2},
            {"name": "Force Google SafeSearch", "key": "ForceGoogleSafeSearch", "value": True},
            {"name": "Filter Adult Content (SafeSites)", "key": "SafeSitesFilterBehavior", "value": 1, "browsers": ("brave", "chrome")},
            {"name": "Disable Guest Mode", "key": "BrowserGuestModeEnabled", "value": False},
            {"name": "Block All Extensions", "key": "ExtensionInstallBlocklist", "value": ["*"]},
            {"name": "Disable Incognito Mode", "key": "IncognitoModeAvailability", "value": 1, "group": "incognito", "browsers": ("brave", "chrome")},
            {"name": "Force Incognito Mode", "key": "IncognitoModeAvailability", "value": 2, "group": "incognito", "browsers": ("brave", "chrome")},
        ],
    },
    {
        "name": "Brave Features",
        "browsers": ("brave",),
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
            {"name": "Disable Email Aliases", "key": "EmailAliasesEnabled", "value": False},
        ],
    },
    {
        # Brave 1.83+ content-protection enforcers. These pin Brave's own
        # privacy defaults as managed policy so neither the user nor a
        # malicious page/extension can quietly weaken them.
        "name": "Shields & Content Protection",
        "browsers": ("brave",),
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
        # Chrome-only keys, verified against Chromium policy_definitions
        # YAML (see AUDIT.md). GeminiSettings is supported on chrome.win /
        # chrome.mac only, which this script covers.
        "name": "Chrome Features",
        "browsers": ("chrome",),
        "features": [
            {"name": "Disable Feedback Collection", "key": "UserFeedbackAllowed", "value": False},
            {"name": "Disable Chrome Labs", "key": "BrowserLabsEnabled", "value": False},
            {"name": "Disable Search Side Panel", "key": "GoogleSearchSidePanelEnabled", "value": False},
            {"name": "Disable Gemini Integrations", "key": "GeminiSettings", "value": 1},
            {"name": "Restrict Field Trials (Critical Only)", "key": "ChromeVariations", "value": 1},
        ],
    },
    {
        # Edge-only keys, verified against Microsoft's per-policy Edge
        # documentation (see AUDIT.md). Includes Edge's renamed equivalents
        # of Chromium policies (InPrivate, WebRTC, SmartScreen, Password
        # Monitor, Efficiency Mode). StartupBoostEnabled and Spotlight are
        # Windows-only and deliberately absent here.
        "name": "Edge Features",
        "browsers": ("edge",),
        "features": [
            {"name": "Minimize Diagnostic Data", "key": "DiagnosticData", "value": 0},
            {"name": "Disable Personalization Reporting", "key": "PersonalizationReportingEnabled", "value": False},
            {"name": "Disable Feedback Collection", "key": "UserFeedbackAllowed", "value": False},
            {"name": "Disable Sidebar & Copilot Hub", "key": "HubsSidebarEnabled", "value": False},
            {"name": "Disable Collections", "key": "EdgeCollectionsEnabled", "value": False},
            {"name": "Disable Shopping Assistant", "key": "EdgeShoppingAssistantEnabled", "value": False},
            {"name": "Disable Microsoft Rewards", "key": "ShowMicrosoftRewards", "value": False},
            {"name": "Disable Wallet Checkout", "key": "EdgeWalletCheckoutEnabled", "value": False},
            {"name": "Disable New Tab MSN Feed", "key": "NewTabPageContentEnabled", "value": False},
            {"name": "Disable Asset Delivery Service", "key": "EdgeAssetDeliveryServiceEnabled", "value": False},
            {"name": "Enable Sleeping Tabs", "key": "SleepingTabsEnabled", "value": True},
            {"name": "Enable Efficiency Mode", "key": "EfficiencyModeEnabled", "value": True},
            {"name": "Disable SmartScreen", "key": "SmartScreenEnabled", "value": False},
            {"name": "Disable Password Monitor", "key": "PasswordMonitorAllowed", "value": False},
            {"name": "Disable WebRTC IP Leak (Edge)", "key": "WebRtcLocalhostIpHandling", "value": "disable_non_proxied_udp"},
            {"name": "Force Bing SafeSearch (Strict)", "key": "ForceBingSafeSearch", "value": 2},
            {"name": "Disable InPrivate Mode", "key": "InPrivateModeAvailability", "value": 1, "group": "incognito"},
            {"name": "Force InPrivate Mode", "key": "InPrivateModeAvailability", "value": 2, "group": "incognito"},
        ],
    },
    {
        # Note: BackgroundModeEnabled is intentionally absent here — the
        # Chromium policy is only supported on Windows and Linux, so on
        # macOS it would just surface as an unrecognized-policy error in
        # brave://policy.
        "name": "Performance & Bloat",
        "features": [
            {"name": "Enable Memory Saver", "key": "HighEfficiencyModeEnabled", "value": True, "browsers": ("brave", "chrome")},
            {"name": "Force Hardware Acceleration", "key": "HardwareAccelerationModeEnabled", "value": True},
            {"name": "Disable Media Router (Cast)", "key": "EnableMediaRouter", "value": False},
            {"name": "Disable Media Recommendations", "key": "MediaRecommendationsEnabled", "value": False, "browsers": ("brave", "chrome")},
            {"name": "Disable Shopping List", "key": "ShoppingListEnabled", "value": False, "browsers": ("brave", "chrome")},
            {"name": "Always Open PDF Externally", "key": "AlwaysOpenPdfExternally", "value": True},
            {"name": "Disable Translate", "key": "TranslateEnabled", "value": False},
            {"name": "Disable Spellcheck", "key": "SpellcheckEnabled", "value": False},
            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False},
            {"name": "Disable Printing", "key": "PrintingEnabled", "value": False},
            {"name": "Disable Default Browser Prompt", "key": "DefaultBrowserSettingEnabled", "value": False},
            {"name": "Disable Developer Tools", "key": "DeveloperToolsAvailability", "value": 2},
            {"name": "Disable Wayback Machine", "key": "BraveWaybackMachineEnabled", "value": False, "browsers": ("brave",)},
        ],
    },
    # ------------------------------------------------------------------
    # Mozilla Firefox catalog. Firefox speaks its own policy dialect
    # (policies.json / org.mozilla.firefox), so nothing above applies to
    # it; every row is verified against mozilla/enterprise-admin-reference
    # policies-schema.json (see AUDIT.md). Values may be nested objects —
    # the writers serialize them as-is.
    # ------------------------------------------------------------------
    {
        "name": "Telemetry & Reporting",
        "browsers": ("firefox",),
        "features": [
            {"name": "Disable Telemetry", "key": "DisableTelemetry", "value": True},
            {"name": "Disable Firefox Studies", "key": "DisableFirefoxStudies", "value": True},
            {"name": "Disable Feedback Commands", "key": "DisableFeedbackCommands", "value": True},
            {"name": "Disable Captive Portal Pings", "key": "CaptivePortal", "value": False},
        ],
    },
    {
        "name": "Privacy & Security",
        "browsers": ("firefox",),
        "features": [
            {"name": "Enforce Tracking Protection (Strict)", "key": "EnableTrackingProtection",
             "value": {"Value": True, "Locked": True, "Cryptomining": True,
                       "Fingerprinting": True, "EmailTracking": True}},
            {"name": "Force HTTPS-Only Mode", "key": "HttpsOnlyMode", "value": "force_enabled"},
            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False},
            {"name": "Disable Login Save Prompts", "key": "OfferToSaveLogins", "value": False},
            {"name": "Disable Form History", "key": "DisableFormHistory", "value": True},
            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False},
            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False},
            {"name": "Disable Firefox Accounts & Sync", "key": "DisableFirefoxAccounts", "value": True},
            {"name": "Disable Network Prediction (Prefetch)", "key": "NetworkPrediction", "value": False},
            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False},
        ],
    },
    {
        "name": "Permissions & Access",
        "browsers": ("firefox",),
        "features": [
            {"name": "Block Location & Notification Prompts", "key": "Permissions",
             "value": {"Location": {"BlockNewRequests": True, "Locked": True},
                       "Notifications": {"BlockNewRequests": True, "Locked": True}}},
            {"name": "Disable Private Browsing", "key": "DisablePrivateBrowsing", "value": True},
            {"name": "Block about:config", "key": "BlockAboutConfig", "value": True},
            {"name": "Block All Extensions", "key": "ExtensionSettings",
             "value": {"*": {"installation_mode": "blocked"}}},
        ],
    },
    {
        "name": "Firefox Features",
        "browsers": ("firefox",),
        "features": [
            {"name": "Disable Pocket", "key": "DisablePocket", "value": True},
            {"name": "Clean New Tab (No Sponsored Content)", "key": "FirefoxHome",
             "value": {"Search": True, "TopSites": True, "SponsoredTopSites": False,
                       "Highlights": False, "Pocket": False, "SponsoredPocket": False,
                       "Stories": False, "SponsoredStories": False, "Weather": False,
                       "Snippets": False, "Locked": True}},
            {"name": "Disable Recommendations & Onboarding", "key": "UserMessaging",
             "value": {"WhatsNew": False, "ExtensionRecommendations": False,
                       "FeatureRecommendations": False, "UrlbarInterventions": False,
                       "SkipOnboarding": True, "MoreFromMozilla": False,
                       "FirefoxLabs": False, "Locked": True}},
            {"name": "Disable AI Features", "key": "AIControls",
             "value": {"Default": {"Value": "blocked", "Locked": True}}},
        ],
    },
    {
        "name": "Performance & Bloat",
        "browsers": ("firefox",),
        "features": [
            {"name": "Force Hardware Acceleration", "key": "HardwareAcceleration", "value": True},
            {"name": "Disable Default Browser Prompt", "key": "DontCheckDefaultBrowser", "value": True},
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


def build_rows(installations=None):
    """Return a list of dicts describing each visual row.

    The main list shows feature toggles + the DNS section. On macOS,
    channel selection is asked at Apply time (see prompt_channel_selection)
    rather than as a permanent row, so the main list stays focused on the
    policies themselves regardless of how many channels are installed.
    `installations` is accepted for symmetry with callers but isn't used
    here anymore.
    """
    del installations  # kept for API stability; no longer affects layout
    browser = SELECTED_BROWSER
    rows = []
    for cat in CATEGORIES:
        cat_browsers = cat.get("browsers", CHROMIUM_BROWSERS)
        if browser not in cat_browsers:
            continue
        # Feature rows inherit their category's browser scope unless
        # they narrow it further with their own tag.
        feats = [f for f in cat["features"]
                 if browser in f.get("browsers", cat_browsers)]
        if not feats:
            continue
        rows.append({"type": ROW_HEADER, "text": cat["name"]})
        for feat in feats:
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
    """True if any of the listed Brave installations have a live process.

    When `installations` is None, falls back to the legacy single-channel
    process name (Stable on each platform), preserving old behaviour for
    callers that haven't been updated.
    """
    default_name = _browser_channels()[0]["process_name"]
    if not installations:
        names = [default_name]
    else:
        names = [i["process_name"] for i in installations if i.get("process_name")]
        if not names:
            names = [default_name]

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
    """Scrub SlimBrave's Shields-disabled exceptions from a single Preferences file.

    Returns the number of exception entries removed (0 if file missing or
    no matching keys present).
    """
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
    # Brave stores the policy patterns with a secondary-pattern marker (",*")
    # appended. Match SlimBrave's two canonical writes; leave any user-set
    # per-site overrides alone.
    for pattern in ("http://*,*", "https://*,*"):
        if pattern in bs:
            del bs[pattern]
            removed += 1

    if removed == 0:
        return 0

    try:
        # Preserve the original file mode — Brave creates Preferences as 0600
        # and the default _atomic_write mode would widen it to 0644, exposing
        # session state (cookies, sync info) to other local users.
        original_mode = os.stat(pref_path).st_mode & 0o777
        # Brave reads the file as compact JSON; preserve that shape.
        _atomic_write(
            pref_path,
            json.dumps(prefs, separators=(",", ":")),
            mode=original_mode,
        )
    except OSError:
        return 0

    # We're root via sudo — return the file to its original owner so the
    # user's Brave can rewrite it on the next session.
    _chown_to_sudo_user(pref_path)

    return removed


def repair_brave_prefs(installations=None):
    """Remove SlimBrave-leaked Shields exceptions across all given channels.

    Returns (removed_count, brave_was_running). When `installations` is None,
    repairs only the legacy stable-channel prefs path (back-compat).
    """
    if not browser_config()["prefs_repair"]:
        return (0, _is_brave_running(installations or []))
    if installations is None:
        # Legacy single-channel path — synthesise a stable installation.
        ch_def = _browser_channels()[0]
        installations = [{"prefs_path": _channel_prefs_path(ch_def["user_data_dir"])}]

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
# Persistence on macOS — off vs on (install a Configuration Profile) so
# policies survive reboot on macOS 13+, where cfprefsd/mdmclient may clear
# directly-written /Library/Managed Preferences/*.plist files without a
# backing profile. See README's "Persistence on macOS" section.
# ---------------------------------------------------------------------------


def _stable_uuid(slug):
    """Derive a deterministic UUID from a slug (uuid5 over DNS namespace).

    Stable across runs so re-applying generates the same UUID — macOS then
    treats an updated mobileconfig as an "update" instead of a new profile.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, slug)).upper()


def _is_profile_installed():
    """True if the SlimBrave Neo Configuration Profile is in the system db.

    Reads `profiles list -output stdout-xml` (a plist mapping a domain
    label to an array of profile dicts) and scans for our identifier.
    Returns False on any error so callers treat "unknown" the same as
    "not installed" — the worst case is we redundantly remove a missing
    profile, which is silent.
    """
    if not IS_MAC:
        return False
    try:
        result = subprocess.run(
            ["profiles", "list", "-output", "stdout-xml",
             "-type", "configuration"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0 or not result.stdout:
        return False
    try:
        data = plistlib.loads(result.stdout)
    except Exception:
        return False
    for v in (data.values() if isinstance(data, dict) else []):
        if not isinstance(v, list):
            continue
        for prof in v:
            if (isinstance(prof, dict)
                    and prof.get("ProfileIdentifier") == PERSIST_PROFILE_IDENTIFIER):
                return True
    return False


def _build_mobileconfig(policy_by_bundle):
    """Build a Configuration profile dict covering one or more channels.

    `policy_by_bundle` maps bundle_id → policy dict. Each bundle becomes
    a separate inner com.apple.ManagedClient.preferences payload, so a
    single user-facing profile entry manages every selected channel.
    """
    inner_payloads = []
    for bundle_id, policy in policy_by_bundle.items():
        inner_payloads.append({
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadVersion": 1,
            "PayloadIdentifier":
                f"{PERSIST_PROFILE_IDENTIFIER}.payload.{bundle_id}",
            "PayloadUUID": _stable_uuid(
                f"{PERSIST_PROFILE_IDENTIFIER}.payload.{bundle_id}"
            ),
            "PayloadDisplayName": f"{browser_label()} Policy ({bundle_id})",
            "PayloadContent": {
                bundle_id: {
                    "Forced": [{"mcx_preference_settings": dict(policy)}],
                },
            },
        })
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": PERSIST_PROFILE_IDENTIFIER,
        "PayloadUUID": _stable_uuid(PERSIST_PROFILE_IDENTIFIER),
        "PayloadDisplayName": PERSIST_PROFILE_DISPLAY,
        "PayloadDescription": (
            f"{browser_label()} enterprise policies managed by SlimBrave Neo. "
            "Remove via SlimBrave Neo --reset or in System Settings."
        ),
        "PayloadOrganization": "SlimBrave Neo",
        "PayloadScope": "System",
        "PayloadContent": inner_payloads,
    }


def _remove_profile():
    """Remove the SlimBrave Neo profile via the `profiles` CLI.

    `profiles remove -identifier ... -forced` is the root-only path that
    still works without a GUI on macOS 11+. Silent when nothing to remove.
    """
    if not IS_MAC:
        return
    try:
        subprocess.run(
            ["profiles", "remove",
             "-identifier", PERSIST_PROFILE_IDENTIFIER,
             "-type", "configuration",
             "-forced"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _install_profile_from_policy(policy_by_bundle):
    """Generate the mobileconfig and hand it to System Settings.

    macOS 11+ disallows CLI install of configuration profiles (see
    `man profiles`), so the only path is `open <file.mobileconfig>`
    which lets macOS route the file to System Settings > General >
    Device Management for user approval. Any prior version is removed
    first so the user sees a single fresh entry.

    `open` is run as the invoking user (SUDO_USER) so LaunchServices
    targets that user's GUI session — running it as root produces
    inconsistent behaviour when the console user differs.
    """
    if _is_profile_installed():
        _remove_profile()
    mc = _build_mobileconfig(policy_by_bundle)
    try:
        # /tmp is world-readable but the profile contents aren't secret —
        # they're the same policy key/values otherwise written to a
        # world-readable system plist. 0o644 lets the user's `open` read
        # the file when we drop privileges below.
        _atomic_write(
            PERSIST_PROFILE_FILE, plistlib.dumps(mc),
            binary=True, mode=0o644,
        )
    except OSError as e:
        return False, f"Failed to write mobileconfig: {e}"

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        open_cmd = ["sudo", "-u", sudo_user, "open"]
    else:
        open_cmd = ["open"]
    try:
        subprocess.run(
            open_cmd + [PERSIST_PROFILE_FILE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
        # Also jump System Settings to the Device Management pane — the
        # `open` of the .mobileconfig only queues the download on
        # macOS 13+ and doesn't surface the install UI on its own.
        subprocess.run(
            open_cmd + [
                "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        # The .mobileconfig is on disk regardless; user can double-click
        # it from Finder if the auto-open path fails.
        pass
    return True, ""


def _flush_cfprefsd():
    """Restart cfprefsd so it re-reads /Library/Managed Preferences/.

    Without this, cfprefsd may keep returning a stale "not forced"
    result after we change managed values, leaving Brave on the old
    policy until next reboot. cfprefsd is designed to be restartable;
    launchd respawns it on demand.
    """
    if not IS_MAC:
        return
    try:
        subprocess.run(
            ["/usr/bin/killall", "cfprefsd"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _clear_persistence_artifacts():
    """Remove any installed Configuration Profile and its mobileconfig.

    Called by reset and by apply when switching modes (so an `off` Apply
    after a previous `on` Apply cleanly tears the profile down). Plist
    file deletion is the caller's responsibility — apply/reset already
    iterate over plist_path targets. The staged mobileconfig in /tmp is
    removed too so a reset leaves nothing behind; a persist=on Apply
    rewrites it immediately afterwards.
    """
    if not IS_MAC:
        return
    _remove_profile()
    try:
        os.remove(PERSIST_PROFILE_FILE)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Policy I/O
# ---------------------------------------------------------------------------


def _read_one_policy(plist_path):
    """Read a single policy file (plist on macOS, JSON on Linux)."""
    try:
        if IS_MAC:
            with open(plist_path, "rb") as f:
                return plistlib.load(f)
        else:
            with open(plist_path, "r") as f:
                data = json.load(f)
                if browser_engine() == "firefox" and isinstance(data, dict):
                    return data.get("policies", {})
                return data
    except (FileNotFoundError, PermissionError):
        return {}
    except Exception:
        return {}


def load_existing_policy(installations=None):
    """Read the current on-disk policy and return its dict.

    With multi-channel installations, returns the first non-empty policy
    found (so the TUI's pre-check reflects an existing state when one
    exists). Falls back to legacy POLICY_FILE when no installations are
    supplied.
    """
    if installations is None:
        return _read_one_policy(POLICY_FILE)

    # On Linux all channels share POLICY_FILE; dedupe to avoid reading the
    # same file repeatedly.
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

    # Refuse to write a broken DNS config: selecting "custom" without a
    # template URL would set DnsOverHttpsMode=secure with no server,
    # breaking DNS resolution in Brave.
    if dns_mode == "custom" and not dns_template:
        return None, "Custom DNS requires a DoH template URL."

    # "unmanaged" writes no DNS keys at all; since Apply fully overwrites
    # the policy file, any previously-managed DNS policy is removed.
    # Firefox has no mode enum — its DNSOverHTTPS object maps as:
    # off = Enabled false; automatic = Enabled true (fallback allowed);
    # secure/custom = Enabled true with fallback off (+ ProviderURL).
    if dns_mode and dns_mode != "unmanaged":
        if browser_engine() == "firefox":
            if dns_mode == "off":
                policy["DNSOverHTTPS"] = {"Enabled": False, "Locked": True}
            elif dns_mode == "automatic":
                policy["DNSOverHTTPS"] = {"Enabled": True, "Locked": True}
            else:  # secure / custom
                doh = {"Enabled": True, "Fallback": False, "Locked": True}
                if dns_template:
                    doh["ProviderURL"] = dns_template
                policy["DNSOverHTTPS"] = doh
        elif dns_mode == "custom":
            policy["DnsOverHttpsMode"] = "secure"
            policy["DnsOverHttpsTemplates"] = dns_template
        else:
            policy["DnsOverHttpsMode"] = dns_mode
            if dns_mode == "secure" and dns_template:
                policy["DnsOverHttpsTemplates"] = dns_template

    if IS_MAC and browser_engine() == "firefox":
        # Firefox's macOS policy engine only activates when this marker
        # key is present in the preference domain.
        policy["EnterprisePoliciesEnabled"] = True
    return policy, ""


def _write_one_policy(plist_path, policy):
    """Write a single policy file and return (ok, error_msg).

    Firefox on Linux reads a top-level {"policies": {...}} wrapper in
    policies.json; on macOS its policy keys go straight into the
    preference domain (EnterprisePoliciesEnabled is injected by
    _build_policy to activate the policy engine).
    """
    if browser_engine() == "firefox" and not IS_MAC:
        policy = {"policies": policy}
    try:
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        if IS_MAC:
            _atomic_write(plist_path, plistlib.dumps(policy), binary=True)
        else:
            _atomic_write(plist_path, json.dumps(policy, indent=4))
    except PermissionError:
        return False, "Permission denied. Run as root."
    except OSError as e:
        return False, f"Failed to write policy: {e}"
    return True, ""


def _selected_channel_targets(installations, selected_ids=None):
    """Return the subset of installations the user has actually selected.

    `selected_ids` is an optional set of channel id strings; when None
    (single-channel installs, Linux, or `--channels` already filtered
    installations upstream), every installation is targeted.
    """
    if selected_ids is None:
        return list(installations)
    return [i for i in installations if i["channel"] in selected_ids]


def _dedupe_plist_targets(installations):
    """Return distinct (plist_path, label) pairs for write/delete operations.

    On Linux every channel maps to the same POLICY_FILE; on macOS each
    channel has its own plist. Labels are joined when several channels
    collapse onto one path so status messages stay informative. Insertion
    order is preserved by the dict (Python 3.7+).
    """
    grouped = {}
    for inst in installations:
        path = inst.get("plist_path") or POLICY_FILE
        grouped.setdefault(path, []).append(inst["label"])
    return [(path, ", ".join(labels)) for path, labels in grouped.items()]


def _bundle_id_for_plist(plist_path):
    """Strip directory and `.plist` suffix to recover the bundle id."""
    base = os.path.basename(plist_path)
    return base[:-6] if base.endswith(".plist") else base


def apply_policy(rows, installations=None, persist_mode=PERSIST_DEFAULT,
                 selected_channel_ids=None):
    """Write the policy with or without durable persistence.

    Persistence modes (macOS only — Linux ignores `persist_mode` since
    its /etc/brave/policies file is already durable):
        off  Write plist to /Library/Managed Preferences/. May reset
             after reboot on macOS 13+; useful for quick tests.
        on   Install an Apple Configuration Profile via System Settings
             so policies survive reboots. Requires a one-time GUI step.

    Switching `on` ↔ `off` implicitly clears the previous artifact so
    the on-disk state always matches the new mode.
    """
    if not IS_MAC and persist_mode != "off":
        persist_mode = "off"
    if persist_mode not in PERSIST_MODES:
        return False, (
            f"Unknown persist mode '{persist_mode}'. "
            f"Valid: {', '.join(PERSIST_MODES)}."
        )

    policy, err = _build_policy(rows)
    if policy is None:
        return False, err

    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(_selected_channel_targets(installations, selected_channel_ids))

    if not targets:
        return False, f"No {browser_label()} channel selected. Check at least one channel."

    # On macOS, drop any previously-installed profile so switching modes
    # is never additive — e.g. an `off` Apply after a previous `on` Apply
    # should leave only the plist, not both.
    if IS_MAC:
        _clear_persistence_artifacts()

    written_labels = []

    if persist_mode == "on":
        # Configuration Profile is cfprefsd's only forced source. Wipe
        # any plist a prior `off` Apply left under /Library/Managed
        # Preferences/ so cfprefsd doesn't see two competing sources
        # for the same bundle.
        policy_by_bundle = {}
        for plist_path, label in targets:
            try:
                os.remove(plist_path)
            except OSError:
                pass
            bundle = _bundle_id_for_plist(plist_path)
            if bundle:
                policy_by_bundle[bundle] = policy
            if label:
                written_labels.append(label)
        if not policy_by_bundle:
            return False, "No valid Brave channel bundle id found."
        ok, err = _install_profile_from_policy(policy_by_bundle)
        if not ok:
            return False, err
    else:
        # `off`: plain plist into /Library/Managed Preferences/. cfprefsd
        # is flushed so it re-reads the fresh values instead of serving
        # a stale "not managed" cache.
        for plist_path, label in targets:
            ok, err = _write_one_policy(plist_path, policy)
            if not ok:
                scope = f" ({label})" if label else ""
                return False, f"{err}{scope}"
            if label:
                written_labels.append(label)
        if IS_MAC:
            _flush_cfprefsd()

    repair_targets = (
        _selected_channel_targets(installations, selected_channel_ids)
        if installations else None
    )
    return True, _post_apply_message(
        *repair_brave_prefs(repair_targets),
        labels=written_labels, persist_mode=persist_mode,
    )


def _post_apply_message(repaired, brave_running, labels=None,
                        persist_mode=PERSIST_DEFAULT):
    """Build the status message after a successful Apply."""
    scope = f" to {', '.join(labels)}" if labels else ""
    if persist_mode == "on":
        base = (
            f"Profile generated{scope}. Finish in "
            "System Settings > General > Device Management."
        )
    elif IS_MAC:
        base = (
            f"Settings applied{scope}. Restart {browser_label()} to see changes. "
            "Persistence is off — values may reset on macOS 13+."
        )
    else:
        base = f"Settings applied{scope}. Restart {browser_label()} to see changes."

    if repaired > 0:
        prefs = f"pref{'s' if repaired != 1 else ''}"
        base += f" Cleaned {repaired} leaked profile {prefs}."
    if brave_running:
        base += f" ({browser_label()} is running — fully close it before reopening.)"
    return base


def reset_policy(rows, installations=None, selected_channel_ids=None):
    """Reset all SlimBrave state: plists, profile, prefs leak.

    Unconditionally tears down the Configuration Profile (if installed)
    and every plist file, regardless of which mode was last used, so
    --reset is always a clean slate.
    """
    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(_selected_channel_targets(installations, selected_channel_ids))

    if not targets:
        return False, "No Brave channel selected. Check at least one channel."

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

    if IS_MAC:
        _clear_persistence_artifacts()
        _flush_cfprefsd()

    repair_targets = (
        _selected_channel_targets(installations, selected_channel_ids)
        if installations else None
    )
    repaired, running = repair_brave_prefs(repair_targets)
    scope = f" for {', '.join(cleared_labels)}" if cleared_labels else ""
    msg = f"All settings reset{scope}. Restart {browser_label()} to see changes."
    if repaired > 0:
        msg = (
            f"Reset{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart {browser_label()}."
        )
    if running:
        msg += f" ({browser_label()} is running — fully close it before reopening.)"
    return True, msg


def detect_managed_channel_ids(installations):
    """Return the set of channel ids whose plist already holds a policy.

    Used as the sticky default for the Apply-time channel prompt — so a
    user who previously managed Stable + Beta sees those two pre-ticked
    and can press Enter to keep the same scope.
    """
    if not installations:
        return set()
    managed = set()
    for inst in installations:
        existing = _read_one_policy(inst.get("plist_path") or "")
        if existing:
            managed.add(inst["channel"])
    return managed


def _policy_dns_state(policy):
    """Return (mode, template) from an on-disk policy, engine-aware."""
    if browser_engine() == "firefox":
        doh = policy.get("DNSOverHTTPS")
        if not isinstance(doh, dict):
            return (None, "")
        if not doh.get("Enabled", False):
            return ("off", "")
        tmpl = doh.get("ProviderURL", "")
        if doh.get("Fallback", True) and not tmpl:
            return ("automatic", "")
        return ("secure", tmpl)
    return (policy.get("DnsOverHttpsMode"),
            policy.get("DnsOverHttpsTemplates", ""))


def sync_rows_with_policy(rows, policy):
    """Pre-check rows that match an existing policy on disk."""
    if not policy:
        return
    for row in rows:
        if row["type"] == ROW_FEATURE:
            if row["key"] in policy and policy[row["key"]] == row["value"]:
                row["checked"] = True
        elif row["type"] == ROW_DNS:
            dns_val, dns_tmpl = _policy_dns_state(policy)
            # If mode is "secure" and a template is set, show as "custom"
            if dns_val == "secure" and dns_tmpl:
                if "custom" in row["options"]:
                    row["selected"] = row["options"].index("custom")
            elif dns_val in row["options"]:
                row["selected"] = row["options"].index(dns_val)
        elif row["type"] == ROW_DNS_TEMPLATE:
            _, tmpl = _policy_dns_state(policy)
            if tmpl:
                row["value"] = tmpl
                row["cursor"] = len(tmpl)


def detect_persist_mode():
    """Detect whether persistence is currently in use on this Mac.

    Returns "on" if the SlimBrave Neo Configuration Profile is in the
    system db, otherwise "off". Non-macOS always returns "off".
    """
    if not IS_MAC:
        return "off"
    return "on" if _is_profile_installed() else "off"

# ---------------------------------------------------------------------------
# Import / Export (PS1-compatible JSON format)
# ---------------------------------------------------------------------------


def export_settings(rows, path):
    """Export current TUI selections to a SlimBrave Neo JSON config file.

    Writes the new key-value map format so multi-value policies (e.g.
    IncognitoModeAvailability, which can be 1 for Disable or 2 for Force)
    round-trip cleanly instead of collapsing to just a key name.
    """
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

    # DnsMode is omitted when DNS is unmanaged, so importing the file
    # (on any platform) lands back on "unmanaged" instead of forcing a
    # managed DNS policy. The template only matters for custom/secure.
    settings = {"Browser": SELECTED_BROWSER, "Features": features}
    if dns_mode and dns_mode != "unmanaged":
        settings["DnsMode"] = dns_mode
        if dns_template and dns_mode in ("custom", "secure"):
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
    """Normalize the Features field from a config file.

    Accepts two formats:
      - New: {"KeyName": value, ...} — authoritative, round-trips multi-value policies.
      - Legacy: ["KeyName", ...] — pre-2026 exports; value is implicit.
    Returns (mapping, is_legacy). `mapping` is {key: value_or_None}; for the
    legacy format values are None, signalling "first matching row wins".
    """
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

    declared = str(config.get("Browser", "")).strip().lower()
    if declared and declared != SELECTED_BROWSER:
        return False, (
            f"Config targets '{declared}' but the selected browser is "
            f"'{SELECTED_BROWSER}'. Re-run with --browser {declared}."
        )

    features_map, is_legacy = _parse_imported_features(config.get("Features"))
    dns_mode = config.get("DnsMode", "")
    dns_template = config.get("DnsTemplates", "") or ""
    if not dns_mode:
        # No DnsMode in the file means DNS is unmanaged (a bare
        # DnsTemplates is treated as custom for legacy exports).
        dns_mode = "custom" if dns_template else "unmanaged"

    # Legacy array format can't distinguish value-1 vs value-2 for keys
    # with multiple rows (IncognitoModeAvailability). To avoid silently
    # picking the later entry — which historically force-incognitoed users
    # who imported the Parental Controls preset — only the first matching
    # row per key is checked in legacy mode.
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
            if dns_mode in row["options"]:
                row["selected"] = row["options"].index(dns_mode)
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

# Focus zones
FOCUS_LIST = 0
FOCUS_BUTTONS = 1
FOCUS_PROMPT = 2   # status-line text input mode


def init_colors():
    """Initialize curses color pairs."""
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
            if r["type"] in (ROW_FEATURE, ROW_DNS, ROW_DNS_TEMPLATE)]


def draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
         status_msg, status_ok, install_method="",
         prompt_label="", prompt_buf="", prompt_cur=0):
    """Render the full TUI screen."""
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1  # avoid writing to the last column

    # Title bar
    if install_method:
        title = f" SlimBrave Neo - {browser_label()} Debloater [{install_method}] "
    else:
        title = f" SlimBrave Neo - {browser_label()} Debloater "
    pad = max(0, (usable_w - len(title)) // 2)
    try:
        stdscr.addnstr(0, 0, " " * usable_w, usable_w,
                        curses.color_pair(CP_TITLE) | curses.A_BOLD)
        stdscr.addnstr(0, pad, title, usable_w - pad,
                        curses.color_pair(CP_TITLE) | curses.A_BOLD)
    except curses.error:
        pass

    # Key hints below title
    hint = " [Q/Esc] Quit  [Space/Enter] Toggle  [Tab] Buttons "
    try:
        stdscr.addnstr(1, 0, hint.center(usable_w), usable_w,
                        curses.color_pair(CP_NORMAL) | curses.A_DIM)
    except curses.error:
        pass

    # How many rows fit between title (line 1) and bottom area (3 lines)
    list_start_y = 2
    list_end_y = max_y - 4  # leave room for: blank, buttons, status
    visible_count = list_end_y - list_start_y
    if visible_count < 1:
        visible_count = 1

    # Current DNS mode (for dimming the template row)
    current_dns_mode = get_dns_mode(rows)

    # Draw the scrollable feature list
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
        elif row["type"] == ROW_DNS:
            current = row["options"][row["selected"]]
            line = f"    < {current} >"
            attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl_active = current_dns_mode in ("custom", "secure")
            val = row["value"] if row["value"] else ""
            if tmpl_active:
                # Show editable field
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

        # Draw text cursor for active template row
        if (is_cursor and row["type"] == ROW_DNS_TEMPLATE
                and current_dns_mode in ("custom", "secure")):
            tmpl_val = row["value"]
            field_start = 15  # len("    Template: [")
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

    # Scroll indicators
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

    # Bottom buttons
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

    # Status / prompt line
    status_y = max_y - 1
    if focus == FOCUS_PROMPT:
        # Show text input prompt
        prompt_text = f" {prompt_label}: {prompt_buf}"
        try:
            stdscr.addnstr(status_y, 0, prompt_text.ljust(usable_w),
                            usable_w, curses.color_pair(CP_TITLE))
            # Show cursor in the prompt
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

        if key == 27:  # Escape - cancel
            return False, ""
        elif key in (curses.KEY_ENTER, 10, 13):
            return True, "".join(buf).strip()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1
        elif key == curses.KEY_DC:  # Delete key
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
        elif 32 <= key <= 126:  # printable ASCII
            buf.insert(cur, chr(key))
            cur += 1


PERSIST_DESCRIPTIONS = {
    "off": "plist only; values may reset after reboot on macOS 13+",
    "on": "install Configuration Profile; durable, one-time GUI step",
}


def prompt_channel_selection(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                             install_method, installations, default_ids):
    """Ask which Brave channels to apply policies to (multi-select).

    Renders a two-line prompt overlaid on the buttons row: one line of
    `[x] Stable  [x] Beta  [ ] Nightly` style checkboxes, one line of
    key hints. Left/right move the focus between channels, Space (or
    Y/N) toggles the focused one, Enter confirms, Esc cancels.

    `default_ids` pre-ticks whichever channels are already managed by
    SlimBrave (sticky default) so re-Apply with no scope change is one
    keystroke. Returns (ok, selected_ids_set).
    """
    channels = list(installations)
    if not channels:
        return True, set()
    selected = set(default_ids or {i["channel"] for i in channels})
    focus_idx = 0

    def render():
        draw(stdscr, rows, cursor_idx, scroll_offset,
             FOCUS_BUTTONS, btn_idx, "", True, install_method)
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        parts = ["  Apply to which Brave channels?"]
        for i, inst in enumerate(channels):
            mark = "x" if inst["channel"] in selected else " "
            tag = f"[{mark}] {inst['label']}"
            parts.append(f"<{tag}>" if i == focus_idx else f" {tag} ")
        desc_line = "   ".join(parts)
        keys_line = (
            "  ←/→ move   Space toggle   Y/N toggle   "
            "Enter=confirm   Esc=cancel"
        )
        try:
            stdscr.addnstr(
                max_y - 2, 0, desc_line.ljust(usable_w)[:usable_w],
                usable_w, curses.color_pair(CP_TITLE) | curses.A_BOLD,
            )
            stdscr.addnstr(
                max_y - 1, 0, keys_line.ljust(usable_w)[:usable_w],
                usable_w, curses.color_pair(CP_STATUS_OK),
            )
        except curses.error:
            pass
        stdscr.refresh()

    def toggle(i):
        cid = channels[i]["channel"]
        if cid in selected:
            selected.discard(cid)
        else:
            selected.add(cid)

    while True:
        render()
        key = stdscr.getch()
        if key == 27:
            return False, set()
        if key in (curses.KEY_ENTER, 10, 13):
            if not selected:
                # No channel checked — keep prompting; an empty selection
                # would be a no-op Apply that confuses users.
                continue
            return True, selected
        if key == curses.KEY_LEFT:
            focus_idx = (focus_idx - 1) % len(channels)
        elif key == curses.KEY_RIGHT:
            focus_idx = (focus_idx + 1) % len(channels)
        elif key == ord(" "):
            toggle(focus_idx)
        elif key in (ord("y"), ord("Y")):
            selected.add(channels[focus_idx]["channel"])
        elif key in (ord("n"), ord("N")):
            selected.discard(channels[focus_idx]["channel"])


def prompt_persist_mode(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                        install_method, current_mode):
    """Ask the user whether to persist the policies across reboots.

    Two-line prompt overlaid on the buttons row: the top line cycles
    through `< on >` / `< off >` and shows the highlighted mode's
    description; the bottom line lists the keys. ←/→ to browse, Y/N
    for direct pick, Enter to confirm, Esc to cancel.

    The highlight starts on `current_mode` (sticky default), so Enter
    alone keeps whatever's currently installed — re-Apply with no
    change is one keystroke.
    """
    if current_mode not in PERSIST_MODES:
        current_mode = "off"
    idx = PERSIST_MODES.index(current_mode)
    while True:
        mode = PERSIST_MODES[idx]
        draw(stdscr, rows, cursor_idx, scroll_offset,
             FOCUS_BUTTONS, btn_idx, "", True, install_method)
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        desc_line = (
            f"  Persist across reboots: < {mode} >    "
            f"↳ {PERSIST_DESCRIPTIONS[mode]}"
        )
        keys_line = (
            "  ←/→ select   Y/N quick-pick   "
            "Enter=confirm   Esc=cancel"
        )
        try:
            stdscr.addnstr(
                max_y - 2, 0, desc_line.ljust(usable_w)[:usable_w],
                usable_w, curses.color_pair(CP_TITLE) | curses.A_BOLD,
            )
            stdscr.addnstr(
                max_y - 1, 0, keys_line.ljust(usable_w)[:usable_w],
                usable_w, curses.color_pair(CP_STATUS_OK),
            )
        except curses.error:
            pass
        stdscr.refresh()

        key = stdscr.getch()
        if key == 27:
            return False, ""
        if key in (curses.KEY_ENTER, 10, 13):
            return True, mode
        if key in (curses.KEY_LEFT, curses.KEY_RIGHT):
            idx = (idx + 1) % len(PERSIST_MODES)
        elif key in (ord("y"), ord("Y")):
            return True, "on"
        elif key in (ord("n"), ord("N")):
            return True, "off"


def main(stdscr, override_installations=None):
    """Main TUI event loop.

    `override_installations` lets `--policy-file` force a single synthetic
    target through to the TUI without touching detection.
    """
    curses.curs_set(0)
    init_colors()
    stdscr.keypad(True)
    stdscr.timeout(-1)

    # Detect Brave installation(s) first — channel rows depend on it.
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

    # Load existing policy and pre-check matching features
    policy = load_existing_policy(installations)
    sync_rows_with_policy(rows, policy)

    cursor_pos = 0          # index into sel[]
    cursor_idx = sel[0]     # index into rows[]
    scroll_offset = 0
    focus = FOCUS_LIST
    btn_idx = 0

    # Show detection warnings on startup, if any
    if brave_info["warnings"]:
        status_msg = brave_info["warnings"][0]
        status_ok = not brave_info["found"]
    else:
        status_msg = ""
        status_ok = True

    while True:
        # Compute scroll
        max_y, _ = stdscr.getmaxyx()
        list_start_y = 2
        list_end_y = max_y - 4
        visible_count = max(1, list_end_y - list_start_y)

        if cursor_idx < scroll_offset:
            scroll_offset = cursor_idx
        if cursor_idx >= scroll_offset + visible_count:
            scroll_offset = cursor_idx - visible_count + 1
        # Keep headers visible: if the row above cursor is a header, include it
        if cursor_idx > 0 and rows[cursor_idx - 1]["type"] == ROW_HEADER:
            if cursor_idx - 1 < scroll_offset:
                scroll_offset = cursor_idx - 1

        draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
             status_msg, status_ok, install_method)

        key = stdscr.getch()
        row = rows[cursor_idx]

        # --- Editing mode for DNS template row ---
        if (focus == FOCUS_LIST
                and row["type"] == ROW_DNS_TEMPLATE
                and get_dns_mode(rows) in ("custom", "secure")):
            # Typing into the template field
            if 32 <= key <= 126:
                val = row["value"]
                cur = row["cursor"]
                row["value"] = val[:cur] + chr(key) + val[cur:]
                row["cursor"] = cur + 1
                # Update horizontal scroll
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
            # For other keys (arrows up/down, tab, etc.), fall through
            # to normal handling below

        # --- Global keys ---
        if key == ord("q") or key == 27:  # q or Escape
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
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key in (curses.KEY_ENTER, 10, 13):
            if focus == FOCUS_BUTTONS:
                btn_label = BUTTONS[btn_idx]

                if btn_label == "Apply":
                    # Validate: custom DNS requires a template URL
                    dns_mode = get_dns_mode(rows)
                    dns_tmpl = get_dns_template(rows)
                    if dns_mode == "custom" and not dns_tmpl:
                        status_msg = "Custom DNS requires a DoH template URL."
                        status_ok = False
                    elif IS_MAC:
                        # Two macOS-only prompts, in order: scope (which
                        # channels) first, mechanism (persist on/off)
                        # second. Each prompt has a sticky default so a
                        # one-keystroke Enter-Enter Apply re-uses prior
                        # state.
                        selected_ids = None
                        if installations and len(installations) > 1:
                            default_ids = (
                                detect_managed_channel_ids(installations)
                                or {i["channel"] for i in installations}
                            )
                            ok, selected_ids = prompt_channel_selection(
                                stdscr, rows, cursor_idx, scroll_offset,
                                btn_idx, install_method, installations,
                                default_ids,
                            )
                            if not ok:
                                status_msg = "Apply cancelled."
                                status_ok = True
                                continue
                        current = detect_persist_mode()
                        ok, persist_mode = prompt_persist_mode(
                            stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                            install_method, current,
                        )
                        if not ok:
                            status_msg = "Apply cancelled."
                            status_ok = True
                        else:
                            status_ok, status_msg = apply_policy(
                                rows, installations,
                                persist_mode=persist_mode,
                                selected_channel_ids=selected_ids,
                            )
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
                        # Rebuild selectable indices (unchanged, but safe)
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
                # Enter on a list item acts like spacebar
                if row["type"] == ROW_FEATURE:
                    toggle_feature_row(rows, row)
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

# ---------------------------------------------------------------------------
# CLI (non-interactive)
# ---------------------------------------------------------------------------


def _filter_installations_by_channels(installations, channel_spec):
    """Apply --channels flag semantics to detected installations.

    `channel_spec` is the raw CLI string. "auto" or empty means keep all
    detected. A comma list keeps only matching channel ids.
    Returns (filtered, error_msg). On error, filtered is None.
    """
    if not channel_spec or channel_spec == "auto":
        return installations, ""
    valid_ids = [c["id"] for c in _browser_channels()]
    requested = [c.strip().lower() for c in channel_spec.split(",") if c.strip()]
    unknown = [c for c in requested if c not in valid_ids]
    if unknown:
        return None, (
            f"Unknown channel(s): {', '.join(unknown)}. "
            f"Valid: {', '.join(valid_ids)}"
        )
    filtered = [i for i in installations if i["channel"] in requested]
    if not filtered:
        return None, (
            f"No installed {browser_label()} channel matches --channels {channel_spec}. "
            f"Detected: {', '.join(i['channel'] for i in installations) or 'none'}"
        )
    return filtered, ""


def cli_import(path, installations, doh_templates="",
               persist_mode=PERSIST_DEFAULT):
    """Non-interactive: import config and apply policies."""
    rows = build_rows(installations)
    ok, msg = import_settings(rows, path)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)

    # Override DoH templates if provided via CLI flag
    if doh_templates:
        for row in rows:
            if row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = doh_templates
                break

    ok, msg = apply_policy(rows, installations, persist_mode=persist_mode)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)
    if IS_MAC and persist_mode == "on":
        # macOS 11+ disallows CLI-driven profile installs (see `man
        # profiles`); finish the step in System Settings.
        print(
            "Finish in System Settings > General > Device Management: "
            "double-click the downloaded profile and click Install. "
            "See https://support.apple.com/guide/mac-help/mh35561/mac"
        )
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
    """Non-interactive: tear down every SlimBrave artifact and repair leaks.

    Removes plist files, the Configuration Profile (if installed), and
    repairs leaked Brave-profile prefs. Unconditional so a single
    --reset always leaves a clean slate.
    """
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

    if IS_MAC:
        profile_was_installed = _is_profile_installed()
        _clear_persistence_artifacts()
        _flush_cfprefsd()
        if profile_was_installed:
            print(f"Removed Configuration Profile "
                  f"({PERSIST_PROFILE_IDENTIFIER})")

    repaired, running = repair_brave_prefs(installations)
    if repaired > 0:
        print(
            f"Cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''} from Brave's user profile."
        )
    if running:
        print(f"Note: {browser_label()} is running — fully close it before reopening.")
    return 0


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="slimbrave",
        description="SlimBrave Neo - Brave Browser debloater for Linux and macOS",
        epilog="Run without arguments to launch the interactive TUI.",
    )
    parser.add_argument(
        "--browser", choices=sorted(BROWSERS), default="brave",
        help="which browser to manage (default: brave; edge is macOS/Windows only, "
             "firefox uses Mozilla's policies.json / managed-preferences dialect)",
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
            "comma-separated channels to target on macOS "
            f"({', '.join(CHANNEL_IDS)}). Default 'auto' = all detected. "
            "Linux ignores this flag because all channels share one policy file."
        ),
    )
    parser.add_argument(
        "--persist", metavar="MODE", default=None,
        choices=list(PERSIST_MODES),
        help=(
            "macOS persistence: 'off' (plist only; may reset after reboot "
            "on macOS 13+) or 'on' (install a Configuration Profile via "
            "System Settings; durable, Apple-recommended). When omitted, "
            "reuse whatever's currently installed; falls back to 'off' "
            "if nothing is. Linux ignores this flag."
        ),
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    args = parse_args()
    select_browser(args.browser)

    # Override policy file path if requested. This is a single-target
    # override that bypasses channel detection — useful for tests and for
    # legacy callers that always wrote to one file.
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
        # Build a synthetic single-channel installation pointing at the
        # supplied path so apply/reset still have a well-formed target.
        # Reuse the stable channel's user-data dir / process name for prefs
        # repair and "is Brave running" detection.
        default_channel = MAC_CHANNELS[0] if IS_MAC else LINUX_CHANNELS[0]
        override_installations = [_make_installation(
            {**default_channel, "id": "override", "label": "Override",
             "bundle_id": ""},
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
        # Non-interactive CLI mode
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

        # Resolve --persist: when omitted, reuse whichever mode is
        # currently installed (matches TUI's sticky default) so a
        # re-run never silently demotes a profile back to plist-only.
        persist_mode = args.persist
        if persist_mode is None:
            persist_mode = detect_persist_mode() if IS_MAC else PERSIST_DEFAULT

        # Accumulate so a later success cannot mask an earlier failure
        # (e.g. --reset failing followed by a clean --import).
        rc = 0
        if args.reset:
            rc = max(rc, cli_reset(installations))
        if args.import_path:
            rc = max(rc, cli_import(args.import_path, installations,
                                    doh_templates=args.doh_templates or "",
                                    persist_mode=persist_mode))
        if args.export_path:
            rc = max(rc, cli_export(args.export_path, installations))
        sys.exit(rc)

    # Interactive TUI mode
    try:
        curses.wrapper(lambda s: main(s, override_installations))
    except KeyboardInterrupt:
        pass  # Clean exit on Ctrl+C
