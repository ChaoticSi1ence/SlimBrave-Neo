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
    user-data directory and to detect running channels. Brave Origin reads
    the same directory and is detected as its own "origin" channel.

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
import locale
import os
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
import tempfile

IS_MAC = sys.platform == "darwin"
# Prefix for the per-run mobileconfig staging directories, defined
# unconditionally so the sweep helper is well-formed on every platform.
STAGE_DIR_PREFIX = "slimbrave-neo-"

if IS_MAC:
    import plistlib
    import uuid
    POLICY_DIR = "/Library/Managed Preferences"
    POLICY_FILE = os.path.join(POLICY_DIR, "com.brave.Browser.plist")
    # Directories a `--policy-file` argument may name a file directly inside
    # on macOS (see _is_allowed_policy_file for the file-name rule). Allowed
    # locations mirror the documented Chromium managed-policy paths.
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
    PERSIST_PROFILE_NAME = "slimbrave-neo-policy.mobileconfig"
else:
    POLICY_DIR = "/etc/brave/policies/managed"
    POLICY_FILE = os.path.join(POLICY_DIR, "slimbrave.json")
    ALLOWED_POLICY_DIRS = (
        "/etc/brave/policies/managed",
        "/etc/chromium/policies/managed",
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
    # Brave Origin is a separate build rather than a channel of this one,
    # but on Linux it walks the same paths: brave-core's chrome_paths_linux.cc
    # names its profile BraveSoftware/Brave-Origin with the same -Beta and
    # -Nightly suffixes, and its launcher is brave-origin[-beta|-nightly] on
    # every packaging (the AUR wrapper, the deb/rpm script). The launcher's
    # bash process stays alive around the browser, and its comm is the name
    # it was started by: brave-origin from the AUR wrapper, brave-origin-st
    # (comm's 15-char cap) from the deb/rpm desktop file's
    # /usr/bin/brave-origin-stable - the SingletonLock check covers that
    # case, as it does the long beta and nightly names. Beta and nightly ship
    # as brave-origin-beta / brave-origin-nightly (apt, rpm and AUR *-bin);
    # brave-core also names a dev channel, but no such package is published,
    # so it gets no row.
    {"id": "origin", "label": "Origin",
     "user_data_dir": "Brave-Origin", "process_name": "brave-origin"},
    {"id": "origin-beta", "label": "Origin Beta",
     "user_data_dir": "Brave-Origin-Beta", "process_name": "brave-origin-beta"},
    {"id": "origin-nightly", "label": "Origin Nightly",
     "user_data_dir": "Brave-Origin-Nightly", "process_name": "brave-origin-nightly"},
]

CHANNEL_IDS = [c["id"] for c in (MAC_CHANNELS if IS_MAC else LINUX_CHANNELS)]


# Policy keys whose handler Brave Origin compiles out. Each one's entry in
# brave-core's browser/policy/brave_simple_policy_map.h sits under a
# BUILDFLAG whose .gni definition carries `&& !is_brave_origin_branded`
# (v1.94.121; the receipts, including a check on the shipped binary, are in
# AUDIT.md, Brave Origin). On a machine whose only Brave is Origin these rows
# are shown inert: the feature is not in the binary, so there is nothing
# for a policy to switch. P3A and the stats ping are not listed - their
# entries are unguarded, Origin merely defaults them off, and a managed
# value pins them.
ORIGIN_BUILTIN_KEYS = frozenset((
    "BraveRewardsDisabled", "BraveWalletDisabled", "BraveVPNDisabled",
    "BraveAIChatEnabled", "BraveLocalAIEnabled", "BraveNewsDisabled",
    "BraveTalkDisabled", "BravePlaylistEnabled", "BraveWebDiscoveryEnabled",
    "BraveSpeedreaderEnabled", "BraveWaybackMachineEnabled", "TorDisabled",
    "EmailAliasesEnabled",
))

# The suffix an inert row carries in the list.
INERT_SUFFIX = "(built into Origin)"

# The launch notes: one status line each at 80 columns, which is 76 chars.
ORIGIN_NOTE_ONLY = "Brave Origin found: policies apply; rows for features it removes are inert."
ORIGIN_NOTE_BESIDE = "Origin beside Brave: one policy file serves both; every row stays live."


def is_origin_only(installations):
    """True when every detected Brave is a Brave Origin build.

    The one shared policy file is read by every Brave on the machine, so a
    row goes inert only when no regular Brave could be reading it: an old
    Brave-Browser profile beside Origin keeps every row live, as does the
    --policy-file override and any macOS channel. A record detect_brave()
    made carries the whole machine's answer in "origin_only", so a list
    narrowed by --channels cannot turn a mixed machine into an Origin-only
    one; a record built by hand answers for its channel.
    """
    return bool(installations) and all(
        i.get("origin_only", str(i.get("channel", "")).startswith("origin"))
        for i in installations)


def _invoking_user():
    """Return (name, uid, gid, home) of the user who ran this, or None.

    The one answer to "who is the user here": the prefs scrub, Export and
    the macOS profile hand-off all act for this account. The name is
    SUDO_USER, else USER, which a plain `su` to root leaves as the caller's.
    None when neither is set, the name is root, pwd does not know it (or
    there is no pwd, as on Windows), or it maps to uid 0, so nothing is ever
    done as root, or in root's home, on its behalf.
    """
    name = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not name or name == "root":
        return None
    try:
        import pwd
        info = pwd.getpwnam(name)
    except (ImportError, KeyError):
        return None
    if info.pw_uid == 0:
        return None
    return (name, info.pw_uid, info.pw_gid, info.pw_dir)


def _user_home_for_brave():
    """Return the invoking user's home directory (see _invoking_user).

    Brave's profile lives under the invoking user's home, not root's.
    """
    identity = _invoking_user()
    return identity[3] if identity else None


def _mac_app_search_paths(app_name):
    """Possible locations for a Brave app bundle (system + per-user).

    The per-user one is the invoking user's ~/Applications (_invoking_user),
    so a plain `su` searches theirs, not root's; with no invoking user (a
    root login) it is the running account's own.
    """
    paths = [f"/Applications/{app_name}"]
    home = _user_home_for_brave()
    if home:
        paths.append(os.path.join(home, "Applications", app_name))
    else:
        paths.append(os.path.expanduser(f"~/Applications/{app_name}"))
    return paths


def _channel_prefs_path(user_data_dir):
    """Return the Default profile Preferences path for a channel."""
    home = _user_home_for_brave()
    if not home:
        return None
    if IS_MAC:
        return os.path.join(
            home, "Library", "Application Support", "BraveSoftware",
            user_data_dir, "Default", "Preferences",
        )
    return os.path.join(
        home, ".config", "BraveSoftware", user_data_dir, "Default", "Preferences",
    )


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


def _is_allowed_policy_file(path):
    """True if `path` is a policy file SlimBrave may write and delete.

    Prevents `--policy-file /etc/shadow --reset` (run under a permissive
    sudoers rule) from deleting arbitrary files. Two rules, both on the
    realpath, so a symlinked directory or file cannot lead out: the file
    sits directly in one of ALLOWED_POLICY_DIRS, never in a subdirectory,
    and its name is SlimBrave's own. On macOS that is a channel's
    com.brave.Browser[.beta|.nightly].plist, the only plists Brave reads
    there (by bundle id); on Linux, slimbrave*.json. Chromium reads a
    managed directory without descending into it, so neither rule hides a
    file Brave would read. On Linux, Brave reads policies only from
    /etc/brave/policies; it never reads /etc/chromium/policies, which the
    list still accepts.
    """
    real = os.path.realpath(path)
    parent, name = os.path.split(real)
    allowed = {os.path.realpath(d) if os.path.exists(d) else d
               for d in ALLOWED_POLICY_DIRS}
    if parent not in allowed:
        return False
    if IS_MAC:
        return name in {c["bundle_id"] + ".plist" for c in MAC_CHANNELS}
    return name.startswith("slimbrave") and name.endswith(".json")


def _atomic_write(path, data, *, binary=False, mode=0o644):
    """Write `data` to `path` atomically via a same-directory tempfile.

    `tempfile.mkstemp` uses O_CREAT|O_EXCL so it cannot be tricked into
    writing through a symlink, and `os.replace` atomically replaces the
    target directory entry without following a symlink that happened to
    exist there. Also avoids leaving a half-written policy if the
    process is killed mid-write.

    The data is fsynced before the rename, as Chromium's ImportantFileWriter
    does, so a crash or power cut leaves the old file or the new one, never
    an empty one: ext4's rename heuristic misses a freshly created file and
    XFS has none. The directory is fsynced afterwards where POSIX allows it,
    on a best-effort basis.
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
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # BaseException, so a Ctrl+C mid-write leaves no temp file either.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if os.name == "posix":
        # Makes the rename itself durable. Outside the cleanup above: the
        # file is already in place, so a directory that cannot be opened or
        # synced fails nothing.
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass

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
        for ch in MAC_CHANNELS:
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
            stable = MAC_CHANNELS[0]
            return {
                "found": False,
                "method": "not found",
                "path": "",
                "warnings": [
                    "Brave browser not found. Policies will be written but may have no effect."
                ],
                "notes": [],
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
            "notes": [],
            "installations": installations,
        }

    # ---- Linux ----
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
    # Whether a regular Brave is on the machine at all, started or not. The
    # inert-row decision hangs on it: it must never fire beside one.
    regular_found = found_any

    # Brave Origin is a separate package that can sit beside regular Brave,
    # so it is probed on its own rather than as one more arm of the chain
    # above. Arch: the brave-origin-bin AUR package (PKGBUILD maintained by
    # Brave, mirrored in the CachyOS repo) unpacks the upstream zip under
    # /opt/brave-origin-bin. Deb / RPM: brave-core's installer config sets
    # INSTALLDIR=/opt/brave.com/brave-origin and keeps PROGNAME=brave, so the
    # launcher is brave-origin and the binary is brave, mirroring the regular
    # /opt/brave.com/brave layout. Origin reads /etc/brave/policies like
    # regular Brave: brave_main_delegate.cc overrides DIR_POLICY_FILES for
    # every POSIX build with no branding guard (AUDIT.md, Brave Origin).
    origin_method, origin_path = "", ""
    if os.path.isfile("/opt/brave-origin-bin/brave"):
        origin_method, origin_path = "arch", "/opt/brave-origin-bin/brave"
    elif os.path.isfile("/opt/brave.com/brave-origin/brave-origin"):
        origin_method, origin_path = "deb/rpm", "/opt/brave.com/brave-origin/brave-origin"
    elif os.path.isfile("/opt/brave.com/brave-origin/brave"):
        origin_method, origin_path = "deb/rpm", "/opt/brave.com/brave-origin/brave"
    if origin_path and not found_any:
        method, primary_path, found_any = f"{origin_method} (Brave Origin)", origin_path, True

    # Flatpak and Snap are probed unconditionally, not as the `else` of the
    # native chain: a mixed install has both, and the Snap warning applies
    # whenever a Snap Brave exists. Flatpak is checked on the filesystem
    # rather than via `flatpak info`, which under sudo runs with HOME=/root
    # and so never sees the user's --user installation.
    if os.path.isdir("/var/lib/flatpak/app/com.brave.Browser") or (
            home and os.path.isdir(os.path.join(
                home, ".local", "share", "flatpak", "app", "com.brave.Browser"))):
        regular_found = True
        if not found_any:
            method, primary_path, found_any = "flatpak", "com.brave.Browser", True

    snap_path = "/snap/brave/current/opt/brave.com/brave/brave"
    if os.path.isfile(snap_path) or os.path.isdir("/snap/brave/current"):
        regular_found = True
        if not found_any:
            method, primary_path, found_any = "snap", snap_path, True
        warnings.append(
            "Snap confinement may prevent policies from taking effect. "
            "Native packages are recommended."
        )

    # Probed whenever no regular Brave has turned up yet, not only when
    # nothing has, so a launcher on PATH still counts beside a native Origin.
    if not regular_found:
        for name in ("brave-browser-stable", "brave-browser", "brave"):
            found = shutil.which(name)
            if found:
                regular_found = True
                if not found_any:
                    method, primary_path, found_any = "unknown", found, True
                break

    # Origin's launcher names, for a hand-unpacked zip: the deb ships the
    # /usr/bin/brave-origin-stable symlink and its postinst registers the
    # bare brave-origin alternative, the same way regular Brave gets
    # brave-browser-stable; the beta and nightly debs ship their launcher
    # symlink directly. There is no official Flatpak or Snap of Origin
    # (Flathub carries only com.brave.Browser, the Snap store only brave;
    # unofficial Origin Flatpaks are not probed, though one of them,
    # io.github.shyvortex.BraveOrigin, reads host policy).
    if not found_any:
        for name in ("brave-origin-stable", "brave-origin",
                     "brave-origin-beta", "brave-origin-nightly"):
            found = shutil.which(name)
            if found:
                method, primary_path, found_any = "unknown (Brave Origin)", found, True
                if name in ("brave-origin-stable", "brave-origin"):
                    origin_path = found
                break

    if not found_any:
        method = "not found"
        warnings.append(
            "Brave browser not found. Policies will be written but may have no effect."
        )

    # Detect installed Linux channels by user-data dir presence (best effort).
    # On Linux all channels share POLICY_FILE, so installations is used only
    # for prefs repair and "is Brave running" checks.
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
            # A native stable Origin whose launcher is off PATH and that has
            # never been started still needs its record, or the stable
            # fallback below would stand in for it. Beta and nightly Origin
            # are found the way Brave's own beta and nightly are: by profile
            # directory or launcher on PATH.
            or (ch["id"] == "origin" and bool(origin_path))
        )
        if installed:
            if ch["id"] == "stable":
                app_path = "" if primary_path == origin_path else primary_path
            elif ch["id"] == "origin":
                app_path = origin_path
            else:
                app_path = ""
            installations.append(_make_installation(
                ch,
                app_path=app_path,
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

    # A regular Brave found by package, Flatpak, Snap or launcher but never
    # started has no profile, so the loop above made it no record. Alone on
    # a machine, the fallback below stands in for it, as it always has;
    # beside Origin it would let the machine pass for Origin-only, so it
    # gets its record here, ahead of Origin's.
    if (regular_found
            and not any(i["channel"] == "stable" for i in installations)
            and any(i["channel"].startswith("origin") for i in installations)):
        stable = LINUX_CHANNELS[0]
        installations.insert(0, _make_installation(
            stable,
            app_path="" if primary_path == origin_path else primary_path,
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(stable["user_data_dir"]),
        ))
        detected_labels.insert(0, stable["label"])

    if not installations:
        # Nothing detected per-channel — fall back to a single stable record so
        # apply/reset still has a target plist.
        stable = LINUX_CHANNELS[0]
        installations.append(_make_installation(
            stable,
            app_path=primary_path,
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(stable["user_data_dir"]),
        ))

    if found_any and len(detected_labels) > 1:
        method = f"{method}: " + ", ".join(detected_labels)

    # Not a warning: nothing is wrong, and the status line paints warnings
    # in the error color. Origin honors the shared policy file - verified
    # end to end on 1.94.121, where a managed ExtensionInstallForcelist put
    # its extensions into the Brave-Origin profile - so every row works
    # there except the ones whose feature Origin compiles out.
    # Stamp the whole machine's answer on every record, so a list narrowed
    # by --channels still knows whether a regular Brave shares the file.
    origin_only = is_origin_only(installations)
    for inst in installations:
        inst["origin_only"] = origin_only
    notes = []
    if origin_only:
        notes.append(ORIGIN_NOTE_ONLY)
    elif any(i["channel"].startswith("origin") for i in installations):
        notes.append(ORIGIN_NOTE_BESIDE)

    return {
        "found": found_any,
        "method": method,
        "path": primary_path,
        "warnings": warnings,
        "notes": notes,
        "installations": installations,
    }


# ---------------------------------------------------------------------------
# Feature definitions - mirrors the Windows SlimBrave Neo PS1 categories
# ---------------------------------------------------------------------------

# Features with a `group` key are mutually exclusive within that group:
# checking one silently unchecks the others. Used for policies where two
# rows set conflicting values for the same key (IncognitoModeAvailability,
# HardwareAccelerationModeEnabled, DefaultBraveReferrersSetting,
# ChromeVariations, SafeBrowsingProtectionLevel), for the Shields URL
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
# Serial, WebHID) and for local fonts / window management / clipboard,
# value 1 is not a schema member. Chromium does not reject one: it drops it
# for the guard settings and applies it as a managed Allow for the other
# three, so those rows never offer "Allow".
# Notifications offers no Ask either: a managed Ask lets no notification
# through (AUDIT.md, DefaultNotificationsSetting row).
# Each row keeps the `value` it wrote as a checkbox: that is what a legacy
# array-format config resolves to on import, and what the SlimBrave.ps1
# feature table is compared against.
CHOICES_ALLOW_ASK_BLOCK = [("Not managed", None), ("Allow", 1), ("Ask", 3), ("Block", 2)]
CHOICES_ALLOW_BLOCK = [("Not managed", None), ("Allow", 1), ("Block", 2)]
CHOICES_ASK_BLOCK = [("Not managed", None), ("Ask", 3), ("Block", 2)]

CATEGORIES = [
    {
        "name": "Telemetry & Reporting",
        "features": [
            {"name": "Disable Metrics Reporting", "key": "MetricsReportingEnabled", "value": False, "desc": "Stops Brave from uploading crash reports: locks 'Automatically send diagnostic reports' off, hides the prompt after a crash and blocks Send now on brave://crashes. Beta and Nightly turn it on by default; on Release the welcome page pre-ticks it. P3A and the usage ping have their own rows."},

            {"name": "Disable URL Data Collection", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False, "desc": "Locks 'Make searches and browsing better' (URL-keyed anonymized data collection) off. Brave already ships it off; its only switch, the hidden Privacy Guide at brave://settings/privacy/guide, goes away once any policy is set. This also overrides an opt-in made there earlier."},

            {"name": "Disable Google Image Descriptions", "key": "AccessibilityImageLabelsEnabled", "value": False, "desc": "Brave already keeps Google's image descriptions off and no longer offers the opt-in. A profile that accepted it in an older version still sends unlabeled images to Google whenever a screen reader runs; this turns that off and locks it."},

            {"name": "Disable P3A Analytics", "key": "BraveP3AEnabled", "value": False, "desc": "Disables P3A (Privacy-Preserving Product Analytics), Brave's anonymized product usage telemetry."},

            {"name": "Disable Stats Ping", "key": "BraveStatsPingEnabled", "value": False, "desc": "Stops the daily usage ping that counts this install in Brave's active-user statistics, plus the search-engine usage counts it carries and the referral-code check. P3A Analytics sends its own copy of the search counts until it is disabled too."},

            {"name": "Limit Variations to Critical Fixes", "key": "ChromeVariations", "value": 1, "group": "variations", "desc": "Restricts Brave's remote seed (Griffin) to studies Brave marks critical, so features Brave turns on only that way stay off, such as WebGL/WebGPU fingerprint masking (brave://flags restores it) and a Google sign-in fix. Takes effect after a restart. Mutually exclusive with Disable Variations."},

            {"name": "Disable Variations / Griffin Experiments", "key": "ChromeVariations", "value": 2, "group": "variations", "desc": "Refuses every study in Brave's remote seed (Griffin), critical fixes too, so features Brave turns on only that way stay off, such as WebGL/WebGPU fingerprint masking and a Google sign-in fix. The seed is still downloaded. Takes effect after a restart. Mutually exclusive with Limit Variations."},

            {"name": "Disable Enhanced Spell Check", "key": "SpellCheckServiceEnabled", "value": False, "group": "spellcheck", "desc": "Locks off enhanced spell check, which sends what you type in web forms to Google. Brave already ships it off with no setting to turn it on; offline spell checking keeps working. Mutually exclusive with Disable Spellcheck, which turns spell checking off altogether and makes this row do nothing."},

        ],
    },
    {
        "name": "Privacy & Security",
        "features": [
            {"name": "Disable Safe Browsing (security downgrade)", "key": "SafeBrowsingProtectionLevel", "value": 0, "group": "safebrowsing", "desc": "Turns Safe Browsing fully off. Brave routes these lookups through its own servers, so Google never learns who made them; turning it off buys almost no privacy and costs you the phishing and malware warning pages. Excluded from every preset. Mutually exclusive with Lock Safe Browsing On."},

            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False, "desc": "Stops Brave from saving and auto-filling addresses and other contact details in web forms. Chromium has deprecated this policy, so brave://policy lists it as Deprecated, but Brave still applies it; its replacement (AutofillSettings) does not work in Brave yet."},

            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False, "desc": "Stops Brave from saving and auto-filling credit card numbers in web forms. Chromium has deprecated this policy, so brave://policy lists it as Deprecated, but Brave still applies it; its replacement (AutofillSettings) does not work in Brave yet."},

            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False, "desc": "Stops the built-in password manager from offering to save or generate passwords. Passwords already saved still autofill. Recommended if you use a dedicated password manager."},

            {"name": "Disable Password Leak Detection", "key": "PasswordLeakDetectionEnabled", "value": False, "desc": "Locks off the online check of your credentials against known breach lists, which runs after you sign in to a site and when you edit a saved login. Brave already ships it off; this keeps it off."},

            {"name": "Disable Browser Sign-in", "key": "BrowserSignin", "value": 0, "desc": "Brave has no Google browser sign-in; this locks 'Allow Google login for extensions' (brave://settings/extensions) off, as Brave already ships it. Extensions can still open Google's sign-in popup via chrome.identity. Brave Account is not affected. Takes effect after a restart."},

            {"name": "Enable Global Privacy Control", "key": "BraveGlobalPrivacyControlEnabled", "value": True, "desc": "Brave already sends the Global Privacy Control signal (asking sites not to sell or share your data) on every request and has no setting for it; this keeps it on if Adblock-Only mode (English UI only) is turned on. Works even where Shields are down."},

            {"name": "Enable De-AMP", "key": "BraveDeAmpEnabled", "value": True, "desc": "Keeps De-AMP on: Google AMP pages are skipped for the publisher's original page. Brave already does this by default; this locks the Settings toggle and stops Adblock-Only mode from turning it off."},

            {"name": "Enable Debouncing", "key": "BraveDebouncingEnabled", "value": True, "desc": "Keeps debouncing on: known tracking redirects are skipped and you go straight to the final URL. Brave already does this by default; this locks the Settings toggle and stops Adblock-Only mode from turning it off."},

            {"name": "Strip Tracking URL Parameters", "key": "BraveTrackingQueryParametersFilteringEnabled", "value": True, "desc": "Brave already strips known tracking parameters (fbclid, gclid, mc_eid, ...) from URLs and has no setting for it; this keeps stripping on if Adblock-Only mode (English UI only) is turned on. Needs Shields up."},

            {"name": "Reduce Language Fingerprinting", "key": "BraveReduceLanguageEnabled", "value": True, "desc": "Brave already does this by default; this locks its Settings toggle on. Sites get only your first language in the Accept-Language header and, on Windows, macOS and a few Linux distros, only a standard font list. Needs Shields up and fingerprinting protection on."},

            {"name": "Disable WebRTC IP Leak", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp", "desc": "Restricts WebRTC to proxied connections so video/voice calls can't expose your real IP address behind a VPN or proxy."},

            {"name": "Disable QUIC Protocol", "key": "QuicAllowed", "value": False, "desc": "Disables QUIC (HTTP/3) for web requests so they use TCP (HTTP/2 or HTTP/1.1). Useful when a firewall or filter can't inspect QUIC; may slightly slow some Google sites. WebRTC calls and WebTransport still use UDP."},

            {"name": "Disable Network Prediction (Prefetch)", "key": "NetworkPredictionOptions", "value": 2, "desc": "Stops Brave from fetching pages ahead of your click when a site's speculation rules or prerender hints ask for it, and from pre-connecting to your search engine. Brave already defaults to this; the policy locks it against Sync and extensions."},

            {"name": "Block Third Party Cookies", "key": "BlockThirdPartyCookies", "value": True, "desc": "Brave already blocks third-party cookies by default; this locks that, so the global 'Allow all cookies' choice in Shields settings, extensions, Sync and Adblock-Only mode can't turn it off. Per-site Shields exceptions still work, e.g. for an embedded login that breaks."},

            {"name": "Block Payment Method Probing", "key": "PaymentMethodQueryEnabled", "value": False, "desc": "Stops sites from learning whether you have payment methods saved: canMakePayment() always answers yes and hasEnrolledInstrument() always answers no, so neither reveals anything."},

            {"name": "Block Remote Debugging", "key": "RemoteDebuggingAllowed", "value": False, "desc": "Blocks the remote debugging port and pipe, the interface automation tools use to drive the browser and read your cookies and logged-in sessions. Disable Developer Tools does not cover this. Breaks Puppeteer, Playwright and the brave://inspect remote-debugging toggle. No restart needed."},

            {"name": "Require HTTPS for Basic Auth", "key": "BasicAuthOverHttpEnabled", "value": False, "desc": "Refuses HTTP Basic authentication over plain HTTP so your username and password are never sent in the clear. Breaks logins on legacy routers, printers and other appliances that only serve HTTP, and plain-HTTP proxies that use Basic authentication."},

            {"name": "Block Local Network Access", "key": "LocalNetworkAccessBlockedForUrls", "value": ["*"], "desc": "Stops public websites from reaching devices on your local network (router, NAS, printers, smart-home hubs) or apps on this computer, with no prompt or per-site exception; Brave otherwise asks. Pages opened from a local address still work. Breaks web apps that pair with local devices or helper apps."},

            {"name": "Disable XSLT", "key": "XSLTEnabled", "value": False, "desc": "Turns off XSLT, the legacy XML transform engine behind XSLTProcessor and xml-stylesheet pages, an attack surface Chromium is removing; this keeps it off, even for sites that opt back in. XML styled with it (some RSS feeds and sitemaps) shows unstyled. Takes full effect after a restart."},

            {"name": "Disable JavaScript Optimization (hardening)", "key": "DefaultJavaScriptOptimizerSetting", "value": 2, "desc": "Turns off V8's optimizing compilers (TurboFan, Maglev) on websites; Brave says this makes it more resistant to attacks. Sites keep working, WebAssembly included, but script-heavy pages and web apps run slower, with no per-site exception. Applies to tabs opened after the change."},

            {"name": "Remove 'Always Allow' from App-Launch Prompts", "key": "ExternalProtocolDialogShowAlwaysOpenCheckbox", "value": False, "desc": "Removes the 'Always allow' checkbox from the prompt Brave shows before a site opens an external app, so every launch (mailto:, Zoom, Teams, Steam, ms-* links) needs a click. Apps you already set to always open from a site still open without asking."},

            {"name": "Force Site Isolation for Every Site", "key": "SitePerProcess", "value": True, "desc": "Keeps every site in its own process, as Brave already does on desktop, and stops brave://flags#site-isolation-trial-opt-out or --disable-site-isolation-trials from turning it off. Takes effect after a restart."},

            {"name": "Isolate Subdomains in Separate Processes", "key": "OriginKeyedProcessesEnabled", "value": True, "desc": "Puts each origin (for example mail.example.com and docs.example.com) in its own process rather than one per site, for stronger protection against Spectre-style leaks between subdomains. Uses more processes and memory. Takes effect after a restart. A brave://flags setting overrides it."},

            # NetworkServiceSandboxEnabled is chrome.win / chrome.linux only;
            # it is appended below when this script runs on Linux.
            # DynamicCodeSettings is chrome.win only: SlimBrave.ps1 alone offers it.
        ],
    },
    {
        # Content-setting defaults sites are granted: each is a selector
        # (Not managed / Ask / Block, plus Allow where Chromium has one).
        # The microphone and camera rows at the end are checkboxes: their
        # policies are booleans whose true equals unset.
        "name": "Site Permissions",
        "features": [
            {"name": "Web Notifications", "key": "DefaultNotificationsSetting", "value": 2, "choices": CHOICES_ALLOW_BLOCK, "desc": "Sets the default for desktop notifications. Block stops every site from asking or showing them; Allow lets every site show them. Either overrides your per-site settings. Not managed keeps Brave's normal prompt (a managed Ask would let no notification through)."},

            {"name": "Location Access", "key": "DefaultGeolocationSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK, "desc": "Sets the default for reading your physical location. Block removes the prompt entirely, so maps and delivery sites will need the location typed manually; Ask prompts every time a site asks and remembers no answer. Any choice overrides your per-site settings."},

            {"name": "Motion Sensors", "key": "DefaultSensorsSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK, "desc": "Motion and orientation sensors are a fingerprinting vector, and Brave already blocks them by default. Block locks that: neither the settings page nor a per-site exception, even one made earlier, can allow them. Ask and Allow loosen Brave's default."},

            {"name": "WebUSB Access", "key": "DefaultWebUsbGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites talking to USB devices. Block removes the prompt and breaks web-based hardware wallets (Ledger, Trezor) and in-browser firmware flashers; Ask keeps the prompt. Chromium has no Allow state for this key."},

            {"name": "Web Serial Access", "key": "DefaultSerialGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites opening serial ports. Block removes the prompt and breaks in-browser microcontroller and device programming tools; Ask keeps the prompt. Chromium has no Allow state for this key."},

            {"name": "WebHID Access", "key": "DefaultWebHidGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites talking to human interface devices. Block removes the prompt, cuts Brave Wallet's own Ledger hardware-wallet connection, and may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Chromium has no Allow state for this key."},

            {"name": "Local Font Enumeration", "key": "DefaultLocalFontsSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites asking which fonts are installed on your machine - a strong fingerprinting signal that Shields' font protections don't cover. Blocking rarely breaks anything outside web design tools. Chromium has no Allow state for this key."},

            {"name": "Multi-Screen Access", "key": "DefaultWindowManagementSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites reading your monitor layout and placing windows on a chosen screen. Blocking breaks the full-screen presentation mode in some web apps. Chromium has no Allow state for this key."},

            {"name": "Clipboard Read Access", "key": "DefaultClipboardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites reading your clipboard without you pasting. Block removes the prompt and breaks Paste buttons inside web apps; Ask keeps the prompt. Either one overrides sites you allowed before. Ctrl+V and copy buttons still work. Chromium has no Allow state for this key."},

            {"name": "Block Microphone Access", "key": "AudioCaptureAllowed", "value": False, "desc": "Stops every site and extension from using the microphone or any other audio input, with no prompt; per-site Allow exceptions stop working too. Breaks web calls and meetings (Meet, Zoom or Teams on the web, Discord, Brave Talk), voice messages and dictation on websites."},

            {"name": "Block Camera Access", "key": "VideoCaptureAllowed", "value": False, "desc": "Stops every site and extension from using the camera or any other video input, with no prompt; per-site Allow exceptions stop working too. Breaks web video calls (Meet, Zoom or Teams on the web, Discord, Brave Talk), webcam ID checks and in-browser QR scanners."},

        ],
    },
    {
        # Lockdowns and the escape hatches (guest, incognito, extensions)
        # that would otherwise bypass the rest of the policy set.
        "name": "Access Controls",
        "features": [
            {"name": "Force Google SafeSearch", "key": "ForceGoogleSafeSearch", "value": True, "desc": "Forces SafeSearch on for all Google searches. Mainly useful for parental controls."},

            {"name": "Force YouTube Restricted Mode (Strict)", "key": "ForceYouTubeRestrict", "value": 2, "desc": "Forces YouTube's Strict Restricted Mode on youtube.com and its country domains, including videos other sites embed from them; the user cannot turn it off. Many videos become unavailable and comments are hidden. Videos embedded from youtube-nocookie.com are not restricted."},

            {"name": "Lock Safe Browsing On (Standard)", "key": "SafeBrowsingProtectionLevel", "value": 1, "group": "safebrowsing", "desc": "Locks Safe Browsing at Standard protection so it cannot be switched to No protection in brave://settings/security. Lookups go through Brave's proxy, as they do by default. Mutually exclusive with Disable Safe Browsing."},

            {"name": "Block Bypassing Safe Browsing Warnings", "key": "DisableSafeBrowsingProceedAnyway", "value": True, "desc": "Removes the option to continue past Safe Browsing's malware and phishing warnings, so a flagged site cannot be opened, even one flagged by mistake. Does not cover certificate or download warnings. Does nothing while Safe Browsing is off; Lock Safe Browsing On keeps it on."},

            {"name": "Block Bypassing Certificate Warnings", "key": "SSLErrorOverrideAllowed", "value": False, "desc": "Removes the Proceed link, and the typed bypass, from certificate-error pages, so a site whose certificate is invalid, expired or self-signed cannot be opened at all. Breaks router, NAS and printer admin pages and local dev servers that use self-signed certificates."},

            {"name": "Disable Guest Mode", "key": "BrowserGuestModeEnabled", "value": False, "desc": "Removes guest browsing sessions: off-the-record windows that keep no history and run without your profile's extensions. Disable Incognito Mode does not remove them. These policies still apply inside guest windows."},

            {"name": "Prevent Deleting History", "key": "AllowDeletingBrowserHistory", "value": False, "desc": "Stops anyone deleting browsing and download history in History, Downloads or Clear browsing data; Brave's clear-on-exit keeps them too. Brave's Local history retention setting (brave://settings/privacy) can still expire history after as little as a day, and SlimBrave cannot lock it."},

            {"name": "Block All Extensions", "key": "ExtensionInstallBlocklist", "value": ["*"], "desc": "Blocks installation of every extension and disables ones already installed. For lockdown/parental setups - a proxy or VPN extension would bypass DNS filtering."},

            {"name": "Block Sideloaded (External) Extensions", "key": "BlockExternalExtensions", "value": True, "desc": "Blocks extensions other programs install through the Windows registry or a drop-in file (how bundleware gets in) and removes any added that way at the next launch, even ones you approved. Extensions you install yourself keep working."},

            {"name": "Block Command-Line Extensions (--load-extension)", "key": "ExtensionInstallTypeBlocklist", "value": ["command_line"], "desc": "Ignores extensions passed with --load-extension, which malware adds to Brave's shortcuts to slip one in. Google Chrome ignores that switch; Brave honours it unless this is set. --disable-extensions-except can still load one. Breaks shortcuts and test tools that use the switch. Restart needed."},

            {"name": "Disable Incognito Mode", "key": "IncognitoModeAvailability", "value": 1, "group": "incognito", "desc": "Removes private browsing entirely - no incognito windows can be opened. Mutually exclusive with Force Incognito Mode."},

            {"name": "Force Incognito Mode", "key": "IncognitoModeAvailability", "value": 2, "group": "incognito", "desc": "Every window opens in incognito: no history, and logins and most extensions stop persisting. Tor windows go too, and so do Leo and Brave Rewards, plus Brave Wallet unless it is allowed in private windows. Mutually exclusive with Disable Incognito Mode."},

        ],
    },
    {
        "name": "Brave Features",
        "features": [
            {"name": "Disable Brave Rewards", "key": "BraveRewardsDisabled", "value": True, "desc": "Removes Brave Rewards and keeps Brave's ads service off, so no sponsored New Tab Page images or notification ads. Brave Search's own result ads are not affected, and an anonymous background fetch of the ads encryption key still runs unless Limit or Disable Variations is also set."},

            {"name": "Disable Brave Wallet", "key": "BraveWalletDisabled", "value": True, "desc": "Disables the built-in cryptocurrency wallet and hides its UI."},

            {"name": "Disable Brave VPN", "key": "BraveVPNDisabled", "value": True, "desc": "Removes the Brave VPN feature and its upsell prompts."},

            {"name": "Disable Brave AI Chat", "key": "BraveAIChatEnabled", "value": False, "desc": "Disables Leo, Brave's built-in AI assistant, and removes it from the sidebar and address bar. Brave still downloads Leo's WebMCP tool-scripts component, though nothing uses it while Leo is off."},

            {"name": "Disable Local AI (On-Device Models, Brave 1.94+, off by default on Release)", "key": "BraveLocalAIEnabled", "value": False, "desc": "Stops Brave from downloading and running on-device AI models and from building an AI index of your browsing history; disabling Leo does not cover this. Off by default on Release (on in Nightly and half of Beta); this keeps it off if Brave or you turn it on. Takes effect after a restart."},

            {"name": "Disable Brave Shields", "key": "BraveShieldsDisabledForUrls", "value": ["https://*", "http://*"], "group": "shields", "desc": "Kiosk/testing only. Shields OFF for every site: no ad or tracker blocking; Shields & Content Protection rows, Strip Tracking URL Parameters and Reduce Language Fingerprinting do nothing. De-AMP, Debouncing, GPC and third-party cookie blocking still work. Mutually exclusive with Force Shields On."},

            {"name": "Force Shields On (All Sites)", "key": "BraveShieldsEnabledForUrls", "value": ["https://*", "http://*"], "group": "shields", "desc": "Locks Shields ON for every site: the per-site toggle can no longer drop ad, tracker or fingerprinting protection, but switching it off still unblocks third-party cookies and storage for that site. Mutually exclusive with Disable Brave Shields."},

            {"name": "Disable Brave News", "key": "BraveNewsDisabled", "value": True, "desc": "Removes the Brave News feed from the new tab page."},

            {"name": "Disable Brave Talk", "key": "BraveTalkDisabled", "value": True, "desc": "Hides Brave Talk (private video calls) from the new tab page, sidebar and menus. The talk.brave.com website itself still works."},

            {"name": "Disable Brave Playlist (off by default on Release)", "key": "BravePlaylistEnabled", "value": False, "desc": "Disables the Playlist feature for saving and playing media in the sidebar. Playlist is off by default on Release and Beta (on in Nightly); this keeps it off if Brave or you turn it on."},

            {"name": "Disable Web Discovery", "key": "BraveWebDiscoveryEnabled", "value": False, "desc": "Stops Brave from anonymously contributing pages you visit to the Brave Search index (Web Discovery Project)."},

            {"name": "Disable Speedreader", "key": "BraveSpeedreaderEnabled", "value": False, "desc": "Disables Speedreader, the distraction-free article reading mode."},

            {"name": "Disable Tor", "key": "TorDisabled", "value": True, "desc": "Removes the 'New private window with Tor' option."},

            {"name": "Disable Sync", "key": "SyncDisabled", "value": True, "desc": "Disables Brave Sync, which shares bookmarks, history, and settings across devices via a sync chain. Applying it also removes this device from its chain, so once the policy is lifted it has to rejoin with a sync code from another device."},

            {"name": "Disable Email Aliases", "key": "EmailAliasesEnabled", "value": False, "desc": "Disables the Email Aliases feature for generating throwaway email addresses, which current Brave releases turn on."},

        ],
    },
    {
        # Brave 1.86+ content-protection enforcers (fingerprinting
        # protection also works on 1.85). These pin Brave's own privacy
        # defaults as managed policy so neither the user nor a malicious
        # page/extension can quietly weaken them.
        "name": "Shields & Content Protection",
        "features": [
            {"name": "Enforce Ad Blocking", "key": "DefaultBraveAdblockSetting", "value": 2, "desc": "Pins Brave's network ad and tracker blocking on as managed policy, so it can't be lowered in settings or per site. Cosmetic filtering (element hiding, scriptlets) is not locked, and sites with Shields off are not covered."},

            {"name": "Enforce Fingerprinting Protection", "key": "DefaultBraveFingerprintingV2Setting", "value": 3, "desc": "Pins Shields fingerprinting protection on as managed policy, so it can't be turned off per site. Per-API exceptions (Brave's compatibility list or your own Shields toggles) still apply, and sites with Shields off are not covered."},

            {"name": "Force HTTPS Upgrades (Strict; not enforced on Brave's HTTPS-First rollout)", "key": "DefaultBraveHttpsUpgradeSetting", "value": 2, "desc": "Always upgrades connections to HTTPS; sites that can't serve it show a warning instead of falling back to HTTP. Not enforced where Brave moved to Chromium's HTTPS-First mode (Beta, Nightly, part of Release), which it only presets once; Limit or Disable Variations keeps it enforced."},

            {"name": "Cap Referrers (Strict Origin)", "key": "DefaultBraveReferrersSetting", "value": 2, "group": "referrers", "desc": "Caps the Referer header at the origin for cross-origin requests, as Brave already does by default, and locks it: per-site exceptions stop applying, including any Brave's compatibility list adds to fix sites. Mutually exclusive with Allow Permissive Referrers."},

            {"name": "Allow Permissive Referrers (unsafe-url)", "key": "DefaultBraveReferrersSetting", "value": 1, "group": "referrers", "desc": "Sends your full referring URL cross-origin when a site requests it. Compatibility escape hatch only - this weakens privacy and is excluded from every preset. Mutually exclusive with Cap Referrers."},

            {"name": "Forget First-Party Storage on Close", "key": "DefaultBraveRemember1PStorageSetting", "value": 2, "desc": "Clears a site's cookies and storage when you close its last tab - sites forget you (and your logins) between visits."},

        ],
    },
    {
        # Note: BackgroundModeEnabled is absent from the literal because the
        # Chromium policy is Windows/Linux only, so on macOS it would just
        # surface as an unrecognized-policy error in brave://policy. This
        # script also runs on Linux, where the row is valid — it is inserted
        # back in below.
        "name": "Performance & Bloat",
        "features": [
            {"name": "Enable Memory Saver", "key": "HighEfficiencyModeEnabled", "value": True, "desc": "Forces Memory Saver on: inactive tabs are discarded to free RAM and reload when you return to them."},

            {"name": "Force Hardware Acceleration", "key": "HardwareAccelerationModeEnabled", "value": True, "group": "hwaccel", "desc": "Brave already has 'Use graphics acceleration when available' on; this locks it on, so it can't be turned off in Settings to work around GPU glitches. The GPU blocklist or repeated GPU crashes can still force software rendering. Takes effect after a browser restart."},

            {"name": "Disable Hardware Acceleration", "key": "HardwareAccelerationModeEnabled", "value": False, "group": "hwaccel", "desc": "Forces GPU acceleration off. This is a departure from Brave's default and costs rendering performance and battery, so use it only when the GPU path is itself the problem: flickering or artifacts from a faulty driver, a VM or RDP session with no usable GPU, or corruption while screen sharing. Takes effect after a browser restart."},

            {"name": "Disable Media Router (Cast)", "key": "EnableMediaRouter", "value": False, "desc": "Disables the Google Cast media router and its background device discovery on the local network. Takes effect after a browser restart. On a profile first opened under this policy, Cast stays off after it is removed until the Media Router toggle in brave://settings/extensions is turned back on and Brave restarted."},

            {"name": "Always Open PDF Externally", "key": "AlwaysOpenPdfExternally", "value": True, "desc": "Downloads PDF files instead of showing them in Brave's built-in viewer; nothing opens them until you do. Sites can tell the viewer is off, and fingerprinting protection does not hide it, which makes you easier to fingerprint."},

            {"name": "Disable Translate", "key": "TranslateEnabled", "value": False, "desc": "Disables the built-in page translation feature and its popup prompts."},

            {"name": "Disable Spellcheck", "key": "SpellcheckEnabled", "value": False, "group": "spellcheck", "desc": "Turns off spell checking in text fields entirely. Mutually exclusive with Disable Enhanced Spell Check, which keeps offline checking and only removes the Google lookup."},

            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False, "desc": "Stops sending what you type in the address bar to your search engine for live suggestions."},

            {"name": "Disable Printing", "key": "PrintingEnabled", "value": False, "desc": "Disables printing from the browser entirely (including Ctrl+P and Save as PDF). Brave features built on print preview break too: Leo reading Google Docs and scanned PDFs, and the Screenshot tool's Full page on PDFs and Google Docs."},

            {"name": "Disable Default Browser Prompt", "key": "DefaultBrowserSettingEnabled", "value": False, "desc": "Stops Brave from asking to become your default browser, and brave://settings loses its Make default button. Brave's first-run welcome page still offers Set as default, and clicking it with this policy on crashes Brave: choose Skip there."},

            {"name": "Disable Developer Tools", "key": "DeveloperToolsAvailability", "value": 2, "desc": "Blocks DevTools (F12), extension debugging and the View page source shortcut and menu, and turns extension Developer mode off (no Load unpacked). Brave's Screenshot Full page then never finishes and greys out Screenshot in that window until it is closed. Not for web developers."},

            {"name": "Disable Wayback Machine", "key": "BraveWaybackMachineEnabled", "value": False, "desc": "Stops Brave from offering an archive.org snapshot when a page is missing or fails (404, 408, 410, 451 and some 5xx errors), including the offer Brave can pop up on its own."},

        ],
    },
]

# BackgroundModeEnabled is chrome.win + chrome.linux upstream. Gate on the
# running platform rather than `not IS_MAC` so the row only appears where
# Brave actually honours it. Index 0 of Performance & Bloat matches the
# position it occupies in slimbrave-linux.py and SlimBrave.ps1.
# NetworkServiceSandboxEnabled is chrome.win + chrome.linux only too: macOS
# always sandboxes the network service and is not in its supported_on. It
# is appended last to Privacy & Security, so the order matches
# slimbrave-linux.py.
# BraveVPNDisabled works the other way round: honoured on macOS, compiled
# out of Linux builds. On Linux the row keeps its key and value but takes
# the same label and description note slimbrave-linux.py gives it.
if sys.platform.startswith("linux"):
    for _cat in CATEGORIES:
        if _cat["name"] == "Performance & Bloat":
            _cat["features"].insert(0, {"name": "Disable Background Mode",
                                        "key": "BackgroundModeEnabled", "value": False,
                                        "desc": "Stops Brave from staying open in the background after its last window closes, which it does only while an installed extension asks to run in the background. Without one, the policy only locks off 'Continue running background apps when Brave is closed' (brave://settings/system)."})
        if _cat["name"] == "Privacy & Security":
            _cat["features"].append({"name": "Sandbox the Network Service",
                                     "key": "NetworkServiceSandboxEnabled", "value": True,
                                     "desc": "Runs Brave's network process in the OS sandbox, which Brave leaves off by default. Ignored on Windows on ARM and before Windows 10 20H1, and after a failed sandboxed start until the next major update. On Linux, switched off for good the first time a site asks for Kerberos (Negotiate) sign-in."})
        for _feat in _cat["features"]:
            if _feat["key"] == "BraveVPNDisabled":
                _feat["name"] = "Disable Brave VPN (no effect on Linux builds)"
                _feat["desc"] += " Linux builds have no VPN, so this key changes nothing there."

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

    The main list shows feature toggles + the DNS section. On macOS,
    channel selection is asked at Apply time (see prompt_channel_selection)
    rather than as a permanent row, so the main list stays focused on the
    policies themselves regardless of how many channels are installed.
    `installations` has one effect on the layout, on Linux only: when
    every detected Brave is Brave Origin, the rows whose feature Origin
    compiles out are marked inert (ORIGIN_BUILTIN_KEYS).
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
                    "desc": feat.get("desc", ""),
                    "selected": 0,            # index into choices; 0 = unmanaged
                })
                continue
            rows.append({
                "type": ROW_FEATURE,
                "text": feat["name"],
                "key": feat["key"],
                "value": feat["value"],
                "group": feat.get("group"),
                "desc": feat.get("desc", ""),
                "checked": False,
            })
    # On a machine whose only Brave is Origin, the rows for the features
    # Origin compiles out are shown but inert (see ORIGIN_BUILTIN_KEYS).
    if is_origin_only(installations):
        for row in rows:
            if row["type"] == ROW_FEATURE and row["key"] in ORIGIN_BUILTIN_KEYS:
                row["inert"] = True
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
    Force Incognito, which set conflicting values for the same policy).
    An inert row (built into Brave Origin) never changes."""
    if target.get("inert"):
        return
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
        if row.get("inert"):
            return False
        toggle_feature_row(rows, row)
    elif row["type"] == ROW_CHOICE:
        cycle_choice_row(row, 1)
    elif row["type"] == ROW_DNS:
        row["selected"] = (row["selected"] + 1) % len(row["options"])
    else:
        return False
    return True


def _value_fits_row(row, value):
    """True when `value` has the JSON type of the policy a checkbox row writes.

    Import and policy-sync take a value only in that type, the rule
    SlimBrave.ps1's import applies too: an integer policy only a JSON
    integer, a boolean policy true/false or an integer, a list policy an
    array, the string policy a string.
    """
    want = row["value"]
    if isinstance(want, bool):
        return type(value) in (bool, int)  # Windows exports write 0/1
    if isinstance(want, int):
        return type(value) is int  # True == 1 must not pick an enum member
    if isinstance(want, list):
        return isinstance(value, list)
    return isinstance(value, str)


def _value_matches_row(row, value):
    """True when `value` is exactly what a checkbox row writes."""
    if not _value_fits_row(row, value):
        return False
    if isinstance(row["value"], list):
        # Order means nothing to Chromium, as in SlimBrave.ps1's Compare-Object.
        return sorted(value, key=str) == sorted(row["value"])
    return value == row["value"]


def _enforce_groups(rows):
    """Collapse every group down to at most one checked row.

    Import and policy-sync set `checked` per row with no group awareness,
    so a config naming both BraveShieldsDisabledForUrls and
    BraveShieldsEnabledForUrls ticks both and _build_policy would emit
    force-off and force-on for the same wildcards. The later row in table
    order wins, whatever order the file or policy lists the keys in. Where
    the members sit on different keys that is what Brave enforces when both
    are set: BraveShieldsEnabledForUrls is applied after the Disabled list,
    so it wins for the same patterns, and SpellCheckServiceEnabled does
    nothing once SpellcheckEnabled is false. SlimBrave.ps1's
    Enforce-ExclusionGroups applies the same rule.

    Returns the keys of the rows it unchecked, for the import message.
    """
    # Choice rows never reach the bodies below: every test here is gated on
    # ROW_FEATURE, and a choice row carries neither "checked" nor a group.
    dropped = []
    groups = dict.fromkeys(r["group"] for r in rows
                           if r["type"] == ROW_FEATURE and r.get("group"))
    for group in groups:
        members = [r for r in rows
                   if r["type"] == ROW_FEATURE
                   and r.get("group") == group and r["checked"]]
        for r in members[:-1]:
            r["checked"] = False
            dropped.append(r["key"])
    return dropped

# ---------------------------------------------------------------------------
# BOM-aware JSON reader (handles PowerShell UTF-16 exports)
# ---------------------------------------------------------------------------


# Import reads the file you name as root, so it reads no more than a config
# could ever need. A pipe such as /dev/stdin still works: nothing asks for a
# regular file, the read just stops one byte past the cap.
MAX_IMPORT_BYTES = 1024 * 1024


def read_json_file(path):
    """Read a JSON file, handling BOM and encoding from PS1 exports.

    Raises OSError for a file over MAX_IMPORT_BYTES, which import_settings
    reports as a read error.
    """
    with open(path, "rb") as f:
        data = f.read(MAX_IMPORT_BYTES + 1)
    if len(data) > MAX_IMPORT_BYTES:
        raise OSError("file is larger than 1 MiB")

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
# Some profiles carry braveShields exceptions for exactly the patterns the
# "Disable Brave Shields" row writes (`http://*,*` and `https://*,*`), left
# behind after that policy was applied and removed; while there they keep
# Shields off after the row is unchecked. Brave does not write the managed
# policy into Preferences (policy content settings stay in memory), and no
# writer of these entries has been identified, so this scrub is a guard for
# profiles that carry them, not a fix for a known cause.
# ---------------------------------------------------------------------------


def _pid_is_alive(pid):
    """True if `pid` names a live process.

    /proc is the cheap check on Linux; macOS has no procfs, so fall back
    to signal 0. Never reached off POSIX — os.kill there terminates rather
    than probes.
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
    """Return (host, pid) from a profile's Chromium SingletonLock, or None.

    Chromium symlinks <user-data-dir>/SingletonLock to "<hostname>-<pid>"
    for as long as the profile is open. This is the only running-check that
    covers every channel: `pgrep -x` matches the kernel's accounting name
    (/proc/<pid>/comm, 15 chars on Linux; p_comm, 16 on macOS), so
    "brave-browser-beta" and "Brave Browser Nightly" can never match.
    """
    if not prefs_path:
        return None
    user_data = os.path.dirname(os.path.dirname(prefs_path))
    try:
        target = os.readlink(os.path.join(user_data, "SingletonLock"))
    except OSError:
        return None
    host, sep, pid_part = target.rpartition("-")
    if not sep or not pid_part.isdigit():
        return None
    return host, int(pid_part)


def _lock_holder_is_running(host, pid):
    """True if a SingletonLock's holder still counts as a running Brave.

    A lock taken on another host counts: the profile is in use there (a
    shared home), and Chromium treats it the same way. On this host the
    pid has to be alive, and on Linux it also has to be a Brave binary,
    Chromium's own IsChromeProcess test: a lock a crash left behind can
    name a pid some other program has since been given. Every Brave build
    on Linux, Origin included, runs a binary named brave. macOS has no
    procfs, so there a live pid is enough.
    """
    if host != socket.gethostname():
        return True
    if not _pid_is_alive(pid):
        return False
    if not os.path.isdir("/proc/self"):
        return True
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False
    if exe.endswith(" (deleted)"):
        exe = exe[:-len(" (deleted)")]
    return os.path.basename(exe) == "brave"


# pgrep by absolute path, never through PATH: sudo can pass the caller's
# PATH through, and a script-only sudoers grant must not let it pick the
# program root runs. macOS and procps install it in /usr/bin; /bin covers
# Linux distributions that have not merged /usr.
PGREP_PATHS = ("/usr/bin/pgrep", "/bin/pgrep")


def _pgrep(name, uid=None):
    """Return the exit status of `pgrep [-u uid] -x name`, or None with no pgrep."""
    args = ["-x", name] if uid is None else ["-u", str(uid), "-x", name]
    for exe in PGREP_PATHS:
        try:
            return subprocess.run(
                [exe, *args],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode
        except FileNotFoundError:
            continue
    return None


def _is_brave_running(installations=None):
    """True if any of the listed Brave installations have a live process.

    When `installations` is None, falls back to the legacy single-channel
    process name (Stable on each platform), preserving old behaviour for
    callers that haven't been updated. The process search is limited to
    the invoking user's processes (_invoking_user): theirs is the profile
    the scrub rewrites, and another account's Brave cannot overwrite it.
    """
    if installations is None:
        names = ["Brave Browser"] if IS_MAC else ["brave"]
    else:
        for inst in installations:
            holder = _singleton_lock_pid(inst.get("prefs_path"))
            if holder is not None and _lock_holder_is_running(*holder):
                return True
        names = [i["process_name"] for i in installations if i.get("process_name")]
        if not names:
            names = ["Brave Browser"] if IS_MAC else ["brave"]

    identity = _sudo_user_identity()
    uid = identity[1] if identity else None
    for name in names:
        # A name longer than the kernel's accounting-name cap can only ever
        # be a false negative, so don't spend a process asking.
        if len(name) > 15:
            continue
        rc = _pgrep(name, uid)
        if rc is None:
            return False
        if rc == 0:
            return True
    return False


def _sudo_user_identity():
    """Return (name, uid, gid) of the invoking user, or None (_invoking_user)."""
    identity = _invoking_user()
    return identity[:3] if identity else None


def _run_as_invoking_user(fn, *args, default):
    """Call fn(*args) with the invoking user's rights; return its result.

    As root with an invoking user to drop to, fn runs in a forked child
    that takes on that user's groups, gid and uid first, so it can read,
    create and replace only what the user could; its JSON-encoded result
    comes back over a pipe. A failed fork or drop, an exception in fn, or
    a reply that does not decode gives `default`, never a second try as
    root. Without root, without an invoking user or without fork (Windows),
    fn runs inline.
    """
    identity = _sudo_user_identity()
    if identity is None or not hasattr(os, "fork") or os.geteuid() != 0:
        return fn(*args)

    name, uid, gid = identity
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        return default

    if pid == 0:
        try:
            os.close(read_fd)
            try:
                os.initgroups(name, gid)
            except (AttributeError, OSError):
                # Never keep root's supplementary groups: fall back to the
                # primary group alone, and if even that fails the drop
                # fails and fn never runs.
                os.setgroups([gid])
            os.setgid(gid)
            os.setuid(uid)
            data = json.dumps(fn(*args)).encode("utf-8")
            while data:
                data = data[os.write(write_fd, data):]
        except BaseException:
            pass  # nothing more is sent; a cut-off reply fails to decode
        finally:
            os._exit(0)

    os.close(write_fd)
    chunks = []
    try:
        # Read to EOF before waiting: a reply larger than the pipe buffer
        # would otherwise block the child, and the wait with it.
        while True:
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        chunks = []
    finally:
        os.close(read_fd)
    os.waitpid(pid, 0)
    try:
        return json.loads(b"".join(chunks))
    except ValueError:
        return default


def _scrub_as_invoking_user(scrub, path, default):
    """Run a prefs scrub as the invoking user; `default` when there is none.

    As root with nobody to drop to (a root login, `su -`), nothing is
    scrubbed: rewriting a home directory as root is what the drop avoids.
    """
    if getattr(os, "geteuid", lambda: -1)() == 0 and _sudo_user_identity() is None:
        return default
    return _run_as_invoking_user(scrub, path, default=default)


def _repair_one_prefs(pref_path):
    """Scrub a single Preferences file, dropping root first where we can.

    Every path component under the user's home is theirs to replace, so
    doing the read-modify-write as root would follow a symlinked
    `Default`/`Profile *` into a file root owns and then hand it over.
    Fork and drop to the invoking user's uid/gid instead — the child can
    only reach what that user could already reach. Returns what
    _scrub_one_prefs does (0 when the drop fails, so a broken drop repairs
    nothing rather than repairing as root).
    """
    return _scrub_as_invoking_user(_scrub_one_prefs, pref_path, 0)


def _repair_user_data_dir(default_prefs_path):
    """Scrub every profile of one user-data dir in a single drop.

    The child lists the profiles as well, so root never reads a directory
    inside the user's home. Returns [removed, failed] (_scrub_user_data_dir).
    """
    return _scrub_as_invoking_user(_scrub_user_data_dir, default_prefs_path, [0, 0])


def _scrub_user_data_dir(default_prefs_path):
    """List a user-data dir's profiles and scrub each, as the caller.

    Returns [removed, failed]: the entries removed, and the number of
    profiles whose Preferences could not be read or rewritten. A list, so
    the reply from the dropped child decodes to the same value.
    """
    removed = failed = 0
    for path in _profile_prefs_paths(default_prefs_path):
        count = _scrub_one_prefs(path)
        if count < 0:
            failed += 1
        else:
            removed += count
    return [removed, failed]


def _scrub_one_prefs(pref_path):
    """Remove SlimBrave's Shields-disabled exceptions from one Preferences file.

    Returns the number of exception entries removed: 0 if the file is
    missing, is not JSON (or not UTF-8), or holds none of them; -1 if it
    exists but cannot be read, or holds them and cannot be rewritten.
    """
    if not pref_path or not os.path.isfile(pref_path):
        return 0

    try:
        with open(pref_path, "r", encoding="utf-8") as f:
            prefs = json.load(f)
    except ValueError:
        # JSONDecodeError and UnicodeDecodeError: not a file Brave could
        # load either, so there is nothing of ours to remove.
        return 0
    except OSError:
        return -1

    # Walk with type checks: valid JSON can still hold a null or a list
    # where Brave keeps an object.
    node = prefs
    for key in ("profile", "content_settings", "exceptions"):
        node = node.get(key) if isinstance(node, dict) else None
    bs = node.get("braveShields") if isinstance(node, dict) else None
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
        return -1

    return removed


def repair_brave_prefs(installations=None):
    """Remove the leaked Shields exceptions across all given channels.

    Returns (removed_count, failed, brave_was_running), where `failed` maps
    each user-data dir to the number of its profiles that could not be
    cleaned (_scrub_failure_note words it). When `installations` is None,
    repairs only the legacy stable-channel prefs path (back-compat).
    """
    if installations is None:
        # Legacy single-channel path — synthesise a stable installation.
        ch_def = MAC_CHANNELS[0] if IS_MAC else LINUX_CHANNELS[0]
        installations = [{"prefs_path": _channel_prefs_path(ch_def["user_data_dir"])}]

    running = _is_brave_running(installations)
    total = 0
    failed = {}
    seen = set()
    for inst in installations:
        prefs_path = inst.get("prefs_path")
        if not prefs_path:
            continue
        # One drop per user-data dir, which holds every profile's folder.
        user_data = os.path.dirname(os.path.dirname(prefs_path))
        if user_data in seen:
            continue
        seen.add(user_data)
        removed, not_cleaned = _repair_user_data_dir(prefs_path)
        total += removed
        if not_cleaned:
            failed[user_data] = not_cleaned
    return (total, failed, running)


def _scrub_failure_note(failed):
    """The sentence naming profiles the scrub could not clean, or ''."""
    if not failed:
        return ""
    n = sum(failed.values())
    return (f"Failed to clean {n} profile{'s' if n != 1 else ''}; "
            f"check ownership of {', '.join(failed)}.")


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
    Any error (no `profiles`, a timeout, a non-zero exit, output that does
    not parse) reads as not installed. An omitted --persist then resolves
    to off, so a profile can be removed without being re-staged, and the
    scope guard (_scope_conflict) stays out of the way. Telling "no
    profiles" from "the command failed" needs its output and exit status
    recorded on a real Mac first (AUDIT.md, What's next).
    """
    if not IS_MAC:
        return False
    try:
        result = subprocess.run(
            ["/usr/bin/profiles", "list", "-output", "stdout-xml",
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
            "PayloadDisplayName": f"Brave Policy ({bundle_id})",
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
            "Brave Browser enterprise policies managed by SlimBrave Neo. "
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
    Returns True when `profiles remove` exits 0; a non-zero exit can also
    mean there was nothing to remove, so callers that must know ask
    _is_profile_installed afterwards.
    """
    if not IS_MAC:
        return False
    try:
        result = subprocess.run(
            ["/usr/bin/profiles", "remove",
             "-identifier", PERSIST_PROFILE_IDENTIFIER,
             "-type", "configuration",
             "-forced"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _sweep_stale_stage_dirs(keep=None):
    """Remove staging directories left by earlier runs.

    A staged mobileconfig enumerates the whole privacy configuration, so
    copies shouldn't pile up in the temp dir indefinitely — one Apply
    leaves at most one, and reset leaves none.

    Deleting as root inside a possibly shared temp dir needs care: only
    entries that are real directories (lstat, never a symlink), carry our
    prefix, and are owned by root or by the invoking user are touched. A
    directory another local user planted is skipped, so this can't be
    turned into a root-powered delete of someone else's tree.
    """
    identity = _sudo_user_identity()
    allowed_uids = {0}
    if identity is not None:
        allowed_uids.add(identity[1])
    try:
        parent = tempfile.gettempdir()
        entries = list(os.scandir(parent))
    except OSError:
        return
    for entry in entries:
        if not entry.name.startswith(STAGE_DIR_PREFIX):
            continue
        path = os.path.join(parent, entry.name)
        if keep and os.path.abspath(path) == os.path.abspath(keep):
            continue
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in allowed_uids:
            continue
        shutil.rmtree(path, ignore_errors=True)


def _install_profile_from_policy(policy_by_bundle):
    """Generate the mobileconfig and hand it to System Settings.

    macOS 11+ disallows CLI install of configuration profiles (see
    `man profiles`), so the only path is `open <file.mobileconfig>`
    which lets macOS route the file to System Settings > General >
    Device Management for user approval. The caller (apply_policy) has
    already removed any installed version via _clear_persistence_artifacts,
    so until the user approves this one no Configuration Profile carries
    a SlimBrave policy.

    `open` is run as the invoking user (_invoking_user: SUDO_USER, else
    USER) so LaunchServices targets that user's GUI session — running it
    as root produces inconsistent behaviour when the console user differs.

    Returns (True, profile_path) once `open` has taken the file, or
    (False, message) if the file cannot be written or `open` fails, times
    out or exits non-zero (over SSH with no desktop session for the user,
    say). The staged file is kept then and the message names it, so the
    user can double-click it from a desktop session.
    """
    mc = _build_mobileconfig(policy_by_bundle)
    # mkdtemp, not a fixed /tmp name: any local user can pre-create that
    # path, and a directory there makes os.replace fail for good. The dir
    # stays root-owned and 0755, so the invoking user's `open`, and System
    # Settings whenever they approve the profile, can read the file, but
    # nobody else can rename or swap entries in it. The contents aren't
    # secret; they're the same key/values otherwise written to a
    # world-readable system plist.
    stage_dir = tempfile.mkdtemp(prefix=STAGE_DIR_PREFIX)
    # By path, and still safe: sudo drops TMPDIR, so the parent is the
    # sticky /tmp, where only root can rename this root-owned entry.
    os.chmod(stage_dir, 0o755)
    # Drop every earlier run's copy now that this one exists.
    _sweep_stale_stage_dirs(keep=stage_dir)
    profile_path = os.path.join(stage_dir, PERSIST_PROFILE_NAME)
    try:
        _atomic_write(
            profile_path, plistlib.dumps(mc),
            binary=True, mode=0o644,
        )
    except OSError as e:
        shutil.rmtree(stage_dir, ignore_errors=True)
        return False, f"Failed to write mobileconfig: {e}"

    identity = _invoking_user()
    if identity is not None:
        open_cmd = ["/usr/bin/sudo", "-u", identity[0], "/usr/bin/open"]
    else:
        open_cmd = ["/usr/bin/open"]
    try:
        result = subprocess.run(
            open_cmd + [profile_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
        reason = f"exit status {result.returncode}" if result.returncode else ""
    except subprocess.TimeoutExpired:
        reason = "timed out"
    except (OSError, subprocess.SubprocessError) as e:
        reason = str(e) or type(e).__name__
    if reason:
        # The .mobileconfig stays on disk: double-clicking it from a
        # desktop session finishes the same install.
        return False, (
            f"Could not hand the profile to System Settings ({reason}). "
            f"It is staged at {profile_path}; double-click it while logged "
            "in to the desktop. Until it is installed, no Configuration "
            "Profile carries these settings."
        )
    try:
        # Also jump System Settings to the Device Management pane — the
        # `open` of the .mobileconfig only queues the download on
        # macOS 13+ and doesn't surface the install UI on its own. Only a
        # convenience, so its result is not checked.
        subprocess.run(
            open_cmd + [
                "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return True, profile_path


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
    """Remove any installed Configuration Profile.

    Called by every Apply and Reset except a --policy-file run (so an
    `off` Apply after a previous `on` Apply cleanly tears the profile
    down). Clearing SlimBrave's keys from the plists is the caller's job
    (_strip_managed): apply/reset already iterate over plist_path targets.

    The staged mobileconfig outlives the run that wrote it on purpose:
    approving a profile is an asynchronous, user-driven step in System
    Settings. But tearing the profile down means no approval is pending,
    so the staged copies go too. Returns what _remove_profile does.
    """
    if not IS_MAC:
        return False
    removed = _remove_profile()
    _sweep_stale_stage_dirs()
    return removed


# ---------------------------------------------------------------------------
# Policy I/O
# ---------------------------------------------------------------------------

# Keys earlier versions wrote and this one no longer offers, with the value
# they wrote (AUDIT.md, Considered and rejected). A macOS plist is shared
# with anything else that manages Brave, so Apply and Reset no longer
# rewrite it whole; they delete each of these only while it still holds
# exactly that value, type included (plistlib reads <false/> as a bool, and
# 0 == False in Python). Kept equal to SlimBrave.ps1's
# $script:retiredPolicies by a test. On Linux the policy file is
# SlimBrave's own and is rewritten whole, so these never come up there.
RETIRED_POLICIES = {
    "AlternateErrorPagesEnabled": False,
    "DNSInterceptionChecksEnabled": False,
    "EnableDoNotTrack": True,
    "FeedbackSurveysEnabled": False,
    "IPFSEnabled": False,
    "MediaRecommendationsEnabled": False,
    "PromotionsEnabled": False,
    "SafeBrowsingExtendedReportingEnabled": False,
    "SafeSitesFilterBehavior": 1,
    "ShoppingListEnabled": False,
}
# v1.1.0 to v1.5.0 also wrote this on macOS, where Chromium never reads it.
# It is not retired on Windows or Linux, where a row still writes it.
MAC_ONLY_RETIRED_POLICIES = {"BackgroundModeEnabled": False}


def _managed_keys():
    """Every key a row writes on this platform, plus the two DNS keys."""
    keys = {feat["key"] for cat in CATEGORIES for feat in cat["features"]}
    return keys | {"DnsOverHttpsMode", "DnsOverHttpsTemplates"}


def _holds_managed_key(policy):
    """True if a policy dict holds at least one key SlimBrave manages."""
    managed = _managed_keys()
    return any(k in managed for k in policy)


def _is_retired(key, value):
    """True if `value` is exactly what an earlier version wrote for `key`."""
    retired = {**RETIRED_POLICIES, **MAC_ONLY_RETIRED_POLICIES}
    if key not in retired:
        return False
    expected = retired[key]
    return type(value) is type(expected) and value == expected


def _read_one_policy(plist_path):
    """Read a single policy file (plist on macOS, JSON on Linux).

    Anything that is not a readable dict reads as empty.
    """
    try:
        if IS_MAC:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        else:
            with open(plist_path, "r") as f:
                data = json.load(f)
    except (FileNotFoundError, PermissionError):
        return {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def load_existing_policy(installations=None):
    """Read the current on-disk policy and return its dict.

    With multi-channel installations, returns the first non-empty policy
    found (so the TUI's pre-check reflects an existing state when one
    exists). Falls back to legacy POLICY_FILE when no installations are
    supplied. On macOS a plist counts only if it holds a key SlimBrave
    manages: the plist is shared, and keys another tool wrote are not an
    existing SlimBrave policy (and give --export nothing to save).
    """
    if installations is None:
        data = _read_one_policy(POLICY_FILE)
        return data if not IS_MAC or _holds_managed_key(data) else {}

    # On Linux all channels share POLICY_FILE; dedupe to avoid reading the
    # same file repeatedly.
    seen = set()
    for inst in installations:
        p = inst.get("plist_path") or POLICY_FILE
        if p in seen:
            continue
        seen.add(p)
        data = _read_one_policy(p)
        if data and (not IS_MAC or _holds_managed_key(data)):
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
        if row["type"] == ROW_FEATURE and row["checked"] and not row.get("inert"):
            policy[row["key"]] = row["value"]
        elif row["type"] == ROW_CHOICE:
            choice_value = _choice_value(row)
            if choice_value is not None:
                policy[row["key"]] = choice_value
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    # Refuse to write a broken DNS config: "secure" (or "custom", which
    # maps to it) without a template URL sets DnsOverHttpsMode=secure with
    # no server. Chromium applies the mode anyway, blanks the templates
    # pref, and gates off the system-resolver fallback — every hostname
    # fails, and the user can't undo it in settings because the policy is
    # machine-managed. "automatic" is exempt: empty is valid there.
    if dns_mode in ("custom", "secure") and not dns_template:
        return None, "Secure/custom DNS requires a DoH template URL."

    # "unmanaged" writes no DNS keys at all; since Apply replaces every key
    # SlimBrave manages (_write_one_policy), any previously-managed DNS
    # policy is removed.
    if dns_mode and dns_mode != "unmanaged":
        # "custom" maps to "secure" in the actual Chromium policy
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
    """Write a single policy file and return (ok, error_msg).

    On macOS a channel's plist is shared with anything else that manages
    Brave, so only SlimBrave's own keys are replaced: every key it does not
    manage stays, except a retired one still holding the value an earlier
    version wrote (_is_retired). The Linux slimbrave.json is SlimBrave's
    own and is rewritten whole. Any directory created on the way is 0755
    whatever the caller's umask: under sudo's union with a strict one (027)
    a 0750 root directory would hide every policy from Brave, which runs
    as the user.
    """
    try:
        old_umask = os.umask(0o022)
        try:
            os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        finally:
            os.umask(old_umask)
        if IS_MAC:
            managed = _managed_keys()
            merged = {k: v for k, v in _read_one_policy(plist_path).items()
                      if k not in managed and not _is_retired(k, v)}
            merged.update(policy)
            _atomic_write(plist_path, plistlib.dumps(merged), binary=True)
        else:
            _atomic_write(plist_path, json.dumps(policy, indent=4))
    except PermissionError:
        return False, "Permission denied. Run as root."
    except OSError as e:
        return False, f"Failed to write policy: {e}"
    except (TypeError, OverflowError) as e:
        # A value another tool put in the plist that plistlib cannot write
        # back (a binary-only type, an integer past 64 bits).
        return False, f"Failed to write policy: {e}"
    return True, ""


def _strip_managed(plist_path):
    """Remove SlimBrave's keys from a shared macOS plist.

    Drops every key SlimBrave manages and every retired key still holding
    the value an earlier version wrote; whatever else is there is written
    back, and a plist left with nothing in it is deleted. Returns
    (changed, kept): whether the file changed, and how many keys it still
    holds. A missing plist is (False, 0). Raises OSError when it cannot be
    rewritten or deleted.
    """
    if not os.path.exists(plist_path):
        return False, 0
    data = _read_one_policy(plist_path)
    managed = _managed_keys()
    kept = {k: v for k, v in data.items() if k not in managed and not _is_retired(k, v)}
    if not kept:
        os.remove(plist_path)
        return True, 0
    if len(kept) == len(data):
        return False, len(kept)
    try:
        payload = plistlib.dumps(kept)
    except (TypeError, OverflowError) as e:
        raise OSError(f"cannot rewrite {plist_path}: {e}") from e
    _atomic_write(plist_path, payload, binary=True)
    return True, len(kept)


def _strip_uninstalled_channels(targets):
    """On a full macOS Reset, also clear the channels that were not targeted.

    A channel uninstalled since an earlier Apply keeps its plist in
    /Library/Managed Preferences, and reinstalling it would bring the old
    policy back. Returns [(path, label)] for each plist that changed.
    """
    targeted = {path for path, _label in targets}
    touched = []
    for ch in MAC_CHANNELS:
        path = os.path.join(POLICY_DIR, f"{ch['bundle_id']}.plist")
        if path in targeted:
            continue
        changed, _kept = _strip_managed(path)
        if changed:
            touched.append((path, ch["label"]))
    return touched


def _is_override(installations):
    """True for the single synthetic target --policy-file builds."""
    return bool(installations) and all(
        i.get("channel") == "override" for i in installations)


def _scope_conflict(installations, selected_ids):
    """Labels of channels a scoped Apply or Reset would strip unasked.

    While the SlimBrave Configuration Profile is installed, every Apply and
    Reset removes the whole profile (_clear_persistence_artifacts), and the
    profile covers every channel it was staged for. A channel left out of
    the scope that still holds a SlimBrave policy (a managed key in its
    plist) would lose it, so the caller refuses instead. Empty off macOS,
    for a full scope, for the --policy-file override, and whenever
    `profiles list` does not report the profile, which fails open to the
    old behaviour.
    """
    if (not IS_MAC or selected_ids is None or not installations
            or _is_override(installations)):
        return []
    managed = detect_managed_channel_ids(installations)
    outside = [i["label"] for i in installations
               if i["channel"] not in selected_ids and i["channel"] in managed]
    if not outside or not _is_profile_installed():
        return []
    return outside


def _scope_conflict_message(labels):
    """The refusal Apply and Reset give for _scope_conflict's labels."""
    if len(labels) == 1:
        return f"{labels[0]} also has a SlimBrave policy; select it too, or Reset first."
    return (f"{', '.join(labels)} also have a SlimBrave policy; "
            "select them too, or Reset first.")


def _unreadable_policy_dir(directory, stop="/etc"):
    """Return (dir, mode) of a policy directory Brave cannot read, or None.

    Brave reads its policy directory as the user, so on Linux every
    directory below `stop` down to `directory` needs o+x, and `directory`
    itself o+r to be listed. A version older than the umask fix, run under
    a strict umask (027), created them 0750 as root. Returns the topmost
    offender; None off POSIX, or for a directory not under `stop`.
    """
    if os.name != "posix":
        return None
    stop = os.path.abspath(stop)
    d = os.path.abspath(directory)
    chain = []
    while d != stop:
        parent = os.path.dirname(d)
        if parent == d:
            return None
        chain.append(d)
        d = parent
    leaf = os.path.abspath(directory)
    for d in reversed(chain):
        try:
            mode = stat.S_IMODE(os.stat(d).st_mode)
        except OSError:
            continue
        need = stat.S_IXOTH | (stat.S_IROTH if d == leaf else 0)
        if mode & need != need:
            return d, mode
    return None


def _unreadable_dir_note(plist_path):
    """The Apply-message sentence for _unreadable_policy_dir, or ''."""
    found = _unreadable_policy_dir(os.path.dirname(plist_path))
    if found is None:
        return ""
    d, mode = found
    return f"Brave cannot read {d} (mode {mode:o}); run 'sudo chmod 755 {d}'"


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


# The profile the last persist-`on` Apply staged, for cli_import to print in
# full (the TUI status line has no room for a temp path).
_last_staged_profile = None


def apply_policy(rows, installations=None, persist_mode=PERSIST_DEFAULT,
                 selected_channel_ids=None):
    """Write the policy with or without durable persistence.

    Persistence modes (macOS only — Linux ignores `persist_mode` since
    its /etc/brave/policies file is already durable):
        off  Write plist to /Library/Managed Preferences/. May reset
             after reboot on macOS 13+; useful for quick tests.
        on   Install an Apple Configuration Profile via System Settings
             so policies survive reboots. Requires a one-time GUI step.

    On macOS every Apply except a --policy-file run first removes the
    whole installed SlimBrave profile, whichever mode was used before, so
    the on-disk state always matches the new mode. While that profile is
    installed, a scope that leaves out a channel still holding a SlimBrave
    policy is refused (_scope_conflict) before anything is touched. The
    --policy-file override never touches the profile and takes only `off`.
    """
    global _last_staged_profile
    _last_staged_profile = None
    if not IS_MAC and persist_mode != "off":
        persist_mode = "off"
    if persist_mode not in PERSIST_MODES:
        return False, (
            f"Unknown persist mode '{persist_mode}'. "
            f"Valid: {', '.join(PERSIST_MODES)}."
        )
    override = _is_override(installations)
    if override and persist_mode == "on":
        return False, (
            "Persist on cannot be used with --policy-file: a Configuration "
            "Profile targets each channel's bundle, not a file."
        )

    policy, err = _build_policy(rows)
    if policy is None:
        return False, err

    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(_selected_channel_targets(installations, selected_channel_ids))

    if not targets:
        return False, "No Brave channel selected. Check at least one channel."

    conflict = _scope_conflict(installations, selected_channel_ids)
    if conflict:
        return False, _scope_conflict_message(conflict)

    # On macOS, drop any previously-installed profile so switching modes
    # is never additive — e.g. an `off` Apply after a previous `on` Apply
    # should leave only the plist, not both. A --policy-file run writes
    # one file and leaves the profile alone.
    if IS_MAC and not override:
        _clear_persistence_artifacts()

    written_labels = []
    unreadable = ""

    if persist_mode == "on":
        policy_by_bundle = {}
        for plist_path, label in targets:
            bundle = _bundle_id_for_plist(plist_path)
            if bundle:
                policy_by_bundle[bundle] = policy
            if label:
                written_labels.append(label)
        if not policy_by_bundle:
            return False, "No valid Brave channel bundle id found."
        # The installed profile is already gone (_clear_persistence_
        # artifacts above). Staging before the plists are cleared only
        # keeps them in force if staging fails.
        ok, staged = _install_profile_from_policy(policy_by_bundle)
        if not ok:
            return False, staged
        _last_staged_profile = staged
        # Configuration Profile is cfprefsd's only forced source. Clear
        # SlimBrave's keys from any plist a prior `off` Apply left under
        # /Library/Managed Preferences/ so cfprefsd doesn't see two
        # competing sources for the same bundle; other keys stay.
        for plist_path, _label in targets:
            try:
                _strip_managed(plist_path)
            except OSError:
                pass
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
            if not IS_MAC and not unreadable:
                unreadable = _unreadable_dir_note(plist_path)
        if IS_MAC:
            _flush_cfprefsd()

    repair_targets = (
        _selected_channel_targets(installations, selected_channel_ids)
        if installations else None
    )
    msg = _post_apply_message(
        *repair_brave_prefs(repair_targets),
        labels=written_labels, persist_mode=persist_mode,
    )
    # First, so the TUI's one status line shows it.
    return True, f"{unreadable}. {msg}" if unreadable else msg


def _post_apply_message(repaired, failed, brave_running, labels=None,
                        persist_mode=PERSIST_DEFAULT):
    """Build the status message after a successful Apply."""
    scope = f" to {', '.join(labels)}" if labels else ""
    if persist_mode == "on":
        # The state first: the TUI status line truncates near 76 columns.
        base = (
            f"Profile staged{scope}. Those channels have no SlimBrave policy "
            "until you install it in System Settings > General > Device "
            "Management."
        )
    elif IS_MAC:
        base = (
            f"Settings applied{scope}. Restart Brave to see changes. "
            "Persistence is off — values may reset on macOS 13+."
        )
    else:
        base = f"Settings applied{scope}. Restart Brave to see changes."

    # Only claim a repair count that can survive: Chromium serves prefs
    # from an in-memory PrefService and flushes on shutdown, so a running
    # Brave writes back over whatever we just cleaned.
    if repaired > 0 and not brave_running:
        prefs = f"pref{'s' if repaired != 1 else ''}"
        base += f" Cleaned {repaired} leaked profile {prefs}."
    if failed:
        base += " " + _scrub_failure_note(failed)
    if brave_running:
        base += (
            " Brave is running: any leaked profile prefs cleaned now will be "
            "overwritten when Brave next saves. Fully close Brave and run "
            "Apply again to make it stick."
        )
    return base


# What a Reset reports when `profiles remove` left the profile in place.
PROFILE_STILL_INSTALLED = (
    "Reset, but the Configuration Profile is still installed: remove it in "
    "System Settings > General > Device Management."
)
# Appended to a --policy-file Apply on macOS while the profile is installed.
PROFILE_STILL_APPLIES = (
    " The SlimBrave Configuration Profile is still installed and still applies."
)


def reset_policy(rows, installations=None, selected_channel_ids=None,
                 all_channels=False):
    """Reset all SlimBrave state: plists, profile, prefs leak.

    Tears down the Configuration Profile (if installed) and SlimBrave's
    keys in every targeted plist, regardless of which mode was last used,
    so a Reset is always a clean slate; on macOS a plist is deleted only
    when nothing else is left in it. While the profile is installed, a
    scope that leaves out a channel still holding a SlimBrave policy is
    refused first (_scope_conflict). `all_channels` (a full Reset) also
    clears the plists of macOS channels that are no longer installed. A
    --policy-file run leaves the profile alone. Returns False when the
    profile is still installed afterwards.
    """
    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(_selected_channel_targets(installations, selected_channel_ids))

    if not targets:
        return False, "No Brave channel selected. Check at least one channel."

    conflict = _scope_conflict(installations, selected_channel_ids)
    if conflict:
        return False, _scope_conflict_message(conflict)
    override = _is_override(installations)

    cleared_labels = []
    try:
        for plist_path, label in targets:
            if IS_MAC:
                _strip_managed(plist_path)
            elif os.path.exists(plist_path):
                os.remove(plist_path)
            if label:
                cleared_labels.append(label)
        if IS_MAC and all_channels and not override:
            for _path, label in _strip_uninstalled_channels(targets):
                cleared_labels.append(f"{label} (not installed)")
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

    still_installed = False
    if IS_MAC:
        if not override:
            _clear_persistence_artifacts()
        _flush_cfprefsd()
        # Asked again rather than trusting the exit status: a non-zero one
        # can also mean there was nothing to remove.
        still_installed = not override and _is_profile_installed()

    repair_targets = (
        _selected_channel_targets(installations, selected_channel_ids)
        if installations else None
    )
    repaired, failed, running = repair_brave_prefs(repair_targets)
    if still_installed:
        return False, PROFILE_STILL_INSTALLED
    scope = f" for {', '.join(cleared_labels)}" if cleared_labels else ""
    msg = f"All settings reset{scope}. Restart Brave to see changes."
    if repaired > 0 and not running:
        msg = (
            f"Reset{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if failed:
        msg += " " + _scrub_failure_note(failed)
    if running:
        msg += (
            " Brave is running: any leaked profile prefs cleaned now will be "
            "overwritten when Brave next saves. Fully close Brave and run "
            "Reset again to make it stick."
        )
    return True, msg


def detect_managed_channel_ids(installations):
    """Return the set of channel ids whose plist holds a SlimBrave policy.

    Used as the sticky default for the Apply-time channel prompt — so a
    user who previously managed Stable + Beta sees those two pre-ticked
    and can press Enter to keep the same scope — and by _scope_conflict.
    A plist counts only if it holds a key SlimBrave manages: keys another
    tool wrote neither pre-tick a channel nor block a scope.
    """
    if not installations:
        return set()
    managed = set()
    for inst in installations:
        existing = _read_one_policy(inst.get("plist_path") or "")
        if _holds_managed_key(existing):
            managed.add(inst["channel"])
    return managed


def sync_rows_with_policy(rows, policy):
    """Pre-check rows that match an existing policy on disk."""
    if not policy:
        return
    # A template that is not a string (a hand-edited file) reads as none
    # instead of crashing the TUI at launch.
    dns_tmpl = policy.get("DnsOverHttpsTemplates", "")
    if not isinstance(dns_tmpl, str):
        dns_tmpl = ""
    for row in rows:
        if row["type"] == ROW_FEATURE:
            # An inert row stays unticked whatever the file says, so the
            # next Apply drops the dead key rather than carrying it.
            if row.get("inert"):
                continue
            # The value must be in its policy's JSON type, as on import, so
            # a true on disk does not tick an integer row.
            if row["key"] in policy and _value_matches_row(row, policy[row["key"]]):
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
            # If mode is "secure" and a template is set, show as "custom"
            if dns_val == "secure" and dns_tmpl:
                if "custom" in row["options"]:
                    row["selected"] = row["options"].index("custom")
            elif dns_val in row["options"]:
                row["selected"] = row["options"].index(dns_val)
        elif row["type"] == ROW_DNS_TEMPLATE:
            if dns_tmpl:
                row["value"] = dns_tmpl
                row["cursor"] = len(dns_tmpl)
                row["scroll"] = 0
    _enforce_groups(rows)


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
        if row["type"] == ROW_FEATURE and row["checked"] and not row.get("inert"):
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

    # Written as the invoking user, not as root: the file and any folders
    # it needs are theirs from the start, and a path they could not write
    # themselves fails instead of being created with root's rights.
    text = json.dumps(settings, indent=4)
    ok, msg = _run_as_invoking_user(
        _write_export, path, text,
        default=[False, "Export failed: could not write as the invoking user"])
    return ok, msg


def _write_export(path, text):
    """Create the export file and its folders; returns [ok, message]."""
    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        _atomic_write(path, text)
    except PermissionError as e:
        home = _user_home_for_brave()
        if hasattr(os, "geteuid") and os.geteuid() != 0 and home:
            # The hint spells the home out in full, so it works the same
            # pasted into a shell as typed at the TUI prompt.
            import pwd
            try:
                who = pwd.getpwuid(os.getuid()).pw_name
            except KeyError:
                who = f"uid {os.getuid()}"
            suggestion = os.path.join(home, "SlimBraveNeoSettings.json")
            return [False, f"Export failed: {who} cannot write {path}; try {suggestion}"]
        return [False, f"Export failed: {e}"]
    except OSError as e:
        return [False, f"Export failed: {e}"]
    return [True, f"Exported to {path}"]


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
        # Drop non-string entries: a nested object would be unhashable and
        # blow up the dict comprehension.
        return {k: None for k in features_obj if isinstance(k, str)}, True
    return {}, False


def import_settings(rows, path):
    """Import a SlimBrave Neo JSON config and update TUI row states.

    Every refusal returns before any row is touched, so a failed import
    leaves the selections as they were. The order matches SlimBrave.ps1's
    Import: the file, a JSON object, a Features block, the DNS fields, each
    value against its policy's type, then the exclusion groups.
    """
    try:
        config = read_json_file(path)
    except FileNotFoundError:
        return False, f"File not found: {path}"
    except (ValueError, RecursionError) as e:
        # JSONDecodeError, UnicodeDecodeError and the 4300-digit integer
        # limit are all ValueErrors; a deeply nested file is RecursionError.
        return False, f"Invalid JSON: {e}"
    except OSError as e:
        return False, f"Read error: {e}"

    # `[1,2]`, `null`, `"x"` and `3` are all valid JSON that would die at
    # the first .get() — in the TUI that traceback escapes curses.wrapper.
    if not isinstance(config, dict):
        return False, (
            f"Invalid config: expected a JSON object, got {type(config).__name__}"
        )

    # A file without a Features object or array (the policy file, a
    # Bookmarks dump, a DNS-only file, a lowercase `features`) is not a
    # SlimBrave config. Taking it used to clear every row and report
    # success, and --import then wrote an empty policy.
    features = config.get("Features")
    if not isinstance(features, (dict, list)):
        return False, "Invalid config: no Features block (not a SlimBrave Neo config)"
    features_map, is_legacy = _parse_imported_features(features)

    # Values left unmanaged and named in the result message: a choice
    # key's value that is not a legal member of its enum, a value outside
    # its policy's JSON type, and an unknown DnsMode. Written out, such a
    # value is one Brave would ignore or misapply (a 1 on local fonts,
    # window management or clipboard becomes a managed Allow).
    skipped_choices = []

    # A list of strings is joined with spaces, as SlimBrave.ps1's [string]
    # cast joins an array; anything falsy is no template, as there. No
    # strip: SlimBrave.ps1 does not trim either.
    raw_tmpl = config.get("DnsTemplates")
    if isinstance(raw_tmpl, list) and all(isinstance(t, str) for t in raw_tmpl):
        raw_tmpl = " ".join(raw_tmpl)
    if not raw_tmpl:
        dns_template = ""
    elif isinstance(raw_tmpl, str):
        dns_template = raw_tmpl
    else:
        return False, "Invalid config: DnsTemplates must be a string"
    # No DnsMode in the file means DNS is unmanaged (a bare DnsTemplates is
    # treated as custom for legacy exports). The mode is matched in any
    # letter case, as SlimBrave.ps1 matches it; an unknown one leaves DNS
    # unmanaged and is named.
    raw_mode = config.get("DnsMode")
    if not raw_mode:
        dns_mode = "custom" if dns_template else "unmanaged"
    elif isinstance(raw_mode, str) and raw_mode.lower() in DNS_MODES:
        dns_mode = raw_mode.lower()
    else:
        dns_mode = "unmanaged"
        skipped_choices.append(f"DnsMode={raw_mode}")

    # Legacy array format can't distinguish value-1 vs value-2 for keys
    # with multiple rows (IncognitoModeAvailability). To avoid silently
    # picking the later entry — which historically force-incognitoed users
    # who imported the Parental Controls preset — only the first matching
    # row per key is checked in legacy mode.
    legacy_handled = set()
    # Keys the config names that are built into Brave Origin on this
    # machine: left unmanaged, and counted in the result message.
    skipped_inert = []

    for row in rows:
        if row["type"] == ROW_FEATURE:
            key = row["key"]
            if row.get("inert"):
                row["checked"] = False
                if key in features_map:
                    skipped_inert.append(key)
                continue
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
            elif not _value_fits_row(row, expected):
                row["checked"] = False
                # Two rows can share a key; it is named once.
                if key not in skipped_choices:
                    skipped_choices.append(key)
            else:
                row["checked"] = _value_matches_row(row, expected)
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
            # Always set, so the TUI never keeps its pre-import mode.
            row["selected"] = row["options"].index(dns_mode)
        elif row["type"] == ROW_DNS_TEMPLATE:
            row["value"] = dns_template
            row["cursor"] = len(dns_template)
            row["scroll"] = 0

    dropped = _enforce_groups(rows)
    msg = f"Imported from {path}"
    if skipped_choices:
        msg += ("; left unmanaged because the value is not one this policy "
                "accepts: " + ", ".join(skipped_choices))
    if skipped_inert:
        n = len(skipped_inert)
        msg += (f"; {n} key{'s' if n != 1 else ''} built into Brave Origin "
                "left unmanaged")
    if dropped:
        msg += ("; left unmanaged because it is mutually exclusive with "
                "another imported row: " + ", ".join(dropped))
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

# Focus zones
FOCUS_LIST = 0
FOCUS_BUTTONS = 1
FOCUS_PROMPT = 2   # status-line text input mode

# Every row type the cursor may land on. Headers joined the list when
# Space/Enter started folding them.
SELECTABLE_TYPES = (ROW_HEADER, ROW_FEATURE, ROW_CHOICE, ROW_DNS,
                    ROW_DNS_TEMPLATE)

# Stand-in for "the cursor is on nothing", which a filter matching zero
# rows produces. Its type matches no key branch, so they all fall through.
NO_ROW = {"type": None}


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


BOX_UNICODE = ("\u2500", "\u2502", "\u250c", "\u2510", "\u2514", "\u2518", "\u2026")
BOX_ASCII = ("-", "|", "+", "+", "+", "+", "...")
_box_glyphs = None


def box_glyphs():
    """Return (h, v, tl, tr, bl, br, ellipsis) as this terminal can encode them.

    The same rule as disclosure_glyphs(): ask the codec before drawing.
    """
    global _box_glyphs
    if _box_glyphs is None:
        try:
            enc = locale.getpreferredencoding(False) or "ascii"
            for glyph in BOX_UNICODE:
                glyph.encode(enc)
            _box_glyphs = BOX_UNICODE
        except (LookupError, UnicodeEncodeError, ValueError):
            _box_glyphs = BOX_ASCII
    return _box_glyphs


# Rows the list keeps before the description pane gives way to it.
DESC_PANE_MIN_LIST = 4


DESC_PANE_MAX_LINES = 4
_desc_pane_lines = {}


def desc_pane_lines(max_x):
    """Text lines the pane needs at this width.

    What the longest description wraps to at this width, up to
    DESC_PANE_MAX_LINES: four lines at 80 columns, where two of the
    descriptions still end in an ellipsis; three from about 120, where none
    does. Sized by the content rather than by a constant so a wider
    terminal gives the list its rows back.
    """
    if max_x not in _desc_pane_lines:
        width = max(1, (max_x - 1) - 4)
        texts = [f.get("desc", "") for cat in CATEGORIES for f in cat["features"]]
        texts += list(DNS_DESC.values()) + list(BUTTON_DESC.values())
        need = max((len(textwrap.wrap(t, width, break_on_hyphens=False))
                    for t in texts), default=1)
        _desc_pane_lines[max_x] = max(1, min(DESC_PANE_MAX_LINES, need))
    return _desc_pane_lines[max_x]


def layout(max_y, max_x, show_desc):
    """The row budget for one frame, shared by draw() and viewport_rows().

    Rows 0-1 are the title and the hints. The list sits in a box, the
    description pane (if shown) in a second, the buttons in a third, and
    the status line is the last row. The pane gives way when it would
    leave the list under DESC_PANE_MIN_LIST rows, so a small terminal
    keeps its list; under 9 rows the boxes go too, and the screen is the
    plain stack it was before them - list from row 2, buttons on the
    second-last row, status on the last - because eight rows of chrome
    would leave nothing else.
    """
    if max_y < 9:
        list_rows = max(1, max_y - 5)
        return {
            "framed": False,
            "list_top": 2,
            "list_rows": list_rows,
            "list_bottom": 2 + list_rows,
            "pane_top": None,
            "pane_lines": 0,
            "btn_top": max_y - 3,
            "btn_y": max_y - 2,
            "status_y": max_y - 1,
        }
    fixed = 2 + 2 + 3 + 1
    pane = desc_pane_lines(max_x) if show_desc else 0
    if pane and max_y - fixed - (pane + 2) < DESC_PANE_MIN_LIST:
        pane = 0
    list_rows = max(1, max_y - fixed - (pane + 2 if pane else 0))
    list_top = 3
    list_bottom = list_top + list_rows
    pane_top = list_bottom + 1 if pane else None
    btn_top = pane_top + pane + 2 if pane else list_bottom + 1
    return {
        "framed": True,
        "list_top": list_top,
        "list_rows": list_rows,
        "list_bottom": list_bottom,
        "pane_top": pane_top,
        "pane_lines": pane,
        "btn_top": btn_top,
        "btn_y": btn_top + 1,
        "status_y": max_y - 1,
    }


def template_field_width(max_x):
    """Width of the editable DoH template field inside the list box.

    The row is '    Template: [' + text + ']' plus a margin; draw() and the
    editing keys in main() must agree on this figure, or the cursor and
    the text scroll drift apart.
    """
    # capped so the closing bracket stays inside the box on a narrow terminal
    return max(1, min(max_x - 21, max(10, (max_x - 1) - 4 - 22)))


def wrap_description(text, width, max_lines, ellipsis="..."):
    """Word-wrap `text` to at most `max_lines` rows of `width`.

    A description that does not fit ends in `ellipsis`, so a cut is
    visible rather than silent.
    """
    if width < 1 or max_lines < 1:
        return []
    # break_on_hyphens off: a resolver URL must not split at "dns-query"
    lines = textwrap.wrap(text or "", width, break_on_hyphens=False)
    if len(lines) <= max_lines:
        return lines
    lines = lines[:max_lines]
    room = max(0, width - len(ellipsis))
    lines[-1] = lines[-1][:room].rstrip() + ellipsis
    return lines


BUTTON_DESC = {
    "Import": "Load a settings file - a preset from Presets/ or an earlier "
              "export - into the list. Nothing is written until Apply.",
    "Export": "Save the current selections as JSON that Import, and the "
              "other platforms' scripts, read back. Under sudo the file is "
              "written as you, not root, so pick a folder you can write to.",
    "Apply": "Asks whether to persist - and which channels, when more than "
             "one is installed - then writes the policy where Brave reads "
             "it at startup. Persisting hands a Configuration Profile to "
             "System Settings to finish.",
    "Reset": "Remove the policy this tool wrote, so Brave returns to its "
             "own defaults. Asks before it does.",
    "Quit": "Leave without writing anything.",
}

DNS_DESC = {
    "mode": "Secure and custom send every lookup to the template below and "
            "never fall back, so a wrong template resolves nothing. "
            "Automatic uses DNS over HTTPS when the resolver offers it and "
            "plain DNS otherwise. Off never uses it. Not managed leaves "
            "Brave's own setting alone.",
    "template": "The DNS-over-HTTPS resolver, as a template such as "
                "https://dns.example/dns-query. Required by secure and "
                "custom; automatic uses it when set.",
}


def describe_row(rows, cursor_idx, focus, btn_idx):
    """The description pane's text for whatever has focus."""
    if focus == FOCUS_BUTTONS:
        return BUTTON_DESC.get(BUTTONS[btn_idx], "")
    if not (0 <= cursor_idx < len(rows)):
        return ""
    row = rows[cursor_idx]
    kind = row["type"]
    if kind == ROW_HEADER:
        on, total = header_counts(rows, cursor_idx)
        inert = header_inert_count(rows, cursor_idx)
        if total or inert:
            built_in = f", {inert} built into Origin" if inert else ""
            return (f"{row['text']}: {total} settings, {on} on{built_in}. "
                    "Left folds the section, Right unfolds it, Space "
                    "toggles it, c folds or unfolds them all.")
        return f"{row['text']}: the resolver mode and its template."
    if kind == ROW_DNS:
        return DNS_DESC["mode"]
    if kind == ROW_DNS_TEMPLATE:
        return DNS_DESC["template"]
    if row.get("inert"):
        return ("Built into Brave Origin: this feature is not in the binary, "
                "so there is nothing for a policy to switch; the row is "
                "shown for reference only. " + row.get("desc", ""))
    return row.get("desc", "")


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
            # Inert rows (built into Brave Origin) count as neither.
            if row.get("inert"):
                continue
            total += 1
            if row["checked"]:
                on += 1
        elif row["type"] == ROW_CHOICE:
            total += 1
            if row["selected"] > 0:
                on += 1
    return on, total


def header_inert_count(rows, header_idx):
    """How many of a header's rows are built into Brave Origin."""
    start, end = header_span(rows, header_idx)
    return sum(1 for row in rows[start:end]
               if row["type"] == ROW_FEATURE and row.get("inert"))


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
        if total or header_inert_count(rows, idx):
            # A section whose every row is built into Origin manages
            # nothing, so it folds like one with nothing ticked.
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


def viewport_rows(stdscr, show_desc=False):
    """Return how many list rows fit inside the list box this frame."""
    max_y, max_x = stdscr.getmaxyx()
    return layout(max_y, max_x, show_desc)["list_rows"]


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
         prompt_label="", prompt_buf="", prompt_cur=0, filter_text="",
         show_desc=False, describe_focus=None):
    """Render the full TUI screen.

    Title and key hints on rows 0-1, the list inside a box, the
    description pane (when shown) inside a second box, the buttons inside
    a third, and the status line last. layout() owns the row arithmetic,
    so this and viewport_rows() cannot disagree about the list's height.
    """
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1  # avoid writing to the last column
    hz, vt, tl, tr, bl, br, ellipsis = box_glyphs()
    lay = layout(max_y, max_x, show_desc)
    framed = lay["framed"]
    inner_x = 2 if framed else 0
    inner_w = max(1, usable_w - 4) if framed else usable_w
    edge_attr = curses.color_pair(CP_NORMAL) | curses.A_DIM

    def put(y, x, text, n, attr):
        try:
            stdscr.addnstr(y, x, text, n, attr)
        except curses.error:
            pass

    def frame(top, bottom, label=""):
        """A box from row `top` to row `bottom`, `label` set in its top edge."""
        edge = hz * max(0, usable_w - 2)
        head = edge
        if label and len(label) + 2 < len(edge):
            head = hz + label + edge[len(label) + 1:]
        put(top, 0, tl + head + tr, usable_w, edge_attr)
        for y in range(top + 1, bottom):
            put(y, 0, vt, 1, edge_attr)
            put(y, usable_w - 1, vt, 1, edge_attr)
        put(bottom, 0, bl + edge + br, usable_w, edge_attr)

    # Title bar
    if install_method:
        title = f" SlimBrave Neo - Brave Browser Debloater [{install_method}] "
    else:
        title = " SlimBrave Neo - Brave Browser Debloater "
    pad = max(0, (usable_w - len(title)) // 2)
    put(0, 0, " " * usable_w, usable_w,
        curses.color_pair(CP_TITLE) | curses.A_BOLD)
    put(0, pad, title, usable_w - pad,
        curses.color_pair(CP_TITLE) | curses.A_BOLD)

    # Key hints below the title, or the live filter and its match count
    vis = visible_indices(rows, filter_text)
    needle = filter_text.strip()
    if needle:
        matches = sum(1 for i in vis if rows[i]["type"] != ROW_HEADER)
        plural = "" if matches == 1 else "es"
        hint = f" Filter: {needle}   {matches} match{plural}   [Esc] Clear "
    else:
        hint = " [Space/Enter] Toggle  [/] Search  [D] Describe  [Q] Quit  [?] Help "
        if len(hint) > usable_w:
            # the shorter hint from before the pane fits down to 55 columns
            hint = " [Space/Enter] Toggle  [/] Search  [Q] Quit  [?] Help "
    put(1, 0, hint.center(usable_w), usable_w,
        curses.color_pair(CP_NORMAL) | curses.A_DIM)

    # The list, in its box
    list_start_y = lay["list_top"]
    visible_count = lay["list_rows"]
    if framed:
        frame(list_start_y - 1, lay["list_bottom"], " Settings ")

    # Current DNS mode (for dimming the template row)
    current_dns_mode = get_dns_mode(rows)

    for vi in range(visible_count):
        vpos = vi + scroll_offset
        if vpos >= len(vis):
            break
        ri = vis[vpos]
        row = rows[ri]
        y = list_start_y + vi

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
            inert = header_inert_count(rows, ri)
            if total:
                counter = f"{on_count}/{total} on"
            elif inert:
                counter = f"{inert} built into Origin"
            else:
                counter = ""
            if counter:
                line = line.ljust(max(len(line) + 2,
                                      inner_w - len(counter) - 1)) + counter
        elif row["type"] == ROW_FEATURE:
            if row.get("inert"):
                # Built into Origin: nothing to tick, drawn the way the
                # unavailable DoH template field is. A long name gives way
                # so the suffix survives an 80-column terminal.
                text = row["text"]
                room = inner_w - len(INERT_SUFFIX) - len("    [-]  ")
                if len(text) > room:
                    text = text[:max(0, room - 3)].rstrip() + "..."
                line = f"    [-] {text} {INERT_SUFFIX}"
                attr = curses.color_pair(CP_DIM) | curses.A_DIM
            else:
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
                field_w = template_field_width(max_x)
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
                # padded to the field width, so the closing bracket keeps
                # its place when the cursor sits at the end of the text
                line = f"    Template: [{visible_text.ljust(field_w)}]"
                attr = curses.color_pair(CP_NORMAL)
            else:
                line = "    Template: (select custom/secure DNS)"
                attr = curses.color_pair(CP_DIM) | curses.A_DIM

        if is_cursor:
            attr = curses.color_pair(CP_CURSOR) | curses.A_BOLD

        put(y, inner_x, line.ljust(inner_w), inner_w, attr)

        # Draw text cursor for active template row
        if (is_cursor and row["type"] == ROW_DNS_TEMPLATE
                and current_dns_mode in ("custom", "secure")):
            tmpl_val = row["value"]
            field_start = inner_x + 15  # len("    Template: [")
            field_w = template_field_width(max_x)
            scroll = row.get("scroll", 0)
            cur_pos = row.get("cursor", 0)
            cur_screen_pos = field_start + cur_pos - scroll
            # Stay inside the bracketed field, not just inside the line.
            if field_start <= cur_screen_pos < min(inner_x + inner_w,
                                                   field_start + field_w):
                ch = tmpl_val[cur_pos] if cur_pos < len(tmpl_val) else " "
                put(y, cur_screen_pos, ch, 1,
                    curses.color_pair(CP_BUTTON_ACTIVE))

    # Scroll indicators, set into the box edges
    mark_x = usable_w - 7 if framed else usable_w - 5
    if scroll_offset > 0:
        put(list_start_y - 1, mark_x, " ^^^ ", 5, edge_attr)
    if scroll_offset + visible_count < len(vis):
        put(lay["list_bottom"], mark_x, " vvv ", 5, edge_attr)

    # Description pane: what the cursor is on, or the focused button
    if lay["pane_lines"]:
        top = lay["pane_top"]
        frame(top, top + lay["pane_lines"] + 1, " Description ")
        what = describe_focus if describe_focus is not None else focus
        text = describe_row(rows, cursor_idx, what, btn_idx)
        parts = wrap_description(text, inner_w, lay["pane_lines"], ellipsis)
        for i, part in enumerate(parts):
            put(top + 1 + i, inner_x, part, inner_w,
                curses.color_pair(CP_NORMAL))

    # Bottom buttons, in their box
    if framed:
        frame(lay["btn_top"], lay["btn_top"] + 2)
    btn_y = lay["btn_y"]
    btn_x = inner_x
    for i, label in enumerate(BUTTONS):
        display = f" {label} "
        if focus == FOCUS_BUTTONS and i == btn_idx:
            attr = curses.color_pair(CP_BUTTON_ACTIVE) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_BUTTON)
        put(btn_y, btn_x, display, max(0, inner_x + inner_w - btn_x), attr)
        btn_x += len(display) + 3

    # Status / prompt line
    status_y = lay["status_y"]
    if focus == FOCUS_PROMPT:
        prompt_text = f" {prompt_label}: {prompt_buf}"
        put(status_y, 0, prompt_text.ljust(usable_w), usable_w,
            curses.color_pair(CP_TITLE))
        cur_x = len(prompt_label) + 3 + prompt_cur
        if cur_x < usable_w:
            ch = prompt_buf[prompt_cur] if prompt_cur < len(prompt_buf) else " "
            put(status_y, cur_x, ch, 1, curses.color_pair(CP_BUTTON_ACTIVE))
    elif status_msg:
        cp = CP_STATUS_OK if status_ok else CP_STATUS_ERR
        put(status_y, 2, status_msg[:usable_w - 3], usable_w - 3,
            curses.color_pair(cp))

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
    "   d                     Show or hide the description pane",
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
                      install_method, label, default="", on_change=None,
                      show_desc=False):
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
             filter_text="" if on_change is None else text,
             show_desc=show_desc,
             # the filter prompt (on_change) describes the cursor row; the
             # Import and Export path prompts describe their button
             describe_focus=None if on_change is not None else FOCUS_BUTTONS)

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


def _draw_prompt_overlay(stdscr, desc_line, keys_line):
    """Paint an Apply-time prompt's two-line overlay and refresh.

    Bottom two screen rows: `desc_line` (title colour, bold) above
    `keys_line` (status colour). Shared by the channel-selection and
    persist-mode prompts.
    """
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1
    # The button row does not move with the pane, so the pane flag is moot
    # here; inside the button box when there is one, full width when not.
    lay = layout(max_y, max_x, False)
    if lay["framed"]:
        x, w = 2, max(1, usable_w - 4)
    else:
        x, w = 0, usable_w
    try:
        stdscr.addnstr(
            lay["btn_y"], x, desc_line.ljust(w)[:w],
            w, curses.color_pair(CP_TITLE) | curses.A_BOLD,
        )
        stdscr.addnstr(
            lay["status_y"], 0, keys_line.ljust(usable_w)[:usable_w],
            usable_w, curses.color_pair(CP_STATUS_OK),
        )
    except curses.error:
        pass
    stdscr.refresh()


def prompt_channel_selection(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                             install_method, installations, default_ids,
                             filter_text="", show_desc=False):
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
             FOCUS_BUTTONS, btn_idx, "", True, install_method,
             filter_text=filter_text, show_desc=show_desc)
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
        _draw_prompt_overlay(stdscr, desc_line, keys_line)

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
                        install_method, current_mode, filter_text="",
                        show_desc=False):
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
             FOCUS_BUTTONS, btn_idx, "", True, install_method,
             filter_text=filter_text, show_desc=show_desc)
        desc_line = (
            f"  Persist across reboots: < {mode} >    "
            f"↳ {PERSIST_DESCRIPTIONS[mode]}"
        )
        keys_line = (
            "  ←/→ select   Y/N quick-pick   "
            "Enter=confirm   Esc=cancel"
        )
        _draw_prompt_overlay(stdscr, desc_line, keys_line)

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


def _expand_prompt_path(path):
    """Expand a leading ~ in a path typed at the TUI's Import/Export prompt.

    `~` and `~/...` mean the invoking user's home (_invoking_user), not
    root's, falling back to os.path.expanduser when there is none;
    `~name/...` goes through os.path.expanduser. Anything else is
    returned unchanged.
    """
    if path == "~" or path.startswith("~/"):
        home = _user_home_for_brave()
        if home is None:
            return os.path.expanduser(path)
        return home if path == "~" else os.path.join(home, path[2:])
    if path.startswith("~"):
        return os.path.expanduser(path)
    return path


def main(stdscr, override_installations=None):
    """Main TUI event loop.

    `override_installations` lets `--policy-file` force a single synthetic
    target through to the TUI without touching detection.
    """
    curses.curs_set(0)
    init_colors()
    stdscr.keypad(True)
    stdscr.timeout(-1)
    # The description pane starts shown wherever layout() finds room for
    # it; `d` toggles it, and layout() drops it on its own below that room.
    max_y, max_x = stdscr.getmaxyx()
    show_desc = layout(max_y, max_x, True)["pane_lines"] > 0

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

    # Fold what is not in use, then re-derive the selectable list: the
    # cursor must never start on a row the fold just hid.
    apply_startup_collapse(rows)
    sel = selectable_indices(rows)
    if not sel:
        return

    cursor_pos = 0          # index into sel[]
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

    # Show detection warnings on startup, if any
    if brave_info["warnings"]:
        status_msg = brave_info["warnings"][0]
        # Both warnings (Snap confinement, Brave not found) are problems —
        # neither belongs in the success color.
        status_ok = False
    elif brave_info.get("notes") and override_installations is None:
        # A note (Brave Origin found) is information, so it keeps the
        # success color; a warning outranks it for the one status line.
        # Under --policy-file the rows come from the override record and
        # stay live, so the note would describe a list that is not shown.
        status_msg = brave_info["notes"][0]
        status_ok = True
    else:
        status_msg = ""
        status_ok = True

    while True:
        visible_count = viewport_rows(stdscr, show_desc)
        # Recomputed every pass: a fold, a filter keystroke or an import can
        # change what is on screen between one getch() and the next.
        vis = visible_indices(rows, filter_text)
        sel = selectable_indices(rows, filter_text)
        cursor_pos, cursor_idx = resolve_cursor(sel, cursor_idx)
        cursor_vpos = vis.index(cursor_idx) if cursor_idx in vis else -1
        scroll_offset = clamp_scroll(rows, vis, scroll_offset,
                                     cursor_vpos, visible_count)

        draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
             status_msg, status_ok, install_method, filter_text=filter_text,
             show_desc=show_desc)

        key = stdscr.getch()
        if key == curses.KEY_RESIZE:
            curses.update_lines_cols()
            continue
        # A filter matching nothing leaves the cursor on no row at all; NO_ROW
        # matches no branch below, so every one of them falls through.
        row = rows[cursor_idx] if 0 <= cursor_idx < len(rows) else NO_ROW

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
                field_w = template_field_width(max_x)
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
                    field_w = template_field_width(max_x)
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
                field_w = template_field_width(max_x)
                row["scroll"] = max(0, row["cursor"] - field_w + 1)
                continue
            # For other keys (arrows up/down, tab, etc.), fall through
            # to normal handling below

        # --- Global keys ---
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

        elif key == ord("d"):
            show_desc = not show_desc
            status_msg = ""
            max_y, max_x = stdscr.getmaxyx()
            if show_desc and layout(max_y, max_x, True)["pane_lines"] == 0:
                status_msg = "Terminal too short for the description pane."
                status_ok = False

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
                default=filter_text, on_change=preview,
                show_desc=show_desc)
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
                    # Validate: secure/custom DNS requires a template URL
                    dns_mode = get_dns_mode(rows)
                    dns_tmpl = get_dns_template(rows)
                    if dns_mode in ("custom", "secure") and not dns_tmpl:
                        status_msg = "Secure/custom DNS requires a DoH template URL."
                        status_ok = False
                    elif IS_MAC:
                        # Two macOS-only prompts, in order: scope (which
                        # channels) first, mechanism (persist on/off)
                        # second. Each prompt has a sticky default so a
                        # one-keystroke Enter-Enter Apply re-uses prior
                        # state. A --policy-file target is one file, which
                        # a profile cannot stand in for: it is always off.
                        override = _is_override(installations)
                        selected_ids = None
                        if installations and len(installations) > 1:
                            default_ids = (
                                detect_managed_channel_ids(installations)
                                or {i["channel"] for i in installations}
                            )
                            ok, selected_ids = prompt_channel_selection(
                                stdscr, rows, cursor_idx, scroll_offset,
                                btn_idx, install_method, installations,
                                default_ids, filter_text=filter_text,
                                show_desc=show_desc,
                            )
                            if not ok:
                                status_msg = "Apply cancelled."
                                status_ok = True
                                continue
                        if override:
                            ok, persist_mode = True, "off"
                        else:
                            current = detect_persist_mode()
                            ok, persist_mode = prompt_persist_mode(
                                stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                                install_method, current, filter_text=filter_text,
                                show_desc=show_desc,
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
                            if override and status_ok and _is_profile_installed():
                                status_msg += PROFILE_STILL_APPLIES
                    else:
                        status_ok, status_msg = apply_policy(rows, installations)

                elif btn_label == "Reset":
                    status_msg = ("Reset all settings? "
                                  "Press Enter to confirm, any key to cancel.")
                    status_ok = True
                    draw(stdscr, rows, cursor_idx, scroll_offset,
                         focus, btn_idx, status_msg, status_ok,
                         install_method, filter_text=filter_text,
                         show_desc=show_desc)
                    confirm = stdscr.getch()
                    if confirm in (curses.KEY_ENTER, 10, 13):
                        # The TUI's Reset covers every channel, so it also
                        # clears the plists of uninstalled ones (macOS).
                        status_ok, status_msg = reset_policy(
                            rows, installations,
                            all_channels=override_installations is None)
                    else:
                        status_msg = "Reset cancelled."
                        status_ok = True

                elif btn_label == "Import":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "Import path (Esc=cancel)",
                        default="./Presets/", show_desc=show_desc)
                    if ok and path:
                        status_ok, status_msg = import_settings(
                            rows, _expand_prompt_path(path))
                    else:
                        status_msg = "Import cancelled."
                        status_ok = True

                elif btn_label == "Export":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "Export path (Esc=cancel)",
                        default="./SlimBraveNeoSettings.json", show_desc=show_desc)
                    if ok and path:
                        status_ok, status_msg = export_settings(
                            rows, _expand_prompt_path(path))
                    else:
                        status_msg = "Export cancelled."
                        status_ok = True

                elif btn_label == "Quit":
                    break

            elif focus == FOCUS_LIST:
                # Enter on a list item acts like spacebar
                if activate_row(rows, row):
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


def cli_import(path, installations, doh_templates="",
               persist_mode=PERSIST_DEFAULT):
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

    ok, msg = apply_policy(rows, installations, persist_mode=persist_mode)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    if IS_MAC and _is_override(installations) and _is_profile_installed():
        msg += PROFILE_STILL_APPLIES
    print(msg)
    if IS_MAC and persist_mode == "on":
        # The status text has no room for it; the CLI prints the path in
        # full, so the file can be found again if the hand-off is missed.
        if _last_staged_profile:
            print(f"Profile file: {_last_staged_profile}")
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
    # Keys on disk that are built into Brave Origin here never reach the
    # rows, so they never reach the file either; say so rather than let a
    # backup silently shrink.
    left_out = [r["key"] for r in rows
                if r["type"] == ROW_FEATURE and r.get("inert") and r["key"] in policy]
    if left_out:
        n = len(left_out)
        print(f"Note: {n} key{'s' if n != 1 else ''} built into Brave Origin "
              "left out of the export", file=sys.stderr)

    ok, msg = export_settings(rows, path)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)
    return 0


def cli_reset(installations, all_channels=False):
    """Non-interactive: tear down every SlimBrave artifact and repair leaks.

    Clears SlimBrave's keys from each targeted policy file (on macOS a
    plist is deleted only when nothing else is left in it; the Linux file
    is SlimBrave's own and is deleted), removes the Configuration Profile
    (if installed) and repairs leaked Brave-profile prefs, whichever mode
    was used before, so a single --reset always leaves a clean slate.
    `all_channels` (--channels auto) also clears the plists of macOS
    channels that are no longer installed. A --policy-file run leaves the
    profile alone. Returns 1 if the profile is still installed afterwards.
    """
    targets = _dedupe_plist_targets(installations)
    if not targets:
        print(f"No policy file found at {POLICY_FILE}")
        return 0
    override = _is_override(installations)
    try:
        for plist_path, label in targets:
            scope = f" ({label})" if label else ""
            if not os.path.exists(plist_path):
                print(f"No policy file found at {plist_path}{scope}")
            elif not IS_MAC:
                os.remove(plist_path)
                print(f"Removed {plist_path}{scope}")
            else:
                changed, kept = _strip_managed(plist_path)
                if not changed:
                    print(f"No SlimBrave keys in {plist_path}{scope}")
                elif kept:
                    print(f"Removed SlimBrave keys from {plist_path}{scope}; "
                          f"kept {kept} other key{'s' if kept != 1 else ''}")
                else:
                    print(f"Removed {plist_path}{scope}")
        if IS_MAC and all_channels and not override:
            for path, label in _strip_uninstalled_channels(targets):
                print(f"Removed SlimBrave keys from {path} ({label}, not installed)")
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    rc = 0
    if IS_MAC:
        if override:
            _flush_cfprefsd()
        else:
            profile_was_installed = _is_profile_installed()
            _clear_persistence_artifacts()
            _flush_cfprefsd()
            # Asked again rather than trusting the exit status: a non-zero
            # one can also mean there was nothing to remove.
            if _is_profile_installed():
                print(f"Error: {PROFILE_STILL_INSTALLED}", file=sys.stderr)
                rc = 1
            elif profile_was_installed:
                print(f"Removed Configuration Profile "
                      f"({PERSIST_PROFILE_IDENTIFIER})")

    repaired, failed, running = repair_brave_prefs(installations)
    if repaired > 0 and not running:
        print(
            f"Cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''} from Brave's user profile."
        )
    if failed:
        print(f"Warning: {_scrub_failure_note(failed)}", file=sys.stderr)
    if running:
        print(
            "Note: Brave is running — any leaked profile prefs cleaned now "
            "will be overwritten when Brave next saves. Fully close Brave "
            "and run --reset again to make it stick."
        )
    return rc


def _cli_scope_error(args, detected, selected):
    """The CLI's refusal for a --channels scope _scope_conflict would block.

    `detected` is every channel found, `selected` what --channels kept.
    Returns the message __main__ prints before exiting 2, or None.
    """
    if args.policy_file is not None or (args.import_path is None and not args.reset):
        return None
    outside = _scope_conflict(detected, {i["channel"] for i in selected})
    if not outside:
        return None
    one = len(outside) == 1
    return (
        f"Error: {', '.join(outside)} also hold{'s' if one else ''} a SlimBrave "
        "policy, and with the Configuration Profile installed every Apply or "
        f"Reset removes the whole profile. Add {'it' if one else 'them'} to "
        "--channels, or run --reset first and then apply to "
        f"{', '.join(i['label'] for i in selected)}."
    )


def _check_args(args):
    """Return the error for a command line that cannot run, or None.

    Checked before the root check, so a bad command line is refused
    without sudo; __main__ exits 2 on any of them.
    """
    for flag, value in (("--import", args.import_path),
                        ("--export", args.export_path),
                        ("--policy-file", args.policy_file)):
        if value == "":
            return f"Error: {flag} needs a path."
    # --doh-templates is only ever read by cli_import; --reset, --export and
    # the TUI would drop it without a word.
    if args.doh_templates and args.import_path is None:
        return "Error: --doh-templates requires --import"
    # --reset runs first, so an export after it would save nothing; and a
    # failed export would not stop the reset that loses the policy.
    if args.reset and args.export_path is not None:
        return ("Error: --export cannot be combined with --reset. "
                "Run --export first, then --reset.")
    acting = (args.import_path is not None or args.export_path is not None
              or args.reset)
    if args.channels != "auto" and (args.policy_file is not None or not acting):
        return ("Error: --channels applies only to --import, --export or "
                "--reset, and not with --policy-file.")
    if args.persist == "on" and args.policy_file is not None:
        return ("Error: --persist on cannot be combined with --policy-file: "
                "a Configuration Profile targets each channel's bundle, not a file.")
    return None


def parse_args(argv=None):
    """Parse command-line arguments (sys.argv[1:] when argv is None)."""
    parser = argparse.ArgumentParser(
        prog="slimbrave",
        description="SlimBrave Neo - Brave Browser debloater for Linux and macOS",
        epilog=("Run without arguments to launch the interactive TUI. "
                "--reset runs before --import; --export runs last."),
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
            "comma-separated channels "
            f"({', '.join(CHANNEL_IDS)}). Default 'auto' = all detected. "
            "On macOS this selects which per-channel plists are written; on "
            "Linux all channels share one policy file, so it only narrows "
            "prefs-repair and running-process detection."
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
            "if nothing is, or with --policy-file. Linux accepts only 'off'."
        ),
    )
    return parser.parse_args(argv)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    args = parse_args()

    error = _check_args(args)
    if error:
        print(error, file=sys.stderr)
        sys.exit(2)

    # Override policy file path if requested. This is a single-target
    # override that bypasses channel detection — useful for tests and for
    # legacy callers that always wrote to one file.
    override_installations = None
    if args.policy_file is not None:
        if not _is_allowed_policy_file(args.policy_file):
            if IS_MAC:
                rule = "com.brave.Browser[.beta|.nightly].plist"
            else:
                rule = "a slimbrave*.json file"
            print(
                f"--policy-file must be {rule} directly inside one of: "
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

    is_cli = (args.import_path is not None or args.export_path is not None
              or args.reset)

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
            for n in brave_info.get("notes", []):
                print(f"Note: {n}", file=sys.stderr)
            # Before any action: with the profile installed, an Apply or
            # Reset scoped away from a channel that holds a SlimBrave
            # policy would strip that channel too.
            error = _cli_scope_error(args, brave_info["installations"], installations)
            if error:
                print(error, file=sys.stderr)
                sys.exit(2)

        # Resolve --persist: when omitted, reuse whichever mode is
        # currently installed (matches TUI's sticky default) so a
        # re-run never silently demotes a profile back to plist-only.
        # A --policy-file target is one file, so it is always off.
        persist_mode = args.persist
        if persist_mode is None:
            if args.policy_file is not None:
                persist_mode = "off"
            else:
                persist_mode = detect_persist_mode() if IS_MAC else PERSIST_DEFAULT

        # Accumulate so a later success cannot mask an earlier failure
        # (e.g. --reset failing followed by a clean --import).
        rc = 0
        if args.reset:
            rc = max(rc, cli_reset(
                installations,
                all_channels=override_installations is None and args.channels == "auto"))
        if args.import_path is not None:
            rc = max(rc, cli_import(args.import_path, installations,
                                    doh_templates=args.doh_templates or "",
                                    persist_mode=persist_mode))
        if args.export_path is not None:
            rc = max(rc, cli_export(args.export_path, installations))
        sys.exit(rc)

    # Interactive TUI mode
    try:
        curses.wrapper(lambda s: main(s, override_installations))
    except KeyboardInterrupt:
        pass  # Clean exit on Ctrl+C
